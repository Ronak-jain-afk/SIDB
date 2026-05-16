"""
Asset Discovery Module for Shadow IT Discovery Bot.
Handles discovery of internet-facing assets using Shodan API, network scanning, or mock data.
"""

import asyncio
import json
import logging
import httpx
from typing import List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

from config import get_settings, is_shodan_available
from models import Asset, ExposureLevel
from utils.rate_limiter import get_rate_limiter
from discovery.network_scanner import NetworkScanner, ScanConfig
from discovery.subdomain_enum import get_subdomain_enumerator


class AssetDiscovery:
    """
    Discovers internet-facing assets for a given domain.
    
    Data sources (in order of preference):
    1. Shodan API - when API key is configured
    2. Network Scanner - when enabled (requires explicit opt-in)
    3. Mock Data - fallback for demos
    
    Includes rate limiting for API calls.
    """
    
    SHODAN_BASE_URL = "https://api.shodan.io"
    
    # Shodan API rate limits (free tier: 1 req/sec)
    SHODAN_RATE_LIMIT = 1.0  # requests per second
    SHODAN_BURST_SIZE = 1    # burst capacity
    
    def __init__(self):
        self.settings = get_settings()
        self.mock_data_path = Path(self.settings.mock_dir) / "mock_assets.json"
        self.rate_limiter = get_rate_limiter()
        self.network_scanner = None
        self._shodan_client = httpx.AsyncClient(timeout=30.0)
        
        # Initialize Shodan rate limiter
        self.rate_limiter.get_limiter(
            "shodan",
            requests_per_second=self.SHODAN_RATE_LIMIT,
            burst_size=self.SHODAN_BURST_SIZE
        )
    
    async def discover_assets(
        self, 
        domain: str,
        use_network_scan: bool = False,
        scan_timeout: float = 1.0
    ) -> List[Asset]:
        """
        Main discovery entry point.
        
        Args:
            domain: Target domain to discover assets for
            use_network_scan: Enable network scanning (requires permission)
            scan_timeout: Timeout per port when scanning
            
        Returns:
            List of discovered assets
        """
        all_assets = []
        
        # ======= SOURCE 1: SHODAN API =======
        if is_shodan_available():
            try:
                logger.info("[Discovery] Querying Shodan API for %s...", domain)
                shodan_assets = await self._discover_via_shodan(domain)
                if shodan_assets:
                    all_assets.extend(shodan_assets)
                    logger.info("[Discovery] Shodan returned %d assets", len(shodan_assets))
            except Exception as e:
                logger.warning("[Discovery] Shodan API error: %s", e)
        
        # ======= SOURCE 2: NETWORK SCANNER =======
        if use_network_scan:
            try:
                logger.info("[Discovery] Running network scan for %s...", domain)
                scan_assets = await self._discover_via_scan(domain, scan_timeout)
                if scan_assets:
                    # Deduplicate with Shodan results
                    existing_ips_ports = {
                        (a.ip, a.port) for a in all_assets
                    }
                    new_assets = [
                        a for a in scan_assets 
                        if (a.ip, a.port) not in existing_ips_ports
                    ]
                    all_assets.extend(new_assets)
                    logger.info("[Discovery] Network scan found %d new assets", len(new_assets))
            except Exception as e:
                logger.warning("[Discovery] Network scan error: %s", e)
        
        # ======= SOURCE 3: CRT.SH SUBDOMAIN ENUMERATION =======
        try:
            logger.info("[Discovery] Enumerating subdomains via crt.sh for %s...", domain)
            enumerator = get_subdomain_enumerator()
            subdomain_assets = await enumerator.enumerate_as_assets(domain)
            if subdomain_assets:
                existing_ips = {a.ip for a in all_assets}
                new_assets = [a for a in subdomain_assets if a.ip not in existing_ips]
                if new_assets:
                    all_assets.extend(new_assets)
                    logger.info("[Discovery] crt.sh found %d new subdomain assets", len(new_assets))
        except Exception as e:
            logger.warning("[Discovery] crt.sh enumeration error: %s", e)
        
        # ======= SOURCE 4: MOCK DATA FALLBACK =======
        if not all_assets:
            logger.info("[Discovery] Using mock data for %s", domain)
            all_assets = await self._load_mock_assets(domain)
        
        return all_assets
    
    async def _discover_via_scan(
        self, 
        domain: str, 
        timeout: float = 1.0
    ) -> List[Asset]:
        """
        Discover assets using network 
        scanning.
        
        WARNING: Only scan networks you own or have permission to test.
        
        Args:
            domain: Target domain
            timeout: Connection timeout per port
            
        Returns:
            List of discovered assets
        """
        if self.network_scanner is None:
            config = ScanConfig(timeout=timeout)
            self.network_scanner = NetworkScanner(config)
        
        return await self.network_scanner.scan_domain(domain)
    
    async def _discover_via_shodan(self, domain: str) -> List[Asset]:
        """
        Query Shodan API for assets related to a domain.
        
        Uses FREE Shodan API endpoints:
        - /dns/resolve: Resolve domain to IP (free)
        - /shodan/host/{ip}: Get host details (free)
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered assets from Shodan
        """
        assets = []
        api_key = self.settings.shodan_api_key
        
        client = self._shodan_client
        # Step 1: Resolve domain to IP using free DNS endpoint
        wait_time = await self.rate_limiter.acquire("shodan")
        if wait_time > 0:
            logger.info("[Shodan] Rate limited, waited %.2fs", wait_time)
        
        dns_url = f"{self.SHODAN_BASE_URL}/dns/resolve"
        params = {"hostnames": domain, "key": api_key}
        
        response = await client.get(dns_url, params=params)
        
        if response.status_code != 200:
            logger.warning("Shodan DNS API returned status %d", response.status_code)
            return []
        
        dns_data = response.json()
        ip_address = dns_data.get(domain)
        
        if not ip_address:
            logger.warning("[Shodan] Could not resolve %s", domain)
            return []
        
        logger.info("[Shodan] Resolved %s to %s", domain, ip_address)
        
        # Step 2: Get host info using free /shodan/host/{ip} endpoint
        wait_time = await self.rate_limiter.acquire("shodan")
        
        host_url = f"{self.SHODAN_BASE_URL}/shodan/host/{ip_address}"
        params = {"key": api_key}
        
        response = await client.get(host_url, params=params)
        
        if response.status_code == 404:
            logger.info("[Shodan] No data found for %s", ip_address)
            return []
        
        if response.status_code == 429:
            logger.warning("[Shodan] Rate limit exceeded, backing off...")
            await asyncio.sleep(2.0)
            return []
        
        if response.status_code == 200:
            host_data = response.json()
            # Host data contains ports array with service info
            ports_data = host_data.get("data", [])
            
            for idx, port_info in enumerate(ports_data[:20]):
                asset = self._normalize_shodan_host_result(
                    host_data, port_info, domain, idx
                )
                assets.append(asset)
                
            if not ports_data:
                # Create a basic asset for the IP even without port data
                assets.append(Asset(
                    asset_id=f"SHODAN-{domain.upper().replace('.', '-')}-{ip_address.replace('.', '-')}",
                    ip=ip_address,
                    port=0,
                    service="Unknown",
                    technology=host_data.get("os", "Unknown"),
                    hostname=(host_data.get("hostnames") or [None])[0],
                    exposure=ExposureLevel.PUBLIC,
                    risk_score=0,
                    risk_level="Low"
                ))
        else:
            logger.warning("Shodan Host API returned status %d", response.status_code)
        
        return assets
    
    def _normalize_shodan_host_result(
        self, 
        host_data: dict, 
        port_info: dict,
        domain: str,
        index: int
    ) -> Asset:
        """
        Convert Shodan /shodan/host/{ip} response into Asset object.
        
        Args:
            host_data: Main host response
            port_info: Individual port/service data
            domain: Original domain
            index: Index for ID generation
            
        Returns:
            Normalized Asset object
        """
        ip = host_data.get("ip_str", "Unknown")
        port = port_info.get("port", 0)
        
        # Detect service/product
        product = port_info.get("product", "")
        module = port_info.get("_shodan", {}).get("module", "")
        transport = port_info.get("transport", "tcp")
        
        service = product or module or self._guess_service_from_port(port)
        
        # Technology detection
        technology = port_info.get("product", "Unknown")
        version = port_info.get("version", "")
        if version:
            technology = f"{technology} {version}"
        
        return Asset(
            asset_id=f"SHODAN-{domain.upper().replace('.', '-')}-{index:03d}",
            ip=ip,
            port=port,
            service=service,
            technology=technology.strip() or "Unknown",
            version=version or None,
            hostname=(host_data.get("hostnames") or [None])[0],
            exposure=ExposureLevel.PUBLIC,
            risk_score=0,
            risk_level="Low"
        )
    
    def _guess_service_from_port(self, port: int) -> str:
        """Guess service name from common port numbers."""
        port_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        return port_services.get(port, f"Port-{port}")
    
    async def _load_mock_assets(self, domain: str) -> List[Asset]:
        """
        Load mock asset data for demo purposes.
        
        The mock data simulates realistic organizational exposures
        with varied risk levels for interesting demo visualizations.
        
        Args:
            domain: Domain to customize mock data for
            
        Returns:
            List of mock assets
        """
        # Try to load from file first
        if self.mock_data_path.exists():
            try:
                with open(self.mock_data_path, 'r') as f:
                    mock_data = json.load(f)
                    
                # Customize hostnames with the requested domain
                assets = []
                for item in mock_data.get("assets", []):
                    # Replace placeholder domain with actual domain
                    if "hostname" in item and item["hostname"]:
                        item["hostname"] = item["hostname"].replace("{domain}", domain)
                    assets.append(Asset(**item))
                
                return assets
            except Exception as e:
                logger.error("Error loading mock data: %s", e)
        
        # Fallback to hardcoded mock data
        return self._generate_default_mock_assets(domain)
    
    def _generate_default_mock_assets(self, domain: str) -> List[Asset]:
        """
        Generate default mock assets when no mock file exists.
        
        These represent common Shadow IT exposures found in organizations:
        - FTP servers with outdated software
        - Admin panels exposed to internet
        - Database ports open
        - Development/staging servers
        - Legacy services
        
        Args:
            domain: Domain for hostname generation
            
        Returns:
            List of mock assets
        """
        return [
            # Critical: FTP with anonymous access
            Asset(
                asset_id="MOCK-A001",
                ip="34.102.45.12",
                port=21,
                service="FTP",
                technology="vsFTPd",
                version="2.3.4",
                hostname=f"ftp.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Critical",
                risk_score=0,
                risk_factors=[]
            ),
            # Critical: Open MongoDB
            Asset(
                asset_id="MOCK-A002",
                ip="34.102.45.15",
                port=27017,
                service="MongoDB",
                technology="MongoDB",
                version="3.6.0",
                hostname=f"db.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Critical",
                risk_score=0,
                risk_factors=[]
            ),
            # High: Admin panel exposed
            Asset(
                asset_id="MOCK-A003",
                ip="34.102.45.20",
                port=8080,
                service="HTTP",
                technology="WordPress",
                version="5.2.1",
                hostname=f"admin.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="High",
                risk_score=0,
                risk_factors=[]
            ),
            # High: Telnet enabled
            Asset(
                asset_id="MOCK-A004",
                ip="34.102.45.22",
                port=23,
                service="Telnet",
                technology="Linux Telnetd",
                version=None,
                hostname=f"legacy.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="High",
                risk_score=0,
                risk_factors=[]
            ),
            # Medium: SSH on non-standard port
            Asset(
                asset_id="MOCK-A005",
                ip="34.102.45.25",
                port=22,
                service="SSH",
                technology="OpenSSH",
                version="7.4",
                hostname=f"dev.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Medium",
                risk_score=0,
                risk_factors=[]
            ),
            # Medium: Staging server without TLS
            Asset(
                asset_id="MOCK-A006",
                ip="34.102.45.30",
                port=80,
                service="HTTP",
                technology="nginx",
                version="1.14.0",
                hostname=f"staging.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Medium",
                risk_score=0,
                risk_factors=[]
            ),
            # Medium: MySQL exposed
            Asset(
                asset_id="MOCK-A007",
                ip="34.102.45.35",
                port=3306,
                service="MySQL",
                technology="MySQL",
                version="5.7.21",
                hostname=f"mysql.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="High",
                risk_score=0,
                risk_factors=[]
            ),
            # Low: HTTPS API
            Asset(
                asset_id="MOCK-A008",
                ip="34.102.45.40",
                port=443,
                service="HTTPS",
                technology="nginx",
                version="1.18.0",
                hostname=f"api.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Low",
                risk_score=0,
                risk_factors=[]
            ),
            # High: Redis exposed
            Asset(
                asset_id="MOCK-A009",
                ip="34.102.45.45",
                port=6379,
                service="Redis",
                technology="Redis",
                version="4.0.9",
                hostname=f"cache.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Critical",
                risk_score=0,
                risk_factors=[]
            ),
            # Medium: RDP exposed
            Asset(
                asset_id="MOCK-A010",
                ip="34.102.45.50",
                port=3389,
                service="RDP",
                technology="Microsoft RDP",
                version=None,
                hostname=f"desktop.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="High",
                risk_score=0,
                risk_factors=[]
            ),
            # Low: Mail server
            Asset(
                asset_id="MOCK-A011",
                ip="34.102.45.55",
                port=25,
                service="SMTP",
                technology="Postfix",
                version="3.3.0",
                hostname=f"mail.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Low",
                risk_score=0,
                risk_factors=[]
            ),
            # Critical: Jenkins exposed
            Asset(
                asset_id="MOCK-A012",
                ip="34.102.45.60",
                port=8080,
                service="HTTP",
                technology="Jenkins",
                version="2.150.1",
                hostname=f"ci.{domain}",
                exposure=ExposureLevel.PUBLIC,
                risk_level="Critical",
                risk_score=0,
                risk_factors=[]
            ),
        ]


# Singleton instance (eager initialization)
_discovery_instance: AssetDiscovery = AssetDiscovery()


def get_discovery() -> AssetDiscovery:
    """Get the discovery singleton instance."""
    return _discovery_instance
