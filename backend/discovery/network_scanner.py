"""
Basic Network Scanner for Shadow IT Discovery Bot.
Performs lightweight port scanning using Python sockets.

WARNING: Only scan networks/systems you own or have explicit permission to test.
Unauthorized scanning may be illegal in your jurisdiction.
"""

import asyncio
import logging
import socket
import uuid
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime

from models import Asset, ExposureLevel

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for network scanning."""
    # Common ports to scan (subset for speed)
    ports: List[int] = None
    # Timeout per port in seconds
    timeout: float = 1.0
    # Maximum concurrent connections
    max_concurrent: int = 50
    # Whether to attempt service detection
    detect_service: bool = True
    
    def __post_init__(self):
        if self.ports is None:
            # Default: Most common risky ports
            self.ports = [
                21,    # FTP
                22,    # SSH
                23,    # Telnet
                25,    # SMTP
                53,    # DNS
                80,    # HTTP
                110,   # POP3
                143,   # IMAP
                443,   # HTTPS
                445,   # SMB
                993,   # IMAPS
                995,   # POP3S
                1433,  # MSSQL
                1521,  # Oracle
                3306,  # MySQL
                3389,  # RDP
                5432,  # PostgreSQL
                5900,  # VNC
                6379,  # Redis
                8080,  # HTTP Proxy
                8443,  # HTTPS Alt
                9200,  # Elasticsearch
                27017, # MongoDB
            ]


class NetworkScanner:
    """
    Basic async network scanner using Python sockets.
    
    This is a lightweight scanner suitable for:
    - Quick connectivity checks
    - Basic port enumeration
    - Demo/educational purposes
    
    For production EASM, consider dedicated tools like nmap, masscan, or Shodan.
    """
    
    # Service banners/signatures for basic detection
    SERVICE_SIGNATURES = {
        b"SSH-": "SSH",
        b"220 ": "FTP/SMTP",
        b"HTTP/": "HTTP",
        b"+OK": "POP3",
        b"* OK": "IMAP",
        b"MongoDB": "MongoDB",
        b"redis": "Redis",
        b"-ERR": "Redis",
        b"mysql": "MySQL",
    }
    
    # Port to service mapping
    PORT_SERVICE_MAP = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }
    
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self._semaphore = None
    
    async def scan_target(
        self,
        target: str,
        ports: List[int] = None,
        domain: str = None
    ) -> List[Asset]:
        """
        Scan a target IP or hostname for open ports.
        
        Args:
            target: IP address or hostname to scan
            ports: List of ports to scan (uses default if None)
            domain: Original domain for context
            
        Returns:
            List of discovered assets (one per open port)
        """
        ports = ports or self.config.ports
        
        # Resolve hostname to IP
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            logger.warning("Could not resolve hostname: %s", target)
            return []
        
        # Create semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        
        # Scan all ports concurrently
        tasks = [
            self._scan_port(ip, port, target if target != ip else None)
            for port in ports
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        assets = []
        for result in results:
            if isinstance(result, Asset):
                assets.append(result)
        
        return assets
    
    async def scan_domain(self, domain: str) -> List[Asset]:
        """
        Scan a domain by resolving and scanning the main host.
        
        For a more comprehensive scan, combine with subdomain enumeration.
        
        Args:
            domain: Domain to scan
            
        Returns:
            List of discovered assets
        """
        # Scan the main domain
        assets = await self.scan_target(domain, domain=domain)
        
        # Also try common subdomains (lightweight enumeration)
        common_subdomains = [
            "www", "mail", "ftp", "admin", "dev", "staging",
            "api", "app", "portal", "vpn", "remote"
        ]
        
        for subdomain in common_subdomains:
            full_host = f"{subdomain}.{domain}"
            try:
                # Quick check if subdomain resolves
                await asyncio.to_thread(socket.gethostbyname, full_host)
                # If it resolves, do a quick scan of common ports
                sub_assets = await self.scan_target(
                    full_host,
                    ports=[80, 443, 22, 21, 3389],  # Quick scan
                    domain=domain
                )
                assets.extend(sub_assets)
            except socket.gaierror:
                # Subdomain doesn't exist
                continue
        
        # Deduplicate by (ip, port) since multiple subdomains can resolve to the same host
        seen = set()
        unique = []
        for asset in assets:
            key = (asset.ip, asset.port)
            if key not in seen:
                seen.add(key)
                unique.append(asset)
        return unique
    
    async def _scan_port(
        self,
        ip: str,
        port: int,
        hostname: str = None
    ) -> Optional[Asset]:
        """
        Scan a single port on a target.
        
        Args:
            ip: Target IP address
            port: Port number to scan
            hostname: Optional hostname
            
        Returns:
            Asset if port is open, None otherwise
        """
        async with self._semaphore:
            try:
                # Create connection with timeout
                conn = asyncio.open_connection(
                    ip, port
                )
                reader, writer = await asyncio.wait_for(
                    conn,
                    timeout=self.config.timeout
                )
                
                # Port is open - try to detect service
                service = self.PORT_SERVICE_MAP.get(port, f"Unknown-{port}")
                banner = None
                
                if self.config.detect_service:
                    banner = await self._grab_banner(reader, writer, port)
                    if banner:
                        detected = self._detect_service_from_banner(banner)
                        if detected:
                            service = detected
                
                # Close connection
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                
                # Create asset
                return Asset(
                    asset_id=f"SCAN-{uuid.uuid4().hex[:8].upper()}",
                    ip=ip,
                    port=port,
                    service=service,
                    technology=self._extract_technology(banner) if banner else None,
                    version=self._extract_version(banner) if banner else None,
                    hostname=hostname,
                    exposure=ExposureLevel.PUBLIC,
                    risk_level="Low",  # Will be set by risk engine
                    risk_score=0,
                    risk_factors=[]
                )
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port is closed or filtered
                return None
            except Exception as e:
                # Other errors
                return None
    
    async def _grab_banner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int
    ) -> Optional[bytes]:
        """
        Attempt to grab service banner.
        
        Some services send banners immediately, others need a probe.
        """
        try:
            # First try to read any immediate banner
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=0.5
            )
            if banner:
                return banner
        except asyncio.TimeoutError:
            pass
        
        # Try sending HTTP probe for web ports
        if port in [80, 8080, 443, 8443]:
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=0.5
                )
                return banner
            except:
                pass
        
        return None
    
    def _detect_service_from_banner(self, banner: bytes) -> Optional[str]:
        """Detect service type from banner content."""
        banner_lower = banner.lower()
        
        for signature, service in self.SERVICE_SIGNATURES.items():
            if signature.lower() in banner_lower:
                return service
        
        return None
    
    def _extract_technology(self, banner: bytes) -> Optional[str]:
        """Extract technology/product name from banner."""
        if not banner:
            return None
        
        try:
            text = banner.decode('utf-8', errors='ignore')
            
            # Common patterns
            if "nginx" in text.lower():
                return "nginx"
            elif "apache" in text.lower():
                return "Apache"
            elif "openssh" in text.lower():
                return "OpenSSH"
            elif "microsoft" in text.lower():
                return "Microsoft IIS"
            elif "vsftpd" in text.lower():
                return "vsFTPd"
            
        except:
            pass
        
        return None
    
    def _extract_version(self, banner: bytes) -> Optional[str]:
        """Extract version number from banner."""
        if not banner:
            return None
        
        try:
            import re
            text = banner.decode('utf-8', errors='ignore')
            
            # Common version patterns
            patterns = [
                r'(\d+\.\d+(?:\.\d+)?)',  # x.y or x.y.z
                r'version[:\s]+(\d+\.\d+)',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except:
            pass
        
        return None


# Singleton instance (eager initialization)
_scanner_instance: NetworkScanner = NetworkScanner()


def get_network_scanner(config: ScanConfig = None) -> NetworkScanner:
    """Get the network scanner singleton. If config provided, return a new instance."""
    if config is not None:
        return NetworkScanner(config)
    return _scanner_instance
