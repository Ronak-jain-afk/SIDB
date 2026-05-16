"""
Scan Service for Shadow IT Discovery Bot.
Orchestrates the entire scan workflow as a background task.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional

from models import Asset, ChangedAsset, ScanComparison, ScanResult, ScanStatus, Recommendation, RiskLevel
from storage import get_database
from discovery import get_discovery, get_dns_analyzer
from analysis import get_risk_engine, get_ssl_analyzer
from intelligence import get_cve_lookup, get_recommendation_engine
from utils import calculate_posture_score


class ScanService:
    """
    Orchestrates the scan workflow.
    
    Workflow:
    1. Create initial scan record
    2. Discover assets (Shodan or mock)
    3. Analyze risk for each asset
    4. Generate recommendations
    5. Calculate security posture
    6. Save final results
    
    Each step updates the scan status for polling.
    """
    
    def __init__(self):
        self.db = get_database()
        self.discovery = get_discovery()
        self.risk_engine = get_risk_engine()
        self.recommendation_engine = get_recommendation_engine()
    
    async def create_scan(self, target: str) -> ScanResult:
        """
        Initialize a new scan record.
        
        Creates a pending scan with unique ID for tracking.
        
        Args:
            target: Target domain or CIDR to scan
            
        Returns:
            Initial ScanResult with pending status
        """
        scan_id = f"SCAN-{uuid.uuid4().hex[:12].upper()}"
        
        scan = ScanResult(
            scan_id=scan_id,
            domain=target,
            status=ScanStatus.PENDING,
            started_at=datetime.utcnow(),
            assets=[],
            recommendations=[],
            posture_score=None
        )
        
        await self.db.save_scan(scan)
        return scan
    
    async def run_scan(
        self, 
        scan_id: str, 
        domain: str,
        enable_network_scan: bool = False,
        cidr: str = None
    ) -> None:
        """
        Execute the full scan workflow as background task.
        
        This is called after the API returns to the client,
        allowing async scan completion with status polling.
        
        Args:
            scan_id: Scan identifier for tracking
            domain: Target domain to scan
            enable_network_scan: Enable active network scanning
            cidr: Optional CIDR range to scan instead of domain
        """
        try:
            target = cidr or domain
            # ======= PHASE 1: SCANNING =======
            logger.info("[%s] Starting asset discovery for %s", scan_id, target)
            if enable_network_scan:
                logger.info("[%s] Network scanning enabled", scan_id)
            await self._update_status(scan_id, ScanStatus.SCANNING)
            
            # Add small delay for realistic demo feel
            await asyncio.sleep(1)
            
            # Discover assets (with optional network scan / CIDR)
            assets = await self.discovery.discover_assets(
                domain,
                use_network_scan=enable_network_scan,
                cidr=cidr
            )
            logger.info("[%s] Discovered %d assets", scan_id, len(assets))
            
            # ======= PHASE 2: ANALYZING =======
            logger.info("[%s] Analyzing risks", scan_id)
            await self._update_status(scan_id, ScanStatus.ANALYZING)
            
            await asyncio.sleep(0.5)
            
            # Analyze each asset
            analyzed_assets = self.risk_engine.analyze_assets(assets)
            
            # Generate recommendations
            recommendations = self.recommendation_engine.generate_recommendations(
                analyzed_assets
            )
            logger.info("[%s] Generated %d recommendations", scan_id, len(recommendations))
            
            # ======= SSL/TLS ANALYSIS =======
            ssl_analyzer = get_ssl_analyzer()
            ssl_ports = {443, 8443, 993, 995}
            for asset in analyzed_assets:
                if asset.port in ssl_ports and asset.ip:
                    try:
                        factors = await ssl_analyzer.analyze_asset(
                            asset.ip, asset.port, asset.hostname
                        )
                        for factor in factors:
                            if factor not in asset.risk_factors:
                                asset.risk_factors.append(factor)
                                asset.risk_score = min(asset.risk_score + 15, 100)
                        if factors:
                            asset.risk_level = self.risk_engine._classify_risk(asset.risk_score)
                    except Exception as e:
                        logger.debug("[%s] SSL analysis failed for %s:%d - %s",
                                     scan_id, asset.ip, asset.port, e)
            
            # ======= CVE LOOKUP =======
            cve_lookup = get_cve_lookup()
            for asset in analyzed_assets:
                if asset.technology and asset.technology != "Unknown":
                    try:
                        cve_result = await cve_lookup.lookup(asset.technology, asset.version)
                        if cve_result.risk_factors:
                            for factor in cve_result.risk_factors:
                                if factor not in asset.risk_factors:
                                    asset.risk_factors.append(factor)
                                    asset.risk_score = min(asset.risk_score + 10, 100)
                            asset.risk_level = self.risk_engine._classify_risk(asset.risk_score)
                    except Exception as e:
                        logger.debug("[%s] CVE lookup failed for %s - %s",
                                     scan_id, asset.technology, e)
            
            # ======= DNS ANALYSIS =======
            dns_recs = []
            if not cidr:
                logger.info("[%s] Analyzing DNS security records for %s", scan_id, target)
                try:
                    dns = get_dns_analyzer()
                    dns_result = await dns.analyze(target)
                    for idx, factor in enumerate(dns_result.risk_factors):
                        dns_recs.append(Recommendation(
                            recommendation_id=f"DNS-{scan_id[:8]}-{idx:03d}",
                            asset_id="DOMAIN",
                            title=f"DNS Security: {factor.split(' - ')[0]}",
                            description=factor,
                            priority=RiskLevel.MEDIUM,
                            category="Email Security"
                        ))
                    if dns_recs:
                        logger.info("[%s] DNS analysis found %d issues", scan_id, len(dns_recs))
                except Exception as e:
                    logger.warning("[%s] DNS analysis error: %s", scan_id, e)
            
            # Calculate posture score (include DNS findings)
            posture_score = calculate_posture_score(analyzed_assets)
            logger.info("[%s] Security posture: %d/100 (%s)", scan_id, posture_score.score, posture_score.rating.value)
            
            # ======= PHASE 3: COMPLETING =======
            scan = await self.db.get_scan(scan_id)
            if not scan:
                raise RuntimeError(f"Scan record {scan_id} not found in database")
            
            scan.assets = analyzed_assets
            scan.recommendations = recommendations + dns_recs
            scan.posture_score = posture_score
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            
            await self.db.save_scan(scan)
            logger.info("[%s] Scan completed successfully", scan_id)
            
        except Exception as e:
            logger.error("[%s] Scan failed: %s", scan_id, e)
            await self._update_status(
                scan_id, 
                ScanStatus.FAILED, 
                error_message=str(e)
            )
    
    async def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """
        Retrieve scan results by ID.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            ScanResult if found, None otherwise
        """
        return await self.db.get_scan(scan_id)
    
    async def get_scan_status(self, scan_id: str) -> Optional[dict]:
        """
        Get current scan status for polling.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Status dict or None if not found
        """
        scan = await self.db.get_scan(scan_id)
        if not scan:
            return None
        
        # Map status to progress message
        progress_messages = {
            ScanStatus.PENDING: "Initializing scan...",
            ScanStatus.SCANNING: "Discovering assets...",
            ScanStatus.ANALYZING: "Analyzing risks and generating recommendations...",
            ScanStatus.COMPLETED: "Scan complete",
            ScanStatus.FAILED: "Scan failed"
        }
        
        return {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "progress": progress_messages.get(scan.status, "Unknown"),
            "started_at": scan.started_at,
            "completed_at": scan.completed_at
        }
    
    async def compare_scans(self, scan_id_1: str, scan_id_2: str) -> Optional[ScanComparison]:
        """
        Compare two completed scans and return the diff.
        
        Args:
            scan_id_1: Earlier scan ID
            scan_id_2: Later scan ID
            
        Returns:
            ScanComparison with added/removed/changed assets
        """
        scan1 = await self.db.get_scan(scan_id_1)
        scan2 = await self.db.get_scan(scan_id_2)
        
        if not scan1 or not scan2:
            return None
        if scan1.status != ScanStatus.COMPLETED or scan2.status != ScanStatus.COMPLETED:
            return None
        
        assets1 = {(a.ip, a.port): a for a in scan1.assets}
        assets2 = {(a.ip, a.port): a for a in scan2.assets}
        
        keys1 = set(assets1.keys())
        keys2 = set(assets2.keys())
        
        new_keys = keys2 - keys1
        removed_keys = keys1 - keys2
        common_keys = keys1 & keys2
        
        new_assets = [assets2[k] for k in sorted(new_keys)]
        removed_assets = [assets1[k] for k in sorted(removed_keys)]
        
        changed_assets = []
        for key in common_keys:
            a1, a2 = assets1[key], assets2[key]
            if a1.risk_score != a2.risk_score:
                changed_assets.append(ChangedAsset(
                    asset=a2,
                    risk_score_before=a1.risk_score,
                    risk_level_before=a1.risk_level.value,
                    risk_score_after=a2.risk_score,
                    risk_level_after=a2.risk_level.value
                ))
        
        score1 = scan1.posture_score.score if scan1.posture_score else 0
        score2 = scan2.posture_score.score if scan2.posture_score else 0
        
        return ScanComparison(
            scan_id_before=scan_id_1,
            scan_id_after=scan_id_2,
            domain_before=scan1.domain,
            domain_after=scan2.domain,
            new_assets=new_assets,
            removed_assets=removed_assets,
            changed_assets=changed_assets,
            score_before=score1,
            score_after=score2,
            rating_before=scan1.posture_score.rating.value if scan1.posture_score else "",
            rating_after=scan2.posture_score.rating.value if scan2.posture_score else "",
            total_new=len(new_assets),
            total_removed=len(removed_assets),
            total_changed=len(changed_assets)
        )
    
    async def _update_status(
        self, 
        scan_id: str, 
        status: ScanStatus,
        error_message: Optional[str] = None
    ) -> None:
        """Update scan status in database."""
        await self.db.update_scan_status(scan_id, status, error_message)


# Singleton instance (eager initialization)
_service_instance: ScanService = ScanService()


def get_scan_service() -> ScanService:
    """Get the scan service singleton."""
    return _service_instance
