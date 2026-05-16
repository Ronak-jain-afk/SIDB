"""
Risk Analysis Engine for Shadow IT Discovery Bot.
Evaluates security risks for discovered assets using rule-based heuristics.
"""

from typing import List
from models import Asset, RiskLevel


class RiskEngine:
    """
    Rule-based risk analysis engine.
    
    Applies cybersecurity heuristics to calculate risk scores
    and classify risk levels for each discovered asset.
    
    This is NOT machine learning - it uses deterministic rules
    based on common security best practices and known risk factors.
    """
    
    # ============== HIGH-RISK PORTS ==============
    # These ports represent services commonly exploited in attacks
    
    CRITICAL_PORTS = {
        21: ("FTP", 40, "FTP service exposed - legacy protocol without encryption"),
        23: ("Telnet", 50, "Telnet exposed - unencrypted terminal access"),
        6379: ("Redis", 45, "Redis exposed - often misconfigured without authentication"),
        27017: ("MongoDB", 45, "MongoDB exposed - database accessible from internet"),
        9200: ("Elasticsearch", 45, "Elasticsearch exposed - data store publicly accessible"),
        11211: ("Memcached", 40, "Memcached exposed - cache amplification risk"),
    }
    
    HIGH_RISK_PORTS = {
        22: ("SSH", 25, "SSH exposed - brute force target"),
        3389: ("RDP", 35, "RDP exposed - common ransomware entry point"),
        5900: ("VNC", 35, "VNC exposed - remote desktop without encryption"),
        1433: ("MSSQL", 30, "MS SQL Server exposed - database accessible"),
        3306: ("MySQL", 30, "MySQL exposed - database accessible"),
        5432: ("PostgreSQL", 30, "PostgreSQL exposed - database accessible"),
        1521: ("Oracle", 30, "Oracle DB exposed - database accessible"),
        445: ("SMB", 35, "SMB exposed - file sharing vulnerability risk"),
        139: ("NetBIOS", 30, "NetBIOS exposed - Windows networking risk"),
    }
    
    MEDIUM_RISK_PORTS = {
        25: ("SMTP", 15, "SMTP exposed - mail server may relay spam"),
        53: ("DNS", 15, "DNS exposed - potential amplification attack vector"),
        80: ("HTTP", 10, "HTTP without encryption - data transmitted in clear"),
        8080: ("HTTP-Proxy", 15, "HTTP proxy/admin interface exposed"),
        8443: ("HTTPS-Alt", 10, "Alternative HTTPS port - verify configuration"),
    }
    
    # ============== RISKY KEYWORDS ==============
    # Technology/hostname patterns that increase risk
    
    ADMIN_KEYWORDS = ["admin", "administrator", "wp-admin", "phpmyadmin", "cpanel", "webmin"]
    DEV_KEYWORDS = ["dev", "staging", "test", "debug", "internal", "beta", "demo"]
    CI_CD_KEYWORDS = ["jenkins", "gitlab", "travis", "circleci", "bamboo", "teamcity"]
    
    # ============== OUTDATED VERSIONS ==============
    # Known vulnerable versions of common software
    
    OUTDATED_VERSIONS = {
        "vsFTPd": {"vulnerable_below": "3.0.0", "reason": "Pre-3.0 has known backdoor vulnerabilities"},
        "OpenSSH": {"vulnerable_below": "8.0", "reason": "Older versions have privilege escalation risks"},
        "nginx": {"vulnerable_below": "1.16.0", "reason": "HTTP/2 vulnerabilities in older versions"},
        "Apache": {"vulnerable_below": "2.4.50", "reason": "Path traversal vulnerabilities"},
        "WordPress": {"vulnerable_below": "6.0", "reason": "Multiple security patches missing"},
        "MySQL": {"vulnerable_below": "8.0", "reason": "Security improvements in 8.x series"},
        "MongoDB": {"vulnerable_below": "4.0", "reason": "Authentication bypass in older versions"},
        "Redis": {"vulnerable_below": "6.0", "reason": "Security mode improvements in 6.x"},
        "Jenkins": {"vulnerable_below": "2.300", "reason": "Multiple CVEs in older versions"},
    }
    
    def analyze_asset(self, asset: Asset) -> Asset:
        """
        Analyze a single asset and calculate its risk score.
        
        The analysis applies multiple heuristics cumulatively:
        1. Port-based risk (what service is exposed)
        2. Technology detection (known risky software)
        3. Version analysis (outdated = vulnerable)
        4. Hostname/keyword analysis (admin panels, dev servers)
        5. Exposure level (public internet = higher risk)
        
        Args:
            asset: Asset to analyze
            
        Returns:
            Asset with populated risk_score, risk_level, and risk_factors
        """
        score = 0
        factors = []
        
        # ======= 1. PORT-BASED RISK ANALYSIS =======
        port_score, port_factors = self._analyze_port(asset.port)
        score += port_score
        factors.extend(port_factors)
        
        # ======= 2. TECHNOLOGY ANALYSIS =======
        tech_score, tech_factors = self._analyze_technology(asset.technology, asset.hostname)
        score += tech_score
        factors.extend(tech_factors)
        
        # ======= 3. VERSION ANALYSIS =======
        version_score, version_factors = self._analyze_version(asset.technology, asset.version)
        score += version_score
        factors.extend(version_factors)
        
        # ======= 4. HOSTNAME/KEYWORD ANALYSIS =======
        keyword_score, keyword_factors = self._analyze_keywords(asset.hostname, asset.service)
        score += keyword_score
        factors.extend(keyword_factors)
        
        # ======= 5. EXPOSURE MODIFIER =======
        if asset.exposure.value == "Public":
            score += 10
            factors.append("Asset publicly accessible from internet")
        
        # Cap score at 100
        score = min(score, 100)
        
        # Classify risk level
        risk_level = self._classify_risk(score)
        
        # Update asset with results
        asset.risk_score = score
        asset.risk_level = risk_level
        asset.risk_factors = factors
        
        return asset
    
    def analyze_assets(self, assets: List[Asset]) -> List[Asset]:
        """
        Analyze multiple assets.
        
        Args:
            assets: List of assets to analyze
            
        Returns:
            List of analyzed assets with risk data
        """
        return [self.analyze_asset(asset) for asset in assets]
    
    def _analyze_port(self, port: int) -> tuple:
        """
        Analyze risk based on open port.
        
        Different ports have different inherent risks:
        - Critical: Legacy protocols, databases without auth
        - High: Remote access, databases
        - Medium: Web services, mail
        
        Returns:
            Tuple of (score_impact, list_of_factors)
        """
        score = 0
        factors = []
        
        if port in self.CRITICAL_PORTS:
            _, impact, reason = self.CRITICAL_PORTS[port]
            score += impact
            factors.append(reason)
        elif port in self.HIGH_RISK_PORTS:
            _, impact, reason = self.HIGH_RISK_PORTS[port]
            score += impact
            factors.append(reason)
        elif port in self.MEDIUM_RISK_PORTS:
            _, impact, reason = self.MEDIUM_RISK_PORTS[port]
            score += impact
            factors.append(reason)
        else:
            # Unknown port still gets minimal score
            score += 5
            factors.append(f"Non-standard port {port} exposed")
        
        return score, factors
    
    def _analyze_technology(self, technology: str, hostname: str) -> tuple:
        """
        Analyze risk based on detected technology.
        
        Certain technologies are inherently riskier when exposed:
        - CI/CD systems (contain secrets, code)
        - Admin panels (authentication bypass targets)
        - Legacy systems (often unpatched)
        
        Returns:
            Tuple of (score_impact, list_of_factors)
        """
        score = 0
        factors = []
        
        if not technology:
            return score, factors
        
        tech_lower = technology.lower()
        host_lower = (hostname or "").lower()
        
        # CI/CD systems are high value targets
        for keyword in self.CI_CD_KEYWORDS:
            if keyword in tech_lower or keyword in host_lower:
                score += 30
                factors.append(f"CI/CD system ({technology}) exposed - contains secrets and code access")
                break
        
        # Admin panels
        for keyword in self.ADMIN_KEYWORDS:
            if keyword in tech_lower:
                score += 25
                factors.append(f"Admin interface ({technology}) exposed - authentication bypass risk")
                break
        
        return score, factors
    
    def _analyze_version(self, technology: str, version: str) -> tuple:
        """
        Analyze risk based on software version.
        
        Outdated software is a primary attack vector.
        We compare against known vulnerable version thresholds.
        
        Returns:
            Tuple of (score_impact, list_of_factors)
        """
        score = 0
        factors = []
        
        if not technology or not version:
            return score, factors
        
        # Check if technology has known version issues
        for tech_name, vuln_info in self.OUTDATED_VERSIONS.items():
            if tech_name.lower() in technology.lower():
                if self._is_version_outdated(version, vuln_info["vulnerable_below"]):
                    score += 20
                    factors.append(
                        f"Outdated {technology} {version} - {vuln_info['reason']}"
                    )
                break
        
        return score, factors
    
    def _is_version_outdated(self, current: str, threshold: str) -> bool:
        """
        Compare version strings to determine if outdated.
        
        Simple comparison - extracts first numeric portion.
        For hackathon purposes, we don't need complex semver parsing.
        """
        try:
            # Extract major.minor from version strings
            current_parts = current.split(".")[:2]
            threshold_parts = threshold.split(".")[:2]
            
            current_tuple = tuple(int(p) for p in current_parts if p.isdigit())
            threshold_tuple = tuple(int(p) for p in threshold_parts if p.isdigit())
            
            return current_tuple < threshold_tuple
        except (ValueError, IndexError):
            return False  # Can't determine, assume OK
    
    def _analyze_keywords(self, hostname: str, service: str) -> tuple:
        """
        Analyze hostname and service for risky keywords.
        
        Development/staging servers are often:
        - Less secured than production
        - Contain test credentials
        - Forgotten and unpatched
        
        Returns:
            Tuple of (score_impact, list_of_factors)
        """
        score = 0
        factors = []
        
        combined = f"{hostname or ''} {service or ''}".lower()
        
        # Check for admin keywords
        for keyword in self.ADMIN_KEYWORDS:
            if keyword in combined:
                score += 20
                factors.append(f"Admin interface detected in hostname/service")
                break
        
        # Check for development keywords
        for keyword in self.DEV_KEYWORDS:
            if keyword in combined:
                score += 15
                factors.append(f"Development/staging server detected - often less secured")
                break
        
        return score, factors
    
    def _classify_risk(self, score: int) -> RiskLevel:
        """
        Classify numeric score into risk level.
        
        Thresholds:
        - 0-25: Low - minimal exposure, properly configured
        - 26-50: Medium - some concerns, should address
        - 51-75: High - significant risks, prioritize
        - 76-100: Critical - immediate action required
        """
        if score <= 25:
            return RiskLevel.LOW
        elif score <= 50:
            return RiskLevel.MEDIUM
        elif score <= 75:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL


# Singleton instance (eager initialization)
_engine_instance: RiskEngine = RiskEngine()


def get_risk_engine() -> RiskEngine:
    """Get the risk engine singleton instance."""
    return _engine_instance
