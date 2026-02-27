"""
Recommendation Engine for Shadow IT Discovery Bot.
Generates actionable remediation guidance based on identified risks.
"""

import uuid
from typing import List, Dict
from models import Asset, Recommendation, RiskLevel


class RecommendationEngine:
    """
    Maps identified risks to actionable remediation recommendations.
    
    Each recommendation includes:
    - Specific actions to take
    - Priority based on risk level
    - Category for grouping related fixes
    """
    
    # ============== SERVICE-BASED RECOMMENDATIONS ==============
    # Recommendations keyed by service type
    
    SERVICE_RECOMMENDATIONS: Dict[str, Dict] = {
        "FTP": {
            "title": "Secure or Disable FTP Service",
            "description": (
                "1. If FTP is required, migrate to SFTP (SSH File Transfer Protocol) for encrypted transfers.\n"
                "2. Disable anonymous FTP access immediately.\n"
                "3. Implement IP whitelist restrictions.\n"
                "4. Enable logging for all FTP activities.\n"
                "5. Consider using cloud-based secure file sharing instead."
            ),
            "category": "Network Security"
        },
        "Telnet": {
            "title": "Disable Telnet and Migrate to SSH",
            "description": (
                "1. Disable Telnet service immediately - it transmits credentials in plaintext.\n"
                "2. Use SSH for all remote terminal access.\n"
                "3. Implement key-based SSH authentication.\n"
                "4. Remove Telnet packages from the system.\n"
                "5. Audit systems for other legacy protocols."
            ),
            "category": "Network Security"
        },
        "SSH": {
            "title": "Harden SSH Configuration",
            "description": (
                "1. Disable password authentication, use SSH keys only.\n"
                "2. Change default port 22 to a non-standard port.\n"
                "3. Implement fail2ban or similar brute-force protection.\n"
                "4. Restrict SSH access to specific IP ranges.\n"
                "5. Disable root login over SSH.\n"
                "6. Use SSH protocol version 2 only."
            ),
            "category": "Access Control"
        },
        "RDP": {
            "title": "Secure Remote Desktop Access",
            "description": (
                "1. Place RDP behind a VPN - never expose directly to internet.\n"
                "2. Enable Network Level Authentication (NLA).\n"
                "3. Implement account lockout policies.\n"
                "4. Use multi-factor authentication.\n"
                "5. Keep Windows systems patched (BlueKeep, etc.).\n"
                "6. Monitor for brute-force attempts."
            ),
            "category": "Access Control"
        },
        "MongoDB": {
            "title": "Secure MongoDB Instance",
            "description": (
                "1. Enable authentication immediately - MongoDB defaults to open access.\n"
                "2. Bind to localhost or private network only (not 0.0.0.0).\n"
                "3. Enable TLS/SSL for all connections.\n"
                "4. Create specific user accounts with minimal privileges.\n"
                "5. Enable audit logging.\n"
                "6. Consider network segmentation."
            ),
            "category": "Database Security"
        },
        "MySQL": {
            "title": "Secure MySQL Database",
            "description": (
                "1. Bind to localhost or internal network only.\n"
                "2. Remove anonymous user accounts.\n"
                "3. Set strong passwords for all accounts.\n"
                "4. Enable SSL/TLS for remote connections.\n"
                "5. Implement IP-based access restrictions.\n"
                "6. Regularly audit user privileges."
            ),
            "category": "Database Security"
        },
        "PostgreSQL": {
            "title": "Secure PostgreSQL Database",
            "description": (
                "1. Configure pg_hba.conf to restrict access.\n"
                "2. Use SSL for all connections.\n"
                "3. Implement role-based access control.\n"
                "4. Bind to internal interfaces only.\n"
                "5. Enable connection logging.\n"
                "6. Regular security updates."
            ),
            "category": "Database Security"
        },
        "Redis": {
            "title": "Secure Redis Instance",
            "description": (
                "1. Enable protected mode and set a strong password.\n"
                "2. Bind to internal interfaces only (not 0.0.0.0).\n"
                "3. Rename or disable dangerous commands (FLUSHALL, CONFIG).\n"
                "4. Use Redis 6+ with ACLs for fine-grained access control.\n"
                "5. Enable TLS encryption.\n"
                "6. Never expose Redis to the public internet."
            ),
            "category": "Database Security"
        },
        "HTTP": {
            "title": "Enable HTTPS and Security Headers",
            "description": (
                "1. Obtain SSL/TLS certificate and redirect all HTTP to HTTPS.\n"
                "2. Implement security headers (HSTS, CSP, X-Frame-Options).\n"
                "3. Configure secure TLS versions (1.2 or 1.3 only).\n"
                "4. Disable weak cipher suites.\n"
                "5. Implement rate limiting.\n"
                "6. Enable access logging and monitoring."
            ),
            "category": "Web Security"
        },
        "HTTPS": {
            "title": "Verify HTTPS Configuration",
            "description": (
                "1. Verify certificate validity and chain.\n"
                "2. Test configuration with SSL Labs (ssllabs.com/ssltest).\n"
                "3. Implement HSTS with long max-age.\n"
                "4. Enable OCSP stapling.\n"
                "5. Disable TLS 1.0 and 1.1.\n"
                "6. Regular certificate renewal process."
            ),
            "category": "Web Security"
        },
        "SMB": {
            "title": "Secure SMB File Sharing",
            "description": (
                "1. Never expose SMB to the internet.\n"
                "2. Disable SMBv1 immediately.\n"
                "3. Restrict to internal network only.\n"
                "4. Require SMB signing.\n"
                "5. Use strong authentication.\n"
                "6. Keep Windows systems patched (EternalBlue, etc.)."
            ),
            "category": "Network Security"
        },
        "VNC": {
            "title": "Secure VNC Remote Access",
            "description": (
                "1. Place VNC behind a VPN.\n"
                "2. Use strong authentication.\n"
                "3. Enable encryption if supported.\n"
                "4. Consider alternatives like SSH tunneling.\n"
                "5. Change default port.\n"
                "6. Monitor access logs."
            ),
            "category": "Access Control"
        },
        "SMTP": {
            "title": "Secure Mail Server",
            "description": (
                "1. Implement SPF, DKIM, and DMARC records.\n"
                "2. Disable open relay.\n"
                "3. Require TLS (STARTTLS) for connections.\n"
                "4. Implement rate limiting.\n"
                "5. Configure spam filtering.\n"
                "6. Regular monitoring for abuse."
            ),
            "category": "Email Security"
        },
    }
    
    # ============== TECHNOLOGY-SPECIFIC RECOMMENDATIONS ==============
    
    TECHNOLOGY_RECOMMENDATIONS: Dict[str, Dict] = {
        "Jenkins": {
            "title": "Secure Jenkins CI/CD Platform",
            "description": (
                "1. Place Jenkins behind VPN or reverse proxy with authentication.\n"
                "2. Enable security realm and authorization.\n"
                "3. Use Role-Based Access Control plugin.\n"
                "4. Disable CLI over remoting.\n"
                "5. Restrict script console access.\n"
                "6. Audit and remove unnecessary plugins.\n"
                "7. Secure credentials with Credentials plugin."
            ),
            "category": "CI/CD Security"
        },
        "WordPress": {
            "title": "Secure WordPress Installation",
            "description": (
                "1. Keep WordPress core, themes, and plugins updated.\n"
                "2. Use strong admin passwords and change default username.\n"
                "3. Implement two-factor authentication.\n"
                "4. Install security plugin (Wordfence, Sucuri).\n"
                "5. Restrict wp-admin access by IP.\n"
                "6. Disable file editing in dashboard.\n"
                "7. Regular security scans."
            ),
            "category": "CMS Security"
        },
    }
    
    # ============== GENERIC RECOMMENDATIONS ==============
    
    GENERIC_RECOMMENDATIONS: Dict[str, Dict] = {
        "outdated": {
            "title": "Update Outdated Software",
            "description": (
                "1. Update to the latest stable version immediately.\n"
                "2. Subscribe to security advisories for this software.\n"
                "3. Implement automated patching where possible.\n"
                "4. Test updates in staging before production.\n"
                "5. Maintain an inventory of software versions."
            ),
            "category": "Patch Management"
        },
        "public_exposure": {
            "title": "Restrict Public Access",
            "description": (
                "1. Evaluate if public access is necessary.\n"
                "2. Implement VPN or IP whitelisting.\n"
                "3. Use reverse proxy with authentication.\n"
                "4. Consider zero-trust network architecture.\n"
                "5. Segment critical services from internet."
            ),
            "category": "Network Segmentation"
        },
        "admin_panel": {
            "title": "Secure Administrative Interface",
            "description": (
                "1. Restrict access to internal network or VPN.\n"
                "2. Implement multi-factor authentication.\n"
                "3. Use strong unique passwords.\n"
                "4. Enable audit logging.\n"
                "5. Change default URLs if possible.\n"
                "6. Implement account lockout policies."
            ),
            "category": "Access Control"
        },
    }
    
    def generate_recommendations(self, assets: List[Asset]) -> List[Recommendation]:
        """
        Generate remediation recommendations for analyzed assets.
        
        Recommendations are generated based on:
        1. Service type (FTP, SSH, databases, etc.)
        2. Technology detected (Jenkins, WordPress, etc.)
        3. Risk factors identified by the analysis engine
        
        Args:
            assets: List of analyzed assets with risk data
            
        Returns:
            List of recommendations sorted by priority
        """
        recommendations = []
        
        for asset in assets:
            # Skip low-risk assets - focus on actionable items
            if asset.risk_level == RiskLevel.LOW:
                continue
            
            asset_recommendations = self._generate_for_asset(asset)
            recommendations.extend(asset_recommendations)
        
        # Sort by priority (Critical > High > Medium > Low)
        priority_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3
        }
        recommendations.sort(key=lambda r: priority_order.get(r.priority, 4))
        
        return recommendations
    
    def _generate_for_asset(self, asset: Asset) -> List[Recommendation]:
        """
        Generate recommendations for a single asset.
        
        Args:
            asset: Asset to generate recommendations for
            
        Returns:
            List of recommendations for this asset
        """
        recommendations = []
        
        # 1. Service-based recommendation
        service_rec = self._get_service_recommendation(asset)
        if service_rec:
            recommendations.append(service_rec)
        
        # 2. Technology-based recommendation
        tech_rec = self._get_technology_recommendation(asset)
        if tech_rec:
            recommendations.append(tech_rec)
        
        # 3. Check risk factors for additional recommendations
        factor_recs = self._get_factor_recommendations(asset)
        recommendations.extend(factor_recs)
        
        return recommendations
    
    def _get_service_recommendation(self, asset: Asset) -> Recommendation:
        """Get recommendation based on service type."""
        service = asset.service
        
        if service in self.SERVICE_RECOMMENDATIONS:
            rec_data = self.SERVICE_RECOMMENDATIONS[service]
            return Recommendation(
                recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                asset_id=asset.asset_id,
                title=rec_data["title"],
                description=rec_data["description"],
                priority=asset.risk_level,
                category=rec_data["category"]
            )
        
        return None
    
    def _get_technology_recommendation(self, asset: Asset) -> Recommendation:
        """Get recommendation based on technology detected."""
        if not asset.technology:
            return None
        
        for tech_name, rec_data in self.TECHNOLOGY_RECOMMENDATIONS.items():
            if tech_name.lower() in asset.technology.lower():
                return Recommendation(
                    recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                    asset_id=asset.asset_id,
                    title=rec_data["title"],
                    description=rec_data["description"],
                    priority=asset.risk_level,
                    category=rec_data["category"]
                )
        
        return None
    
    def _get_factor_recommendations(self, asset: Asset) -> List[Recommendation]:
        """Get recommendations based on specific risk factors."""
        recommendations = []
        seen_categories = set()
        
        for factor in asset.risk_factors:
            factor_lower = factor.lower()
            
            # Check for outdated software
            if "outdated" in factor_lower and "outdated" not in seen_categories:
                rec_data = self.GENERIC_RECOMMENDATIONS["outdated"]
                recommendations.append(Recommendation(
                    recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                    asset_id=asset.asset_id,
                    title=rec_data["title"],
                    description=rec_data["description"],
                    priority=asset.risk_level,
                    category=rec_data["category"]
                ))
                seen_categories.add("outdated")
            
            # Check for admin interface
            elif "admin" in factor_lower and "admin" not in seen_categories:
                rec_data = self.GENERIC_RECOMMENDATIONS["admin_panel"]
                recommendations.append(Recommendation(
                    recommendation_id=f"REC-{uuid.uuid4().hex[:8].upper()}",
                    asset_id=asset.asset_id,
                    title=rec_data["title"],
                    description=rec_data["description"],
                    priority=asset.risk_level,
                    category=rec_data["category"]
                ))
                seen_categories.add("admin")
        
        return recommendations


# Singleton instance
_engine_instance = None


def get_recommendation_engine() -> RecommendationEngine:
    """Get or create the recommendation engine singleton instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = RecommendationEngine()
    return _engine_instance
