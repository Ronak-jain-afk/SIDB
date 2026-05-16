"""
CVE lookup module for Shadow IT Discovery Bot.
Queries the NVD (National Vulnerability Database) API to find known
vulnerabilities for discovered software versions.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from utils.rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 5.0 / 30.0  # 5 requests per 30 seconds (free tier)
NVD_BURST = 1


@dataclass
class CVEFinding:
    """A single CVE match for a software version."""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    attack_vector: Optional[str] = None


@dataclass
class CVEResult:
    """CVE lookup results for a single asset."""
    technology: str
    version: Optional[str]
    findings: List[CVEFinding] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)


class CVELookup:
    """
    Looks up known CVEs for software versions using the NVD API.

    Uses the NVD API 2.0:
    https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=...
    """

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=15.0)
        self._init_limiter()

    def _init_limiter(self):
        """Register NVD rate limiter."""
        limiter = get_rate_limiter()
        limiter.get_limiter("nvd", requests_per_second=NVD_RATE_LIMIT, burst_size=NVD_BURST)

    async def lookup(self, technology: str, version: str = None) -> CVEResult:
        """
        Look up CVEs for a software product and optional version.

        Args:
            technology: Product name (e.g., 'openssh', 'nginx')
            version: Version string (e.g., '7.4', '1.14.0')

        Returns:
            CVEResult with matching CVEs and risk factors
        """
        result = CVEResult(technology=technology, version=version)

        if not technology or technology == "Unknown":
            return result

        # Build search keywords
        keywords = [technology]
        if version and version != "Unknown":
            # Extract major.minor for focused search
            parts = version.split(".")
            if len(parts) >= 2:
                keywords.append(f"{parts[0]}.{parts[1]}")
            else:
                keywords.append(version)

        query = " ".join(keywords)

        try:
            # Rate limit NVD requests
            limiter = get_rate_limiter()
            await limiter.acquire("nvd", tokens=1)

            params = {
                "keywordSearch": query,
                "resultsPerPage": 5,
                "cvssV3Severity": "CRITICAL,HIGH"
            }

            response = await self._client.get(NVD_BASE_URL, params=params)

            if response.status_code == 403:
                logger.warning("[CVE] NVD API rate limited (403)")
                return result
            if response.status_code != 200:
                logger.debug("[CVE] NVD API returned %d", response.status_code)
                return result

            data = response.json()
            vulns = data.get("vulnerabilities", [])

            for vuln in vulns[:5]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")

                # Description
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d["value"][:200]
                        break
                if not desc:
                    continue

                # CVSS score
                cvss_score = 0.0
                severity = "UNKNOWN"
                attack_vector = None
                metrics = cve.get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        attack_vector = cvss_data.get("attackVector", None)
                        break

                result.findings.append(CVEFinding(
                    cve_id=cve_id,
                    description=desc,
                    cvss_score=cvss_score,
                    severity=severity,
                    attack_vector=attack_vector
                ))

            if result.findings:
                result.risk_factors.append(
                    f"Found {len(result.findings)} known CVE(s) for {technology}"
                    + (f" {version}" if version else "")
                )
                for cve in result.findings[:3]:
                    result.risk_factors.append(
                        f"{cve.cve_id} (CVSS: {cve.cvss_score}) - {cve.description[:80]}..."
                    )

        except httpx.RequestError as e:
            logger.debug("[CVE] NVD request failed: %s", e)
        except Exception as e:
            logger.warning("[CVE] Lookup error: %s", e)

        return result


_singleton_instance: Optional[CVELookup] = None


def get_cve_lookup() -> CVELookup:
    """Get the CVE lookup singleton instance."""
    global _singleton_instance
    if _singleton_instance is None:
        _singleton_instance = CVELookup()
    return _singleton_instance
