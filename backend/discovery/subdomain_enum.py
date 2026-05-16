"""
Subdomain enumeration via Certificate Transparency logs (crt.sh).
Discovers subdomains by querying public SSL/TLS certificate logs.
"""

import asyncio
import logging
import socket
from typing import List, Optional
from urllib.parse import quote

import httpx

from config import get_settings
from models import Asset, ExposureLevel

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """
    Enumerates subdomains using crt.sh Certificate Transparency API.

    crt.sh aggregates SSL/TLS certificates from public CT logs.
    Each certificate lists domain names, revealing subdomains
    even if they don't resolve publicly.

    API: https://crt.sh/?q=%25.{domain}&output=json
    Free, no API key required.
    """

    CRT_SH_URL = "https://crt.sh"

    def __init__(self):
        self.settings = get_settings()
        self._client = httpx.AsyncClient(timeout=30.0)

    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """
        Query crt.sh for all subdomains of a domain.

        Args:
            domain: The root domain to enumerate (e.g., 'example.com')

        Returns:
            Sorted list of unique subdomain hostnames
        """
        try:
            encoded = quote(f"%{domain}")
            url = f"{self.CRT_SH_URL}/?q={encoded}&output=json"

            response = await self._client.get(url)

            if response.status_code != 200:
                logger.warning("[crt.sh] API returned status %d", response.status_code)
                return []

            entries = response.json()
            if not entries:
                return []

            subdomains = set()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    # Skip wildcard entries like *.example.com
                    if name.startswith("*."):
                        name = name[2:]
                    # Only include names under the target domain
                    if name and name.endswith(f".{domain}") or name == domain:
                        # Remove any trailing dots
                        name = name.rstrip(".")
                        subdomains.add(name)

            result = sorted(subdomains)
            logger.info("[crt.sh] Found %d subdomains for %s", len(result), domain)
            return result

        except httpx.RequestError as e:
            logger.warning("[crt.sh] Request failed: %s", e)
            return []
        except Exception as e:
            logger.error("[crt.sh] Unexpected error: %s", e)
            return []

    async def enumerate_as_assets(self, domain: str) -> List[Asset]:
        """
        Enumerate subdomains and return as basic Asset objects.

        Each subdomain is resolved to an IP and returned as an
        asset with no specific port (port 0). The risk engine
        will score them based on exposure.

        Args:
            domain: The root domain to enumerate

        Returns:
            List of Asset objects (one per resolved subdomain)
        """
        subdomains = await self.enumerate_subdomains(domain)
        assets = []

        for subdomain in subdomains:
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, subdomain)
                asset_id = f"SUBDOMAIN-{subdomain.upper().replace('.', '-')[:32]}"
                assets.append(Asset(
                    asset_id=asset_id,
                    ip=ip,
                    port=0,
                    service="Unknown",
                    hostname=subdomain,
                    exposure=ExposureLevel.PUBLIC,
                    risk_score=0,
                    risk_level="Low"
                ))
            except socket.gaierror:
                logger.debug("[crt.sh] Could not resolve %s", subdomain)
                continue

        logger.info("[crt.sh] Resolved %d/%d subdomains to assets", len(assets), len(subdomains))
        return assets


_singleton_instance: Optional[SubdomainEnumerator] = None


def get_subdomain_enumerator() -> SubdomainEnumerator:
    """Get the subdomain enumerator singleton instance."""
    global _singleton_instance
    if _singleton_instance is None:
        _singleton_instance = SubdomainEnumerator()
    return _singleton_instance
