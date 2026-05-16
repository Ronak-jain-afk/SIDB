"""
DNS and WHOIS analysis for Shadow IT Discovery Bot.
Analyzes DNS security records (SPF, DMARC, DKIM) and performs basic WHOIS lookups.
"""

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from typing import List, Optional

import dns.resolver

logger = logging.getLogger(__name__)


@dataclass
class DNSAnalysis:
    """Results of DNS security record analysis."""
    domain: str
    spf_record: Optional[str] = None
    spf_valid: bool = False
    dmarc_record: Optional[str] = None
    dmarc_valid: bool = False
    dkim_record: Optional[str] = None
    dkim_valid: bool = False
    mx_servers: List[str] = field(default_factory=list)
    has_mx: bool = False
    whois_org: Optional[str] = None
    whois_created: Optional[str] = None
    risk_factors: List[str] = field(default_factory=list)


class DNSAnalyzer:
    """
    Analyzes DNS security configurations for a domain.
    
    Checks:
    - SPF records (sender policy framework)
    - DMARC records (domain authentication)
    - DKIM records (email signing)
    - MX records (mail servers)
    - Basic WHOIS information
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0

    async def analyze(self, domain: str) -> DNSAnalysis:
        """
        Perform full DNS security analysis for a domain.

        Args:
            domain: The domain to analyze

        Returns:
            DNSAnalysis with all findings and risk factors
        """
        result = DNSAnalysis(domain=domain)

        await asyncio.gather(
            self._check_spf(domain, result),
            self._check_dmarc(domain, result),
            self._check_dkim(domain, result),
            self._check_mx(domain, result),
            self._check_whois(domain, result),
            return_exceptions=True
        )

        self._evaluate_risks(result)
        return result

    async def _check_spf(self, domain: str, result: DNSAnalysis):
        """Check SPF record."""
        try:
            answers = await asyncio.to_thread(
                self.resolver.resolve, domain, "TXT"
            )
            for rdata in answers:
                text = "".join(rdata.strings).lower()
                if text.startswith("v=spf1"):
                    result.spf_record = text
                    result.spf_valid = True
                    return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass

    async def _check_dmarc(self, domain: str, result: DNSAnalysis):
        """Check DMARC record."""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = await asyncio.to_thread(
                self.resolver.resolve, dmarc_domain, "TXT"
            )
            for rdata in answers:
                text = "".join(rdata.strings).lower()
                if text.startswith("v=dmarc1"):
                    result.dmarc_record = text
                    result.dmarc_valid = True
                    return
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass

    async def _check_dkim(self, domain: str, result: DNSAnalysis):
        """Check DKIM record using common selectors."""
        selectors = ["default", "google", "selector1", "selector2", "dkim", "mail"]
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = await asyncio.to_thread(
                    self.resolver.resolve, dkim_domain, "TXT"
                )
                for rdata in answers:
                    text = "".join(rdata.strings)
                    if "v=dkim1" in text.lower():
                        result.dkim_record = f"{selector}: {text[:100]}..."
                        result.dkim_valid = True
                        return
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue

    async def _check_mx(self, domain: str, result: DNSAnalysis):
        """Check MX records."""
        try:
            answers = await asyncio.to_thread(
                self.resolver.resolve, domain, "MX"
            )
            for rdata in answers:
                result.mx_servers.append(str(rdata.exchange).rstrip("."))
            result.has_mx = len(result.mx_servers) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass

    async def _check_whois(self, domain: str, result: DNSAnalysis):
        """Basic WHOIS lookup using whois.iana.org."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("whois.iana.org", 43),
                timeout=5.0
            )
            writer.write(f"{domain}\r\n".encode())
            await writer.drain()

            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            text = data.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                lower = line.lower()
                if "organisation" in lower or "org-name" in lower:
                    result.whois_org = line.split(":", 1)[-1].strip()
                if "created" in lower and ":" in line:
                    result.whois_created = line.split(":", 1)[-1].strip()

        except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as e:
            logger.debug("WHOIS lookup failed for %s: %s", domain, e)

    def _evaluate_risks(self, result: DNSAnalysis):
        """Evaluate security risks based on DNS findings."""
        if not result.spf_valid:
            result.risk_factors.append("SPF record missing - email spoofing protection absent")

        if not result.dmarc_valid:
            result.risk_factors.append("DMARC record missing - no email authentication policy")

        if not result.dkim_valid:
            result.risk_factors.append("DKIM record missing - email signing not configured")

        if result.spf_record and "~all" not in result.spf_record and "-all" not in result.spf_record:
            result.risk_factors.append("SPF record lacks hard/soft fail policy ('-all' or '~all')")


_singleton_instance: Optional[DNSAnalyzer] = None


def get_dns_analyzer() -> DNSAnalyzer:
    """Get the DNS analyzer singleton instance."""
    global _singleton_instance
    if _singleton_instance is None:
        _singleton_instance = DNSAnalyzer()
    return _singleton_instance
