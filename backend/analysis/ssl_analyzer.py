"""
SSL/TLS Configuration Analyzer for Shadow IT Discovery Bot.
Checks certificate validity, protocol versions, and cipher strength.
"""

import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# TLS versions that are considered weak/insecure
WEAK_TLS_VERSIONS = {
    ssl.TLSVersion.SSLv3: "SSLv3",
    ssl.TLSVersion.TLSv1: "TLSv1.0",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
}

SECURE_TLS_VERSIONS = {
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}


@dataclass
class SSLAnalysis:
    """Results of SSL/TLS certificate analysis."""
    hostname: str
    port: int
    has_ssl: bool = False
    tls_version: Optional[str] = None
    tls_version_secure: bool = False
    cipher_name: Optional[str] = None
    cipher_strength: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_expiry: Optional[str] = None
    cert_days_remaining: Optional[int] = None
    cert_expired: bool = False
    cert_expiring_soon: bool = False
    risk_factors: List[str] = field(default_factory=list)


class SSLAnalyzer:
    """
    Analyzes SSL/TLS configuration of a host:port.

    Connects to the target, performs an SSL handshake,
    and inspects the certificate and protocol parameters.
    """

    SECURE_CIPHERS = ["TLS_AES", "TLS_CHACHA", "ECDHE", "AES_256", "AES_128"]

    WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "SHA1", "CBC", "EXPORT", "NULL"]

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def analyze(self, hostname: str, port: int = 443) -> SSLAnalysis:
        """
        Analyze SSL/TLS configuration for a host:port.

        Args:
            hostname: Target hostname or IP
            port: Target port (default 443)

        Returns:
            SSLAnalysis with findings and risk factors
        """
        result = SSLAnalysis(hostname=hostname, port=port)

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(self.timeout)
            raw_sock.connect((hostname, port))

            ssl_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
            result.has_ssl = True

            # TLS version
            tls_version = ssl_sock.version()
            result.tls_version = tls_version
            tls_enum = ssl_sock._sslobj._get_tls_version() if hasattr(ssl_sock._sslobj, '_get_tls_version') else None
            result.tls_version_secure = tls_enum not in WEAK_TLS_VERSIONS if tls_enum else "TLSv1.2" in (tls_version or "")

            # Cipher
            cipher = ssl_sock.cipher()
            if cipher:
                result.cipher_name = cipher[0]
                result.cipher_strength = f"{cipher[2]} bits"

            # Certificate
            cert = ssl_sock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                result.cert_subject = subject.get("commonName", "Unknown")

                issuer = dict(x[0] for x in cert.get("issuer", []))
                result.cert_issuer = issuer.get("commonName", "Unknown")

                not_after = cert.get("notAfter")
                if not_after:
                    result.cert_expiry = not_after
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    result.cert_days_remaining = days_left
                    result.cert_expired = days_left < 0
                    result.cert_expiring_soon = 0 <= days_left <= 30

            ssl_sock.close()
            raw_sock.close()

        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
            logger.debug("SSL analysis failed for %s:%d - %s", hostname, port, e)

        self._evaluate_risks(result)
        return result

    async def analyze_asset(self, ip: str, port: int, hostname: str = None) -> List[str]:
        """
        Convenience method: analyze an asset and return risk factors.

        Args:
            ip: Asset IP address
            port: Asset port
            hostname: Optional hostname for SNI

        Returns:
            List of risk factor strings
        """
        target = hostname or ip
        result = await self.analyze(target, port)
        return result.risk_factors

    def _evaluate_risks(self, result: SSLAnalysis):
        """Evaluate security risks based on SSL/TLS findings."""
        if not result.has_ssl:
            return

        # Expired certificate
        if result.cert_expired:
            result.risk_factors.append(
                f"SSL certificate expired {abs(result.cert_days_remaining)} days ago"
            )

        # Expiring soon
        if result.cert_expiring_soon:
            result.risk_factors.append(
                f"SSL certificate expires in {result.cert_days_remaining} days"
            )

        # Weak TLS version
        if result.tls_version and not result.tls_version_secure:
            result.risk_factors.append(
                f"Weak TLS version: {result.tls_version} - upgrade to TLSv1.2+"
            )

        # Weak cipher
        if result.cipher_name:
            lower = result.cipher_name.lower()
            for weak in self.WEAK_CIPHERS:
                if weak.lower() in lower:
                    result.risk_factors.append(
                        f"Weak cipher: {result.cipher_name}"
                    )
                    break


_singleton_instance: Optional[SSLAnalyzer] = None


def get_ssl_analyzer() -> SSLAnalyzer:
    """Get the SSL analyzer singleton instance."""
    global _singleton_instance
    if _singleton_instance is None:
        _singleton_instance = SSLAnalyzer()
    return _singleton_instance
