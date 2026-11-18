"""Conservative TLS certificate validation using the platform trust store."""
from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlsplit

from .checks import Finding
from .scope import Scope


def inspect_tls(url: str, scope: Scope) -> list[Finding]:
    parts = urlsplit(scope.validate_url(url))
    if parts.scheme != "https":
        return []
    host = parts.hostname
    port = parts.port or 443
    findings: list[Finding] = []
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=scope.timeout_seconds) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                expiry_text = cert.get("notAfter")
                if expiry_text:
                    expiry = datetime.strptime(expiry_text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        findings.append(Finding(
                            "tls", "TLS certificate is expired", "high", "high", url,
                            f"Certificate expired {-days_left} day(s) ago.",
                            "Renew the certificate and verify the full certificate chain.",
                        ))
                    elif days_left <= 21:
                        findings.append(Finding(
                            "tls", "TLS certificate expires soon", "medium", "high", url,
                            f"Certificate expires in {days_left} day(s).",
                            "Renew the certificate before expiration and monitor renewal automation.",
                        ))
    except ssl.SSLCertVerificationError as exc:
        findings.append(Finding(
            "tls", "TLS certificate validation failed", "high", "high", url,
            str(exc)[:300], "Install a valid, trusted certificate with a matching hostname and full chain.",
        ))
    except (OSError, ssl.SSLError, ValueError) as exc:
        findings.append(Finding(
            "tls", "TLS inspection could not complete", "info", "low", url,
            str(exc)[:300], "Review connectivity and TLS configuration manually.", kind="observation",
        ))
    return findings
