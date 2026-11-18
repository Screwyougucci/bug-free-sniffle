"""Bounded TLS certificate, protocol, and weak-cipher assessment."""
from __future__ import annotations

from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlsplit

from .checks import Finding
from .scope import Scope


_NIST_TLS_REFERENCE = "https://csrc.nist.gov/pubs/sp/800/52/r2/final"
_WEAK_CIPHER_RE = r"(?:RC4|3DES|DES-CBC|NULL|EXPORT|ANON|MD5)"


def _finding(url: str, title: str, severity: str, confidence: str,
             evidence: str, remediation: str, kind: str = "finding",
             cwe_ids: list[str] | None = None, references: list[str] | None = None) -> Finding:
    cwes = cwe_ids or ["CWE-326"]
    refs = references or [_NIST_TLS_REFERENCE]
    return Finding(
        category="tls",
        title=title,
        severity=severity,
        confidence=confidence,
        url=url,
        evidence=evidence,
        remediation=remediation,
        kind=kind,
        description="A TLS handshake or certificate observation identified a transport-security configuration issue.",
        impact="Weak protocol versions or cipher suites can reduce the confidentiality and integrity protections of connections.",
        cwe_ids=cwes,
        references=refs,
        remediation_steps=[remediation],
    )


def _handshake(host: str, port: int, version: ssl.TLSVersion, timeout: int,
               cipher_list: str | None = None) -> tuple[str, str] | None:
    """Attempt one TLS handshake with the requested protocol and optional cipher allowlist."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
        if version in {ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1}:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        if cipher_list is not None:
            context.set_ciphers(cipher_list)
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cipher = tls.cipher()
                return tls.version() or version.name, cipher[0] if cipher else "unknown"
    except (OSError, ssl.SSLError, ValueError):
        return None


def inspect_tls(url: str, scope: Scope) -> list[Finding]:
    """Probe TLS 1.0-1.3 and a restricted weak-cipher set; no application data is sent."""
    parts = urlsplit(scope.validate_url(url))
    if parts.scheme != "https":
        return []
    host = parts.hostname
    port = parts.port or 443
    timeout = min(scope.timeout_seconds, 4)
    findings: list[Finding] = []

    # Validate trust chain and record the normal negotiated protocol/cipher.
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                negotiated = tls.version() or "unknown"
                cipher = tls.cipher()
                findings.append(_finding(
                    url, "TLS negotiation details observed", "info", "high",
                    f"Negotiated protocol={negotiated}; cipher={cipher[0] if cipher else 'unknown'}; "
                    f"cipher_bits={cipher[2] if cipher else 'unknown'}.",
                    "No change is required based on this observation alone.",
                    kind="observation",
                    cwe_ids=[],
                    references=[_NIST_TLS_REFERENCE],
                ))
                expiry_text = cert.get("notAfter")
                if expiry_text:
                    expiry = datetime.strptime(expiry_text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        findings.append(_finding(
                            url, "TLS certificate is expired", "high", "high",
                            f"Certificate expired {-days_left} day(s) ago.",
                            "Renew the certificate and verify the complete certificate chain.",
                            cwe_ids=["CWE-295"],
                        ))
                    elif days_left <= 21:
                        findings.append(_finding(
                            url, "TLS certificate expires soon", "medium", "high",
                            f"Certificate expires in {days_left} day(s).",
                            "Renew the certificate before expiration and monitor renewal automation.",
                            cwe_ids=["CWE-324"],
                        ))
    except ssl.SSLCertVerificationError as exc:
        findings.append(_finding(
            url, "TLS certificate validation failed", "high", "high",
            str(exc)[:300],
            "Install a valid, trusted certificate with a matching hostname and complete chain.",
            cwe_ids=["CWE-295"],
        ))
    except (OSError, ssl.SSLError, ValueError) as exc:
        findings.append(_finding(
            url, "Verified TLS handshake could not complete", "info", "low",
            str(exc)[:300],
            "Review connectivity, certificate configuration, and whether the target is actually serving TLS.",
            kind="observation",
        ))

    versions = [
        (getattr(ssl.TLSVersion, "TLSv1", None), "TLS 1.0"),
        (getattr(ssl.TLSVersion, "TLSv1_1", None), "TLS 1.1"),
        (getattr(ssl.TLSVersion, "TLSv1_2", None), "TLS 1.2"),
        (getattr(ssl.TLSVersion, "TLSv1_3", None), "TLS 1.3"),
    ]
    for version, label in versions:
        if version is None:
            continue
        result = _handshake(host, port, version, timeout)
        if result is None:
            continue
        negotiated, cipher = result
        if label in {"TLS 1.0", "TLS 1.1"}:
            findings.append(_finding(
                url, f"Deprecated {label} protocol is accepted", "medium", "high",
                f"A handshake restricted to {label} succeeded; negotiated={negotiated}; cipher={cipher}.",
                "Disable TLS 1.0 and TLS 1.1. Prefer TLS 1.3 and retain TLS 1.2 where compatibility requires it.",
                cwe_ids=["CWE-326"],
            ))
        else:
            findings.append(_finding(
                url, f"{label} protocol is supported", "info", "high",
                f"A handshake restricted to {label} succeeded; negotiated={negotiated}; cipher={cipher}.",
                "No change is required based on protocol support alone.",
                kind="observation",
                cwe_ids=[],
                references=[_NIST_TLS_REFERENCE],
            ))

    # Restrict the client to a short list of obsolete cipher families. A successful
    # handshake proves at least one listed suite is accepted by the server.
    weak_suites = "RC4-SHA:RC4-MD5:DES-CBC3-SHA:NULL-SHA:ADH-AES128-SHA:EXP-RC4-MD5"
    weak_result = _handshake(host, port, getattr(ssl.TLSVersion, "TLSv1_2", ssl.TLSVersion.TLSv1), timeout,
                             cipher_list=weak_suites)
    if weak_result is not None:
        negotiated, cipher = weak_result
        if __import__("re").search(_WEAK_CIPHER_RE, cipher, __import__("re").I):
            findings.append(_finding(
                url, "Server accepts a weak TLS cipher suite", "high", "high",
                f"A TLS 1.2 handshake restricted to legacy cipher suites succeeded; negotiated={negotiated}; cipher={cipher}.",
                "Disable RC4, 3DES/DES, NULL, export-grade, anonymous, and MD5-based cipher suites. Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
                cwe_ids=["CWE-327"],
            ))
    return findings
