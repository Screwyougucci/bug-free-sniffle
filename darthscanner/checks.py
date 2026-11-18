"""Evidence-based passive HTTP checks."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from http.cookies import SimpleCookie

from .http_client import HttpResponse


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    confidence: str
    url: str
    evidence: str
    remediation: str
    kind: str = "finding"

    def to_dict(self) -> dict:
        return asdict(self)


def inspect_http(response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    if response.status is None:
        return findings
    headers = response.headers
    is_html = "text/html" in headers.get("content-type", "").lower()

    if is_html:
        checks = [
            ("content-security-policy", "Content Security Policy is missing", "medium",
             "Define a restrictive Content-Security-Policy; start with report-only mode and tighten it."),
            ("x-content-type-options", "X-Content-Type-Options is missing", "low",
             "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Referrer-Policy is missing", "low",
             "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin."),
            ("permissions-policy", "Permissions-Policy is missing", "low",
             "Explicitly disable browser features the application does not need."),
        ]
        for name, title, severity, remediation in checks:
            if name not in headers:
                findings.append(Finding(
                    "http-headers", title, severity, "high", response.url,
                    f"Response status {response.status}; header {name!r} was not present.",
                    remediation,
                ))
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
            findings.append(Finding(
                "http-headers", "Clickjacking protection was not detected", "low", "medium",
                response.url, "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
                "Set a suitable frame-ancestors directive, for example frame-ancestors 'self'.",
            ))

    if response.url.lower().startswith("https://") and "strict-transport-security" not in headers:
        findings.append(Finding(
            "http-headers", "HSTS header is missing", "low", "high", response.url,
            "HTTPS response did not include Strict-Transport-Security.",
            "Enable HSTS after confirming all subdomains and HTTPS configuration are ready.",
        ))

    server = headers.get("server")
    if server:
        findings.append(Finding(
            "information", "Server banner is disclosed", "info", "high", response.url,
            f"Server header: {server[:160]}",
            "Consider removing unnecessary product/version details from response headers.",
            kind="observation",
        ))

    set_cookie = headers.get("set-cookie")
    if set_cookie:
        cookie = SimpleCookie()
        try:
            cookie.load(set_cookie)
        except Exception:
            cookie = SimpleCookie()
        for name, morsel in cookie.items():
            missing = []
            if response.url.lower().startswith("https://") and not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if not morsel["samesite"]:
                missing.append("SameSite")
            if missing:
                findings.append(Finding(
                    "cookies", f"Cookie {name!r} is missing recommended flags", "low", "medium",
                    response.url, "Missing: " + ", ".join(missing),
                    "Set Secure, HttpOnly, and an appropriate SameSite attribute where compatible.",
                ))

    return findings
