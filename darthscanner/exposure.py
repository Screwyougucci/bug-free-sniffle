"""Non-content exposure checks using HEAD only.

This module never downloads or parses the contents of candidate sensitive files.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from .checks import Finding
from .http_client import SafeHttpClient
from .scope import Scope


# High-signal names only. Every probe uses HEAD and never falls back to GET.
_PROBES = [
    ("/.env", "environment file", "high"),
    ("/.env.local", "local environment file", "high"),
    ("/.env.production", "production environment file", "high"),
    ("/.env.backup", "environment backup", "high"),
    ("/.git/HEAD", "Git metadata", "medium"),
    ("/.git/config", "Git repository configuration", "medium"),
    ("/.svn/entries", "Subversion metadata", "medium"),
    ("/.hg/hgrc", "Mercurial configuration", "medium"),
    ("/id_rsa", "private SSH key file", "high"),
    ("/id_rsa.bak", "private SSH key backup", "high"),
    ("/wp-config.php.bak", "WordPress configuration backup", "high"),
    ("/wp-config.php.old", "WordPress configuration backup", "high"),
    ("/config.php.bak", "PHP configuration backup", "high"),
    ("/configuration.php~", "application configuration backup", "high"),
    ("/web.config.bak", "IIS configuration backup", "high"),
    ("/appsettings.json.bak", "application settings backup", "high"),
    ("/application.properties.bak", "Java application properties backup", "high"),
    ("/settings.py.bak", "Python settings backup", "high"),
    ("/database.sql", "database dump", "high"),
    ("/db.sql", "database dump", "high"),
    ("/dump.sql", "database dump", "high"),
    ("/backup.sql", "database backup", "high"),
    ("/backup.zip", "site backup archive", "medium"),
    ("/site-backup.zip", "site backup archive", "medium"),
    ("/www.zip", "web-root archive", "medium"),
    ("/.DS_Store", "macOS directory metadata", "low"),
    ("/phpinfo.php", "PHP diagnostic page", "medium"),
]


def probe_sensitive_paths(target: str, scope: Scope, client: SafeHttpClient) -> list[Finding]:
    """Check likely sensitive paths with bounded HEAD requests and no body reads."""
    scope.validate_url(target)
    parts = urlsplit(target)
    base = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    findings: list[Finding] = []
    remaining = max(0, client.max_requests - client.requests_made)

    for path, label, severity in _PROBES[:remaining]:
        response = client.head(base.rstrip("/") + path)
        if response.status is None or not 200 <= response.status < 300:
            continue

        content_type = response.headers.get("content-type", "unknown").split(";", 1)[0].strip().lower()
        length = response.headers.get("content-length", "not supplied")
        is_generic_html = content_type in {"text/html", "application/xhtml+xml"}
        confidence = "low" if is_generic_html else "medium"
        actual_severity = "low" if is_generic_html else severity
        evidence = (
            f"HEAD {path} returned HTTP {response.status}; Content-Type={content_type or 'not supplied'}; "
            f"Content-Length={length}. No response body was requested or stored."
        )
        title = f"Potentially exposed {label}: {path}"
        if is_generic_html:
            title += " (verify; may be a generic route fallback)"
        findings.append(Finding(
            category="exposure",
            title=title,
            severity=actual_severity,
            confidence=confidence,
            url=base.rstrip("/") + path,
            evidence=evidence,
            remediation=(
                "Remove the file from the web root, deny direct web access at the server or reverse proxy, "
                "rotate any credentials that may have been exposed, and review access logs. Confirm access "
                "through an approved internal process; this scanner intentionally does not download the file."
            ),
            kind="candidate-exposure" if not is_generic_html else "observation",
            description=f"A HEAD request indicates that a path commonly associated with {label} may be reachable.",
            impact="If the path contains secrets, source metadata, private keys, database exports, or backups, it could disclose sensitive system information.",
            cwe_ids=["CWE-552"],
            references=["https://cwe.mitre.org/data/definitions/552.html"],
            affected_component=path,
            remediation_steps=[
                "Confirm the file is not required to be public.",
                "Move it outside the document root or deny access at the web server.",
                "Rotate secrets if exposure is confirmed.",
                "Review access logs for previous requests to the path.",
            ],
        ))
    return findings
