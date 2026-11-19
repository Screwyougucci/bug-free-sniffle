"""Passive server-side exposure checks over responses already fetched in scope.

No exploit payloads, state-changing methods, or additional network requests are used.
Findings are indicators for manual verification, not proof of exploitability.
"""
from __future__ import annotations

import re

from .checks import Finding


_RULES = (
    ("database-error", "Database error details exposed", "medium", "CWE-209",
     re.compile(r"(?:SQLSTATE\[[0-9A-Z]+\]|you have an error in your sql syntax|\b(?:sqlite|postgresql|mysql|mariadb|odbc)\b.{0,60}\b(?:syntax error|exception|error)\b|\b(?:psycopg2|PDOException|mysqli_sql_exception)\b)", re.I),
     "Database diagnostics can disclose schema, query, driver, or implementation details.",
     "Return generic client errors; keep database diagnostics in access-controlled server logs."),
    ("stack-trace", "Server-side stack trace exposed", "medium", "CWE-209",
     re.compile(r"(?:Traceback \(most recent call last\)|\b(?:NullPointerException|ClassNotFoundException|\w+Exception)\b.{0,160}\bat\s+[\w.$]+\([^)]*:\d+\)|\bat\s+/[^\s:]+\.(?:php|py|rb|java|js):\d+)", re.I),
     "Stack traces can disclose internal paths, component names, and execution details.",
     "Disable detailed error pages in production and log diagnostics privately."),
    ("template-error", "Server-side template diagnostic exposed", "low", "CWE-209",
     re.compile(r"(?:TemplateSyntaxError|TemplateNotFound|UndefinedError:|\bTwig\\Error\\|\bJinja2?\b.{0,80}(?:template|undefined)|\bFreeMarker template error\b|\bThymeleaf\b.{0,80}exception)", re.I),
     "Template diagnostics may reveal template names, engine details, or unsafe rendering paths.",
     "Return generic rendering errors and keep template diagnostics in protected logs."),
    ("local-path", "Internal filesystem path disclosed", "low", "CWE-200",
     re.compile(r'(?:File "/(?:var|srv|opt|home|app|usr/local)/[^"\n]{1,180}"|\b[A-Z]:\\(?:inetpub|wwwroot|app|users)\\[^\r\n]{1,180})', re.I),
     "An absolute server path reveals deployment layout and may aid follow-on attacks.",
     "Avoid returning absolute paths in client-visible errors."),
    ("debug-page", "Development or debug error page exposed", "medium", "CWE-489",
     re.compile(r"(?:Werkzeug Debugger|The install worked successfully!.*Django|You're seeing this error because you have DEBUG = True|Whoops! There was an error|Symfony Exception\s*\[|Whitelabel Error Page|Detailed Error Information.*ASP\.NET)", re.I | re.S),
     "A development error page may expose environment details, stack traces, or interactive diagnostics.",
     "Disable development/debug mode in production and restrict diagnostic interfaces to trusted operators."),
    ("runtime-fatal", "Uncaught server runtime error exposed", "low", "CWE-209",
     re.compile(r"(?:Fatal error:\s*Uncaught|Uncaught exception ['\"]|panic: runtime error:|Unhandled exception\s*[:\[])", re.I),
     "An uncaught runtime error is visible to clients and may disclose implementation details.",
     "Handle exceptions at the application boundary and return generic client responses."),
)

_VERSIONED_SERVER = re.compile(r"(?i)\b(?:nginx|apache|microsoft-iis|iis|openresty|caddy|lighttpd|gunicorn|uvicorn|tomcat|jetty|express)\b[^\r\n]{0,80}?\b\d+\.\d+(?:\.\d+)?")
_DEBUG_HEADERS = {
    "x-debug-token": "Debug token header exposed",
    "x-debug-token-link": "Debug toolbar link header exposed",
    "x-werkzeug-debugger": "Werkzeug debugger header exposed",
    "x-laravel-debugbar": "Laravel debug bar header exposed",
    "x-aspnet-version": "ASP.NET runtime version header exposed",
    "x-aspnetmvc-version": "ASP.NET MVC version header exposed",
}


def _make_finding(response, *, title: str, severity: str, confidence: str,
                  kind: str, cwe: str, description: str, evidence: str,
                  remediation: str, confidence_score: int) -> Finding:
    return Finding(
        category="server-side",
        title=title,
        severity=severity,
        confidence=confidence,
        url=response.url,
        kind=kind,
        description=description,
        impact="This reveals server implementation or diagnostic details; no code execution or unauthorized data access is established.",
        evidence=evidence[:500],
        remediation=remediation,
        cwe_ids=[cwe],
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
        remediation_steps=[remediation],
        confidence_score=confidence_score,
    )


def inspect_server_response(response) -> list[Finding]:
    """Inspect one already-fetched response for server diagnostics and metadata leaks."""
    findings: list[Finding] = []
    headers = getattr(response, "headers", {}) or {}
    status = getattr(response, "status", None)
    body_bytes = getattr(response, "body", b"") or b""

    for header, title in _DEBUG_HEADERS.items():
        value = headers.get(header, "")
        if value:
            findings.append(_make_finding(
                response, title=title, severity="medium", confidence="high",
                kind="debug-header", cwe="CWE-489",
                description="A response header associated with a development diagnostic interface is exposed.",
                evidence=f"HTTP {status}; {header}: {str(value)[:120]!r}.",
                remediation="Disable debug tooling in production and ensure diagnostic endpoints require operator authentication.",
                confidence_score=85,
            ))

    for header, value in (("server", headers.get("server", "")),
                          ("x-powered-by", headers.get("x-powered-by", ""))):
        if value and _VERSIONED_SERVER.search(value):
            findings.append(_make_finding(
                response, title="Detailed server software version disclosed",
                severity="info", confidence="medium", kind="server-banner",
                cwe="CWE-200",
                description="A response header exposes a server product and explicit version string.",
                evidence=f"{header}: {str(value)[:160]!r}.",
                remediation="Suppress unnecessary product/version details in public response headers; maintain accurate internal asset inventory.",
                confidence_score=65,
            ))

    if not body_bytes:
        return findings
    body = body_bytes[:1_000_000].decode("utf-8", errors="replace")
    for kind, title, severity, cwe, pattern, description, remediation in _RULES:
        match = pattern.search(body)
        if not match:
            continue
        snippet = re.sub(r"\s+", " ", match.group(0))[:180]
        score = 85 if kind in {"database-error", "stack-trace", "debug-page"} else 70
        findings.append(_make_finding(
            response, title=title, severity=severity, confidence="high" if score >= 80 else "medium",
            kind=kind, cwe=cwe, description=description,
            evidence=f"HTTP {status}; matched response excerpt: {snippet!r}.",
            remediation=remediation, confidence_score=score,
        ))
    return findings


def inspect_server_fuzz_observations(observations: list[dict]) -> list[Finding]:
    """Turn reproducible 5xx fuzz observations into low-confidence review leads."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for item in observations:
        if not item.get("server_error"):
            continue
        url = str(item.get("endpoint_url") or "")
        parameter = str(item.get("parameter") or "")
        key = (url, parameter)
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            category="server-side",
            title="Input variation triggered an HTTP 5xx response",
            severity="info",
            confidence="low",
            url=url,
            kind="input-error-path",
            description="A benign type/boundary input caused a server error compared with the request baseline.",
            impact="This may indicate an unhandled input edge case or availability risk; it does not establish injection or data exposure.",
            evidence=(
                f"Parameter {parameter!r}; case {item.get('case')!r}; "
                f"baseline HTTP {item.get('baseline_status')}; observed HTTP {item.get('status')}; "
                f"response SHA-256 {item.get('response_sha256', '')}."
            ),
            remediation="Validate input types and bounds; handle expected validation failures with controlled 4xx responses.",
            cwe_ids=["CWE-755"],
            references=["https://cwe.mitre.org/data/definitions/755.html"],
            remediation_steps=["Review the matching server log entry and add input validation and error handling."],
            confidence_score=30,
        ))
    return findings
