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
)


def inspect_server_response(response) -> list[Finding]:
    """Inspect a fetched response for clear diagnostic disclosure signatures."""
    if response.status is None or not response.body:
        return []
    body = response.body[:1_000_000].decode("utf-8", errors="replace")
    findings: list[Finding] = []
    for kind, title, severity, cwe, pattern, description, remediation in _RULES:
        match = pattern.search(body)
        if not match:
            continue
        snippet = re.sub(r"\s+", " ", match.group(0))[:180]
        findings.append(Finding(
            category="server-side",
            title=title,
            severity=severity,
            confidence="high",
            url=response.url,
            kind=kind,
            description=description,
            impact="Diagnostic information may help map the backend; no code execution or data access is established.",
            evidence=f"HTTP {response.status}; matched response excerpt: {snippet!r}",
            remediation=remediation,
            cwe_ids=[cwe],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            remediation_steps=[remediation],
            confidence_score=85,
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
