"""Deeper passive source inspection for security-review candidates.

Only analyzes response content already fetched by the bounded crawler. It does not
execute JavaScript, submit forms, inject payloads, or request discovered endpoints.
A match is a review lead, never proof of a vulnerability or zero-day.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit

from .checks import Finding


class _SourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self._script: list[str] | None = None
        self.api_docs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(k).lower(): (v or "") for k, v in attrs}
        if tag.lower() == "script":
            self._script = [] if not values.get("src") else None
        for key in ("href", "src"):
            value = values.get(key, "")
            if value and re.search(r"(?:openapi|swagger|api-docs)(?:[./?_-]|$)", value, re.I):
                self.api_docs.append(value)

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._script is not None:
            self.scripts.append("\n".join(self._script))
            self._script = None


def _finding(response, *, category: str, title: str, severity: str,
             confidence: str, kind: str, description: str, impact: str,
             evidence: str, remediation: str, cwe: str,
             confidence_score: int) -> Finding:
    return Finding(
        category=category, title=title, severity=severity,
        confidence=confidence, url=response.url, kind=kind,
        description=description, impact=impact, evidence=evidence,
        remediation=remediation, cwe_ids=[cwe],
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
        remediation_steps=[remediation], confidence_score=confidence_score,
    )


def inspect_deep_patterns(response) -> list[Finding]:
    """Inspect fetched HTML for additional risky browser-code patterns."""
    if response.status is None or "text/html" not in response.headers.get("content-type", "").lower():
        return []

    parser = _SourceParser()
    try:
        parser.feed(response.text[:1_000_000])
    except Exception:
        return []

    findings: list[Finding] = []
    for index, script in enumerate(parser.scripts, start=1):
        if len(script) > 200_000:
            continue
        lower = script.lower()

        # Message receivers that consume event.data without an origin check.
        has_message_listener = bool(re.search(
            r"(?:addEventListener|onmessage)\s*\(?\s*['\"]message['\"]", script, re.I
        ))
        consumes_message_data = bool(re.search(r"\bevent\s*\.\s*data\b|\be\s*\.\s*data\b", script))
        checks_origin = bool(re.search(r"\b(?:event|e)\s*\.\s*origin\b", script))
        if has_message_listener and consumes_message_data and not checks_origin:
            findings.append(_finding(
                response, category="browser-messaging",
                title="Message event data may be consumed without origin validation",
                severity="medium", confidence="low",
                kind="static-review-candidate",
                description="An inline message handler appears to read message data, but no event.origin check was found in that same script block.",
                impact="If untrusted origins can send messages that trigger privileged actions, this may enable cross-origin message abuse. The check may exist in another function or external script.",
                evidence=f"Inline script block {index} registers a message handler and reads event data; no origin-check pattern was found in that block.",
                remediation="Validate event.origin against an exact allowlist before trusting message data, and validate the message schema.",
                cwe="CWE-346", confidence_score=30,
            ))

        if re.search(r"\bdangerouslySetInnerHTML\b", script):
            findings.append(_finding(
                response, category="xss-indicator",
                title="React dangerouslySetInnerHTML usage found",
                severity="low", confidence="high",
                kind="static-review-candidate",
                description="Inline JavaScript contains React's raw-HTML rendering property.",
                impact="If attacker-controlled content reaches this property without robust sanitization, stored or reflected script injection may be possible.",
                evidence=f"Inline script block {index} references dangerouslySetInnerHTML; surrounding source and values were not retained.",
                remediation="Prefer normal React text rendering. If HTML rendering is unavoidable, sanitize with a maintained allowlist-based sanitizer immediately before rendering.",
                cwe="CWE-79", confidence_score=60,
            ))

        has_cookie_read = bool(re.search(r"\bdocument\s*\.\s*cookie\b", script))
        has_external_source = bool(re.search(
            r"\b(?:location\.(?:hash|search|href)|document\.URL|URLSearchParams|postMessage)\b",
            script, re.I
        ))
        if has_cookie_read and has_external_source:
            findings.append(_finding(
                response, category="browser-storage",
                title="Browser script combines cookie access with browser-controlled input",
                severity="info", confidence="low",
                kind="static-review-candidate",
                description="The same inline script references document.cookie and a browser-controlled input source.",
                impact="This co-occurrence alone does not establish that cookie data is exposed or that an attacker can control the flow; it is a manual data-flow review lead.",
                evidence=f"Inline script block {index} references document.cookie and at least one browser-controlled source; values were omitted.",
                remediation="Trace the data flow and ensure cookie values are never copied into URLs, messages, logs, or attacker-controlled DOM content. Mark sensitive cookies HttpOnly where applicable.",
                cwe="CWE-522", confidence_score=20,
            ))

    # Discovery only: report references already present in fetched HTML; do not fetch them.
    page_host = urlsplit(response.url).netloc.lower()
    for value in parser.api_docs[:10]:
        resolved = urlsplit(urljoin(response.url, value))
        if resolved.netloc.lower() == page_host:
            findings.append(_finding(
                response, category="api-discovery",
                title="API documentation reference found in page markup",
                severity="info", confidence="high", kind="observation",
                description="The fetched page references a likely API documentation resource on the same origin.",
                impact="API documentation is not inherently a vulnerability, but may reveal routes and schemas that should be reviewed for access-control and data-exposure issues.",
                evidence=f"Same-origin documentation reference observed at {resolved.path[:160]}; the scanner did not request it.",
                remediation="Ensure API documentation is intentionally public and that every documented endpoint independently enforces authentication and authorization.",
                cwe="CWE-200", confidence_score=85,
            ))
    return findings
