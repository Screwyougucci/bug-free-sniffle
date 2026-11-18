"""Deeper static JavaScript review for already-served, same-origin code.

This module never executes JavaScript, injects input, or follows third-party script URLs.
All matches are triage candidates; pattern matching is not proof of data flow or a zero-day.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit

from .checks import Finding


class _ScriptSourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        values = {str(key).lower(): (value or "").strip() for key, value in attrs}
        src = values.get("src")
        if src:
            self.sources.append(src)


def extract_same_origin_script_urls(response, limit: int = 12) -> list[str]:
    """Return unique same-origin script URLs from an already-fetched HTML response."""
    if response.status is None or "text/html" not in response.headers.get("content-type", "").lower():
        return []
    parser = _ScriptSourceParser()
    try:
        parser.feed(response.text[:1_000_000])
    except Exception:
        return []
    base = urlsplit(response.url)
    origin = (base.scheme.lower(), (base.hostname or "").lower(), base.port or (443 if base.scheme == "https" else 80))
    found: list[str] = []
    seen: set[str] = set()
    for source in parser.sources:
        candidate = urljoin(response.url, source)
        parts = urlsplit(candidate)
        candidate_origin = (parts.scheme.lower(), (parts.hostname or "").lower(), parts.port or (443 if parts.scheme == "https" else 80))
        if candidate_origin != origin or parts.username or parts.password:
            continue
        if parts.scheme.lower() not in {"http", "https"} or candidate in seen:
            continue
        seen.add(candidate)
        found.append(candidate)
        if len(found) >= limit:
            break
    return found


def inspect_javascript_source(source_url: str, source: str) -> list[Finding]:
    """Inspect JavaScript text without running it or retaining matched source snippets."""
    text = source[:1_000_000]
    findings: list[Finding] = []

    def add(title: str, severity: str, confidence: str, kind: str, description: str,
            impact: str, evidence: str, remediation: str, cwe: str, score: int) -> None:
        findings.append(Finding(
            category="javascript-static-review",
            title=title,
            severity=severity,
            confidence=confidence,
            url=source_url,
            kind=kind,
            description=description,
            impact=impact,
            evidence=evidence,
            remediation=remediation,
            cwe_ids=[cwe],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            remediation_steps=[remediation],
            confidence_score=score,
        ))

    source_patterns = {
        "URL fragment/query": r"\b(?:location\.(?:hash|search|href)|document\.URL|document\.location|URLSearchParams)\b",
        "message event data": r"\b(?:event|e|evt|messageEvent)\.data\b",
        "window name": r"\bwindow\.name\b",
        "referrer": r"\bdocument\.referrer\b",
    }
    sink_patterns = {
        "HTML-string DOM sink": r"\.(?:innerHTML|outerHTML|insertAdjacentHTML)\b",
        "document.write": r"\bdocument\.write(?:ln)?\s*\(",
        "dynamic code execution": r"\b(?:eval\s*\(|new\s+Function\s*\()",
    }
    sources = [name for name, pattern in source_patterns.items() if re.search(pattern, text, re.I)]
    sinks = [name for name, pattern in sink_patterns.items() if re.search(pattern, text, re.I)]
    if sources and sinks:
        add(
            "Browser-controlled source and dangerous JavaScript sink coexist",
            "medium", "low", "static-review-candidate",
            "The JavaScript source contains both browser-controlled input patterns and potentially dangerous DOM/code sinks.",
            "A vulnerability may exist if attacker-controlled values reach a sink without correct validation and context-aware encoding. Co-occurrence does not establish data flow.",
            f"Source indicators: {', '.join(sources)}; sink indicators: {', '.join(sinks)}. Source text and values were not copied into the report.",
            "Trace each source-to-sink path. Prefer textContent and safe DOM APIs; avoid eval, document.write, and HTML-string sinks.",
            "CWE-79", 35,
        )

    message_listener = re.search(
        r"(?:addEventListener|attachEvent)\s*\(\s*['\"]message['\"]\s*,([\s\S]{0,2500})",
        text, re.I,
    )
    if message_listener:
        block = message_listener.group(1)
        if re.search(r"\.(?:data)\b", block) and not re.search(r"(?:event|e|evt)\.origin|origin\s*!==?|origin\s*===?", block, re.I):
            add(
                "Message event data used without an obvious origin check",
                "medium", "low", "static-review-candidate",
                "A message event listener appears to read event data without a nearby origin-validation pattern.",
                "If untrusted windows can send messages and the handler trusts their data, cross-origin message abuse may be possible. Static context is incomplete.",
                "A message listener and event.data access were found without a recognizable origin comparison in the inspected block; message contents are omitted.",
                "Validate event.origin against an exact allowlist before processing event.data, and validate the message schema.",
                "CWE-346", 30,
            )

    if re.search(r"\.postMessage\s*\([\s\S]{0,300}?,\s*['\"]\*['\"]\s*\)", text):
        add(
            "postMessage uses wildcard target origin",
            "medium", "medium", "static-review-candidate",
            "A postMessage call appears to use '*' as its target origin.",
            "Sensitive message data could reach an unintended browsing context if the target window is navigable or controllable.",
            "Wildcard target origin detected; message contents are not retained.",
            "Use an exact trusted target origin and validate event.origin in message receivers.",
            "CWE-345", 55,
        )

    if re.search(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(?:token|auth|session|jwt|secret)[^'\"]*['\"]", text, re.I):
        add(
            "Authentication-like key written to browser storage",
            "low", "low", "static-review-candidate",
            "JavaScript appears to write data under a token/session-like storage key.",
            "JavaScript-readable storage can be exposed if an XSS vulnerability exists.",
            "Only the presence of an authentication-like key name is reported; key and value are omitted.",
            "Avoid long-lived bearer credentials in JavaScript-readable storage; consider appropriately configured HttpOnly cookies.",
            "CWE-922", 25,
        )

    if re.search(r"\b(?:__proto__|constructor\s*\.\s*prototype)\b\s*(?:\]|\.)?\s*(?:=|\[)", text):
        add(
            "Potential prototype mutation pattern",
            "medium", "low", "static-review-candidate",
            "The JavaScript source contains a pattern associated with direct prototype mutation.",
            "Unsafe merging of attacker-controlled object keys can cause prototype pollution in some applications. This match alone does not prove an exploitable path.",
            "A __proto__ or constructor.prototype mutation-like assignment was detected; surrounding values are omitted.",
            "Reject dangerous property names during object merges, use Object.create(null) where appropriate, and prefer safe structured-copy patterns.",
            "CWE-1321", 30,
        )

    if re.search(r"\bdocument\.domain\s*=", text):
        add(
            "document.domain relaxation detected",
            "low", "high", "hardening-observation",
            "The script assigns document.domain, relaxing the browser's same-origin isolation behavior.",
            "Domain relaxation can broaden the set of sibling contexts able to interact with the page.",
            "An assignment to document.domain was detected; the assigned value is omitted.",
            "Avoid document.domain and use explicit, origin-checked messaging or modern cross-origin isolation mechanisms.",
            "CWE-346", 65,
        )

    return findings
