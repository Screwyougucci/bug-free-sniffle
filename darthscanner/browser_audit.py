"""Passive browser-side vulnerability indicators from already-fetched HTML.

No JavaScript is executed, no forms are submitted, and no payloads are injected.
These are source-review leads, not proof of exploitable XSS.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit

from .checks import Finding


class _BrowserParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inline_scripts: list[str] = []
        self._script_parts: list[str] | None = None
        self.inline_handlers: list[tuple[str, str]] = []
        self.javascript_urls: list[tuple[str, str]] = []
        self.source_maps: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "script":
            src = values.get("src", "")
            if not src:
                self._script_parts = []
            elif src.lower().split("?", 1)[0].endswith(".js.map"):
                self.source_maps.append(src)
        for name, value in values.items():
            if name.startswith("on") and value.strip():
                self.inline_handlers.append((tag, name))
            if name in {"href", "src", "action", "formaction"} and value.lstrip().lower().startswith("javascript:"):
                self.javascript_urls.append((tag, name))

    def handle_data(self, data: str) -> None:
        if self._script_parts is not None:
            self._script_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._script_parts is not None:
            self.inline_scripts.append("\n".join(self._script_parts))
            self._script_parts = None


def inspect_browser_code(response) -> list[Finding]:
    """Find risky browser-side patterns in HTML already retrieved by the crawler."""
    if response.status is None or "text/html" not in response.headers.get("content-type", "").lower():
        return []
    parser = _BrowserParser()
    try:
        parser.feed(response.text[:1_000_000])
    except Exception:
        return []

    findings: list[Finding] = []
    for tag, attr in parser.inline_handlers[:30]:
        findings.append(Finding(
            category="xss-indicator",
            title="Inline JavaScript event handler found",
            severity="info",
            confidence="high",
            url=response.url,
            kind="hardening-observation",
            description="HTML contains an inline event-handler attribute. Such handlers increase reliance on inline script execution and complicate a strict Content Security Policy.",
            impact="This is not proof of XSS. If untrusted data reaches the attribute without context-aware encoding, it may become an injection sink.",
            evidence=f"An inline {attr} attribute was found on a <{tag}> element; attribute values are intentionally omitted.",
            remediation="Move event handling into trusted external scripts, use addEventListener, and deploy a nonce- or hash-based Content Security Policy.",
            cwe_ids=["CWE-79"],
            references=["https://cwe.mitre.org/data/definitions/79.html"],
            remediation_steps=["Remove inline event handlers where practical.", "Use context-aware output encoding for untrusted data.", "Deploy and test a restrictive Content Security Policy."],
            confidence_score=35,
        ))

    for tag, attr in parser.javascript_urls[:30]:
        findings.append(Finding(
            category="xss-indicator",
            title="javascript: URL found in HTML",
            severity="low",
            confidence="high",
            url=response.url,
            kind="hardening-observation",
            description="An HTML URL-bearing attribute uses the javascript: scheme.",
            impact="If the URL can be influenced by untrusted input or activated in an unsafe context, script execution may be possible. Static observation alone does not establish exploitability.",
            evidence=f"A javascript: URL was found in the {attr} attribute of a <{tag}> element; the value is omitted.",
            remediation="Replace javascript: URLs with ordinary links or buttons and attach trusted event listeners.",
            cwe_ids=["CWE-79"],
            references=["https://cwe.mitre.org/data/definitions/79.html"],
            confidence_score=55,
        ))

    source_patterns = (
        r"\blocation\.(?:hash|search|href)\b",
        r"\bdocument\.URL\b",
        r"\bURLSearchParams\b",
        r"\bwindow\.name\b",
        r"\bpostMessage\b",
    )
    sink_patterns = (
        r"\.(?:innerHTML|outerHTML|insertAdjacentHTML)\b",
        r"\bdocument\.write(?:ln)?\s*\(",
        r"\beval\s*\(",
        r"\bnew\s+Function\s*\(",
    )
    for index, script in enumerate(parser.inline_scripts, start=1):
        if len(script) > 200_000:
            continue
        sources = [pattern for pattern in source_patterns if re.search(pattern, script, re.I)]
        sinks = [pattern for pattern in sink_patterns if re.search(pattern, script, re.I)]
        if sources and sinks:
            findings.append(Finding(
                category="xss-indicator",
                title="Potential DOM XSS source-and-sink pattern in inline JavaScript",
                severity="medium",
                confidence="low",
                url=response.url,
                kind="static-review-candidate",
                description="The same inline script contains a browser-controlled source and a potentially dangerous DOM or code-execution sink.",
                impact="If data from the source reaches the sink without validation and context-aware sanitization, DOM-based cross-site scripting may be possible. Static co-occurrence does not prove data flow or exploitability.",
                evidence=f"Inline script block {index} contains {len(sources)} source-pattern match(es) and {len(sinks)} sink-pattern match(es). Source/sink values are not copied into the report.",
                remediation="Trace the data flow manually. Prefer textContent and safe DOM APIs; validate message origins and avoid eval, document.write, and HTML-string sinks.",
                cwe_ids=["CWE-79"],
                references=["https://cwe.mitre.org/data/definitions/79.html"],
                remediation_steps=["Review the exact source-to-sink data flow.", "Replace HTML-string sinks with safe DOM APIs.", "Apply context-aware encoding and strict CSP."],
                confidence_score=30,
            ))

    for src in parser.source_maps[:20]:
        resolved = urlsplit(urljoin(response.url, src))
        if resolved.netloc.lower() == urlsplit(response.url).netloc.lower():
            findings.append(Finding(
                category="information-exposure",
                title="JavaScript source map referenced by page",
                severity="info",
                confidence="high",
                url=response.url,
                kind="observation",
                description="The page references a JavaScript source map. Source maps may expose original source paths and comments.",
                impact="May disclose implementation details, but source maps are not inherently vulnerabilities.",
                evidence=f"Same-origin source-map reference observed at {resolved.path[:160]}; the scanner did not fetch it.",
                remediation="Publish source maps only when intended; avoid embedding secrets or sensitive comments in shipped source.",
                cwe_ids=["CWE-200"],
                references=["https://cwe.mitre.org/data/definitions/200.html"],
                confidence_score=85,
            ))
    return findings
