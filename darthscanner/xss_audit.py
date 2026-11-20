"""Evidence-focused, passive XSS analysis for fetched web content.

No payloads are injected, JavaScript is not executed, and no forms or API
operations are submitted. All results are review candidates, not proof of XSS.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import parse_qsl, urlsplit

from .checks import Finding


_MAX_SOURCE = 1_000_000
_MAX_QUERY_VALUES = 40
_MAX_INLINE_SCRIPTS = 40
_MAX_SCRIPT_SIZE = 200_000

_SOURCE = re.compile(
    r"(?:\b(?:window\s*\.\s*)?location\s*\.\s*(?:hash|search|href)\b|"
    r"\bdocument\s*\.\s*(?:URL|referrer)\b|\bwindow\s*\.\s*name\b|"
    r"\b(?:event|e|evt|messageEvent)\s*\.\s*data\b|"
    r"\bURLSearchParams\s*\([^)]*\)\s*\.\s*get\s*\(|"
    r"\bnew\s+URL\s*\([^)]*\)\s*\.\s*searchParams\s*\.\s*get\s*\()",
    re.I,
)
_SANITIZER = re.compile(
    r"\b(?:DOMPurify\s*\.\s*sanitize|sanitizeHTML|sanitizeHtml|"
    r"sanitize\s*\(|escapeHTML|escapeHtml|encodeForHTML)\s*\(",
    re.I,
)
_ASSIGNMENT = re.compile(
    r"(?m)(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>[^;\n]{1,2000})"
)
_SINKS = (
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*=\s*(?P<expr>[^;\n]{1,2000})", re.I)),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*=\s*(?P<expr>[^;\n]{1,2000})", re.I)),
    ("insertAdjacentHTML", re.compile(r"\.\s*insertAdjacentHTML\s*\([^,]{1,100},\s*(?P<expr>[^)]{1,2000})\)", re.I)),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(\s*(?P<expr>[^)]{1,2000})\)", re.I)),
    ("eval", re.compile(r"\beval\s*\(\s*(?P<expr>[^)]{1,2000})\)", re.I)),
    ("Function constructor", re.compile(r"\bnew\s+Function\s*\(\s*(?P<expr>[^)]{1,2000})\)", re.I)),
)
_SECRET_PARAM = re.compile(r"(?:token|auth|password|passwd|secret|session|signature|credential|api[_-]?key)", re.I)


def _strip_comments(source: str) -> str:
    """Blank JS comments while preserving quoted strings and line positions."""
    out = list(source)
    i = 0
    quote = None
    escaped = False
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "/" and nxt == "/":
            out[i] = out[i + 1] = " "
            i += 2
            while i < len(source) and source[i] not in "\r\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < len(source):
                if source[i] == "*" and i + 1 < len(source) and source[i + 1] == "/":
                    out[i] = out[i + 1] = " "
                    i += 2
                    break
                if source[i] not in "\r\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)



def _mask_strings(source: str) -> str:
    """Blank JS string literals so text that merely mentions a sink is not code."""
    out = list(source)
    quote = None
    escaped = False
    for index, ch in enumerate(source):
        if quote:
            if ch not in "\r\n":
                out[index] = " "
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif ch in ("'", '"', "\`"):
            quote = ch
            out[index] = " "
    return "".join(out)

def _contains_tainted(expression: str, tainted: set[str]) -> bool:
    return any(re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", expression) for name in tainted)


def _make_finding(url: str, *, title: str, evidence: str, kind: str) -> Finding:
    return Finding(
        category="xss-analysis",
        title=title,
        severity="medium",
        confidence="low",
        url=url,
        kind=kind,
        description=(
            "Static analysis found a plausible browser-input-to-executable-HTML or "
            "dynamic-code path. The scanner did not execute the code or inject input."
        ),
        impact=(
            "If attacker-controlled data reaches this context without context-appropriate "
            "sanitization, cross-site scripting may be possible. Framework behavior, runtime "
            "guards, and full control flow require manual validation."
        ),
        evidence=evidence,
        remediation=(
            "Prefer textContent and safe DOM APIs. Where HTML is required, use a maintained "
            "context-appropriate sanitizer immediately before the sink. Avoid eval and "
            "Function-based execution."
        ),
        cwe_ids=["CWE-79"],
        references=["https://cwe.mitre.org/data/definitions/79.html"],
        remediation_steps=[
            "Confirm the source is attacker-controllable in the deployed application.",
            "Trace all transformations and branch conditions to the reported sink.",
            "Use safe DOM APIs or a maintained HTML sanitizer with an explicit allowlist.",
        ],
        confidence_score=45,
    )


def inspect_javascript_xss(source_url: str, source: str) -> list[Finding]:
    """Trace bounded simple assignments from browser-controlled sources to risky sinks."""
    text = _mask_strings(_strip_comments(source[:_MAX_SOURCE]))
    events = []
    for match in _ASSIGNMENT.finditer(text):
        events.append((match.start(), "assignment", match, None))
    for sink_name, pattern in _SINKS:
        for match in pattern.finditer(text):
            events.append((match.start(), "sink", match, sink_name))
    events.sort(key=lambda item: item[0])

    tainted: set[str] = set()
    findings: list[Finding] = []
    reported: set[tuple[str, str]] = set()
    for _, event_type, match, sink_name in events:
        expression = match.group("expr").strip()
        if _SANITIZER.search(expression):
            if event_type == "assignment":
                tainted.discard(match.group("name"))
            continue
        if event_type == "assignment":
            name = match.group("name")
            tainted.discard(name)
            if _SOURCE.search(expression) or _contains_tainted(expression, tainted):
                tainted.add(name)
            continue

        if not (_SOURCE.search(expression) or _contains_tainted(expression, tainted)):
            continue
        line = text.count("\n", 0, match.start()) + 1
        key = (sink_name, str(line))
        if key in reported:
            continue
        reported.add(key)
        source_kind = "browser-controlled source" if _SOURCE.search(expression) else "tainted local variable"
        findings.append(_make_finding(
            source_url,
            title=f"Potential XSS data flow reaches {sink_name}",
            evidence=(
                f"Line {line}: {source_kind} is used in {sink_name}. "
                "Matched expressions and input values are not retained."
            ),
            kind="source-to-sink-candidate",
        ))
    return findings


class _ReflectionParser(HTMLParser):
    def __init__(self, values: list[tuple[str, str]]) -> None:
        super().__init__(convert_charrefs=True)
        self.values = values
        self.script_count = 0
        self.script_parts: list[str] | None = None
        self.matches: list[tuple[str, str]] = []

    def _check(self, context: str, content: str) -> None:
        for name, value in self.values:
            if value and value in content:
                self.matches.append((name, context))

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag == "script":
            self.script_count += 1
            self.script_parts = []
        for attr, value in attrs:
            attr = (attr or "").lower()
            value = value or ""
            if attr.startswith("on"):
                self._check(f"event-handler attribute ({attr})", value)
            elif attr in {"href", "src", "action", "formaction"}:
                if value.strip().lower().startswith(("javascript:", "data:text/html")):
                    self._check(f"executable URL attribute ({attr})", value)

    def handle_data(self, data: str) -> None:
        if self.script_parts is not None:
            self.script_parts.append(data)
            self._check("inline script", data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self.script_parts = None


def inspect_html_xss(response_url: str, html: str) -> list[Finding]:
    """Inspect inline scripts and already-present query reflections without sending probes."""
    findings: list[Finding] = []
    # Reparse bounded inline scripts through the same static data-flow engine.
    class _InlineScripts(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.current: list[str] | None = None
            self.scripts: list[str] = []

        def handle_starttag(self, tag, attrs):
            if tag.lower() == "script" and not any((k or "").lower() == "src" for k, _ in attrs):
                self.current = []

        def handle_data(self, data):
            if self.current is not None and sum(map(len, self.current)) < _MAX_SCRIPT_SIZE:
                self.current.append(data)

        def handle_endtag(self, tag):
            if tag.lower() == "script" and self.current is not None:
                self.scripts.append("\n".join(self.current))
                self.current = None

    inline = _InlineScripts()
    try:
        inline.feed(html[:1_000_000])
    except Exception:
        inline.scripts = []
    for index, script in enumerate(inline.scripts[:_MAX_INLINE_SCRIPTS], start=1):
        if len(script) > _MAX_SCRIPT_SIZE:
            continue
        for finding in inspect_javascript_xss(response_url, script):
            finding.evidence = f"Inline script block {index}; {finding.evidence}"
            findings.append(finding)

    query_values = []
    try:
        for name, value in parse_qsl(urlsplit(response_url).query, keep_blank_values=False)[:_MAX_QUERY_VALUES]:
            if _SECRET_PARAM.search(name) or len(value) < 4 or len(value) > 200:
                continue
            query_values.append((name[:80], value))
    except ValueError:
        query_values = []

    if query_values:
        reflected = _ReflectionParser(query_values)
        try:
            reflected.feed(html[:1_000_000])
        except Exception:
            reflected.matches = []
        seen = set()
        for name, context in reflected.matches:
            key = (name, context)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                category="xss-analysis",
                title="Request query value reflected in an executable HTML context",
                severity="medium",
                confidence="low",
                url=response_url,
                kind="reflected-context-candidate",
                description=(
                    "An existing query parameter value appears in an inline script, event "
                    "handler, or executable URL attribute in the returned HTML. No test "
                    "payload was sent."
                ),
                impact=(
                    "If the reflected value can be controlled by an attacker and is not "
                    "safely encoded for this exact context, reflected XSS may be possible."
                ),
                evidence=f"Query parameter {name!r} was observed in {context}; the value is omitted.",
                remediation=(
                    "Use context-specific output encoding. Avoid placing untrusted values "
                    "in inline scripts, event-handler attributes, or executable URL schemes."
                ),
                cwe_ids=["CWE-79"],
                references=["https://cwe.mitre.org/data/definitions/79.html"],
                confidence_score=50,
            ))
    return findings
