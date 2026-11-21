"""Evidence-based passive HTTP and HTML checks."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from html.parser import HTMLParser
import re
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit


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
    description: str = ""
    impact: str = ""
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    affected_component: str | None = None
    remediation_steps: list[str] = field(default_factory=list)
    confidence_score: int | None = None
    source_excerpt: str | None = None
    source_line: int | None = None

    def __post_init__(self):
        if self.confidence_score is None:
            self.confidence_score = {"high": 90, "medium": 65, "low": 35}.get(self.confidence.lower(), 20)
        self.confidence_score = max(0, min(100, int(self.confidence_score)))

    @property
    def finding_id(self) -> str:
        parts = urlsplit(self.url)
        normalized_url = f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path or '/'}"
        material = "|".join((self.category, self.title, normalized_url, self.affected_component or ""))
        return sha256(material.encode("utf-8")).hexdigest()[:16].upper()

    def to_dict(self) -> dict:
        result = asdict(self)
        result["finding_id"] = self.finding_id
        return result



def source_excerpt_for(response, title: str) -> tuple[str | None, int | None]:
    """Return a short, redacted excerpt from the exact response source, when applicable."""
    body = response.text[:1_000_000]
    title_lower = title.lower()
    patterns = []
    if "password form" in title_lower:
        patterns = [r"""<form\b[^>]*>[\s\S]{0,1200}?<input\b[^>]*type\s*=\s*['"]?password\b[^>]*>"""]
    elif "target-blank" in title_lower:
        patterns = [r"""<a\b[^>]*target\s*=\s*['"]?_blank[^>]*>"""]
    elif "insecure http resource" in title_lower:
        patterns = [r"""<(?:script|link|iframe|img|source)\b[^>]*(?:src|href)\s*=\s*['"]http://[^'"]+['"][^>]*>"""]
    elif "cross-origin script" in title_lower:
        patterns = [r"""<script\b[^>]*src\s*=\s*['"][^'"]+['"][^>]*>"""]
    elif "inline javascript event" in title_lower:
        patterns = [r"""<[a-z][^>]*\bon[a-z]+\s*=\s*['"][^'"]*['"][^>]*>"""]
    elif "javascript: url" in title_lower:
        patterns = [r"""<[a-z][^>]*(?:href|src|action)\s*=\s*['"]\s*javascript:[^'"]*['"][^>]*>"""]
    elif "source-and-sink" in title_lower or "source and dangerous javascript sink" in title_lower:
        patterns = [r"""(?im)^.*(?:location\.(?:hash|search|href)|document\.URL|URLSearchParams).*(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\().*$"""]
    elif "message event data" in title_lower or "origin check" in title_lower:
        patterns = [r"""(?im)^.*(?:addEventListener|attachEvent).*message.*$""", r"""(?im)^.*event\.data.*$"""]
    elif "postmessage" in title_lower:
        patterns = [r"""(?im)^.*postMessage.{0,300}\*.*$"""]
    elif "web storage" in title_lower:
        patterns = [r"""(?im)^.*(?:localStorage|sessionStorage)\.setItem.*$"""]
    elif "prototype mutation" in title_lower:
        patterns = [r"""(?im)^.*(?:__proto__|constructor\s*\.\s*prototype).*(?:=|\[).*$"""]
    elif "document.domain" in title_lower:
        patterns = [r"""(?im)^.*document\.domain\s*=.*$"""]
    elif "source map" in title_lower:
        patterns = [r"""(?im)^.*sourceMappingURL.*$"""]
    elif "directory index" in title_lower:
        patterns = [r"""(?im)^.*(?:<title>index of /|<h1>index of /|directory listing for /).*$"""]
    elif "database error" in title_lower:
        patterns = [r"""(?im)^.*(?:sql syntax|sqlstate\[|postgresql query failed|sqlite.exception|ora-00933).*$"""]
    elif "debug" in title_lower or "traceback" in title_lower:
        patterns = [r"""(?im)^.*(?:werkzeug debugger|django\.core\.handlers|laravel ignition|symfony exception|traceback \(most recent call last\)|stack trace:).*$"""]
    if not patterns:
        return None, None
    match = None
    for pattern in patterns:
        try:
            match = re.search(pattern, body, re.I)
        except re.error:
            match = None
        if match:
            break
    if not match:
        return None, None
    start, end = match.span()
    excerpt = body[max(0, start - 100):min(len(body), max(end, start + 1) + 100)]
    # Keep evidence useful without retaining credentials or token-like values.
    excerpt = re.sub(
        r"""(?i)(password|passwd|[a-z_-]*token|secret|api[_-]?key|authorization|cookie)([\s:=]+)([^\s,;<>"']+)""",
        r"\1\2[REDACTED]", excerpt,
    )
    excerpt = re.sub(r"""(?i)(authorization\s*:\s*)[^\r\n]+""", r"\1[REDACTED]", excerpt)
    if len(excerpt) > 600:
        excerpt = excerpt[:600] + "…"
    return excerpt.strip(), body.count("\n", 0, start) + 1

def _finding(category: str, title: str, severity: str, confidence: str,
             response, evidence: str, remediation: str,
             kind: str = "finding") -> Finding:
    descriptions = {
        "http-headers": "The response does not provide a recommended browser or transport security control.",
        "csp": "The Content Security Policy is missing or contains a permissive directive that can weaken browser-side protections.",
        "cookies": "A cookie is missing one or more attributes that help reduce theft or cross-site request exposure.",
        "cors": "The observed Cross-Origin Resource Sharing policy may expose a resource more broadly than intended.",
        "cache": "The response caching policy may allow sensitive response material to be retained by shared caches.",
        "html": "The delivered HTML contains a pattern that may weaken transport, embedding, or browser isolation protections.",
        "tls": "The TLS certificate or negotiated transport configuration requires review.",
        "information": "The response reveals implementation details that may help an attacker fingerprint the service.",
        "server-error": "The server returned an error response that may indicate an application or infrastructure problem.",
        "debug": "The response appears to expose development or diagnostic information.",
        "directory-listing": "The server response resembles an automatically generated directory index.",
    }
    impacts = {
        "critical": "Potentially severe compromise may be possible if the condition is exploitable in the deployed environment.",
        "high": "Could materially affect confidentiality, integrity, or availability if the affected path is reachable and the condition is exploitable.",
        "medium": "May weaken a security boundary or increase the impact of another vulnerability.",
        "low": "Usually represents defense-in-depth weakness or limited information exposure.",
        "info": "Informational observation; no direct security impact has been established.",
    }
    cwe_ids = []
    if "Password form uses GET" in title:
        cwe_ids = ["CWE-598"]
    elif "Password form is not guaranteed to submit over HTTPS" in title or "insecure HTTP resource" in title:
        cwe_ids = ["CWE-319"]
    elif "Directory index" in title:
        cwe_ids = ["CWE-548"]
    elif "Database error detail" in title:
        cwe_ids = ["CWE-209"]
    elif "debug" in category:
        cwe_ids = ["CWE-497"]
    elif "Target-blank link lacks opener isolation" in title:
        cwe_ids = ["CWE-1022"]
    elif "Clickjacking protection" in title:
        cwe_ids = ["CWE-1021"]
    elif "Content Security Policy" in title:
        cwe_ids = ["CWE-693"]
    elif category == "csp":
        cwe_ids = ["CWE-693"]
    elif category == "cookies":
        if "HttpOnly" in evidence:
            cwe_ids.append("CWE-1004")
        if "Secure" in evidence or "SameSite=None" in evidence or "__Host-" in title or "__Secure-" in title:
            cwe_ids.append("CWE-614")

    references = [f"https://cwe.mitre.org/data/definitions/{item.split('-')[1]}.html"
                  for item in cwe_ids]
    return Finding(
        category=category,
        title=title,
        severity=severity,
        confidence=confidence,
        url=response.url,
        evidence=evidence,
        remediation=remediation,
        kind=kind,
        description=descriptions.get(category, "A security-relevant condition was observed."),
        impact=impacts.get(severity, impacts["info"]),
        remediation_steps=[remediation] if remediation else [],
        cwe_ids=cwe_ids,
        references=references,
        source_excerpt=source_excerpt_for(response, title)[0],
        source_line=source_excerpt_for(response, title)[1],
    )


def _csp_directives(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for item in policy.split(";"):
        parts = item.strip().split()
        if parts:
            directives[parts[0].lower()] = [part.lower() for part in parts[1:]]
    return directives


def inspect_http(response) -> list[Finding]:
    """Inspect one response without sending additional requests."""
    findings: list[Finding] = []
    if response.status is None:
        return findings
    headers = response.headers
    is_html = "text/html" in headers.get("content-type", "").lower()

    source_parts = urlsplit(response.url)
    location = headers.get("location")
    if 300 <= response.status < 400 and location:
        destination = urlsplit(urljoin(response.url, location))
        if source_parts.scheme.lower() == "https" and destination.scheme.lower() == "http":
            findings.append(_finding(
                "redirect", "HTTPS response redirects to an unencrypted HTTP URL", "medium", "high", response,
                f"Location resolves to http://{destination.netloc}{destination.path[:120]}. Redirects were not followed.",
                "Keep redirect destinations on HTTPS and reject downgrade destinations unless explicitly required.",
            ))
        if destination.netloc and source_parts.netloc and destination.netloc.lower() != source_parts.netloc.lower():
            findings.append(_finding(
                "redirect", "Cross-origin redirect observed", "info", "high", response,
                f"Location resolves to {destination.scheme}://{destination.netloc}{destination.path[:120]}. Redirects were not followed; this alone does not prove an open redirect.",
                "Confirm this external destination is intentional and that user-controlled redirect parameters use a strict destination allowlist.",
                kind="observation",
            ))

    auth_challenge = headers.get("www-authenticate", "")
    if source_parts.scheme.lower() == "http" and "basic" in auth_challenge.lower():
        findings.append(_finding(
            "authentication", "HTTP endpoint advertises Basic authentication without TLS", "high", "high", response,
            f"WWW-Authenticate begins with {auth_challenge[:120]!r}; source URL uses HTTP.",
            "Require HTTPS before HTTP Basic authentication and redirect or reject plaintext requests.",
        ))

    if is_html:
        checks = [
            ("content-security-policy", "Content Security Policy is missing", "medium",
             "Define a restrictive Content-Security-Policy; begin with report-only mode and tighten it."),
            ("x-content-type-options", "X-Content-Type-Options is missing", "low",
             "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Referrer-Policy is missing", "low",
             "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin."),
            ("permissions-policy", "Permissions-Policy is missing", "low",
             "Explicitly disable browser features the application does not need."),
        ]
        for name, title, severity, remediation in checks:
            if name not in headers:
                findings.append(_finding(
                    "http-headers", title, severity, "high", response,
                    f"Response status {response.status}; header {name!r} was not present.",
                    remediation,
                ))
        if "x-content-type-options" in headers and headers["x-content-type-options"].strip().lower() != "nosniff":
            findings.append(_finding(
                "http-headers", "X-Content-Type-Options has an ineffective value", "low", "high", response,
                f"Observed value: {headers['x-content-type-options'][:100]!r}.",
                "Set the header value to exactly nosniff.",
            ))

    if response.url.lower().startswith("https://"):
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append(_finding(
                "http-headers", "HSTS header is missing", "low", "high", response,
                "HTTPS response did not include Strict-Transport-Security.",
                "Enable HSTS after confirming all subdomains and HTTPS configuration are ready.",
            ))
        else:
            age = None
            directives = {}
            for directive in hsts.split(";"):
                key, _, value = directive.strip().partition("=")
                directives[key.lower()] = value.strip().strip('"')
                if key.lower() == "max-age":
                    try:
                        age = int(value.strip().strip('"'))
                    except ValueError:
                        pass
            if age == 0:
                findings.append(_finding(
                    "http-headers", "HSTS is explicitly disabled by max-age=0", "medium", "high", response,
                    f"Observed Strict-Transport-Security: {hsts[:180]}.",
                    "Use a positive max-age after validating HTTPS across the host and its subdomains.",
                ))
            elif age is not None and age < 15_552_000:
                findings.append(_finding(
                    "http-headers", "HSTS max-age is shorter than 180 days", "low", "high", response,
                    f"Observed max-age={age} seconds.",
                    "Consider a longer max-age after validating HTTPS readiness.",
                ))
            if "includesubdomains" not in directives:
                findings.append(_finding(
                    "http-headers", "HSTS does not cover subdomains", "info", "high", response,
                    "The includeSubDomains directive was not present.",
                    "Consider includeSubDomains only after confirming every subdomain supports HTTPS.",
                    kind="observation",
                ))

    csp = headers.get("content-security-policy", "")
    report_only = headers.get("content-security-policy-report-only")
    if report_only and not csp:
        findings.append(_finding(
            "csp", "Only report-only CSP is configured", "low", "high", response,
            "Content-Security-Policy-Report-Only is present but enforcing Content-Security-Policy is absent.",
            "After reviewing violation reports and compatibility, deploy an enforcing Content-Security-Policy.",
            kind="observation",
        ))
    if csp:
        directives = _csp_directives(csp)
        script_sources = directives.get("script-src", directives.get("default-src", []))
        for unsafe_value, title in [
            ("'unsafe-inline'", "CSP permits inline scripts"),
            ("'unsafe-eval'", "CSP permits eval-like script execution"),
        ]:
            if unsafe_value in script_sources:
                findings.append(_finding(
                    "csp", title, "medium", "medium", response,
                    f"script-src/default-src contains {unsafe_value}.",
                    "Avoid unsafe script sources; use nonces or hashes and remove eval-like execution.",
                ))
        if "*" in script_sources:
            findings.append(_finding(
                "csp", "CSP script source permits a wildcard", "medium", "medium", response,
                "script-src or default-src contains '*'.",
                "Restrict script sources to explicitly trusted origins.",
            ))
        for directive, title, remediation in [
            ("object-src", "CSP object-src directive is missing",
             "Set object-src 'none' unless legacy embedded objects are required."),
            ("base-uri", "CSP base-uri directive is missing",
             "Set base-uri 'self' or 'none' to reduce base-tag injection risk."),
            ("frame-ancestors", "CSP frame-ancestors directive is missing",
             "Set frame-ancestors to the origins permitted to embed this page."),
        ]:
            if directive not in directives:
                findings.append(_finding(
                    "csp", title, "low", "high", response,
                    f"The {directive} directive was not present in the observed policy.",
                    remediation,
                ))

    if is_html and "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(_finding(
            "http-headers", "Clickjacking protection was not detected", "low", "high", response,
            "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
            "Set an appropriate Content-Security-Policy frame-ancestors directive; use X-Frame-Options for legacy clients.",
        ))
    xfo = headers.get("x-frame-options", "").strip().lower()
    if is_html and xfo and xfo not in {"deny", "sameorigin"}:
        findings.append(_finding(
            "http-headers", "X-Frame-Options contains an unsupported or unsafe value", "low", "high", response,
            f"Observed X-Frame-Options: {headers.get('x-frame-options', '')[:100]!r}.",
            "Use DENY or SAMEORIGIN, or configure CSP frame-ancestors as the primary control.",
        ))

    referrer_policy = headers.get("referrer-policy", "").lower()
    if referrer_policy in {"unsafe-url", "no-referrer-when-downgrade"}:
        findings.append(_finding(
            "http-headers", "Referrer-Policy may disclose full referrer URLs", "low", "high", response,
            f"Observed Referrer-Policy: {referrer_policy}.",
            "Use strict-origin-when-cross-origin, same-origin, or no-referrer as appropriate.",
        ))

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin.strip() == "*":
        findings.append(_finding(
            "cors", "CORS allows requests from any origin", "info", "high", response,
            "Access-Control-Allow-Origin is '*'; this is only a concern for data intended to be private.",
            "Restrict allowed origins when the resource is not intentionally public.",
            kind="observation",
        ))
    if allow_origin.strip() == "*" and allow_credentials == "true":
        findings.append(_finding(
            "cors", "CORS wildcard is combined with credential allowance", "info", "high", response,
            "Both Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true were observed. Browsers reject this combination for credentialed reads, but it often indicates a misconfigured policy.",
            "Use an explicit origin allowlist and validate Origin values server-side.",
            kind="observation",
        ))
    if allow_origin.strip().lower() == "null":
        findings.append(_finding(
            "cors", "CORS explicitly allows the null origin", "low", "medium", response,
            "Access-Control-Allow-Origin: null was observed. Sandboxed documents and other opaque origins can serialize as null.",
            "Allow null only when required; prefer a narrow explicit origin allowlist.",
            kind="observation",
        ))

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    for title, name, value in [
        ("Server banner is disclosed", "Server", server),
        ("X-Powered-By banner is disclosed", "X-Powered-By", powered_by),
    ]:
        if value:
            findings.append(_finding(
                "information", title, "info", "high", response,
                f"{name}: {value[:160]}",
                "Remove unnecessary product and version details from response headers.",
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
                severity = "medium" if any(token in name.lower() for token in ("session", "auth", "token", "sid")) else "low"
                findings.append(_finding(
                    "cookies", f"Cookie {name!r} is missing recommended flags", severity, "medium",
                    response, "Missing: " + ", ".join(missing),
                    "Set Secure, HttpOnly, and an appropriate SameSite attribute where compatible.",
                ))
            if morsel["samesite"].lower() == "none" and not morsel["secure"]:
                findings.append(_finding(
                    "cookies", f"Cookie {name!r} uses SameSite=None without Secure", "medium", "high",
                    response, "SameSite=None was observed without the Secure attribute.",
                    "Set Secure on cookies that use SameSite=None.",
                ))
            if name.startswith("__Host-") and (not morsel["secure"] or morsel["path"] != "/" or morsel["domain"]):
                findings.append(_finding(
                    "cookies", f"Cookie {name!r} violates the __Host- prefix requirements", "medium", "high",
                    response, "__Host- cookies require Secure, Path=/, and no Domain attribute.",
                    "Set Secure; set Path=/; and omit the Domain attribute for __Host- cookies.",
                ))
            if name.startswith("__Secure-") and not morsel["secure"]:
                findings.append(_finding(
                    "cookies", f"Cookie {name!r} violates the __Secure- prefix requirements", "medium", "high",
                    response, "__Secure- cookies must be set with the Secure attribute.",
                    "Set the Secure attribute or remove the __Secure- prefix.",
                ))
        cache_control = headers.get("cache-control", "").lower()
        if "no-store" not in cache_control and "private" not in cache_control:
            severity = "medium" if "public" in cache_control else "low"
            findings.append(_finding(
                "cache", "Response sets cookies without a private/no-store cache directive", severity, "medium",
                response, f"Set-Cookie was observed with Cache-Control: {cache_control or '(missing)'}.",
                "Use Cache-Control: no-store for sensitive responses that set session or account cookies.",
            ))

    if response.status >= 500:
        findings.append(_finding(
            "server-error", "Server returned an HTTP 5xx response", "info", "high", response,
            f"Observed HTTP {response.status}; response bytes={len(response.body)}.",
            "Review server and application logs for the matching request; verify the error is not caused by routine maintenance.",
            kind="observation",
        ))

    body_lower = response.text[:1_000_000].lower()
    debug_signatures = [
        ("werkzeug debugger", "Werkzeug interactive debugger signature detected"),
        ("django.core.handlers", "Django internal handler detail detected"),
        ("laravel ignition", "Laravel Ignition debug page signature detected"),
        ("symfony exception", "Symfony exception debug page signature detected"),
        ("whoops\\\\\\\\exception", "Whoops exception page signature detected"),
        ("traceback (most recent call last)", "Python traceback signature detected"),
        ("stack trace:", "Stack trace text detected"),
    ]
    for signature, title in debug_signatures:
        if signature in body_lower:
            findings.append(_finding(
                "debug", title, "high", "medium", response,
                f"Response body contains diagnostic signature {signature!r}; body content was not copied into this finding.",
                "Disable production debug pages; return generic error responses and keep stack traces in protected server logs.",
            ))

    listing_signatures = ("<title>index of /", "<h1>index of /", "directory listing for /")
    if any(signature in body_lower for signature in listing_signatures):
        findings.append(_finding(
            "directory-listing", "Directory index appears to be enabled", "medium", "high", response,
            "Response body contains a common web-server directory-index signature.",
            "Disable automatic directory indexing and ensure files are not exposed through public web roots.",
        ))

    sql_error_signatures = (
        "you have an error in your sql syntax",
        "warning: mysql_",
        "sqlstate[",
        "unclosed quotation mark after the character string",
        "postgresql query failed",
        "sqlite.exception",
        "ora-00933",
    )
    for signature in sql_error_signatures:
        if signature in body_lower:
            findings.append(_finding(
                "error-disclosure", "Database error detail is exposed in the response", "medium", "high", response,
                f"Response body contains database error signature {signature!r}; no surrounding response content was retained.",
                "Return generic client errors; log database exceptions server-side and use parameterized queries.",
            ))
            break

    return findings


class _HtmlAudit(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources: list[tuple[str, str, dict[str, str]]] = []
        self.blank_links: list[dict[str, str]] = []
        self.forms: list[dict[str, object]] = []
        self._active_form: dict[str, object] | None = None

    def handle_starttag(self, tag, attrs):
        values = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            form = {"action": values.get("action", ""), "method": values.get("method", "get").lower(),
                    "has_password": False}
            self.forms.append(form)
            self._active_form = form
        elif tag == "input" and self._active_form is not None and values.get("type", "").lower() == "password":
            self._active_form["has_password"] = True

        if tag in {"script", "img", "iframe", "source", "link"}:
            attr = "href" if tag == "link" else "src"
            if values.get(attr):
                self.resources.append((tag, values[attr], values))
        if tag == "a" and values.get("target", "").lower() == "_blank":
            self.blank_links.append(values)

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._active_form = None


def inspect_html(response) -> list[Finding]:
    """Inspect already-downloaded HTML only; no forms or scripts are executed."""
    if response.status is None or "text/html" not in response.headers.get("content-type", "").lower():
        return []
    audit = _HtmlAudit()
    try:
        audit.feed(response.text)
    except Exception:
        return []

    findings: list[Finding] = []
    page = urlsplit(response.url)
    for tag, value, attrs in audit.resources:
        absolute = urlsplit(urljoin(response.url, value))
        if page.scheme == "https" and absolute.scheme == "http" and tag in {"script", "link", "iframe", "img", "source"}:
            findings.append(_finding(
                "html", "HTTPS page references an insecure HTTP resource", "medium", "high", response,
                f"{tag} resource uses {absolute.scheme}://{absolute.netloc}{absolute.path[:120]}.",
                "Serve all page resources over HTTPS and remove mixed-content references.",
            ))
        is_external = absolute.scheme in {"http", "https"} and absolute.netloc and absolute.netloc.lower() != page.netloc.lower()
        if tag == "script" and value and is_external and not attrs.get("integrity"):
            findings.append(_finding(
                "html", "Cross-origin script has no Subresource Integrity attribute", "info", "medium",
                response, f"External script source: {absolute.netloc}{absolute.path[:100]}.",
                "Use Subresource Integrity where the external asset is version-pinned and supports it.",
                kind="observation",
            ))

    for attrs in audit.blank_links:
        rel = {item.lower() for item in attrs.get("rel", "").split()}
        if not ({"noopener", "noreferrer"} & rel):
            findings.append(_finding(
                "html", "Target-blank link lacks opener isolation", "low", "high", response,
                f"Link target=_blank with href={attrs.get('href', '')[:120]!r}.",
                "Add rel=noopener (optionally noreferrer) to target=_blank links.",
            ))

    for form in audit.forms:
        if not form["has_password"]:
            continue
        action = urlsplit(urljoin(response.url, str(form["action"])))
        if page.scheme != "https" or action.scheme != "https":
            findings.append(_finding(
                "html", "Password form is not guaranteed to submit over HTTPS", "high", "high",
                response, f"Page scheme={page.scheme}; form action resolves to {action.scheme or 'relative'}://{action.netloc}{action.path[:100]}.",
                "Serve the login page over HTTPS and submit credentials only to an HTTPS endpoint.",
            ))
        elif action.netloc.lower() != page.netloc.lower():
            findings.append(_finding(
                "html", "Password form submits to a different origin", "medium", "medium",
                response, f"Password form action origin is {action.scheme}://{action.netloc}.",
                "Verify the cross-origin authentication destination is an intentional trusted identity provider.",
                kind="observation",
            ))
        if form["method"] == "get":
            findings.append(_finding(
                "html", "Password form uses GET", "high", "high", response,
                "A form containing a password input declares method=GET or omits method (GET is the default).",
                "Use POST over HTTPS and ensure secrets are never placed in query strings.",
            ))
    return findings
