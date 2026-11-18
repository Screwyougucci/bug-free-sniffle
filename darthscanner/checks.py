"""Evidence-based passive HTTP and HTML checks."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit

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


def _finding(category: str, title: str, severity: str, confidence: str,
             response: HttpResponse, evidence: str, remediation: str,
             kind: str = "finding") -> Finding:
    return Finding(category, title, severity, confidence, response.url,
                   evidence, remediation, kind)


def _csp_directives(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for item in policy.split(";"):
        parts = item.strip().split()
        if parts:
            directives[parts[0].lower()] = [part.lower() for part in parts[1:]]
    return directives


def inspect_http(response: HttpResponse) -> list[Finding]:
    """Inspect one response without sending additional requests."""
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
                findings.append(_finding(
                    "http-headers", title, severity, "high", response,
                    f"Response status {response.status}; header {name!r} was not present.",
                    remediation,
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
            for directive in hsts.split(";"):
                key, _, value = directive.strip().partition("=")
                if key.lower() == "max-age":
                    try:
                        age = int(value.strip().strip('"'))
                    except ValueError:
                        pass
            if age is not None and age < 15_552_000:
                findings.append(_finding(
                    "http-headers", "HSTS max-age is shorter than 180 days", "low", "high", response,
                    f"Observed max-age={age}.",
                    "Consider a longer max-age after validating HTTPS readiness.",
                ))

    csp = headers.get("content-security-policy", "")
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
            "cors", "CORS wildcard is combined with credential allowance", "low", "medium", response,
            "Both Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true were observed.",
            "Use an explicit origin allowlist and validate Origin values server-side.",
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
                findings.append(_finding(
                    "cookies", f"Cookie {name!r} is missing recommended flags", "low", "medium",
                    response, "Missing: " + ", ".join(missing),
                    "Set Secure, HttpOnly, and an appropriate SameSite attribute where compatible.",
                ))
            if morsel["samesite"].lower() == "none" and not morsel["secure"]:
                findings.append(_finding(
                    "cookies", f"Cookie {name!r} uses SameSite=None without Secure", "medium", "high",
                    response, "SameSite=None was observed without the Secure attribute.",
                    "Set Secure on cookies that use SameSite=None.",
                ))
        cache_control = headers.get("cache-control", "").lower()
        if "no-store" not in cache_control and "private" not in cache_control:
            findings.append(_finding(
                "cache", "Response sets cookies without a private/no-store cache directive", "low", "medium",
                response, f"Set-Cookie was observed with Cache-Control: {cache_control or '(missing)'}.",
                "Use Cache-Control: no-store for sensitive responses that set session or account cookies.",
            ))

    if is_html and response.status >= 400:
        findings.append(_finding(
            "http", "HTML page returned an error status", "info", "high", response,
            f"HTTP status {response.status}.",
            "Review whether the response is expected and whether error pages disclose internal details.",
            kind="observation",
        ))
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


def inspect_html(response: HttpResponse) -> list[Finding]:
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
        if page.scheme == "https" and action.scheme != "https":
            findings.append(_finding(
                "html", "Password form may submit over an insecure connection", "high", "high",
                response, f"Password form action resolves to {action.scheme or 'relative'}://{action.netloc}{action.path[:100]}.",
                "Ensure password forms submit only to HTTPS endpoints on trusted origins.",
            ))
        if form["method"] == "get":
            findings.append(_finding(
                "html", "Password form uses GET", "high", "high", response,
                "A form containing a password input declares method=GET or omits method (GET is the default).",
                "Use POST over HTTPS and ensure secrets are never placed in query strings.",
            ))
    return findings
