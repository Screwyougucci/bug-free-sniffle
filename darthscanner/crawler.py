"""Deep, bounded same-origin route and asset discovery.

The crawler follows ordinary navigational links and same-origin script assets,
then extracts route-like literals from downloaded JavaScript. It never executes
JavaScript, submits forms, follows redirects, or visits state-changing URL paths.
"""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
import re
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from .http_client import HttpResponse, SafeHttpClient
from .scope import Scope


_SKIP_PATH_PARTS = {
    "logout", "log-out", "signout", "sign-out", "delete", "remove",
    "unsubscribe", "purchase", "checkout", "confirm", "activate",
}
_ASSET_EXTENSIONS = (".js", ".mjs")
_ROUTE_PATTERNS = (
    re.compile(r"""(?:(?:fetch|axios\.(?:get|post|put|patch|delete)|open)\s*\(\s*)?['"]((?:/|\./|\.\./)[^'"<>\\\s]{1,240})['"]""", re.I),
    re.compile(r"""(?:url|endpoint|api|path)\s*[:=]\s*['"]((?:/|\./|\.\./)[^'"<>\\\s]{1,240})['"]""", re.I),
)


class _ReferenceParser(HTMLParser):
    """Extract navigational links and same-origin script resources, not images."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.base_href: str | None = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {str(key).lower(): (value or "").strip() for key, value in attrs}
        if tag == "base" and values.get("href") and self.base_href is None:
            self.base_href = values["href"]
        elif tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag == "link" and values.get("href"):
            rel = {part.lower() for part in values.get("rel", "").split()}
            if rel & {"canonical", "next", "prev"}:
                self.links.append(values["href"])


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    default_port = 443 if parts.scheme.lower() == "https" else 80
    return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port or default_port


def _normalize_candidate(base_url: str, reference: str) -> str | None:
    reference = (reference or "").strip()
    if not reference or reference.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    candidate = urldefrag(urljoin(base_url, reference))[0]
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        return None
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def _is_state_changing_path(url: str) -> bool:
    parts = urlsplit(url)
    segments = {segment.lower() for segment in parts.path.split("/") if segment}
    return bool(segments & _SKIP_PATH_PARTS)


def _javascript_routes(source: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for pattern in _ROUTE_PATTERNS:
        for match in pattern.finditer(source[:1_000_000]):
            route = match.group(1)
            if route not in seen:
                seen.add(route)
                found.append(route)
    return found


def crawl(
    start_url: str,
    scope: Scope,
    client: SafeHttpClient,
    max_pages: int | None = None,
) -> list[HttpResponse]:
    """Crawl HTML routes and same-origin JS assets within explicit shared budgets."""
    scope.validate_url(start_url)
    start_url = _normalize_candidate(start_url, start_url)
    if not start_url:
        return []

    origin = _origin(start_url)
    page_limit = min(scope.max_pages, max_pages) if max_pages is not None else scope.max_pages
    queue = deque([(start_url, "page")])
    queued = {start_url}
    seen: set[str] = set()
    responses: list[HttpResponse] = []

    while queue and len(responses) < page_limit and client.requests_made < client.max_requests and not client.cancelled:
        url, kind = queue.popleft()
        queued.discard(url)
        if url in seen:
            continue
        seen.add(url)
        try:
            scope.validate_url(url)
            if _origin(url) != origin or _is_state_changing_path(url):
                continue
            response = client.get(url)
        except (ValueError, RuntimeError):
            continue
        responses.append(response)

        if response.status is None or response.status >= 400:
            continue
        content_type = response.headers.get("content-type", "").lower()
        path = urlsplit(url).path.lower()

        references: list[tuple[str, str]] = []
        base = url
        if "text/html" in content_type or (kind == "page" and not content_type and path.endswith((".html", ".htm", "/"))):
            parser = _ReferenceParser()
            try:
                parser.feed(response.text[:1_000_000])
            except Exception:
                continue
            base = _normalize_candidate(url, parser.base_href) or url
            references.extend((item, "page") for item in parser.links)
            references.extend((item, "asset") for item in parser.scripts)
        elif "javascript" in content_type or path.endswith(_ASSET_EXTENSIONS):
            references.extend((item, "page") for item in _javascript_routes(response.text))

        for reference, next_kind in references:
            candidate = _normalize_candidate(base, reference)
            if not candidate or candidate in seen or candidate in queued:
                continue
            try:
                scope.validate_url(candidate)
            except ValueError:
                continue
            if _origin(candidate) != origin or _is_state_changing_path(candidate):
                continue
            if len(seen) + len(queued) >= page_limit:
                break
            queued.add(candidate)
            queue.append((candidate, next_kind))

    return responses
