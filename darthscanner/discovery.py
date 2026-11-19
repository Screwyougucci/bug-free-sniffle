"""Coverage-guided route and query-parameter discovery from fetched HTML.

Only links already present in fetched, same-origin pages are considered.
Forms are not submitted, scripts are not executed, and this module makes no requests.
"""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from .http_client import HttpResponse
from .scope import Scope


SENSITIVE_PARAMETER_PARTS = (
    "token", "secret", "password", "passwd", "auth", "session",
    "cookie", "key", "signature", "sig", "code", "credential",
)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return (
        parts.scheme.lower(),
        (parts.hostname or "").lower(),
        parts.port or (443 if parts.scheme.lower() == "https" else 80),
    )


def _sensitive_name(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(part in lowered for part in SENSITIVE_PARAMETER_PARTS)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag.lower() not in {"a", "link", "area"}:
            return
        values = {str(key).lower(): value for key, value in attrs}
        href = values.get("href")
        if href:
            self.links.append(href)


def discover_query_targets(
    responses: list[HttpResponse],
    scope: Scope,
    max_targets: int = 40,
) -> list[dict[str, object]]:
    """Return unique same-origin URLs with safe-to-test existing query keys."""
    if not 1 <= max_targets <= 100:
        raise ValueError("max_targets must be between 1 and 100.")
    discovered: dict[str, dict[str, object]] = {}
    origins = {_origin(response.url) for response in responses}
    for response in responses:
        if response.status is None or response.status >= 400:
            continue
        candidates = [response.url]
        if "text/html" in response.headers.get("content-type", "").lower():
            parser = _LinkParser()
            try:
                parser.feed(response.text[:1_000_000])
            except Exception:
                parser.links = []
            candidates.extend(urljoin(response.url, href) for href in parser.links)
        for candidate in candidates:
            candidate = urldefrag(candidate)[0]
            try:
                scope.validate_url(candidate)
                parts = urlsplit(candidate)
                if _origin(candidate) not in origins:
                    continue
                if parts.scheme.lower() not in {"http", "https"}:
                    continue
                from urllib.parse import parse_qsl
                pairs = parse_qsl(parts.query, keep_blank_values=True)
                names = list(dict.fromkeys(name for name, _ in pairs))
                if not names or any(_sensitive_name(name) for name in names):
                    continue
                discovered.setdefault(candidate, {
                    "url": candidate,
                    "parameters": names,
                })
                if len(discovered) >= max_targets:
                    return list(discovered.values())
            except ValueError:
                continue
    return list(discovered.values())
