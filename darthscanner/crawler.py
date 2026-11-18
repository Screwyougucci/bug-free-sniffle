"""Bounded same-origin HTML link discovery; never submits forms."""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from .http_client import HttpResponse, SafeHttpClient
from .scope import Scope


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() not in {"a", "link"}:
            return
        values = dict(attrs)
        href = values.get("href")
        if href:
            self.links.append(href)


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    default_port = 443 if parts.scheme == "https" else 80
    return parts.scheme, (parts.hostname or "").lower(), parts.port or default_port


def crawl(start_url: str, scope: Scope, client: SafeHttpClient) -> list[HttpResponse]:
    scope.validate_url(start_url)
    start_url = urldefrag(start_url)[0]
    origin = _origin(start_url)
    queue = deque([start_url])
    seen: set[str] = set()
    responses: list[HttpResponse] = []

    while queue and len(responses) < scope.max_pages and client.requests_made < client.max_requests:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        response = client.get(url)
        responses.append(response)

        if response.status is None or response.status >= 400:
            continue
        if "text/html" not in response.headers.get("content-type", "").lower():
            continue

        parser = _LinkParser()
        try:
            parser.feed(response.text)
        except Exception:
            continue
        for href in parser.links:
            candidate = urldefrag(urljoin(url, href))[0]
            try:
                scope.validate_url(candidate)
            except ValueError:
                continue
            if _origin(candidate) == origin and candidate not in seen and len(seen) + len(queue) < scope.max_pages:
                queue.append(candidate)

    return responses
