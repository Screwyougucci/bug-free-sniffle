"""Bounded discovery of literal same-origin GET routes in served JavaScript.

JavaScript is never executed. Only explicit, static GET call forms are indexed.
Discovered routes are inventory evidence; this module does not request them.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .discovery import _origin, _sensitive_name
from .scope import Scope


_PATTERNS = (
    ("fetch", re.compile(r"""\bfetch\s*\(\s*(['"])([^'"\\\n]{1,2048})\1\s*\)""", re.I)),
    ("axios.get", re.compile(r"""\baxios\s*\.\s*get\s*\(\s*(['"])([^'"\\\n]{1,2048})\1""", re.I)),
    ("xhr.open", re.compile(r"""\b(?:xhr|request|http)\s*\.\s*open\s*\(\s*(['"])GET\1\s*,\s*(['"])([^'"\\\n]{1,2048})\2""", re.I)),
)


def discover_static_get_routes(
    source_url: str,
    source: str,
    scope: Scope,
    max_routes: int = 100,
) -> list[dict[str, object]]:
    """Index literal same-origin GET endpoints without retaining query values."""
    if not 1 <= max_routes <= 100:
        raise ValueError("max_routes must be between 1 and 100.")
    scope.validate_url(source_url)
    source = source[:1_000_000]
    source_origin = _origin(source_url)
    routes: dict[str, dict[str, object]] = {}

    for api_name, pattern in _PATTERNS:
        for match in pattern.finditer(source):
            raw_url = match.group(2) if api_name != "xhr.open" else match.group(3)
            candidate = urljoin(source_url, raw_url.strip())
            try:
                scope.validate_url(candidate)
                parts = urlsplit(candidate)
                if parts.scheme.lower() not in {"http", "https"} or _origin(candidate) != source_origin:
                    continue
                if parts.username or parts.password:
                    continue
                parameter_names = list(dict.fromkeys(
                    name for name, _ in parse_qsl(parts.query, keep_blank_values=True)
                ))
                if any(_sensitive_name(name) for name in parameter_names):
                    continue
                endpoint = urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", "", ""))
            except ValueError:
                continue

            line = source.count("\n", 0, match.start()) + 1
            record = routes.get(endpoint)
            if record is None:
                record = {
                    "method": "GET",
                    "endpoint": endpoint,
                    "parameters": [],
                    "discovered_from": source_url,
                    "client_api": api_name,
                    "source_line": line,
                }
                routes[endpoint] = record
            merged = list(record["parameters"])
            for name in parameter_names:
                if name not in merged:
                    merged.append(name)
            record["parameters"] = merged
            if len(routes) >= max_routes:
                return list(routes.values())

    return list(routes.values())
