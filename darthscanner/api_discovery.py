"""Static discovery of explicit same-origin GET API URLs in served JavaScript.

JavaScript is never executed. Only literal URL arguments to unambiguous GET APIs
are considered; discovered URLs are still checked by the caller's exact-host scope.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from .discovery import _origin, _sensitive_name
from .scope import Scope


# Deliberately limited to literal strings and APIs that unambiguously issue GET.
_PATTERNS = (
    re.compile(r"""\bfetch\s*\(\s*(['"])([^'"\\\n]{1,2048})\1\s*\)""", re.I),
    re.compile(r"""\baxios\s*\.\s*get\s*\(\s*(['"])([^'"\\\n]{1,2048})\1""", re.I),
    re.compile(r"""\b(?:xhr|request|http)\s*\.\s*open\s*\(\s*(['"])GET\1\s*,\s*(['"])([^'"\\\n]{1,2048})\2""", re.I),
)


def discover_static_get_targets(
    source_url: str,
    source: str,
    scope: Scope,
    max_targets: int = 40,
) -> list[dict[str, object]]:
    """Extract literal, same-origin GET URLs with non-sensitive query keys."""
    if not 1 <= max_targets <= 100:
        raise ValueError("max_targets must be between 1 and 100.")
    scope.validate_url(source_url)
    found: dict[str, dict[str, object]] = {}
    source_origin = _origin(source_url)
    text = source[:1_000_000]
    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            raw_url = match.group(2) if len(match.groups()) == 2 else match.group(3)
            candidate = urljoin(source_url, raw_url.strip())
            try:
                scope.validate_url(candidate)
                parts = urlsplit(candidate)
                if parts.scheme.lower() not in {"http", "https"} or _origin(candidate) != source_origin:
                    continue
                if parts.username or parts.password:
                    continue
                names = list(dict.fromkeys(
                    name for name, _ in parse_qsl(parts.query, keep_blank_values=True)
                ))
                if not names or any(_sensitive_name(name) for name in names):
                    continue
                found.setdefault(candidate, {"url": candidate, "parameters": names, "discovered_from": source_url})
                if len(found) >= max_targets:
                    return list(found.values())
            except ValueError:
                continue
    return list(found.values())
