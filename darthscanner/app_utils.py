"""Small, UI-independent helpers for the desktop app."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_SCHEME_PREFIX = re.compile(r"^(https?):(?:/{0,2})", re.IGNORECASE)


def parse_target_url(value: str) -> tuple[str, str]:
    """Normalize an HTTP(S) URL and return its exact hostname.

    Accept bare hosts, normal URLs, and common input mistakes such as
    https/example.com or https://https/example.com. Never treat the
    literal protocol word as the target hostname.
    """
    value = value.strip()
    if not value:
        raise ValueError("Enter a website URL first.")
    if any(char.isspace() for char in value):
        raise ValueError("The website address cannot contain spaces.")

    prefix = _SCHEME_PREFIX.match(value)
    if prefix:
        scheme = prefix.group(1).lower()
        value = f"{scheme}://{value[prefix.end():]}"
    elif "://" not in value:
        value = "https://" + value

    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// websites are supported.")
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("Enter a valid website URL without embedded credentials.")

    raw_host = parts.hostname.rstrip(".")
    path = parts.path or "/"
    # Recover values double-prefixed by a UI protocol helper.
    if raw_host.lower() in {"http", "https"} and parts.path.startswith("/"):
        segments = parts.path.lstrip("/").split("/", 1)
        candidate = segments[0]
        if candidate and "." in candidate and not candidate.startswith("."):
            raw_host = candidate
            path = "/" + segments[1] if len(segments) == 2 else "/"

    try:
        host = raw_host.encode("idna").decode("ascii").lower().rstrip(".")
        if ":" in host:
            raise ValueError("IPv6 literal targets are not supported by the current exact-host scope.")
        port = parts.port
    except (UnicodeError, ValueError) as exc:
        raise ValueError("The website address or port is invalid.") from exc

    if not host or "/" in host or "\\" in host:
        raise ValueError("Enter a valid hostname, such as example.com.")
    netloc = host if port is None else f"{host}:{port}"
    # Never persist query strings that may contain session tokens.
    normalized = f"{scheme}://{netloc}{path}"
    return normalized, host
