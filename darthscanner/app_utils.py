"""Small, UI-independent helpers for the desktop app."""
from urllib.parse import urlsplit


def parse_target_url(value: str) -> tuple[str, str]:
    """Return a normalized HTTP(S) URL and exact hostname."""
    value = value.strip()
    if not value:
        raise ValueError("Enter a website URL first.")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// websites are supported.")
    if not parts.hostname or parts.username or parts.password:
        raise ValueError("Enter a valid website URL without embedded credentials.")
    try:
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parts.port
    except (UnicodeError, ValueError) as exc:
        raise ValueError("The website address or port is invalid.") from exc
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path or "/"
    normalized = f"{parts.scheme.lower()}://{netloc}{path}"
    if parts.query:
        normalized += "?" + parts.query
    return normalized, host
