"""Authorization and target-scope enforcement."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when a target is outside the declared authorization scope."""


@dataclass(frozen=True)
class Scope:
    authorized: bool
    allowed_hosts: tuple[str, ...]
    max_pages: int = 30
    max_requests: int = 50
    request_delay_seconds: float = 1.0
    timeout_seconds: int = 8
    root_domain: str | None = None
    include_subdomains: bool = False
    max_subdomain_depth: int = 5
    max_subdomain_hosts: int = 25

    def validate_url(self, url: str) -> str:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            raise ScopeError("Only http:// and https:// URLs are supported.")
        if not parts.hostname or parts.username or parts.password:
            raise ScopeError("URL must include a hostname and must not contain credentials.")
        try:
            host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise ScopeError("Invalid internationalized hostname.") from exc
        allowed = {h.lower().rstrip(".") for h in self.allowed_hosts}
        in_subdomain_scope = bool(
            self.include_subdomains and self.root_domain
            and host.endswith("." + self.root_domain.lower().rstrip("."))
        )
        if host not in allowed and not in_subdomain_scope:
            raise ScopeError(f"Host {host!r} is outside the explicitly authorized host scope.")
        if parts.port is not None and not (1 <= parts.port <= 65535):
            raise ScopeError("Invalid destination port.")
        return url


def load_scope(path: str | Path) -> Scope:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"Could not read scope file: {exc}") from exc

    if not isinstance(raw, dict):
        raise ScopeError("Scope file must contain a JSON object.")
    hosts = raw.get("allowed_hosts")
    if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h.strip() for h in hosts):
        raise ScopeError("allowed_hosts must be a non-empty list of exact hostnames.")
    hosts = tuple(h.strip().lower().rstrip(".") for h in hosts)
    if any("://" in h or "/" in h or ":" in h for h in hosts):
        raise ScopeError("allowed_hosts entries must be hostnames only, without scheme, path, or port.")

    def bounded_int(name: str, default: int, low: int, high: int) -> int:
        value = raw.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ScopeError(f"{name} must be an integer from {low} to {high}.")
        return value

    delay = raw.get("request_delay_seconds", 1.0)
    timeout = bounded_int("timeout_seconds", 8, 1, 30)
    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not 0.5 <= float(delay) <= 10:
        raise ScopeError("request_delay_seconds must be between 0.5 and 10 seconds.")

    include_subdomains = raw.get("include_subdomains", False)
    if not isinstance(include_subdomains, bool):
        raise ScopeError("include_subdomains must be true or false.")
    root_domain = raw.get("root_domain")
    if include_subdomains:
        if not isinstance(root_domain, str) or not root_domain.strip():
            raise ScopeError("root_domain is required when include_subdomains is true.")
        root_domain = root_domain.strip().encode("idna").decode("ascii").lower().rstrip(".")
        labels = root_domain.split(".")
        public_suffix_prefixes = {"ac", "co", "com", "edu", "gov", "net", "org", "mil", "go", "ne", "or"}
        if len(labels) < 2 or (len(labels) == 2 and len(labels[1]) == 2 and labels[0] in public_suffix_prefixes):
            raise ScopeError("Use a registrable root domain, not a public suffix such as com or co.uk.")
        if root_domain not in hosts:
            raise ScopeError("root_domain must exactly match one allowed_hosts entry.")
    else:
        root_domain = None

    return Scope(
        authorized=raw.get("authorized") is True,
        allowed_hosts=hosts,
        root_domain=root_domain,
        include_subdomains=include_subdomains,
        max_subdomain_depth=bounded_int("max_subdomain_depth", 5, 1, 8),
        max_subdomain_hosts=bounded_int("max_subdomain_hosts", 25, 1, 100),
        max_pages=bounded_int("max_pages", 30, 1, 200),
        max_requests=bounded_int("max_requests", 50, 1, 500),
        request_delay_seconds=float(delay),
        timeout_seconds=timeout,
    )


def require_authorization(scope: Scope, acknowledged: bool) -> None:
    if not scope.authorized:
        raise ScopeError("Set authorized=true in the scope file only after obtaining permission.")
    if not acknowledged:
        raise ScopeError("Pass --acknowledge-authorization after confirming permission to test this system.")
