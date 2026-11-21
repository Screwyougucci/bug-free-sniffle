"""Bounded recursive passive certificate-transparency discovery.

Names are candidates until DNS resolves them to public addresses. Discovery is
passive; active checks still require explicit root-domain authorization.
"""
from __future__ import annotations

from collections import deque
import ipaddress
import json
import re
import socket
import time
from urllib.parse import quote
from urllib.request import Request, urlopen

_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
_DISCOVERY_CACHE: dict[tuple[str, int, int], tuple[float, list[dict]]] = {}
_CACHE_TTL_SECONDS = 900
MAX_SUBDOMAIN_DEPTH = 8
MAX_SUBDOMAIN_HOSTS = 100


def validate_discovery_limits(max_depth: int, limit: int) -> tuple[int, int]:
    """Validate UI/CLI recursive-discovery limits before any network activity."""
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= MAX_SUBDOMAIN_DEPTH:
        raise ValueError(f"Max subdomain depth must be an integer from 1 to {MAX_SUBDOMAIN_DEPTH}.")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SUBDOMAIN_HOSTS:
        raise ValueError(f"Max subdomain hosts must be an integer from 1 to {MAX_SUBDOMAIN_HOSTS}.")
    return max_depth, limit


def _fetch_ct_names(zone: str, timeout: int) -> list[str]:
    request = Request(
        f"https://crt.sh/?q={quote('%.' + zone, safe='')}&output=json",
        headers={"User-Agent": "DarthScanner/0.13 (+passive-authorized-assessment)"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(2_000_001)
    except Exception:
        return []
    if len(payload) > 2_000_000:
        return []
    try:
        records = json.loads(payload.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeError):
        return []
    if not isinstance(records, list):
        return []
    names: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        for candidate in str(record.get("name_value", "")).splitlines():
            host = candidate.strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if _HOST_RE.fullmatch(host):
                names.add(host)
    return sorted(names)


def _resolves_to_public_address(host: str) -> bool:
    """Require DNS to resolve exclusively to globally routable addresses."""
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    addresses = set()
    for record in records:
        try:
            address = ipaddress.ip_address(record[4][0].split("%", 1)[0])
        except (ValueError, IndexError, TypeError):
            continue
        addresses.add(address)
    return bool(addresses) and all(address.is_global for address in addresses)


def discover_subdomain_tree(
    root_domain: str,
    *,
    max_depth: int = 5,
    limit: int = 25,
    timeout: int = 8,
    resolver=None,
    fetcher=None,
    cache_ttl: int = _CACHE_TTL_SECONDS,
) -> list[dict]:
    """Discover nested subdomains breadth-first, with depth/host/query bounds.

    Entries contain host, depth, nearest discovered parent, and DNS status.
    Resolver and fetcher callbacks are injectable for deterministic tests.
    """
    try:
        root = root_domain.encode("idna").decode("ascii").lower().strip(".")
    except (AttributeError, UnicodeError) as exc:
        raise ValueError("Invalid root domain for passive subdomain discovery.") from exc
    if not root or len(root) > 253 or not _HOST_RE.fullmatch(root):
        raise ValueError("Invalid root domain for passive subdomain discovery.")
    validate_discovery_limits(max_depth, limit)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
        raise ValueError("timeout must be an integer from 1 to 30.")

    cache_key = (root, max_depth, limit)
    now = time.monotonic()
    cached = _DISCOVERY_CACHE.get(cache_key)
    if cache_ttl > 0 and cached and now - cached[0] < cache_ttl:
        return [dict(item) for item in cached[1]]

    resolve = resolver or _resolves_to_public_address
    fetch = fetcher or _fetch_ct_names
    queue = deque([(root, 0)])
    queried: set[str] = set()
    discovered: dict[str, dict] = {}

    # One CT lookup for the root plus at most one for each accepted host.
    query_budget = limit + 1
    while queue and len(discovered) < limit and len(queried) < query_budget:
        zone, zone_depth = queue.popleft()
        if zone in queried or zone_depth >= max_depth:
            continue
        queried.add(zone)
        try:
            candidates = fetch(zone, timeout)
        except Exception:
            candidates = []
        normalized = set()
        for raw_host in candidates:
            try:
                host = str(raw_host).strip().encode("idna").decode("ascii").lower().rstrip(".")
            except (UnicodeError, AttributeError):
                continue
            if not _HOST_RE.fullmatch(host) or host == root or not host.endswith("." + root):
                continue
            if host == zone or not host.endswith("." + zone):
                continue
            depth = len(host.split(".")) - len(root.split("."))
            if 1 <= depth <= max_depth:
                normalized.add(host)

        for host in sorted(normalized, key=lambda value: (len(value.split(".")), value)):
            if host in discovered or len(discovered) >= limit:
                continue
            try:
                verified = bool(resolve(host))
            except Exception:
                verified = False
            if not verified:
                continue
            depth = len(host.split(".")) - len(root.split("."))
            discovered[host] = {
                "host": host,
                "depth": depth,
                "parent": root,
                "dns_verified": True,
            }
            if depth < max_depth and len(queried) + len(queue) < query_budget:
                queue.append((host, depth))

    # Attach each host to its nearest discovered ancestor, not merely the root.
    for host, item in discovered.items():
        labels = host.split(".")
        for index in range(1, len(labels) - len(root.split(".")) + 1):
            ancestor = ".".join(labels[index:])
            if ancestor in discovered:
                item["parent"] = ancestor
                break

    result = sorted(discovered.values(), key=lambda item: (item["depth"], item["host"]))
    if cache_ttl > 0:
        _DISCOVERY_CACHE[cache_key] = (time.monotonic(), [dict(item) for item in result])
    return result


def discover_subdomains(root_domain: str, *, limit: int = 25, timeout: int = 8) -> list[str]:
    """Backward-compatible wrapper returning recursively discovered hostnames."""
    return [
        item["host"]
        for item in discover_subdomain_tree(root_domain, limit=limit, timeout=timeout)
    ]
