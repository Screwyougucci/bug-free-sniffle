"""Passive certificate-transparency subdomain discovery.

Discovered names are candidates only. Active checks are performed only when the
user explicitly opts into the root-domain scope in the desktop app.
"""
from __future__ import annotations

import json
import re
from urllib.parse import quote
from urllib.request import Request, urlopen

_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+$", re.I)


def discover_subdomains(root_domain: str, *, limit: int = 25, timeout: int = 8) -> list[str]:
    """Return at most 25 unique subdomains listed in crt.sh certificate records."""
    root = root_domain.encode("idna").decode("ascii").lower().strip(".")
    if not root or len(root) > 253 or "/" in root or ":" in root:
        raise ValueError("Invalid root domain for passive subdomain discovery.")
    request = Request(
        f"https://crt.sh/?q={quote('%.' + root, safe='')}&output=json",
        headers={"User-Agent": "DarthScanner/0.11 (+passive-authorized-assessment)"},
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
    found: set[str] = set()
    if not isinstance(records, list):
        return []
    for record in records:
        if not isinstance(record, dict):
            continue
        for candidate in str(record.get("name_value", "")).splitlines():
            host = candidate.strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if host == root or not host.endswith("." + root):
                continue
            if len(host) <= 253 and _HOST_RE.fullmatch(host + "."):
                found.add(host)
                if len(found) >= limit:
                    return sorted(found)[:limit]
    return sorted(found)[:limit]
