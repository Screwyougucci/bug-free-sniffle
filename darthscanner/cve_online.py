"""Rate-limited, cached NVD 2.0 lookup for detected CPE/version candidates."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .cve import match_cves
from .fingerprint import SoftwareComponent

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = timedelta(hours=24)
MIN_REQUEST_INTERVAL = 6.2
_LAST_REQUEST_AT = 0.0


def default_cache_path() -> Path:
    """Return a per-user cache path that works in Windows and packaged builds."""
    root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".cache"))
    folder = root / "DarthScanner"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "nvd-cve-cache.json"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _read_cache(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_cache(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(cache, ensure_ascii=True), encoding="utf-8")
    temporary.replace(path)


def _fetch_nvd(cpe: str, timeout: int = 15) -> list[dict]:
    """Fetch candidate CVEs for one exact CPE name from NVD API 2.0."""
    global _LAST_REQUEST_AT
    wait = MIN_REQUEST_INTERVAL - (time.monotonic() - _LAST_REQUEST_AT)
    if wait > 0:
        time.sleep(wait)
    query = urlencode({
        "cpeName": cpe,
        "isVulnerable": "true",
        "resultsPerPage": "2000",
    })
    headers = {"User-Agent": "DarthScanner/0.12 (NVD CPE candidate lookup)"}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    request = Request(f"{NVD_CVE_API}?{query}", headers=headers)
    _LAST_REQUEST_AT = time.monotonic()
    with urlopen(request, timeout=timeout) as response:
        payload = response.read(12_000_001)
    if len(payload) > 12_000_000:
        raise ValueError("NVD response exceeded the 12 MB safety limit.")
    raw = json.loads(payload.decode("utf-8", errors="replace"))
    records = raw.get("vulnerabilities") if isinstance(raw, dict) else None
    if not isinstance(records, list):
        raise ValueError("NVD returned an unexpected response format.")
    return [
        entry["cve"] for entry in records
        if isinstance(entry, dict)
        and isinstance(entry.get("cve"), dict)
        and str(entry["cve"].get("vulnStatus", "")).upper() != "REJECTED"
    ]


def lookup_cves_for_components(
    components: list[SoftwareComponent],
    *,
    cache_path: str | Path | None = None,
    max_network_lookups: int = 1,
) -> tuple[list, dict]:
    """Match detected components to NVD CVEs, caching results for 24 hours.

    At most one uncached CPE is queried per scan cycle by default. This keeps
    repeated watch cycles below NVD's unauthenticated request-rate ceiling.
    A CVE match remains a candidate, not proof that the deployment is vulnerable.
    """
    path = Path(cache_path) if cache_path else default_cache_path()
    cache = _read_cache(path)
    now = _now()
    findings = []
    looked_up = 0
    cache_hits = 0
    errors: list[str] = []
    seen_cpes: set[str] = set()

    for component in components:
        if component.cpe in seen_cpes:
            continue
        seen_cpes.add(component.cpe)
        entry = cache.get(component.cpe)
        fetched_at = _parse_timestamp(entry.get("fetched_at", "")) if isinstance(entry, dict) else None
        fresh = bool(fetched_at and now - fetched_at < CACHE_TTL and isinstance(entry.get("vulnerabilities"), list))
        if fresh:
            feed = entry["vulnerabilities"]
            cache_hits += 1
        elif looked_up < max_network_lookups:
            try:
                feed = _fetch_nvd(component.cpe)
                cache[component.cpe] = {
                    "fetched_at": now.isoformat(),
                    "vulnerabilities": feed,
                }
                looked_up += 1
                _write_cache(path, cache)
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{component.name} {component.version}: {type(exc).__name__}: {exc}")
                continue
        else:
            continue
        findings.extend(match_cves([component], feed))

    status = {
        "source": "NVD CVE API 2.0",
        "network_lookups": looked_up,
        "cache_hits": cache_hits,
        "components_seen": len(seen_cpes),
        "components_checked": cache_hits + looked_up,
        "components_deferred": max(0, len(seen_cpes) - cache_hits - looked_up - len(errors)),
        "cache_ttl_hours": int(CACHE_TTL.total_seconds() // 3600),
        "errors": errors,
    }
    return findings, status
