"""Passive API and well-known resource inventory with strict same-origin limits."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit

from .http_client import SafeHttpClient
from .api_schema_audit import inspect_openapi_schema
from .scope import Scope


_CANDIDATES = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port or (443 if parts.scheme == "https" else 80)


def _same_origin(url: str, origin: tuple[str, str, int], scope: Scope) -> bool:
    try:
        scope.validate_url(url)
        return _origin(url) == origin
    except ValueError:
        return False


def discover_api_resources(base_url: str, scope: Scope, client: SafeHttpClient,
                           *, max_resources: int = 7) -> dict:
    """Fetch a small fixed set of same-origin metadata resources and inventory API paths.

    No discovered API operation is invoked. OpenAPI paths and sitemap URLs are
    metadata only; the module never sends requests to paths found inside schemas.
    """
    scope.validate_url(base_url)
    if not 1 <= max_resources <= len(_CANDIDATES):
        raise ValueError("max_resources must be between 1 and 7.")
    origin = _origin(base_url)
    root = f"{origin[0]}://{origin[1]}" + (f":{origin[2]}" if origin[2] not in (80, 443) else "") + "/"
    resources = []
    endpoints: dict[str, dict] = {}
    sitemap_urls: set[str] = set()
    robots_sitemaps: set[str] = set()
    schema_findings: list[dict] = []

    candidates = [urljoin(root, path) for path in _CANDIDATES[:max_resources]]
    for url in candidates:
        if client.requests_made >= client.max_requests:
            break
        response = client.get(url)
        content_type = response.headers.get("content-type", "").lower()
        record = {"url": response.url, "status": response.status,
                  "response_bytes": len(response.body), "resource_type": "metadata"}
        resources.append(record)
        if response.status is None or not 200 <= response.status < 300 or not response.body:
            continue
        text = response.text[:1_000_000]
        path = urlsplit(url).path.lower()
        if path.endswith("robots.txt"):
            for line in text.splitlines():
                match = re.match(r"\s*sitemap\s*:\s*(\S+)", line, re.I)
                if match:
                    candidate = urljoin(url, match.group(1))
                    if _same_origin(candidate, origin, scope):
                        robots_sitemaps.add(candidate)
        elif path.endswith("sitemap.xml"):
            try:
                root_xml = ET.fromstring(text)
                for node in root_xml.iter():
                    if node.tag.rsplit("}", 1)[-1].lower() == "loc" and node.text:
                        candidate = urljoin(url, node.text.strip())
                        if _same_origin(candidate, origin, scope):
                            sitemap_urls.add(candidate)
            except ET.ParseError:
                record["parse_note"] = "Invalid sitemap XML; no URLs extracted."
        elif path.endswith(("openapi.json", "swagger.json", "/api-docs")) or "json" in content_type:
            try:
                spec = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(spec, dict):
                continue
            schema_findings.extend(item.to_dict() for item in inspect_openapi_schema(spec, response.url))
            paths = spec.get("paths", {})
            if isinstance(paths, dict):
                for api_path, operations in paths.items():
                    if not isinstance(api_path, str) or not api_path.startswith("/"):
                        continue
                    methods = sorted(k.upper() for k, v in operations.items()
                                     if k.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}
                                     and isinstance(v, dict)) if isinstance(operations, dict) else []
                    endpoints[api_path] = {"path": api_path, "methods_documented": methods}
                record["api_title"] = (spec.get("info") or {}).get("title") if isinstance(spec.get("info"), dict) else None
                record["api_version"] = (spec.get("info") or {}).get("version") if isinstance(spec.get("info"), dict) else None
                record["api_paths_found"] = len(paths) if isinstance(paths, dict) else 0
        elif path.endswith("security.txt"):
            fields = {}
            for line in text.splitlines():
                if ":" not in line or line.lstrip().startswith("#"):
                    continue
                key, value = line.split(":", 1)
                if key.lower().strip() in {"contact", "expires", "policy", "preferred-languages", "canonical"}:
                    fields.setdefault(key.lower().strip(), []).append(value.strip()[:300])
            record["security_txt_fields"] = sorted(fields)
            record["security_txt_present"] = True

    # Sitemap index URLs are reported only; no recursive sitemap or endpoint fetches.
    return {
        "resources": resources,
        "api_endpoints": sorted(endpoints.values(), key=lambda item: item["path"]),
        "sitemap_urls_discovered": sorted(sitemap_urls),
        "robots_sitemaps_discovered": sorted(robots_sitemaps),
        "schema_findings": schema_findings,
        "note": "Discovered URLs and API methods are inventory only; no API operations were invoked."
    }
