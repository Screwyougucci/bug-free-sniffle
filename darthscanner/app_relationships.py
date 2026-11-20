"""Correlate passive frontend routes and forms with documented API contracts.

This module consumes already-collected metadata only. It never sends requests,
executes JavaScript, submits forms, or infers runtime authorization from a schema.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_SENSITIVE_SEGMENTS = {
    "account", "accounts", "admin", "administrator", "billing", "payment",
    "payments", "invoice", "invoices", "member", "members", "order", "orders",
    "permission", "permissions", "profile", "profiles", "role", "roles",
    "tenant", "tenants", "user", "users",
}
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def _path(value: str) -> str:
    parts = urlsplit(value)
    raw = parts.path if parts.scheme or parts.netloc else value
    raw = raw.split("?", 1)[0].split("#", 1)[0]
    if not raw.startswith("/"):
        raw = "/" + raw
    return re.sub(r"/{2,}", "/", raw).rstrip("/") or "/"


def _segments(path: str) -> list[str]:
    return [part for part in _path(path).strip("/").split("/") if part]


def _looks_dynamic(segment: str) -> bool:
    return (
        segment.isdigit()
        or bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", segment))
        or bool(re.fullmatch(r"[0-9a-fA-F]{24}", segment))
    )


def _match(client_path: str, api_path: str) -> str | None:
    left, right = _segments(client_path), _segments(api_path)
    if len(left) != len(right):
        return None
    exact = True
    for actual, declared in zip(left, right):
        if declared.startswith("{") and declared.endswith("}"):
            exact = False
            continue
        if actual.lower() == declared.lower():
            continue
        if _looks_dynamic(actual):
            exact = False
            continue
        return None
    return "exact" if exact else "path-template"


def _sensitive(path: str) -> bool:
    return any(part.lower() in _SENSITIVE_SEGMENTS for part in _segments(path))


def build_app_api_relationships(
    app_surfaces: list[dict],
    javascript_routes: list[dict],
    api_endpoints: list[dict],
    graphql_operations: list[dict] | None = None,
    *,
    max_relationships: int = 500,
) -> dict:
    """Join frontend form/route metadata to OpenAPI paths using bounded matching."""
    if not 1 <= max_relationships <= 2000:
        raise ValueError("max_relationships must be between 1 and 2000.")

    contracts = []
    for item in api_endpoints[:5000]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        methods = sorted({
            str(method).upper() for method in item.get("methods_documented", [])
            if str(method).upper() in _METHODS
        })
        contracts.append({"path": _path(item["path"]), "methods": methods})

    clients = []
    for surface in app_surfaces[:200]:
        if not isinstance(surface, dict):
            continue
        for form in surface.get("forms", [])[:100]:
            if not isinstance(form, dict) or not isinstance(form.get("action"), str):
                continue
            if form.get("same_origin_action") is not True:
                continue
            method = str(form.get("method", "GET")).upper()
            if method not in _METHODS:
                continue
            clients.append({
                "client_type": "html-form",
                "page_url": str(surface.get("page_url", "")),
                "endpoint": form["action"],
                "method": method,
            })

    for route in javascript_routes[:1000]:
        if not isinstance(route, dict) or not isinstance(route.get("endpoint"), str):
            continue
        method = str(route.get("method", "GET")).upper()
        if method not in _METHODS:
            continue
        clients.append({
            "client_type": "javascript-route",
            "page_url": str(route.get("discovered_from", "")),
            "endpoint": route["endpoint"],
            "method": method,
        })

    relationships = []
    unmatched = []
    seen = set()
    for client in clients:
        endpoint = _path(client["endpoint"])
        key = (client["client_type"], client["page_url"], endpoint, client["method"])
        if key in seen:
            continue
        seen.add(key)
        candidates = []
        for contract in contracts:
            quality = _match(endpoint, contract["path"])
            if quality:
                candidates.append((quality, contract))
        candidates.sort(key=lambda item: (item[0] != "exact", item[1]["path"]))
        if not candidates:
            unmatched.append({
                **client,
                "path": endpoint,
                "sensitive_path_hint": _sensitive(endpoint),
                "note": "No matching path was found in the supplied OpenAPI inventory; this is not evidence that the route is undocumented or vulnerable.",
            })
            continue
        for quality, contract in candidates[:5]:
            methods = contract["methods"]
            relationships.append({
                **client,
                "path": endpoint,
                "api_path_template": contract["path"],
                "documented_methods": methods,
                "path_match": quality,
                "method_documented": client["method"] in methods if methods else None,
                "sensitive_path_hint": _sensitive(endpoint),
            })
            if len(relationships) >= max_relationships:
                break
        if len(relationships) >= max_relationships:
            break

    referenced = {item["api_path_template"] for item in relationships}
    unreferenced = [
        {"path": item["path"], "methods_documented": item["methods"]}
        for item in contracts if item["path"] not in referenced
    ][:500]

    graphql = []
    for operation in (graphql_operations or [])[:500]:
        if not isinstance(operation, dict):
            continue
        graphql.append({
            "source_url": str(operation.get("source_url", "")),
            "operation_type": str(operation.get("operation_type", "")),
            "operation_name": str(operation.get("operation_name", ""))[:120],
            "root_field_names": [
                str(name)[:100] for name in operation.get("root_field_names", [])[:40]
            ],
            "source_line": operation.get("source_line"),
        })

    return {
        "relationships": relationships,
        "relationship_count": len(relationships),
        "unmatched_client_routes": unmatched[:500],
        "unmatched_client_route_count": len(unmatched),
        "unreferenced_api_contracts": unreferenced,
        "unreferenced_api_contract_count": len(unreferenced),
        "graphql_operations": graphql,
        "graphql_operation_count": len(graphql),
        "analysis_note": (
            "Frontend-to-API links are matched from already-fetched HTML, static JavaScript "
            "route metadata, and supplied OpenAPI paths. GraphQL operation metadata is listed "
            "separately. A path or method match does not establish runtime reachability, "
            "authorization behavior, or exploitability; no operations are executed."
        ),
    }
