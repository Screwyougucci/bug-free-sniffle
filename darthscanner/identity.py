"""Stable discovery identities and lifecycle tracking.

IDs are deterministic, privacy-conscious fingerprints. Raw response bodies,
cookies, credentials, and request secrets are never stored here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from urllib.parse import urlsplit, urlunsplit


def _digest(prefix: str, *parts: str) -> str:
    material = json.dumps([str(part) for part in parts], ensure_ascii=True, separators=(",", ":"))
    return f"{prefix}-{sha256(material.encode('utf-8')).hexdigest()[:20]}"


def normalize_url(url: str) -> str:
    """Normalize URL identity without query strings, fragments, or credentials."""
    parts = urlsplit(str(url))
    host = (parts.hostname or "").lower()
    if parts.port:
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), host, path, "", ""))


def target_id(target: str) -> str:
    parts = urlsplit(str(target))
    origin = f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}"
    if parts.port:
        origin += f":{parts.port}"
    return _digest("tgt", origin)


def resource_id(url: str) -> str:
    return _digest("res", normalize_url(url))


def finding_identity(finding: dict) -> dict:
    url = normalize_url(finding.get("url", ""))
    category = str(finding.get("category", "unknown"))
    title = str(finding.get("title", "untitled"))
    kind = str(finding.get("kind", "finding"))
    legacy_id = str(finding.get("finding_id") or _digest("fnd", category, title, url))
    return {
        "finding_id": legacy_id,
        "resource_id": resource_id(url),
        "behavior_id": _digest("beh", url, category, title),
        "evidence_id": _digest("evd", legacy_id, str(finding.get("evidence", ""))),
        "test_id": _digest("tst", category, kind),
    }


def report_identity(target: str, pages: list[dict]) -> dict:
    resources = []
    for page in pages:
        url = page.get("url")
        if url:
            resources.append({"url": normalize_url(url), "resource_id": resource_id(url)})
    unique = {item["resource_id"]: item for item in resources}
    return {
        "target_id": target_id(target),
        "resources": sorted(unique.values(), key=lambda item: item["resource_id"]),
    }


def update_finding_registry(
    history: dict,
    findings: list[dict],
    *,
    complete_round: bool = False,
    now: str | None = None,
) -> dict:
    """Update persistent lifecycle state; resolve only after a complete check round."""
    timestamp = now or datetime.now(timezone.utc).isoformat()
    registry = history.setdefault("finding_registry", {})
    round_seen = set(history.get("round_seen_finding_ids") or [])
    newly_seen = []
    changed = []
    recurring = []
    for finding in findings:
        identity = finding_identity(finding)
        url = normalize_url(finding.get("url", ""))
        fid = identity["finding_id"]
        signature = _digest(
            "sig",
            str(finding.get("severity", "")),
            str(finding.get("title", "")),
            str(finding.get("evidence", "")),
            str(finding.get("remediation", "")),
        )
        previous = registry.get(fid)
        if previous is None:
            entry = {
                **identity,
                "status": "new",
                "first_seen": timestamp,
                "last_seen": timestamp,
                "occurrences": 1,
                "signature": signature,
                "title": str(finding.get("title", "Untitled")),
                "severity": str(finding.get("severity", "info")),
                "category": str(finding.get("category", "unknown")),
                "url": url,
                "description": str(finding.get("description", "")),
                "evidence": str(finding.get("evidence", "")),
                "source_excerpt": finding.get("source_excerpt"),
                "source_line": finding.get("source_line"),
                "remediation": str(finding.get("remediation", "")),
            }
            newly_seen.append(fid)
        else:
            entry = dict(previous)
            if entry.get("signature") != signature:
                entry["status"] = "changed"
                entry["changes"] = int(entry.get("changes", 0)) + 1
                changed.append(fid)
            else:
                entry["status"] = "recurring"
                recurring.append(fid)
            entry["last_seen"] = timestamp
            entry["occurrences"] = int(entry.get("occurrences", 0)) + 1
            entry["signature"] = signature
            entry.update(identity)
            entry.update({
                "title": str(finding.get("title", entry.get("title", "Untitled"))),
                "severity": str(finding.get("severity", entry.get("severity", "info"))),
                "category": str(finding.get("category", entry.get("category", "unknown"))),
                "url": url,
                "description": str(finding.get("description", entry.get("description", ""))),
                "evidence": str(finding.get("evidence", entry.get("evidence", ""))),
                "source_excerpt": finding.get("source_excerpt", entry.get("source_excerpt")),
                "source_line": finding.get("source_line", entry.get("source_line")),
                "remediation": str(finding.get("remediation", entry.get("remediation", ""))),
            })
        registry[fid] = entry
        round_seen.add(fid)

    resolved = []
    if complete_round:
        for fid, entry in registry.items():
            if fid not in round_seen and entry.get("status") != "resolved":
                entry["status"] = "resolved"
                entry["resolved_at"] = timestamp
                resolved.append(fid)
        round_seen.clear()

    history["finding_registry"] = registry
    history["round_seen_finding_ids"] = sorted(round_seen)
    return {
        "new": newly_seen,
        "changed": changed,
        "recurring": recurring,
        "resolved": resolved,
    }
