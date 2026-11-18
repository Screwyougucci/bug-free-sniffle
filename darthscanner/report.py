"""JSON report serialization with normalized summaries."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

from . import __version__


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}


def write_report(path: str, *, target: str, requests_made: int,
                 pages: list[dict], findings: list,
                 fuzz_observations: list[dict] | None = None,
                 software_components: list[dict] | None = None) -> None:
    """Write a stable report containing detailed findings and coverage totals."""
    unique = {}
    for item in findings:
        unique[item.finding_id] = item
    normalized = sorted(
        unique.values(),
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 6),
            -(item.cvss_score or 0.0),
            item.category,
            item.url,
            item.title,
        ),
    )
    severity_counts = Counter(item.severity for item in normalized)
    category_counts = Counter(item.category for item in normalized)
    kind_counts = Counter(item.kind for item in normalized)
    page_statuses = Counter(
        "error" if page.get("status") is None else
        "2xx" if 200 <= page["status"] < 300 else
        "3xx" if 300 <= page["status"] < 400 else
        "4xx" if 400 <= page["status"] < 500 else
        "5xx" if page["status"] >= 500 else "other"
        for page in pages
    )
    cve_findings = [item for item in normalized if item.category == "cve"]
    payload = {
        "tool": "Darth Scanner",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "coverage": {
            "requests_made": requests_made,
            "pages_reviewed": len(pages),
            "page_statuses": dict(page_statuses),
            "software_components_identified": len(software_components or []),
            "findings_total": len(normalized),
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "kind_counts": dict(kind_counts),
            "cve_matches": len(cve_findings),
        },
        "software_components": software_components or [],
        "pages": pages,
        "findings": [item.to_dict() for item in normalized],
        "fuzz_observations": fuzz_observations or [],
        "disclaimer": (
            "CVE matches are candidates based on available CPE/version data and must be "
            "validated against vendor advisories, platform conditions, and backported fixes. "
            "Fuzz anomalies are triage signals, not proof of exploitability."
        ),
    }
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
