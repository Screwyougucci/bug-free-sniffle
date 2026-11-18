"""JSON report serialization."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path


def write_report(path: str, *, target: str, requests_made: int,
                 pages: list[dict], findings: list, fuzz_observations: list[dict] | None = None) -> None:
    payload = {
        "tool": "Darth Scanner",
        "version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "requests_made": requests_made,
        "pages": pages,
        "findings": [item.to_dict() for item in findings],
        "fuzz_observations": fuzz_observations or [],
        "disclaimer": "Fuzz anomalies are triage signals, not proof of exploitability.",
    }
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
