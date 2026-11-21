"""Adaptive, content-aware watch orchestration with persistent scan history."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

FOCUSES = ("headers", "cookies", "cors", "redirects", "html", "browser", "javascript", "fingerprint")
# Backwards-compatible name for the 0.7.0 tests and callers.
PROFILES = FOCUSES


def profile_for_cycle(cycle: int) -> str:
    """Return a deterministic focus for a zero-based cycle."""
    if cycle < 0:
        raise ValueError("cycle must be non-negative")
    return FOCUSES[cycle % len(FOCUSES)]


def eligible_focuses(report: dict) -> list[str]:
    """Choose checks supported by observed response metadata; never broaden scope."""
    pages = report.get("pages") or []
    if not pages:
        return ["headers", "fingerprint"]
    page = pages[0]
    content_type = str(page.get("content_type", "")).lower()
    resource_type = str(page.get("resource_type", "")).lower()
    status = page.get("status")
    eligible = ["headers"]
    if page.get("has_set_cookie"):
        eligible.append("cookies")
    if page.get("has_cors_headers"):
        eligible.append("cors")
    if page.get("has_redirect") or (isinstance(status, int) and 300 <= status < 400):
        eligible.append("redirects")
    if resource_type == "html" or "text/html" in content_type:
        eligible.extend(["html", "browser"])
        if int(page.get("script_count", 0) or 0) > 0:
            eligible.append("javascript")
    eligible.append("fingerprint")
    return eligible


def choose_next_focus(eligible: list[str], completed: list[str], cycle: int = 0) -> str:
    """Pick an eligible focus not completed in the current response revision."""
    choices = [item for item in eligible if item in FOCUSES]
    if not choices:
        choices = ["headers", "fingerprint"]
    remaining = [item for item in choices if item not in set(completed)]
    pool = remaining or choices
    return pool[cycle % len(pool)]


def _load_history(path: Path) -> dict:
    empty = {
        "target": None, "seen_finding_ids": [], "cycles_completed": 0,
        "completed_focuses": [], "eligible_focuses": [],
        "response_fingerprint": None,
    }
    if not path.exists():
        return empty
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(data, dict):
        return empty
    for key, value in empty.items():
        data.setdefault(key, value)
    if not isinstance(data.get("seen_finding_ids"), list):
        data["seen_finding_ids"] = []
    if not isinstance(data.get("completed_focuses"), list):
        data["completed_focuses"] = []
    if not isinstance(data.get("eligible_focuses"), list):
        data["eligible_focuses"] = []
    return data


def run_watch(*, target: str, scope_path: str, acknowledge_authorization: bool,
              output_dir: str, interval: int = 30, cycles: int | None = None) -> int:
    """Run one content-aware, read-only web analysis focus per cycle."""
    if interval < 30:
        raise ValueError("--interval must be at least 30 seconds for continuous rechecks")
    if cycles is not None and cycles < 1:
        raise ValueError("--cycles must be at least 1")
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    history_path = folder / "history.json"
    history = _load_history(history_path)
    if history.get("target") != target:
        history.update({
            "target": target,
            "seen_finding_ids": [],
            "completed_focuses": [],
            "eligible_focuses": [],
            "response_fingerprint": None,
        })
    seen = set(str(item) for item in history["seen_finding_ids"])
    cycle = 0
    print("Darth Scanner 0.8 adaptive watch started. Press Ctrl+C to stop.", flush=True)
    print("Only applicable, same-target web analyses run; TLS, host-wide methods, and exposure-path probes are excluded.", flush=True)
    try:
        while cycles is None or cycle < cycles:
            eligible = history.get("eligible_focuses") or ["headers", "fingerprint"]
            completed_focuses = history.get("completed_focuses") or []
            focus = choose_next_focus(eligible, completed_focuses, cycle)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            report_path = folder / f"cycle-{cycle + 1:06d}-{focus}-{stamp}.json"
            command = [
                sys.executable, "-m", "darthscanner", "scan",
                "--target", target,
                "--scope", scope_path,
                "--profile", "web",
                "--focus", focus,
                "--output", str(report_path),
            ]
            if acknowledge_authorization:
                command.append("--acknowledge-authorization")
            print(f"\nCycle {cycle + 1}: {focus} analysis -> {report_path}", flush=True)
            completed = subprocess.run(command, check=False)
            if completed.returncode != 0:
                print(f"Watch stopped: scan exited with status {completed.returncode}.", file=sys.stderr, flush=True)
                return completed.returncode
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Watch stopped: could not read generated report: {exc}", file=sys.stderr, flush=True)
                return 2

            pages = report.get("pages") or []
            page_fingerprint = pages[0].get("response_fingerprint") if pages else None
            if history.get("response_fingerprint") and page_fingerprint and history["response_fingerprint"] != page_fingerprint:
                completed_focuses = []
                print("Response changed; resetting completed checks and adapting to the new content.", flush=True)
            next_eligible = eligible_focuses(report)
            if focus not in completed_focuses:
                completed_focuses.append(focus)
            if all(item in completed_focuses for item in next_eligible):
                completed_focuses = []
                print("Applicable checks completed; beginning a fresh recheck round.", flush=True)

            findings = report.get("findings", [])
            new_items = [item for item in findings if item.get("finding_id") and item["finding_id"] not in seen]
            for item in findings:
                finding_id = item.get("finding_id")
                if finding_id:
                    seen.add(finding_id)
            cycle += 1
            history.update({
                "target": target,
                "cycles_completed": int(history.get("cycles_completed", 0)) + 1,
                "last_focus": focus,
                "last_report": str(report_path),
                "seen_finding_ids": sorted(seen),
                "eligible_focuses": next_eligible,
                "completed_focuses": completed_focuses,
                "response_fingerprint": page_fingerprint,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
            print(f"New finding IDs this run: {len(new_items)}; total unique IDs seen: {len(seen)}.", flush=True)
            print(f"Applicable analyses: {', '.join(next_eligible)}", flush=True)
            if cycles is None or cycle < cycles:
                print(f"Next adaptive analysis in {interval} seconds.", flush=True)
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\nDarth Scanner adaptive watch stopped by user.", flush=True)
        return 130
    return 0
