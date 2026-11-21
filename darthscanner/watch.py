"""Evidence-driven adaptive watch orchestration.

The scheduler learns from response metadata and prior check outcomes. It never
expands the authorized origin, executes JavaScript, submits forms, or sends
exploit payloads.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

FOCUSES = ("headers", "cookies", "cors", "redirects", "html", "browser", "javascript", "fingerprint")
# Kept for compatibility with early 0.8 development tests.
PROFILES = FOCUSES

_BASE_PRIORITY = {
    "headers": 8,
    "cookies": 7,
    "cors": 6,
    "redirects": 6,
    "html": 7,
    "browser": 7,
    "javascript": 8,
    "fingerprint": 5,
}
_SIGNAL_FOCUS = {
    "cookie_present": ("cookies",),
    "cors_present": ("cors",),
    "redirect_present": ("redirects",),
    "html_present": ("html", "browser"),
    "scripts_present": ("javascript",),
    "javascript_content": ("javascript",),
}
_FINDING_FOCUS = {
    "http-headers": "headers",
    "csp": "headers",
    "cookies": "cookies",
    "cache": "cookies",
    "cors": "cors",
    "redirect": "redirects",
    "xss-indicator": "browser",
    "browser-messaging": "browser",
    "browser-storage": "browser",
    "javascript-static-review": "javascript",
}


def profile_for_cycle(cycle: int) -> str:
    """Legacy deterministic helper retained for API compatibility."""
    if cycle < 0:
        raise ValueError("cycle must be non-negative")
    return FOCUSES[cycle % len(FOCUSES)]


def discover_signals(report: dict) -> list[str]:
    """Convert observed report metadata into explicit, auditable evidence signals."""
    pages = report.get("pages") or []
    if not pages:
        return []
    page = pages[0]
    content_type = str(page.get("content_type", "")).lower()
    resource_type = str(page.get("resource_type", "")).lower()
    signals: set[str] = set()
    if page.get("has_set_cookie"):
        signals.add("cookie_present")
    if page.get("has_cors_headers"):
        signals.add("cors_present")
    if page.get("has_redirect") or (
        isinstance(page.get("status"), int) and 300 <= page["status"] < 400
    ):
        signals.add("redirect_present")
    if resource_type == "html" or "text/html" in content_type:
        signals.add("html_present")
    if int(page.get("script_count", 0) or 0) > 0:
        signals.add("scripts_present")
    if "javascript" in content_type or resource_type == "javascript":
        signals.add("javascript_content")
    if resource_type:
        signals.add("resource:" + resource_type)
    if "json" in content_type or resource_type == "json":
        signals.add("json_content")
    if "image/svg+xml" in content_type or resource_type == "svg":
        signals.add("svg_content")
    return sorted(signals)


def eligible_focuses(report: dict) -> list[str]:
    """Return only analyses applicable to the observed resource and metadata."""
    pages = report.get("pages") or []
    if not pages:
        return ["headers", "fingerprint"]
    page = pages[0]
    signals = set(discover_signals(report))
    eligible = ["headers"]
    if "cookie_present" in signals:
        eligible.append("cookies")
    if "cors_present" in signals:
        eligible.append("cors")
    if "redirect_present" in signals:
        eligible.append("redirects")
    if "html_present" in signals:
        eligible.extend(["html", "browser"])
    if "scripts_present" in signals or "javascript_content" in signals:
        eligible.append("javascript")
    # Keep ordering stable and remove accidental duplicates.
    eligible.append("fingerprint")
    return list(dict.fromkeys(item for item in eligible if item in FOCUSES))


def _focus_score(focus: str, history: dict, signals: set[str], cycle: int) -> float:
    """Score a check using novelty, observed evidence, and past useful outcomes."""
    stats = (history.get("focus_stats") or {}).get(focus, {})
    attempts = int(stats.get("attempts", 0) or 0)
    findings = int(stats.get("finding_count", 0) or 0)
    empty_runs = int(stats.get("empty_runs", 0) or 0)
    score = float(_BASE_PRIORITY[focus])
    if attempts == 0:
        score += 8.0  # explore an untried applicable analysis
    else:
        score -= min(empty_runs * 1.5, 6.0)  # de-prioritize repeatedly unproductive checks
        score += min(findings * 0.75, 3.0)  # retain attention on historically useful checks
    for signal, related in _SIGNAL_FOCUS.items():
        if focus in related and signal in signals:
            score += 5.0
    return score


def choose_next_focus(
    eligible: list[str],
    completed: list[str],
    cycle: int = 0,
    history: dict | None = None,
    signals: list[str] | set[str] | None = None,
) -> str:
    """Choose the highest-scoring applicable, not-yet-completed analysis."""
    if cycle < 0:
        raise ValueError("cycle must be non-negative")
    history = history or {}
    signal_set = set(signals or history.get("discovery_signals", []))
    choices = [item for item in eligible if item in FOCUSES]
    if not choices:
        choices = ["headers", "fingerprint"]
    remaining = [item for item in choices if item not in set(completed)]
    pool = remaining or choices
    if not history and not signals:
        return pool[0]
    return max(pool, key=lambda item: _focus_score(item, history, signal_set, cycle))


def _load_history(path: Path) -> dict:
    empty = {
        "target": None,
        "seen_finding_ids": [],
        "cycles_completed": 0,
        "completed_focuses": [],
        "eligible_focuses": [],
        "response_fingerprint": None,
        "focus_stats": {},
        "discovery_signals": [],
        "finding_categories": [],
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
    for key in ("seen_finding_ids", "completed_focuses", "eligible_focuses", "discovery_signals", "finding_categories"):
        if not isinstance(data.get(key), list):
            data[key] = []
    if not isinstance(data.get("focus_stats"), dict):
        data["focus_stats"] = {}
    return data


def _save_history(path: Path, history: dict) -> None:
    """Atomically persist learning state so interruption cannot truncate history."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def run_watch(
    *, target: str, scope_path: str, acknowledge_authorization: bool,
    output_dir: str, interval: int = 30, cycles: int | None = None,
) -> int:
    """Run evidence-driven, read-only focused analysis until interrupted."""
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
            "focus_stats": {},
            "discovery_signals": [],
            "finding_categories": [],
        })
    seen = set(str(item) for item in history["seen_finding_ids"])
    cycle = 0
    print("Darth Scanner adaptive watch started. Press Ctrl+C to stop.", flush=True)
    print("The scheduler ranks applicable checks from observed evidence and past outcomes; scope remains fixed to the authorized target.", flush=True)
    try:
        while cycles is None or cycle < cycles:
            eligible = history.get("eligible_focuses") or ["headers", "fingerprint"]
            completed_focuses = history.get("completed_focuses") or []
            signals = set(history.get("discovery_signals") or [])
            focus = choose_next_focus(eligible, completed_focuses, cycle, history, signals)
            score = _focus_score(focus, history, signals, cycle)
            total_cycle = int(history.get("cycles_completed", 0)) + 1
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            report_path = folder / f"cycle-{total_cycle:06d}-{focus}-{stamp}.json"
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
            print(f"\nCycle {total_cycle}: selected {focus} (priority {score:.2f}) from evidence: {', '.join(sorted(signals)) or 'initial discovery'}", flush=True)
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
            response_changed = bool(
                history.get("response_fingerprint")
                and page_fingerprint
                and history["response_fingerprint"] != page_fingerprint
            )
            if response_changed:
                completed_focuses = []
                print("Response fingerprint changed; clearing stale completion state and reprioritizing.", flush=True)

            next_signals = discover_signals(report)
            next_eligible = eligible_focuses(report)
            if focus in next_eligible and focus not in completed_focuses:
                completed_focuses.append(focus)
            if all(item in completed_focuses for item in next_eligible):
                completed_focuses = []
                print("All currently applicable checks completed; a new evidence-ranked review round will begin.", flush=True)

            findings = report.get("findings", [])
            new_items = [item for item in findings if item.get("finding_id") and item["finding_id"] not in seen]
            for item in findings:
                finding_id = item.get("finding_id")
                if finding_id:
                    seen.add(finding_id)
            stats = history.setdefault("focus_stats", {})
            focus_stats = stats.setdefault(focus, {"attempts": 0, "finding_count": 0, "empty_runs": 0})
            focus_stats["attempts"] = int(focus_stats.get("attempts", 0)) + 1
            focus_stats["finding_count"] = int(focus_stats.get("finding_count", 0)) + len(findings)
            focus_stats["empty_runs"] = 0 if findings else int(focus_stats.get("empty_runs", 0)) + 1
            focus_stats["last_cycle"] = total_cycle
            focus_stats["last_response_fingerprint"] = page_fingerprint

            categories = set(history.get("finding_categories") or [])
            categories.update(str(item.get("category")) for item in findings if item.get("category"))
            cycle += 1
            history.update({
                "target": target,
                "cycles_completed": total_cycle,
                "last_focus": focus,
                "last_priority": round(score, 3),
                "last_report": str(report_path),
                "seen_finding_ids": sorted(seen),
                "eligible_focuses": next_eligible,
                "completed_focuses": completed_focuses,
                "response_fingerprint": page_fingerprint,
                "discovery_signals": next_signals,
                "finding_categories": sorted(categories),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            _save_history(history_path, history)
            print(f"New finding IDs this run: {len(new_items)}; total unique IDs seen: {len(seen)}.", flush=True)
            print(f"Applicable analyses: {', '.join(next_eligible)}", flush=True)
            if cycles is None or cycle < cycles:
                print(f"Next evidence-ranked analysis in {interval} seconds.", flush=True)
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\nDarth Scanner adaptive watch stopped by user.", flush=True)
        return 130
    return 0
