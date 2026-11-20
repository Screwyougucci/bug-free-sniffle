"""Continuous, rotating scan orchestration with persistent finding history."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

PROFILES = ("web", "tls", "exposure", "methods")


def profile_for_cycle(cycle: int) -> str:
    """Return the deterministic profile for a zero-based cycle."""
    if cycle < 0:
        raise ValueError("cycle must be non-negative")
    return PROFILES[cycle % len(PROFILES)]


def _load_history(path: Path) -> dict:
    if not path.exists():
        return {"target": None, "seen_finding_ids": [], "cycles_completed": 0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"target": None, "seen_finding_ids": [], "cycles_completed": 0}
    if not isinstance(data, dict) or not isinstance(data.get("seen_finding_ids"), list):
        return {"target": None, "seen_finding_ids": [], "cycles_completed": 0}
    return data


def run_watch(*, target: str, scope_path: str, acknowledge_authorization: bool,
              output_dir: str, interval: int = 10, cycles: int | None = None) -> int:
    """Rotate passive/bounded profiles until interrupted or an optional cycle limit."""
    if interval < 10:
        raise ValueError("--interval must be at least 10 seconds to avoid rapid repeat requests")
    if cycles is not None and cycles < 1:
        raise ValueError("--cycles must be at least 1")
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    history_path = folder / "history.json"
    history = _load_history(history_path)
    seen = set(str(item) for item in history["seen_finding_ids"])
    history["target"] = target

    cycle = 0
    print("Darth Scanner adaptive watch started. Press Ctrl+C to stop.", flush=True)
    try:
        while cycles is None or cycle < cycles:
            profile = profile_for_cycle(cycle)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            report_path = folder / f"cycle-{cycle + 1:06d}-{profile}-{stamp}.json"
            command = [
                sys.executable, "-m", "darthscanner", "scan",
                "--target", target,
                "--scope", scope_path,
                "--profile", profile,
                "--output", str(report_path),
            ]
            if acknowledge_authorization:
                command.append("--acknowledge-authorization")
            print(f"\nCycle {cycle + 1}: {profile} profile -> {report_path}", flush=True)
            completed = subprocess.run(command, check=False)
            if completed.returncode != 0:
                print(f"Watch stopped: scan exited with status {completed.returncode}.", file=sys.stderr, flush=True)
                return completed.returncode

            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Watch stopped: could not read generated report: {exc}", file=sys.stderr, flush=True)
                return 2
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
                "last_profile": profile,
                "last_report": str(report_path),
                "seen_finding_ids": sorted(seen),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
            print(f"New finding IDs this run: {len(new_items)}; total unique IDs seen: {len(seen)}.", flush=True)
            if cycles is None or cycle < cycles:
                print(f"Next profile in {interval} seconds.", flush=True)
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\nDarth Scanner adaptive watch stopped by user.", flush=True)
        return 130
    return 0
