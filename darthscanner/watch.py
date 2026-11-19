"""Long-running, resumable watch mode for authorized, low-rate scans."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_watch(*, target: str, scope: str, acknowledged: bool, interval: int,
              output: str, state_path: str, max_cycles: int = 0) -> int:
    """Repeat the existing bounded scan; alert once per stable finding ID."""
    from .cli import main

    state_file = Path(state_path)
    output_file = Path(output)
    latest_file = output_file.with_name(output_file.stem + ".latest.json")
    state = {"target": target, "cycles": 0, "seen_finding_ids": [],
             "findings": [], "started_at": _utc(), "last_scan_at": None}
    if state_file.exists():
        try:
            previous = json.loads(state_file.read_text(encoding="utf-8"))
            if previous.get("target") != target:
                raise ValueError("Watch state belongs to a different target; choose another --state file.")
            state.update(previous)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Watch state JSON is invalid: {exc}") from exc

    seen = set(state.get("seen_finding_ids", []))
    known = {item.get("finding_id"): item for item in state.get("findings", [])
             if item.get("finding_id")}
    print(f"[WATCH] Monitoring {target}; interval={interval}s; max_cycles={max_cycles or 'unlimited'}.")
    print("[WATCH] Press Ctrl+C to stop. Each cycle is bounded by the authorized scope.")
    try:
        while max_cycles == 0 or state["cycles"] < max_cycles:
            started = time.monotonic()
            rc = main(["scan", "--target", target, "--scope", scope,
                       "--acknowledge-authorization", "--output", str(latest_file)])
            if rc != 0:
                print(f"[WATCH] Scan cycle failed with exit code {rc}; retrying after the interval.")
                state["last_cycle_exit_code"] = rc
                state["last_error_at"] = _utc()
                state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                try:
                    report = json.loads(latest_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    print(f"[WATCH] Could not read cycle report: {exc}")
                    report = {}
                new_items = []
                for finding in report.get("findings", []):
                    finding_id = finding.get("finding_id")
                    if not finding_id:
                        continue
                    known[finding_id] = finding
                    if finding_id not in seen:
                        seen.add(finding_id)
                        new_items.append(finding)
                for item in new_items:
                    print(f"\n[NEW SECURITY FINDING] [{item.get('severity', 'unknown').upper()}] "
                          f"{item.get('title', 'Untitled finding')}")
                    print(f"  URL: {item.get('url', '')}")
                    print(f"  Confidence: {item.get('confidence', 'unknown')} "
                          f"({item.get('confidence_score', 0)}/100)")
                    print(f"  Evidence: {item.get('evidence', '')[:500]}")
                    print("  Status: lead requiring verification; not automatically a confirmed exploit.")
                state["cycles"] += 1
                state["last_scan_at"] = _utc()
                state["seen_finding_ids"] = sorted(seen)
                state["findings"] = list(known.values())
                state["last_cycle_exit_code"] = rc
                state["last_report"] = str(latest_file)
                state["updated_at"] = _utc()
                output_file.write_text(json.dumps({
                    "tool": "Darth Scanner Watch", "target": target,
                    "started_at": state["started_at"], "updated_at": state["updated_at"],
                    "cycles_completed": state["cycles"], "unique_findings": len(known),
                    "findings": state["findings"], "latest_cycle_report": str(latest_file),
                    "note": "Findings are observations requiring verification, not proof of exploitability."
                }, indent=2, ensure_ascii=False), encoding="utf-8")
                state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
                print(f"[WATCH] Cycle {state['cycles']} complete; {len(new_items)} new finding(s); "
                      f"{len(known)} unique finding(s) saved to {output_file}.")
            remaining = interval - (time.monotonic() - started)
            if (max_cycles == 0 or attempts_this_run < max_cycles) and remaining > 0:
                time.sleep(remaining)
    except KeyboardInterrupt:
        print("\n[WATCH] Stop requested. Saving state and exiting cleanly.")
        state["stopped_at"] = _utc()
        state["seen_finding_ids"] = sorted(seen)
        state["findings"] = list(known.values())
        state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0
