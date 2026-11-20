"""Long-running, resumable watch mode for authorized, low-rate scans."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save_json(path: Path, data: dict) -> None:
    """Replace JSON state atomically so an interrupted write keeps the prior file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def run_watch(*, target: str, scope: str, acknowledged: bool, interval: int,
              output: str, state_path: str, max_cycles: int = 0) -> int:
    """Repeat bounded scans and retain durable finding lifecycle/history."""
    from .cli import main

    state_file = Path(state_path)
    output_file = Path(output)
    latest_file = output_file.with_name(output_file.stem + ".latest.json")
    state = {
        "target": target, "cycles": 0, "seen_finding_ids": [],
        "findings": [], "history": [], "started_at": _utc(), "last_scan_at": None,
    }
    if state_file.exists():
        try:
            previous = json.loads(state_file.read_text(encoding="utf-8"))
            if not isinstance(previous, dict):
                raise ValueError("Watch state must contain a JSON object.")
            if previous.get("target") != target:
                raise ValueError("Watch state belongs to a different target; choose another --state file.")
            state.update(previous)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Watch state JSON is invalid: {exc}") from exc

    seen = set(state.get("seen_finding_ids", []))
    known = {
        item.get("finding_id"): item for item in state.get("findings", [])
        if item.get("finding_id")
    }
    cycles_this_run = 0
    print(f"[WATCH] Monitoring {target}; interval={interval}s; max_cycles={max_cycles or 'unlimited'}.")
    print("[WATCH] Press Ctrl+C to stop. Each cycle is bounded by the authorized scope.")
    try:
        while max_cycles == 0 or cycles_this_run < max_cycles:
            started = time.monotonic()
            rc = main(["scan", "--target", target, "--scope", scope,
                       "--acknowledge-authorization", "--output", str(latest_file)])
            cycles_this_run += 1
            cycle_number = int(state.get("cycles", 0)) + 1
            if rc != 0:
                print(f"[WATCH] Scan cycle failed with exit code {rc}; retrying after the interval.")
                state["last_cycle_exit_code"] = rc
                state["last_error_at"] = _utc()
                state.setdefault("history", []).append({
                    "cycle": cycle_number, "at": _utc(), "status": "error",
                    "exit_code": rc, "finding_count": None,
                })
            else:
                try:
                    report = json.loads(latest_file.read_text(encoding="utf-8"))
                    if not isinstance(report, dict):
                        raise ValueError("scan report must be a JSON object")
                except (OSError, json.JSONDecodeError, ValueError) as exc:
                    print(f"[WATCH] Could not read cycle report: {exc}")
                    report = None

                if report is not None:
                    current_ids = set()
                    new_items = []
                    reappeared_items = []
                    for finding in report.get("findings", []):
                        finding_id = finding.get("finding_id")
                        if not finding_id:
                            continue
                        current_ids.add(finding_id)
                        previous = known.get(finding_id, {})
                        was_resolved = previous.get("lifecycle_status") == "resolved"
                        finding["first_seen_at"] = previous.get("first_seen_at") or _utc()
                        finding["last_seen_at"] = _utc()
                        finding["first_seen_cycle"] = previous.get("first_seen_cycle") or cycle_number
                        finding["last_seen_cycle"] = cycle_number
                        finding["occurrences"] = int(previous.get("occurrences", 0)) + 1
                        finding["lifecycle_status"] = "active"
                        if was_resolved:
                            finding.pop("resolved_at", None)
                        known[finding_id] = finding
                        if finding_id not in seen:
                            new_items.append(finding)
                        elif was_resolved:
                            reappeared_items.append(finding)
                        seen.add(finding_id)

                    for finding_id, finding in known.items():
                        if finding_id not in current_ids and finding.get("lifecycle_status") != "resolved":
                            finding["lifecycle_status"] = "resolved"
                            finding["resolved_at"] = _utc()
                            finding["last_seen_cycle"] = finding.get("last_seen_cycle")

                    for item in new_items:
                        print(f"\n[NEW SECURITY FINDING] [{item.get('severity', 'unknown').upper()}] {item.get('title', 'Untitled finding')}")
                        print(f"  URL: {item.get('url', '')}")
                        print(f"  Confidence: {item.get('confidence', 'unknown')} ({item.get('confidence_score', 0)}/100)")
                        print(f"  Evidence: {item.get('evidence', '')[:500]}")
                        print("  Status: lead requiring verification; not automatically a confirmed exploit.")
                    for item in reappeared_items:
                        print(f"\n[REAPPEARED FINDING] {item.get('title', item.get('finding_id'))}")

                    state["cycles"] = cycle_number
                    state["last_scan_at"] = _utc()
                    state["seen_finding_ids"] = sorted(seen)
                    state["findings"] = list(known.values())
                    state["last_cycle_exit_code"] = rc
                    state["last_report"] = str(latest_file)
                    state["updated_at"] = _utc()
                    state.setdefault("history", []).append({
                        "cycle": cycle_number, "at": state["last_scan_at"],
                        "status": "ok", "finding_count": len(current_ids),
                        "new_findings": len(new_items),
                        "reappeared_findings": len(reappeared_items),
                        "active_findings": sum(1 for item in known.values()
                                               if item.get("lifecycle_status") == "active"),
                        "resolved_findings": sum(1 for item in known.values()
                                                 if item.get("lifecycle_status") == "resolved"),
                    })
                    # Keep a useful bounded timeline while preserving cumulative findings.
                    state["history"] = state["history"][-500:]
                    _save_json(output_file, {
                        "tool": "Darth Scanner Watch", "target": target,
                        "started_at": state["started_at"], "updated_at": state["updated_at"],
                        "cycles_completed": state["cycles"], "unique_findings": len(known),
                        "active_findings": sum(1 for item in known.values()
                                               if item.get("lifecycle_status") == "active"),
                        "resolved_findings": sum(1 for item in known.values()
                                                 if item.get("lifecycle_status") == "resolved"),
                        "findings": state["findings"], "history": state["history"],
                        "latest_cycle_report": str(latest_file),
                        "note": "Lifecycle status reflects presence in the latest successful scan, not proof that a vulnerability was fixed. Findings require verification."
                    })
            state["history"] = state.get("history", [])[-500:]
            _save_json(state_file, state)
            print(f"[WATCH] Cycle {state.get('cycles', cycle_number)} finished; "
                  f"{sum(1 for item in known.values() if item.get('lifecycle_status') == 'active')} active; "
                  f"{sum(1 for item in known.values() if item.get('lifecycle_status') == 'resolved')} resolved.")
            remaining = interval - (time.monotonic() - started)
            if (max_cycles == 0 or cycles_this_run < max_cycles) and remaining > 0:
                time.sleep(remaining)
    except KeyboardInterrupt:
        print("\n[WATCH] Stop requested. Saving state and exiting cleanly.")
        state["stopped_at"] = _utc()
        state["seen_finding_ids"] = sorted(seen)
        state["findings"] = list(known.values())
        _save_json(state_file, state)
    return 0
