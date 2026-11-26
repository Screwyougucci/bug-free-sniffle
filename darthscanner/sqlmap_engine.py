"""Bounded SQL injection verification using the official, locally installed sqlmap source.

Only owner-authorized targets are accepted by the caller. The runner tests at most
two already-discovered same-origin GET URLs, uses low-risk error/boolean/union
techniques, and never requests database enumeration, table listing, dumping,
OS-shell, file read/write, or stacked queries. Results are summarized; raw
sqlmap console output and response bodies are not persisted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit

from .toolchain import ToolchainError, tool_root, _is_in_scope, _safe_url


def _python_command() -> str | None:
    if not getattr(sys, "frozen", False) and sys.executable and Path(sys.executable).exists():
        return sys.executable
    return shutil.which("python") or shutil.which("python3")


def _has_query_parameter(url: str) -> bool:
    try:
        return bool(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    except ValueError:
        return False


def run_sqlmap_checks(urls: list[str], root_url: str, output_dir: Path, *,
                      include_subdomains: bool = False, stop_event=None,
                      progress=lambda message: None) -> list[dict]:
    """Run conservative SQLMap detection on at most two discovered GET endpoints."""
    source = tool_root() / "sqlmap" / "sqlmap.py"
    python = _python_command()
    if not source.is_file():
        raise ToolchainError("sqlmap source is missing. Click INSTALL / UPDATE TOOLS.")
    if not python:
        raise ToolchainError("SQLMap source is installed, but Python 3 is not available to run it.")
    candidates = []
    for url in urls:
        safe = _safe_url(url)
        if safe and _is_in_scope(root_url, safe, include_subdomains) and _has_query_parameter(safe):
            if safe not in candidates:
                candidates.append(safe)
        if len(candidates) >= 2:
            break
    if not candidates:
        progress("SQLMap: no in-scope discovered GET URLs with query parameters; skipped.")
        return []
    output_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    for index, url in enumerate(candidates, 1):
        if stop_event is not None and stop_event.is_set():
            break
        progress(f"SQLMap: bounded low-risk SQL injection check {index}/{len(candidates)} (GET only).")
        case_dir = output_dir / f"case-{index}"
        command = [
            python, str(source), "-u", url, "--batch", "--smart",
            "--risk=1", "--level=1", "--technique=BEU",
            "--threads=1", "--delay=1", "--timeout=5", "--retries=0",
            "--flush-session", "--disable-coloring",
            "--output-dir", str(case_dir),
        ]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                errors="replace", timeout=120, creationflags=flags,
            )
            output = result.stdout or ""
            vulnerable = bool(re.search(r"is vulnerable|parameter .* appears to be", output, re.I))
            dbms_match = re.search(r"back-end DBMS:\s*([^\r\n]+)", output, re.I)
            error_match = re.search(r"all tested parameters do not appear to be injectable", output, re.I)
            outcome = "candidate_detected" if vulnerable else ("no_injection_detected" if error_match else "inconclusive")
            summaries.append({
                "url": url,
                "outcome": outcome,
                "dbms_fingerprint": dbms_match.group(1).strip()[:100] if dbms_match else None,
                "exit_code": result.returncode,
                "confidence": "requires_manual_confirmation",
                "database_enumeration_performed": False,
                "raw_output_saved": False,
            })
            progress(f"SQLMap result: {outcome}; no database enumeration or data extraction was run.")
        except subprocess.TimeoutExpired:
            summaries.append({
                "url": url, "outcome": "time_limit", "confidence": "not_confirmed",
                "database_enumeration_performed": False, "raw_output_saved": False,
            })
            progress("SQLMap: 120-second per-endpoint time limit reached.")
        except OSError as exc:
            summaries.append({
                "url": url, "outcome": "execution_error", "detail": str(exc)[:300],
                "database_enumeration_performed": False, "raw_output_saved": False,
            })
            progress(f"SQLMap could not start: {exc}")
        finally:
            # SQLMap may create session/log files; keep only the redacted summary.
            shutil.rmtree(case_dir, ignore_errors=True)
    report = {
        "schema_version": 1,
        "tests": summaries,
        "limits": {
            "max_endpoints": 2, "methods": ["GET"], "risk": 1, "level": 1,
            "techniques": ["boolean-based", "error-based", "union-based"],
            "threads": 1, "delay_seconds": 1, "timeout_seconds": 5,
            "database_enumeration": False, "table_listing": False,
            "data_dump": False, "os_shell": False, "file_read_write": False,
        },
        "disclaimer": "SQLMap signals are unconfirmed candidates. Verify manually in a staging environment.",
    }
    (output_dir / "sqlmap-summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return summaries
