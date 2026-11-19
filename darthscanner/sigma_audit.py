"""Sigma-inspired local server-log detections; never sends network traffic."""
from __future__ import annotations

import json
import re
from pathlib import Path

_RULES = (
    ("web-auth-failure-burst", "Repeated authentication failures", "medium", "auth",
     re.compile(r"(?:401|403).{0,100}(?:login|signin|auth)|(?:failed|invalid).{0,40}(?:password|login|authentication)", re.I),
     "Review source distribution, account lockout controls, and whether failures are expected."),
    ("web-path-traversal-probe", "Path traversal pattern in server log", "high", "web",
     re.compile(r"(?:\.\./|%2e%2e(?:%2f|/)|%252e%252e)", re.I),
     "Confirm normalization occurs before path resolution and enforce an allowlisted file root."),
    ("web-sqli-probe", "SQL injection-like input in server log", "medium", "web",
     re.compile(r"(?:union\s+select|sleep\s*\(|benchmark\s*\(|information_schema|or\s+1\s*=\s*1)", re.I),
     "Review the matching route and use parameterized queries; a logged pattern is not proof of successful injection."),
    ("web-command-probe", "Command-injection-like input in server log", "high", "web",
     re.compile(r"(?:;\s*(?:id|whoami|uname|cat)\b|\$\([^)]{1,80}\)|\x60[^\x60]{1,80}\x60)", re.I),
     "Review any shell invocation on the route; avoid shell interpolation and use fixed argument arrays."),
    ("web-ssrf-private-target", "Request for a private or metadata address in server log", "high", "web",
     re.compile(r"(?:169\.254\.169\.254|127\.0\.0\.1|localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", re.I),
     "Review server-side URL fetchers and enforce destination allowlists plus private-address blocking."),
    ("web-debug-or-stacktrace", "Debug or stack-trace disclosure recorded", "medium", "web",
     re.compile(r"(?:Traceback \(most recent call last\)|Werkzeug Debugger|Whoops!|Exception in thread| at [\w.$]+\([^)]*:\d+\))", re.I),
     "Disable public debug output and keep detailed diagnostics in protected logs."),
)


def audit_log_file(path: str | Path, *, max_bytes: int = 10_000_000,
                   max_lines: int = 100_000) -> dict:
    """Review a bounded local text/JSONL log file and return rule matches."""
    source = Path(path)
    raw = source.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError(f"Log file exceeds the {max_bytes}-byte limit.")
    text = raw.decode("utf-8", errors="replace")
    findings = []
    lines = text.splitlines()
    for line_number, line in enumerate(lines[:max_lines], 1):
        if not line.strip():
            continue
        searchable = line
        try:
            item = json.loads(line)
            searchable = json.dumps(item, ensure_ascii=False, sort_keys=True)
        except json.JSONDecodeError:
            pass
        for rule_id, title, level, logsource, pattern, guidance in _RULES:
            match = pattern.search(searchable)
            if match:
                findings.append({
                    "rule_id": rule_id, "title": title, "level": level,
                    "logsource": logsource, "line": line_number,
                    "evidence": match.group(0)[:160], "guidance": guidance,
                    "confidence": "low",
                    "note": "Log pattern only; it does not establish successful exploitation."
                })
    return {"path": str(source), "lines_reviewed": min(len(lines), max_lines),
            "rules_loaded": len(_RULES), "matches": findings}
