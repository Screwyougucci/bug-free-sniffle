"""Heuristic static review for common security patterns across source languages.

Python continues to use the AST-based audit. Other languages use bounded,
line-oriented pattern checks and therefore produce lower-confidence review leads.
No source is executed and secret values are never copied into findings.
"""
from __future__ import annotations

from pathlib import Path
import re

from .checks import Finding
from .source_audit import MAX_FILE_BYTES, SKIP_DIRS, _scan_python_file
from .python_taint import scan_python_taint_flows
from .multilang_taint import scan_multilang_taint

SUPPORTED = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".java", ".go", ".rs"}
SECRET = re.compile(
    r"""(?ix)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*(['"])([^\r\n'"]{8,})\2"""
)
PLACEHOLDERS = {"changeme", "change-me", "your-secret", "your_api_key", "example",
                "example-secret", "test", "testing", "dummy", "placeholder",
                "replace-me", "redacted", "none", "null"}

RULES = [
    (re.compile(r"(?i)\b(?:eval|Function)\s*\("),
     "Dynamic code evaluation pattern", "high", "CWE-95",
     "Trace the evaluated value. Avoid executing strings and use a parser or explicit dispatch."),
    (re.compile(r"(?i)\b(?:child_process\s*\.\s*exec|execSync|shell_exec|passthru|system)\s*\("),
     "Shell command API pattern", "high", "CWE-78",
     "Prefer argument-array process APIs without a shell; strictly validate any externally influenced arguments."),
    (re.compile(r"(?i)\b(?:unserialize|readObject)\s*\("),
     "Potential unsafe object deserialization", "high", "CWE-502",
     "Do not deserialize attacker-controlled native objects; use a safe schema-validated format."),
    (re.compile(r"(?i)(?:rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*false|verify\s*=\s*false)"),
     "TLS certificate verification appears disabled", "high", "CWE-295",
     "Enable certificate-chain and hostname verification; configure a trusted CA bundle for private PKI."),
    (re.compile(r"(?i)(?:query|execute)\s*\([^\n]{0,180}(?:\+\s*[A-Za-z_$]|\$\{|\bformat\s*\()"),
     "SQL query may include dynamic string construction", "medium", "CWE-89",
     "Use parameterized queries and bind values separately; review whether untrusted input can reach the query."),
    (re.compile(r"(?i)\b(?:Runtime\s*\.\s*getRuntime\s*\(\)\s*\.\s*exec|os\s*\.\s*exec\s*\.\s*Command)\s*\("),
     "Operating-system process execution pattern", "medium", "CWE-78",
     "Avoid shell interpretation and validate executable paths and argument boundaries."),
]


def _make(path: Path, line: int, title: str, severity: str, cwe: str,
          evidence: str, remediation: str, confidence: int = 35) -> Finding:
    return Finding(
        category="source-analysis",
        title=title,
        severity=severity,
        confidence="low" if confidence < 60 else "medium",
        url=path.resolve().as_uri(),
        kind="source-review-lead",
        description="A language-specific source pattern merits manual security review; static matching does not establish attacker control or exploitability.",
        impact="Impact depends on the surrounding data flow, runtime configuration, and whether untrusted input reaches the operation.",
        evidence=f"{path}:{line}: {evidence}",
        remediation=remediation,
        cwe_ids=[cwe],
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
        affected_component=f"{path.name}:{line}",
        remediation_steps=[remediation, "Trace input sources, validation, and the full call path before classifying this as a vulnerability."],
        confidence_score=confidence,
    )


def _scan_other_language(path: Path) -> list[Finding]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for number, line in enumerate(lines, 1):
        for pattern, title, severity, cwe, remediation in RULES:
            if pattern.search(line):
                key = (number, title)
                if key not in seen:
                    seen.add(key)
                    findings.append(_make(path, number, title, severity, cwe,
                                          "Potentially sensitive API or construction pattern detected; full source line omitted.",
                                          remediation, 45 if severity == "high" else 35))
        match = SECRET.search(line)
        if match:
            value = match.group(3).strip().lower()
            if value not in PLACEHOLDERS and not value.startswith(("your-", "your_", "<", "process.env", "getenv")):
                findings.append(_make(
                    path, number, "Possible hard-coded credential or API secret", "high", "CWE-798",
                    f"Credential-like assignment to {match.group(1)} detected; value redacted.",
                    "Remove the credential from source history, rotate it, and load secrets from a vault or environment configuration.",
                    55,
                ))
    return findings


def audit_source(root: str | Path, max_files: int = 1000) -> tuple[list[Finding], int, int]:
    """Review supported source files; Python uses AST and other languages use heuristics."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise ValueError(f"Source path does not exist: {root_path}")
    if not root_path.is_file() and not root_path.is_dir():
        raise ValueError("Source path must be a file or directory.")
    candidates = [root_path] if root_path.is_file() else [
        item for item in root_path.rglob("*")
        if item.is_file() and item.suffix.lower() in SUPPORTED
        and not any(part in SKIP_DIRS for part in item.parts)
    ]
    findings: list[Finding] = []
    reviewed = skipped = 0
    for path in sorted(candidates)[:max_files]:
        if path.suffix.lower() not in SUPPORTED:
            skipped += 1
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue
        reviewed += 1
        if path.suffix.lower() == ".py":
            findings.extend(_scan_python_file(path))
            findings.extend(scan_python_taint_flows(path))
        else:
            findings.extend(_scan_other_language(path))
            findings.extend(scan_multilang_taint(path))
    if len(candidates) > max_files:
        skipped += len(candidates) - max_files
    return findings, reviewed, skipped
