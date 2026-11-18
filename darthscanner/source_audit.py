"""Deterministic static review rules for local Python source code.

This module reports potentially dangerous code patterns for developer review.
It does not execute the source tree and does not claim to prove exploitability.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re

from .checks import Finding


SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
}
MAX_FILE_BYTES = 2_000_000


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _constant_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _finding(path: Path, line: int, category: str, title: str, severity: str,
             confidence: str, evidence: str, remediation: str,
             cwe: str, description: str, impact: str,
             confidence_score: int = 50) -> Finding:
    return Finding(
        category=category,
        title=title,
        severity=severity,
        confidence=confidence,
        url=path.resolve().as_uri(),
        evidence=f"{path}:{line}: {evidence}",
        remediation=remediation,
        kind="source-review-lead",
        description=description,
        impact=impact,
        cwe_ids=[cwe],
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
        affected_component=f"{path.name}:{line}",
        remediation_steps=[remediation, "Review the calling context and data flow before deciding whether the pattern is exploitable."],
        confidence_score=confidence_score,
    )


_SECRET_RE = re.compile(
    r"""(?ix)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*(['"])([^\r\n'"]{8,})\2"""
)
_SECRET_PLACEHOLDERS = {
    "changeme", "change-me", "your-secret", "your_api_key", "example",
    "example-secret", "test", "testing", "dummy", "placeholder",
    "replace-me", "redacted", "none", "null",
}


def _scan_python_file(path: Path) -> list[Finding]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return []

    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    def add(item: Finding) -> None:
        try:
            line_number = int(item.affected_component.rsplit(":", 1)[1])
        except (AttributeError, ValueError, IndexError):
            line_number = 0
        key = (line_number, item.title)
        if key not in seen:
            seen.add(key)
            findings.append(item)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = _name(node.func)
        line = getattr(node, "lineno", 1)

        if called in {"eval", "builtins.eval", "exec", "builtins.exec"}:
            add(_finding(
                path, line, "source-analysis", "Dynamic code execution via eval/exec",
                "high", "medium", f"Call to {called}() detected.",
                "Avoid evaluating data as code. Use a strict parser, explicit dispatch table, or safe expression evaluator.",
                "CWE-95",
                "Dynamic code execution can become code injection if an attacker can influence the evaluated input.",
                "If untrusted data reaches this call, an attacker may execute code with the application's privileges.",
                60,
            ))

        if called in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "shelve.open", "marshal.loads"}:
            add(_finding(
                path, line, "source-analysis", "Potential unsafe deserialization",
                "high", "medium", f"Call to {called}() detected.",
                "Do not deserialize untrusted or attacker-controlled data with pickle, dill, shelve, or marshal. Use a safe, schema-validated data format.",
                "CWE-502",
                "Native object deserializers may reconstruct objects and trigger behavior during loading.",
                "If the serialized input is attacker-controlled, deserialization may lead to code execution or data tampering.",
                65,
            ))

        if called in {"yaml.load", "yaml.unsafe_load"}:
            safe_loader = (
                any(
                    keyword.arg == "Loader" and _name(keyword.value).endswith(("SafeLoader", "CSafeLoader"))
                    for keyword in node.keywords if keyword.arg
                )
                or (len(node.args) >= 2 and _name(node.args[1]).endswith(("SafeLoader", "CSafeLoader")))
            )
            if not safe_loader:
                add(_finding(
                    path, line, "source-analysis", "YAML loader may construct unsafe Python objects",
                    "high", "medium", f"Call to {called}() without a visibly safe Loader.",
                    "Use yaml.safe_load or explicitly pass yaml.SafeLoader/CSafeLoader for untrusted YAML.",
                    "CWE-502",
                    "Unsafe YAML loading can instantiate arbitrary Python objects.",
                    "Untrusted YAML may trigger unintended object construction and potentially code execution.",
                    55,
                ))

        if called in {"os.system", "os.popen"}:
            add(_finding(
                path, line, "source-analysis", "Operating-system command constructed through a shell API",
                "high", "medium", f"Call to {called}() detected.",
                "Prefer subprocess with an argument list and shell=False; validate each argument against an allowlist.",
                "CWE-78",
                "Shell command construction can become OS command injection when external input is incorporated.",
                "Attacker-controlled command fragments may execute with the process account's privileges.",
                55,
            ))

        if called in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}:
            shell_true = any(
                keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords
            )
            if shell_true:
                add(_finding(
                    path, line, "source-analysis", "Subprocess call enables shell=True",
                    "high", "medium", f"Call to {called}(..., shell=True) detected.",
                    "Use shell=False with a list of arguments. If a shell is unavoidable, never concatenate untrusted values.",
                    "CWE-78",
                    "Shell-enabled subprocess calls can interpret arguments as shell syntax.",
                    "If attacker-controlled values reach the command, they may execute unintended operating-system commands.",
                    65,
                ))

        if called in {"requests.get", "requests.post", "requests.put", "requests.delete",
                      "httpx.get", "httpx.post", "urllib.request.urlopen", "urlopen"}:
            if node.args and not _constant_string(node.args[0]):
                add(_finding(
                    path, line, "source-analysis", "Potential server-side request forgery data flow",
                    "medium", "low", f"Call to {called}() uses a non-literal URL expression.",
                    "Trace the URL to its source. If user-controlled, allowlist scheme, host, and port; resolve and reject private, loopback, link-local, and reserved addresses; revalidate redirects.",
                    "CWE-918",
                    "A dynamically supplied URL may permit requests to attacker-chosen destinations.",
                    "If input is untrusted and not validated, the server may be induced to connect to internal services.",
                    35,
                ))

        if called in {"open", "Path.open", "pathlib.Path.open"} and node.args and not _constant_string(node.args[0]):
            add(_finding(
                path, line, "source-analysis", "Dynamic filesystem path requires traversal review",
                "low", "low", f"Call to {called}() uses a non-literal path expression.",
                "Trace path input and constrain it to an intended base directory using canonical path checks and an allowlist.",
                "CWE-22",
                "A dynamic filesystem path can be unsafe when external input affects the resolved path.",
                "Improper path validation may allow reading or writing files outside the intended directory.",
                30,
            ))

        if called.endswith(".execute") and node.args:
            sql_expression = node.args[0]
            if isinstance(sql_expression, ast.JoinedStr) or (
                isinstance(sql_expression, ast.BinOp) and isinstance(sql_expression.op, ast.Add)
            ):
                add(_finding(
                    path, line, "source-analysis", "SQL query may be assembled through string formatting",
                    "high", "medium", "Database execute() receives an f-string or string-concatenation expression.",
                    "Use parameterized SQL placeholders and pass values separately. Do not interpolate user-controlled values into SQL text.",
                    "CWE-89",
                    "Constructing SQL with dynamic string formatting can allow input to change query structure.",
                    "If untrusted input reaches the formatted fragment, database queries may be altered.",
                    55,
                ))

        if called in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
            add(_finding(
                path, line, "source-analysis", "Legacy hash function used",
                "low", "low", f"Call to {called}() detected.",
                "For password storage use a dedicated password hashing function. For integrity/security-sensitive digests use SHA-256 or stronger, as appropriate.",
                "CWE-328",
                "MD5 and SHA-1 are no longer appropriate for security-sensitive collision-resistant hashing.",
                "Collision attacks may undermine uses that rely on collision resistance; context determines impact.",
                35,
            ))

        if any(keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False
               for keyword in node.keywords):
            add(_finding(
                path, line, "source-analysis", "TLS certificate verification is disabled",
                "high", "high", f"Call to {called}() contains verify=False.",
                "Enable certificate and hostname verification. Use a trusted CA bundle for private PKI.",
                "CWE-295",
                "Disabling certificate verification removes an important server identity check.",
                "Connections may accept impersonated servers or interception proxies.",
                90,
            ))

    for line_number, line in enumerate(source.splitlines(), start=1):
        match = _SECRET_RE.search(line)
        if match:
            value = match.group(3).strip()
            normalized = value.lower()
            if normalized not in _SECRET_PLACEHOLDERS and not normalized.startswith(("your-", "your_", "<", "os.getenv", "getenv")):
                add(_finding(
                    path, line_number, "source-analysis", "Possible hard-coded credential or API secret",
                    "high", "medium", f"Assignment to {match.group(1)} contains a string literal [REDACTED].",
                    "Remove the credential from source history, rotate it, and load secrets from a vault or environment configuration.",
                    "CWE-798",
                    "A credential-like string literal appears to be assigned directly in source code.",
                    "If this is a real credential, anyone with source access may be able to use it.",
                    60,
                ))

    return findings


def audit_python_source(root: str | Path, max_files: int = 1000) -> tuple[list[Finding], int, int]:
    """Scan local Python files only; return findings, files reviewed, and files skipped."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise ValueError(f"Source path does not exist: {root_path}")
    if not root_path.is_file() and not root_path.is_dir():
        raise ValueError("Source path must be a file or directory.")
    files = [root_path] if root_path.is_file() else [
        item for item in root_path.rglob("*.py")
        if not any(part in SKIP_DIRS for part in item.parts)
    ]
    findings: list[Finding] = []
    reviewed = 0
    skipped = 0
    for path in sorted(files)[:max_files]:
        if path.suffix.lower() != ".py":
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
        findings.extend(_scan_python_file(path))
    if len(files) > max_files:
        skipped += len(files) - max_files
    return findings, reviewed, skipped
