"""Bounded AST source-to-sink analysis for Python application code.

Tracks simple assignments from common web-request inputs into security-sensitive
operations. It never executes scanned code. Results are review candidates, not
proof of reachability or exploitability.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .checks import Finding
from .source_audit import MAX_FILE_BYTES, _name

_REQUEST_FIELDS = {
    "args", "form", "values", "json", "get", "post", "headers", "cookies",
    "query_params", "path_params", "data", "files",
}
_SOURCE_HELPERS = {"Query", "Header", "Cookie", "Form", "Body"}

_SQL_SINKS = {"execute", "executemany", "raw"}
_HTTP_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.request", "httpx.get", "httpx.post",
    "httpx.put", "httpx.patch", "httpx.delete", "httpx.request",
    "urllib.request.urlopen", "urlopen", "aiohttp.ClientSession.get",
    "aiohttp.ClientSession.post", "aiohttp.ClientSession.request",
}
_FILE_SINKS = {"open", "Path.open", "pathlib.Path.open", "send_file", "FileResponse"}
_COMMAND_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.Popen",
    "subprocess.call", "subprocess.check_call", "subprocess.check_output",
}
_TEMPLATE_SINKS = {"render_template_string", "jinja2.Template", "Template"}
_DESERIALIZE_SINKS = {
    "pickle.loads", "dill.loads", "marshal.loads", "yaml.load", "yaml.unsafe_load",
}


def _is_request_source(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr in _REQUEST_FIELDS:
            root = _name(child.value).lower()
            if "request" in root or root in {"req", "r"}:
                return True
        if isinstance(child, ast.Call) and _name(child.func).split(".")[-1] in _SOURCE_HELPERS:
            return True
    return False


def _contains_tainted_name(node: ast.AST, tainted: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in tainted for child in ast.walk(node))


def _expression_is_tainted(node: ast.AST, tainted: set[str]) -> bool:
    return _is_request_source(node) or _contains_tainted_name(node, tainted)


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        result: set[str] = set()
        for item in node.elts:
            result.update(_target_names(item))
        return result
    return set()


def scan_python_taint_flows(path: str | Path) -> list[Finding]:
    """Trace simple request-input aliases into SQL, SSRF, file, shell, and template sinks."""
    file_path = Path(path)
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return []
        tree = ast.parse(file_path.read_text(encoding="utf-8", errors="replace"), filename=str(file_path))
    except (OSError, SyntaxError, UnicodeError):
        return []

    events: list[tuple[int, int, int, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
            events.append((getattr(node, "lineno", 0), getattr(node, "col_offset", 0), 0, node))
        elif isinstance(node, ast.Call):
            events.append((getattr(node, "lineno", 0), getattr(node, "col_offset", 0), 1, node))
    events.sort(key=lambda item: (item[0], item[1], item[2]))

    tainted: set[str] = set()
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    def add(call: ast.Call, title: str, cwe: str, severity: str, impact: str, remediation: str) -> None:
        line = getattr(call, "lineno", 1)
        key = (line, title)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            category="source-analysis",
            title=title,
            severity=severity,
            confidence="low",
            url=file_path.resolve().as_uri(),
            kind="source-to-sink-candidate",
            description="A value derived from a common web-request input appears to reach a sensitive operation through simple local assignments.",
            impact=impact + " Static analysis does not establish runtime reachability, validation quality, or exploitability.",
            evidence=f"{file_path}:{line}: request-derived data reaches { _name(call.func) }; values and source text are omitted.",
            remediation=remediation,
            cwe_ids=[cwe],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            affected_component=f"{file_path.name}:{line}",
            remediation_steps=[remediation, "Verify the complete call path and any validation or authorization controls before classifying the issue."],
            confidence_score=48,
        ))

    for _, _, _, node in events:
        if isinstance(node, ast.Assign):
            is_tainted = _expression_is_tainted(node.value, tainted)
            for target in node.targets:
                names = _target_names(target)
                tainted.difference_update(names)
                if is_tainted:
                    tainted.update(names)
            continue
        if isinstance(node, (ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
            value = node.value
            is_tainted = _expression_is_tainted(value, tainted) if value is not None else False
            names = _target_names(node.target)
            tainted.difference_update(names)
            if is_tainted:
                tainted.update(names)
            continue
        if not isinstance(node, ast.Call) or not node.args:
            continue

        called = _name(node.func)
        first_tainted = _expression_is_tainted(node.args[0], tainted)
        any_tainted = any(_expression_is_tainted(arg, tainted) for arg in node.args)

        if called.split(".")[-1] in _SQL_SINKS and first_tainted:
            add(
                node, "Request-derived data reaches a SQL query argument", "CWE-89", "high",
                "If the value changes SQL structure rather than remaining a bound parameter, query manipulation may be possible.",
                "Use parameterized queries with fixed SQL text and pass untrusted values only through bound parameters.",
            )
        if (called in _HTTP_SINKS or called.endswith((".get", ".post", ".request"))
                and ("requests" in called or "httpx" in called or "ClientSession" in called)) and first_tainted:
            add(
                node, "Request-derived data reaches an outbound HTTP request", "CWE-918", "high",
                "If an attacker can influence the destination, the server may make requests to unintended hosts or network locations.",
                "Allowlist destinations and schemes, resolve and reject private/loopback/link-local addresses, and revalidate every redirect.",
            )
        if called in _FILE_SINKS and first_tainted:
            add(
                node, "Request-derived data reaches a filesystem path operation", "CWE-22", "high",
                "If path components are not constrained to an intended directory, files outside the permitted area may be accessed.",
                "Resolve paths against a fixed base directory, verify the canonical result remains beneath that directory, and use an allowlist.",
            )
        if called in _COMMAND_SINKS and any_tainted:
            add(
                node, "Request-derived data reaches an operating-system process API", "CWE-78", "high",
                "If untrusted data affects executable arguments or shell text, unintended commands may be invoked.",
                "Avoid shell execution; use a fixed executable with an argument list and validate each argument against an allowlist.",
            )
        if called in _TEMPLATE_SINKS and first_tainted:
            add(
                node, "Request-derived data reaches a dynamic template compiler", "CWE-94", "high",
                "If untrusted input is interpreted as template source, server-side template injection may be possible.",
                "Keep template source static and pass untrusted values only as template data using the framework's safe rendering API.",
            )
        if called in _DESERIALIZE_SINKS and first_tainted:
            add(
                node, "Request-derived data reaches an unsafe deserialization API", "CWE-502", "high",
                "Native object deserialization of attacker-controlled data can trigger unsafe object construction or behavior.",
                "Do not deserialize untrusted native object formats; use a safe schema-validated serialization format.",
            )

    return findings
