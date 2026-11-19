"""Conservative intraprocedural Python source-to-sink analysis.

Tracks simple aliases from common request/environment inputs to sensitive APIs.
This is static triage only: it does not execute code, resolve interprocedural flows,
or prove that a source is remotely controllable.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .checks import Finding


SOURCES = {
    "args", "form", "values", "json", "cookies", "headers", "query_params",
    "path_params", "GET", "POST", "data",
}
SANITIZERS = {"int", "float", "str"}  # Type conversion only; not general security sanitizers.


class _FlowVisitor(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.tainted: set[str] = set()
        self.findings: list[Finding] = []
        self.seen: set[tuple[int, str]] = set()

    @staticmethod
    def _rooted_request(node: ast.AST) -> bool:
        current = node
        while isinstance(current, ast.Attribute):
            if current.attr in SOURCES:
                return True
            current = current.value
        return isinstance(current, ast.Name) and current.id in {"request", "req"}

    def _is_source(self, node: ast.AST) -> bool:
        if self._rooted_request(node):
            return True
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                name = _call_name(item.func)
                if name in {"input", "os.getenv", "os.environ.get", "getenv"}:
                    return True
                if name in {"request.args.get", "request.form.get", "request.headers.get",
                            "request.cookies.get", "request.values.get", "request.json.get"}:
                    return True
            if isinstance(item, ast.Subscript) and self._rooted_request(item.value):
                return True
        return False

    def _is_tainted(self, node: ast.AST) -> bool:
        return self._is_source(node) or any(
            isinstance(item, ast.Name) and item.id in self.tainted
            for item in ast.walk(node)
        )

    def _add(self, node: ast.AST, title: str, cwe: str, remediation: str) -> None:
        line = getattr(node, "lineno", 1)
        key = (line, title)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append(Finding(
            category="source-analysis",
            title=title,
            severity="medium",
            confidence="low",
            url=self.path.resolve().as_uri(),
            kind="source-dataflow-candidate",
            description="A value from a common request or environment input appears to reach a sensitive operation through simple local assignments.",
            impact="If the source is attacker-controlled and no effective validation or API-specific protection exists, the operation may be vulnerable.",
            evidence=f"{self.path}:{line}: source-to-sink relationship detected; source values and code fragments are omitted.",
            remediation=remediation,
            cwe_ids=[cwe],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            affected_component=f"{self.path.name}:{line}",
            remediation_steps=[remediation, "Verify the complete runtime path, caller trust boundary, and framework protections manually."],
            confidence_score=45,
        ))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous = self.tainted
        self.tainted = set()
        for statement in node.body:
            self.visit(statement)
        self.tainted = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        tainted = self._is_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if tainted:
                    self.tainted.add(target.id)
                else:
                    self.tainted.discard(target.id)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            if node.value is not None and self._is_tainted(node.value):
                self.tainted.add(node.target.id)
            else:
                self.tainted.discard(node.target.id)
        if node.value is not None:
            self.generic_visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        if isinstance(node.target, ast.Name):
            if self._is_tainted(node.value):
                self.tainted.add(node.target.id)
            else:
                self.tainted.discard(node.target.id)
        self.generic_visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        tainted_args = [arg for arg in node.args if self._is_tainted(arg)]
        tainted_keywords = [kw for kw in node.keywords if self._is_tainted(kw.value)]

        if name in {"os.system", "os.popen"} and tainted_args:
            self._add(node, "Request-derived data reaches a shell command API", "CWE-78",
                      "Avoid shell command construction. Use a fixed executable with an argument list and shell=False; validate each argument.")
        elif name in {"eval", "exec", "builtins.eval", "builtins.exec"} and tainted_args:
            self._add(node, "Request-derived data reaches dynamic code evaluation", "CWE-95",
                      "Do not evaluate untrusted strings as code. Replace dynamic evaluation with parsing and explicit dispatch.")
        elif name.endswith((".execute", ".executemany")) and tainted_args:
            query = node.args[0] if node.args else None
            parameterized = (
                isinstance(query, ast.Constant) and isinstance(query.value, str)
                and (len(node.args) > 1 or any(kw.arg in {"params", "parameters"} for kw in node.keywords))
            )
            if not parameterized:
                self._add(node, "Request-derived data may reach a database query", "CWE-89",
                          "Use a constant parameterized query and pass untrusted values separately as bound parameters.")
        elif name in {"requests.get", "requests.post", "requests.put", "requests.delete",
                      "httpx.get", "httpx.post", "httpx.request", "urllib.request.urlopen", "urlopen"}:
            if tainted_args or any(kw.arg in {"url"} for kw in tainted_keywords):
                self._add(node, "Request-derived data may reach an outbound URL", "CWE-918",
                          "Use an explicit destination allowlist, restrict schemes and ports, reject private/reserved address ranges, and revalidate redirects.")
        elif name in {"open", "Path.open", "pathlib.Path.open"} and tainted_args:
            self._add(node, "Request-derived data may reach a filesystem path", "CWE-22",
                      "Resolve paths against a fixed base directory and verify the canonical result remains inside that directory.")
        elif name.startswith("subprocess.") and (
            any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
            and (tainted_args or tainted_keywords)
        ):
            self._add(node, "Request-derived data reaches a shell-enabled subprocess", "CWE-78",
                      "Use shell=False with a fixed executable and a list of arguments; validate argument values against an allowlist.")

        self.generic_visit(node)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def inspect_python_dataflow(path: str | Path, source: str) -> list[Finding]:
    """Return conservative findings for simple source-to-sink flows in Python."""
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return []
    visitor = _FlowVisitor(Path(path))
    visitor.visit(tree)
    return visitor.findings
