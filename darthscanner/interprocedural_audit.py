"""Bounded project-wide Python call-graph taint analysis.

Builds simple function summaries and propagates taint through direct calls,
including imported helpers across files. No code is executed. This is a review
heuristic: dynamic dispatch, decorators, complex scopes, and aliasing are limited.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re

from .checks import Finding
from .source_audit import MAX_FILE_BYTES, SKIP_DIRS, _name

SOURCE_FIELDS = {"args", "form", "values", "json", "get", "post", "headers",
                 "cookies", "query_params", "path_params", "data", "files"}
SOURCE_HELPERS = {"Query", "Header", "Cookie", "Form", "Body"}
SINKS = {
    "sql": ({"execute", "executemany", "raw"}, "CWE-89", "Request-derived data reaches a SQL query through a helper call",
            "Use parameterized queries and bind values separately from fixed query text."),
    "ssrf": ({"get", "post", "put", "patch", "delete", "request", "urlopen"}, "CWE-918",
             "Request-derived data reaches an outbound request through a helper call",
             "Allowlist destination hosts and schemes and revalidate DNS results and redirects."),
    "file": ({"open", "send_file", "FileResponse"}, "CWE-22",
             "Request-derived data reaches a filesystem operation through a helper call",
             "Resolve paths against a fixed base and verify canonical containment."),
    "command": ({"system", "popen", "run", "Popen", "call", "check_call", "check_output"}, "CWE-78",
                "Request-derived data reaches a process API through a helper call",
                "Avoid shell execution and pass validated arguments to a fixed executable."),
    "template": ({"render_template_string", "Template"}, "CWE-94",
                 "Request-derived data reaches a dynamic template through a helper call",
                 "Keep template source trusted and pass untrusted values only as data."),
    "deserialize": ({"loads", "load", "unsafe_load"}, "CWE-502",
                    "Request-derived data reaches a deserializer through a helper call",
                    "Avoid native object deserialization of untrusted data."),
}
MAX_PROJECT_FILES = 1500
MAX_CALL_DEPTH = 8


def _request_source(node: ast.AST) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.Attribute) and item.attr in SOURCE_FIELDS:
            base = _name(item.value).lower()
            if "request" in base or base in {"req", "r"}:
                return True
        if isinstance(item, ast.Call) and _name(item.func).split(".")[-1] in SOURCE_HELPERS:
            return True
    return False


def _names(node: ast.AST, tainted: set[str]) -> bool:
    return any(isinstance(item, ast.Name) and item.id in tainted for item in ast.walk(node))


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        result: set[str] = set()
        for child in node.elts:
            result.update(_target_names(child))
        return result
    return set()


def _call_name(node: ast.Call) -> str:
    return _name(node.func).split(".")[-1]


def _functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _module_key(root: Path, path: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    return ".".join(relative.parts)


def _make(path: Path, line: int, cwe: str, title: str, via: str) -> Finding:
    remediation = next((item[3] for item in SINKS.values() if item[1] == cwe), "Review the complete data flow and apply context-appropriate validation.")
    return Finding(
        category="source-analysis", title=title, severity="medium", confidence="low",
        url=path.resolve().as_uri(), kind="interprocedural-source-to-sink-candidate",
        description="Project-wide call analysis connected request-controlled data to a sensitive operation across a function boundary.",
        impact="The bounded call graph does not prove runtime reachability, attacker control, or exploitability.",
        evidence=f"{path}:{line}: tainted argument path crosses helper call(s): {via}; values omitted.",
        remediation=remediation, cwe_ids=[cwe],
        references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
        affected_component=f"{path.name}:{line}",
        remediation_steps=[remediation, "Verify imports, call sites, validation, and runtime reachability manually."],
        confidence_score=50,
    )


def audit_python_project(root: str | Path, max_files: int = MAX_PROJECT_FILES) -> list[Finding]:
    root_path = Path(root).expanduser().resolve()
    if root_path.is_file():
        paths = [root_path] if root_path.suffix == ".py" else []
        root_path = root_path.parent
    elif root_path.is_dir():
        paths = [p for p in root_path.rglob("*.py")
                 if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)]
    else:
        return []
    paths = sorted(paths)[:max_files]

    modules: dict[str, dict] = {}
    functions: dict[str, dict] = {}
    simple_names: dict[str, list[str]] = {}
    for path in paths:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            continue
        module = _module_key(root_path, path) if path != root_path else path.stem
        imports: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{node.module}.{alias.name}" if node.module else alias.name
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[0]] = alias.name
        modules[module] = {"path": path, "tree": tree, "imports": imports}
        for fn in _functions(tree):
            key = f"{module}.{fn.name}"
            params = [arg.arg for arg in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)]
            info = {"key": key, "name": fn.name, "node": fn, "path": path, "module": module,
                    "params": params, "sink_params": {}, "return_params": set(), "return_source": False}
            functions[key] = info
            simple_names.setdefault(fn.name, []).append(key)

    def resolve(module: str, name: str) -> str | None:
        imported = modules.get(module, {}).get("imports", {}).get(name)
        if imported:
            if imported in functions:
                return imported
            candidates = [key for key in functions if key.endswith("." + imported)]
            if len(candidates) == 1:
                return candidates[0]
        local = f"{module}.{name}"
        if local in functions:
            return local
        candidates = simple_names.get(name, [])
        return candidates[0] if len(candidates) == 1 else None

    # Iterate summaries to a fixed point, bounded to avoid runaway work.
    for _ in range(min(12, max(2, len(functions) + 1))):
        changed = False
        for info in functions.values():
            fn = info["node"]
            tainted = set(info["params"])  # each parameter is considered independently below
            # Summary records which parameters can reach each sink and return.
            for index, parameter in enumerate(info["params"]):
                local_taint = {parameter}
                for node in ast.walk(fn):
                    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
                        value = getattr(node, "value", None)
                        if value is not None:
                            is_tainted = _request_source(value) or _names(value, local_taint)
                            for target in ([*node.targets] if isinstance(node, ast.Assign) else [node.target]):
                                names = _target_names(target)
                                local_taint.difference_update(names)
                                if is_tainted:
                                    local_taint.update(names)
                    elif isinstance(node, ast.Call):
                        called = _call_name(node)
                        if called in {name for names, *_ in SINKS.values() for name in names}:
                            if any(_request_source(arg) or _names(arg, local_taint) for arg in node.args):
                                category = next((cat for cat, (names, *_rest) in SINKS.items() if called in names), None)
                                if category and index not in info["sink_params"].setdefault(category, set()):
                                    info["sink_params"][category].add(index); changed = True
                    elif isinstance(node, ast.Return) and node.value is not None:
                        if _request_source(node.value) or _names(node.value, local_taint):
                            if index not in info["return_params"]:
                                info["return_params"].add(index); changed = True
                # Return/sink summaries propagate through direct helper calls.
                for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
                    callee = resolve(info["module"], _call_name(call))
                    if not callee or callee == info["key"]:
                        continue
                    summary = functions[callee]
                    for category, indexes in summary["sink_params"].items():
                        for arg_index in indexes:
                            if arg_index < len(call.args) and _names(call.args[arg_index], local_taint):
                                if index not in info["sink_params"].setdefault(category, set()):
                                    info["sink_params"][category].add(index); changed = True
                    if any(arg_index < len(call.args) and _names(call.args[arg_index], local_taint)
                           for arg_index in summary["return_params"]):
                        if index not in info["return_params"]:
                            info["return_params"].add(index); changed = True
            if changed:
                continue
        if not changed:
            break

    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()
    for info in functions.values():
        fn = info["node"]
        module = info["module"]
        local_taint: set[str] = set()
        # Handler-like functions seed direct request input and parameters.
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
                value = getattr(node, "value", None)
                if value is not None:
                    tainted_value = _request_source(value) or _names(value, local_taint)
                    targets = [*node.targets] if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        names = _target_names(target)
                        local_taint.difference_update(names)
                        if tainted_value:
                            local_taint.update(names)
            elif isinstance(node, ast.Call):
                callee_key = resolve(module, _call_name(node))
                if not callee_key:
                    continue
                callee = functions[callee_key]
                for category, indexes in callee["sink_params"].items():
                    if any(i < len(node.args) and (_request_source(node.args[i]) or _names(node.args[i], local_taint)) for i in indexes):
                        cwe = next(v[1] for v in SINKS.values() if v[0] and category in SINKS and v[1] == SINKS[category][1])
                        title = SINKS[category][2]
                        key = (callee_key, getattr(callee["node"], "lineno", 1), cwe)
                        if key not in seen:
                            seen.add(key)
                            via = f"{info['key']} -> {callee_key}"
                            findings.append(_make(callee["path"], getattr(callee["node"], "lineno", 1), cwe, title, via))
                if callee["return_params"]:
                    if any(i < len(node.args) and (_request_source(node.args[i]) or _names(node.args[i], local_taint))
                           for i in callee["return_params"]):
                        # Return value is tainted; mark assignment target if present.
                        parent = None
                        for candidate in ast.walk(fn):
                            if isinstance(candidate, (ast.Assign, ast.AnnAssign)) and node in ast.walk(candidate):
                                parent = candidate
                                break
                        if parent:
                            target_nodes = [*parent.targets] if isinstance(parent, ast.Assign) else [parent.target]
                            for target in target_nodes:
                                local_taint.update(_target_names(target))
    return findings
