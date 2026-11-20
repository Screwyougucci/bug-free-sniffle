"""Bounded Python interprocedural and object-property dataflow enrichment.

This adapter adds conservative call/return and property edges to the shared
analysis graph. It resolves only local Python modules under the scanned root.
It never imports or executes scanned code.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .analysis_graph import AnalysisGraph
from .source_audit import MAX_FILE_BYTES, SKIP_DIRS

MAX_SOURCE_FILES = 2000


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _targets(node: ast.AST) -> list[str]:
    names: list[str] = []
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
            names.append(item.id)
        elif isinstance(item, ast.Attribute) and isinstance(item.ctx, (ast.Store, ast.Del)):
            value = _dotted(item)
            if value:
                names.append(value)
    return sorted(set(names))


def _loaded_names(node: ast.AST) -> list[str]:
    return sorted({item.id for item in ast.walk(node)
                   if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)})


def _module_name(path: Path, root: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _source_files(root: Path, max_files: int) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    return sorted(path for path in root.rglob("*.py")
                   if path.is_file() and not any(part in SKIP_DIRS for part in path.parts))[:max_files]


def enrich_python_dataflow(
    root: str | Path,
    graph: AnalysisGraph,
    *,
    max_files: int = MAX_SOURCE_FILES,
) -> int:
    """Add local Python call/return, import-alias, and object-property edges.

    Cross-function edges are confidence-limited and require a statically
    resolved local function plus a recognizable argument/return assignment.
    Returns the number of edges added.
    """
    root_path = Path(root).expanduser().resolve()
    files = _source_files(root_path, max_files)
    if not files:
        return 0
    parsed: dict[Path, ast.Module] = {}
    modules: dict[str, Path] = {}
    for path in files:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            parsed[path] = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                                     filename=str(path))
            modules[_module_name(path, root_path if root_path.is_dir() else root_path.parent)] = path
        except (OSError, SyntaxError, UnicodeError, ValueError):
            continue

    # Index local function definitions by module and name. Nested functions are
    # indexed too, but only unambiguous module-level names are call-resolved.
    functions: dict[tuple[str, str], tuple[Path, ast.AST]] = {}
    for path, tree in parsed.items():
        module = _module_name(path, root_path if root_path.is_dir() else root_path.parent)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[(module, node.name)] = (path, node)

    def graph_node(path: Path, label: str, before_line: int) -> str:
        relative = path.relative_to(root_path if root_path.is_dir() else root_path.parent).as_posix()
        matches = [node for node in graph.nodes.values()
                   if node.path == relative and node.label == label
                   and node.line <= before_line and node.kind in {"source", "transform", "sanitizer"}]
        if not matches:
            return ""
        return max(matches, key=lambda node: (node.line, node.column)).id

    function_nodes: dict[tuple[str, str], tuple[str, dict[str, str]]] = {}
    for (module, name), (path, function) in sorted(functions.items()):
        relative = path.relative_to(root_path if root_path.is_dir() else root_path.parent).as_posix()
        parameters = [arg.arg for arg in function.args.posonlyargs + function.args.args
                      + function.args.kwonlyargs]
        parameter_ids: dict[str, str] = {}
        for parameter in parameters:
            parameter_ids[parameter] = graph.add_node(
                "transform", f"{name}::{parameter}", path=relative,
                line=function.lineno, column=function.col_offset,
                language="python", confidence=0.62,
                metadata={"analysis": "interprocedural", "role": "parameter", "module": module},
            )
        return_id = graph.add_node(
            "transform", f"{name}::return", path=relative,
            line=function.end_lineno or function.lineno, column=function.col_offset,
            language="python", confidence=0.62,
            metadata={"analysis": "interprocedural", "role": "return", "module": module},
        )
        function_nodes[(module, name)] = (return_id, parameter_ids)

        for statement in ast.walk(function):
            if isinstance(statement, ast.Return) and statement.value is not None:
                for loaded in _loaded_names(statement.value):
                    source_id = parameter_ids.get(loaded) or graph_node(path, loaded, statement.lineno)
                    if source_id:
                        graph.add_edge(source_id, return_id, "function-return", 0.58)

    added = 0
    for path, tree in parsed.items():
        module = _module_name(path, root_path if root_path.is_dir() else root_path.parent)
        relative = path.relative_to(root_path if root_path.is_dir() else root_path.parent).as_posix()
        import_aliases: dict[str, tuple[str, str]] = {}
        module_aliases: dict[str, str] = {}
        for item in tree.body:
            if isinstance(item, ast.ImportFrom) and item.module:
                for alias in item.names:
                    import_aliases[alias.asname or alias.name] = (item.module, alias.name)
            elif isinstance(item, ast.Import):
                for alias in item.names:
                    module_aliases[alias.asname or alias.name.split(".")[0]] = alias.name

        for function in (item for item in ast.walk(tree)
                         if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))):
            # Track properties by full dotted name within this function. A
            # property write and later read become explicit graph transforms.
            property_nodes: dict[str, str] = {}
            statements = sorted((item for item in ast.walk(function)
                                 if isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr))),
                                key=lambda item: (item.lineno, item.col_offset))
            for statement in statements:
                value = statement.value
                if value is None:
                    continue
                targets = [statement.targets[0]] if isinstance(statement, ast.NamedExpr) else (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target])
                target_names = [name for target in targets for name in _targets(target)]
                for target_name in target_names:
                    if "." not in target_name:
                        continue
                    prop_id = graph.add_node(
                        "transform", target_name, path=relative, line=statement.lineno,
                        column=statement.col_offset, language="python", confidence=0.52,
                        metadata={"analysis": "object-property", "scope": "function"},
                    )
                    for dependency in _loaded_names(value):
                        dependency_id = property_nodes.get(dependency) or graph_node(path, dependency, statement.lineno)
                        if dependency_id and graph.add_edge(dependency_id, prop_id, "property-write", 0.48):
                            added += 1
                    property_nodes[target_name] = prop_id

            for call in (item for item in ast.walk(function) if isinstance(item, ast.Call)):
                called = _dotted(call.func)
                resolved: tuple[str, str] | None = None
                if called in import_aliases:
                    resolved = import_aliases[called]
                elif "." in called and called.split(".", 1)[0] in module_aliases:
                    prefix, suffix = called.split(".", 1)
                    resolved = (module_aliases[prefix], suffix)
                elif called and "." not in called:
                    resolved = (module, called)
                if not resolved or resolved not in function_nodes:
                    continue
                callee_path, callee_function = functions[resolved]
                return_id, parameter_ids = function_nodes[resolved]
                args = list(call.args)
                params = list(parameter_ids)
                for argument, parameter in zip(args, params):
                    for loaded in _loaded_names(argument):
                        source_id = property_nodes.get(loaded) or graph_node(path, loaded, call.lineno)
                        target_id = parameter_ids.get(parameter)
                        if source_id and target_id and graph.add_edge(
                            source_id, target_id, "call-argument", 0.56
                        ):
                            added += 1
                # Connect the callee's return summary to a local assignment
                # target at this call site, if the shared graph has one.
                parent_assign = next((item for item in ast.walk(function)
                                      if isinstance(item, (ast.Assign, ast.AnnAssign))
                                      and item.value is call), None)
                if parent_assign:
                    targets = parent_assign.targets if isinstance(parent_assign, ast.Assign) else [parent_assign.target]
                    for target in targets:
                        for name in _targets(target):
                            target_id = graph_node(path, name, call.lineno + 1)
                            if target_id and graph.add_edge(return_id, target_id, "call-return", 0.56):
                                added += 1

    return added
