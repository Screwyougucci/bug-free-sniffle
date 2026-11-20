"""Conservative JavaScript/TypeScript interprocedural graph enrichment.

This bounded source-text adapter indexes local function declarations, basic
imports, arguments, returns, and object-property writes. It does not execute
source or claim full JavaScript/TypeScript parsing.
"""
from __future__ import annotations

import re
from pathlib import Path

from .analysis_graph import AnalysisGraph
from .source_audit import MAX_FILE_BYTES

MAX_JS_FILES = 1000
_FUNCTION = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>",
)
_IMPORT = re.compile(r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]")
_ASSIGN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)")
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_SINKS = {
    "query": "CWE-89", "execute": "CWE-89", "exec": "CWE-78",
    "execSync": "CWE-78", "spawn": "CWE-78", "fetch": "CWE-918",
    "sendFile": "CWE-22", "readFile": "CWE-22", "writeFile": "CWE-22",
    "render": "CWE-94", "renderToString": "CWE-94",
}


def _graph_node(graph: AnalysisGraph, path: str, label: str, before: int) -> str:
    candidates = [node for node in graph.nodes.values()
                  if node.path == path and node.label == label and node.line <= before
                  and node.kind in {"source", "transform", "sanitizer"}]
    return max(candidates, key=lambda node: (node.line, node.column)).id if candidates else ""


def enrich_js_ts_dataflow(path: str | Path, graph: AnalysisGraph, *,
                          display_path: str | None = None) -> int:
    file_path = Path(path)
    if file_path.suffix.lower() not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return 0
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return 0
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    relative = display_path or file_path.as_posix()
    source = "\n".join(lines)
    functions: dict[str, dict] = {}
    for match in _FUNCTION.finditer(source):
        name = match.group(1) or match.group(3)
        raw_params = match.group(2) if match.group(1) else match.group(4)
        params = [part.strip().split(":", 1)[0].strip()
                  for part in raw_params.split(",") if part.strip()]
        line = source.count("\n", 0, match.start()) + 1
        functions[name] = {"params": params, "line": line, "body_start": match.end()}

    aliases: dict[str, str] = {}
    for match in _IMPORT.finditer(source):
        module = match.group(2).rsplit("/", 1)[-1].removesuffix(".js").removesuffix(".ts")
        for item in match.group(1).split(","):
            item = item.strip()
            if not item:
                continue
            pieces = re.split(r"\s+as\s+", item)
            aliases[pieces[-1].strip()] = f"{module}.{pieces[0].strip()}"

    function_nodes: dict[str, tuple[str, dict[str, str]]] = {}
    added = 0
    for name, info in sorted(functions.items()):
        parameter_ids = {}
        for param in info["params"]:
            if not re.fullmatch(r"[A-Za-z_$][\w$]*", param):
                continue
            parameter_ids[param] = graph.add_node(
                "transform", f"{name}::{param}", path=relative, line=info["line"],
                language="javascript", confidence=0.58,
                metadata={"analysis": "interprocedural", "role": "parameter",
                          "parser": "bounded-source-adapter"},
            )
        return_id = graph.add_node(
            "transform", f"{name}::return", path=relative, line=info["line"],
            language="javascript", confidence=0.55,
            metadata={"analysis": "interprocedural", "role": "return",
                      "parser": "bounded-source-adapter"},
        )
        function_nodes[name] = (return_id, parameter_ids)

    for name, info in sorted(functions.items()):
        return_id, parameter_ids = function_nodes[name]
        start_line = info["line"]
        # Restrict each function body using balanced braces, avoiding a global
        # search that could attribute another function's sink to this function.
        body_start = info["body_start"]
        open_brace = source.find("{", body_start)
        if open_brace < 0:
            continue
        depth, end = 0, len(source)
        for pos in range(open_brace, len(source)):
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        body = source[open_brace + 1:end]
        body_line = source.count("\n", 0, open_brace) + 1
        for offset, line in enumerate(body.splitlines(), 1):
            line_no = body_line + offset
            identifiers = set(_IDENT.findall(line))
            for sink_name, cwe in _SINKS.items():
                if re.search(rf"\b{re.escape(sink_name)}\s*\(", line):
                    sink = next((node for node in graph.nodes.values()
                                 if node.path == relative and node.line == line_no
                                 and node.kind == "sink" and node.cwe == cwe), None)
                    if sink:
                        for param, param_id in parameter_ids.items():
                            if param in identifiers and graph.add_edge(
                                param_id, sink.id, "parameter-to-sink", 0.54
                            ):
                                added += 1
            if re.search(r"\breturn\b", line):
                for param, param_id in parameter_ids.items():
                    if param in identifiers and graph.add_edge(
                        param_id, return_id, "function-return", 0.52
                    ):
                        added += 1
            prop = re.search(r"\b([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)\s*=\s*(.+)", line)
            if prop:
                prop_id = graph.add_node(
                    "transform", prop.group(1), path=relative, line=line_no,
                    language="javascript", confidence=0.48,
                    metadata={"analysis": "object-property", "parser": "bounded-source-adapter"},
                )
                for param, param_id in parameter_ids.items():
                    if re.search(rf"\b{re.escape(param)}\b", prop.group(2)):
                        if graph.add_edge(param_id, prop_id, "property-write", 0.46):
                            added += 1

    # Resolve local calls only when the callee is indexed in this file. Imported
    # aliases are retained as provenance metadata, not assumed to be resolved
    # across files unless the target function is present in the same graph.
    for caller, info in sorted(functions.items()):
        body_start = info["body_start"]
        open_brace = source.find("{", body_start)
        if open_brace < 0:
            continue
        depth, end = 0, len(source)
        for pos in range(open_brace, len(source)):
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        body = source[open_brace + 1:end]
        base_line = source.count("\n", 0, open_brace) + 1
        for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]*)\)", body):
            callee = match.group(1)
            if callee not in function_nodes or callee == caller:
                continue
            _, callee_params = function_nodes[callee]
            args = [arg.strip() for arg in match.group(2).split(",")]
            call_line = base_line + body.count("\n", 0, match.start())
            for argument, param in zip(args, list(callee_params)):
                for identifier in _IDENT.findall(argument):
                    source_id = _graph_node(graph, relative, identifier, call_line)
                    target_id = callee_params[param]
                    if source_id and graph.add_edge(source_id, target_id, "call-argument", 0.5):
                        added += 1
    return added
