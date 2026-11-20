"""Adapters that combine existing language audits into the shared graph.

The non-Python adapter intentionally preserves the confidence limits of the
existing line-oriented taint engine. It creates provenance edges only for
simple same-file assignments; it does not infer interprocedural flow.
"""
from __future__ import annotations

from pathlib import Path

from .analysis_graph import AnalysisGraph, build_python_graph
from .multilang_taint import _ASSIGN, _IDENT, _LANGUAGES, _SINKS, _SOURCES
from .source_audit import MAX_FILE_BYTES, SKIP_DIRS

DEFAULT_GRAPH_MAX_FILES = 1000


def add_multilang_file_to_graph(
    path: str | Path,
    graph: AnalysisGraph,
    *,
    display_path: str | None = None,
) -> int:
    """Add conservative same-file source/assignment/sink facts to graph.

    Returns the number of source-to-sink edges added. No code is executed.
    """
    file_path = Path(path)
    language = _LANGUAGES.get(file_path.suffix.lower())
    if language is None:
        return 0
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return 0
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0

    label_path = display_path or file_path.as_posix()
    tainted: dict[str, str] = {}
    flow_count = 0
    source_pattern = _SOURCES[language]

    for line_number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("//", "#", "*", "/*")):
            continue

        assignment = _ASSIGN.search(line)
        if assignment:
            variable, expression = assignment.group(1), assignment.group(2)
            identifiers = set(_IDENT.findall(expression))
            direct_source = bool(source_pattern.search(expression))
            dependencies = sorted(identifiers.intersection(tainted))
            if direct_source or dependencies:
                sanitizer = any(
                    marker in expression.lower()
                    for marker in ("escape(", "htmlspecialchars(", "encodeuricomponent(",
                                    "parameterize(", "preparedstatement")
                )
                kind = "sanitizer" if sanitizer else "transform"
                node_id = graph.add_node(
                    kind, variable, path=label_path, line=line_number,
                    language=language, confidence=0.55 if sanitizer else 0.48,
                    metadata={"adapter": "line-oriented", "scope": "same-file"},
                )
                if direct_source:
                    source_id = graph.add_node(
                        "source", "request-input", path=label_path,
                        line=line_number, language=language, confidence=0.5,
                        metadata={"adapter": "line-oriented"},
                    )
                    graph.add_edge(source_id, node_id, "assignment", 0.5)
                for dependency in dependencies:
                    graph.add_edge(tainted[dependency], node_id, "alias-or-assignment", 0.45)
                if node_id:
                    tainted[variable] = node_id
            else:
                tainted.pop(variable, None)

        identifiers = set(_IDENT.findall(line))
        linked = sorted(identifiers.intersection(tainted))
        for _, (pattern, cwe, _title, _remediation) in _SINKS.items():
            if not pattern.search(line):
                continue
            if not linked and not source_pattern.search(line):
                continue
            sink_id = graph.add_node(
                "sink", cwe, path=label_path, line=line_number,
                language=language, cwe=cwe, confidence=0.48,
                metadata={"adapter": "line-oriented", "scope": "same-file"},
            )
            for variable in linked:
                if graph.add_edge(tainted[variable], sink_id, "sensitive-call", 0.45):
                    flow_count += 1
            if not linked and source_pattern.search(line):
                source_id = graph.add_node(
                    "source", "request-input", path=label_path,
                    line=line_number, language=language, confidence=0.4,
                )
                if graph.add_edge(source_id, sink_id, "direct-call", 0.4):
                    flow_count += 1
    return flow_count


def build_project_graph(
    root: str | Path,
    *,
    max_files: int = DEFAULT_GRAPH_MAX_FILES,
    max_nodes: int = 50_000,
    max_edges: int = 100_000,
) -> AnalysisGraph:
    """Build one graph from Python AST and existing JS/TS/PHP/Java/Go heuristics."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists() or not (root_path.is_file() or root_path.is_dir()):
        raise ValueError(f"Source path does not exist or is not a file/directory: {root_path}")
    if max_files < 1:
        raise ValueError("max_files must be at least 1")

    graph = AnalysisGraph(max_nodes=max_nodes, max_edges=max_edges)
    if root_path.is_file():
        candidates = [root_path]
        base_path = root_path.parent
    else:
        base_path = root_path
        candidates = sorted(
            item for item in root_path.rglob("*")
            if item.is_file()
            and item.suffix.lower() in {".py", *_LANGUAGES}
            and not any(part in SKIP_DIRS for part in item.parts)
        )

    selected = candidates[:max_files]
    if len(candidates) > max_files:
        graph.truncated = True

    python_paths = [item for item in selected if item.suffix.lower() == ".py"]
    if python_paths:
        python_graph = build_python_graph(
            root_path if root_path.is_dir() else python_paths[0],
            max_files=len(python_paths), max_nodes=max_nodes, max_edges=max_edges,
        )
        for node in python_graph.nodes.values():
            graph.add_node(
                node.kind, node.label, path=node.path, line=node.line,
                column=node.column, language=node.language, cwe=node.cwe,
                confidence=node.confidence, metadata=node.metadata,
            )
        for edge in python_graph.edges:
            graph.add_edge(edge.source, edge.target, edge.kind, edge.confidence)
        graph.truncated = graph.truncated or python_graph.truncated

    for item in selected:
        if item.suffix.lower() == ".py":
            continue
        relative = item.relative_to(base_path).as_posix()
        add_multilang_file_to_graph(item, graph, display_path=relative)
    return graph
