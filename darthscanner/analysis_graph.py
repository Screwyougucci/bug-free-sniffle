"""Shared, bounded provenance graph for static security analysis.

The graph is deliberately evidence-oriented: adapters may contribute facts from
any language, while the Python adapter supplies an initial AST-backed producer.
It never executes scanned code or performs network activity.
"""
from __future__ import annotations

import ast
from collections import deque
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Iterable

from .source_audit import MAX_FILE_BYTES, SKIP_DIRS

GRAPH_SCHEMA_VERSION = 1
DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_NODES = 50_000
DEFAULT_MAX_EDGES = 100_000
DEFAULT_MAX_PATH_DEPTH = 24
DEFAULT_MAX_PATHS = 500

SOURCE_FIELDS = {
    "args", "form", "values", "json", "get", "post", "headers",
    "cookies", "query_params", "path_params", "data", "files",
}
SOURCE_HELPERS = {"Query", "Header", "Cookie", "Form", "Body"}
SINKS = {
    "execute": "CWE-89", "executemany": "CWE-89", "raw": "CWE-89",
    "urlopen": "CWE-918", "send_file": "CWE-22", "FileResponse": "CWE-22",
    "system": "CWE-78", "popen": "CWE-78", "Popen": "CWE-78",
    "render_template_string": "CWE-94", "unsafe_load": "CWE-502",
}
SANITIZERS = {"escape", "html.escape", "quote", "urlencode", "parameterize"}


def _stable_id(kind: str, path: str, line: int, column: int, label: str) -> str:
    raw = f"{kind}\0{path}\0{line}\0{column}\0{label}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:20]


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    path: str = ""
    line: int = 0
    column: int = 0
    language: str = "unknown"
    cwe: str = ""
    confidence: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: str = "data"
    confidence: float = 1.0


@dataclass
class AnalysisGraph:
    """Deterministic graph with hard resource limits and bounded path search."""

    max_nodes: int = DEFAULT_MAX_NODES
    max_edges: int = DEFAULT_MAX_EDGES
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    truncated: bool = False
    _edge_keys: set[tuple[str, str, str]] = field(default_factory=set, repr=False)

    def add_node(self, kind: str, label: str, *, path: str = "", line: int = 0,
                 column: int = 0, language: str = "unknown", cwe: str = "",
                 confidence: float = 0.0, metadata: dict | None = None) -> str:
        node_id = _stable_id(kind, path, line, column, label)
        if node_id not in self.nodes:
            if len(self.nodes) >= self.max_nodes:
                self.truncated = True
                return ""
            self.nodes[node_id] = GraphNode(
                node_id, kind, label, path, line, column, language, cwe,
                max(0.0, min(1.0, float(confidence))), metadata or {},
            )
        return node_id

    def add_edge(self, source: str, target: str, kind: str = "data",
                 confidence: float = 1.0) -> bool:
        if not source or not target or source not in self.nodes or target not in self.nodes:
            return False
        key = (source, target, kind)
        if key in self._edge_keys:
            return True
        if len(self.edges) >= self.max_edges:
            self.truncated = True
            return False
        self._edge_keys.add(key)
        self.edges.append(GraphEdge(source, target, kind, max(0.0, min(1.0, confidence))))
        return True

    def paths(self, *, source_kinds: Iterable[str] = ("source",),
              sink_kinds: Iterable[str] = ("sink",),
              max_depth: int = DEFAULT_MAX_PATH_DEPTH,
              max_paths: int = DEFAULT_MAX_PATHS) -> list[list[GraphNode]]:
        """Return bounded simple paths; sanitizer nodes remain visible, not magical."""
        starts = sorted(n.id for n in self.nodes.values() if n.kind in set(source_kinds))
        targets = set(n.id for n in self.nodes.values() if n.kind in set(sink_kinds))
        adjacency: dict[str, list[str]] = {}
        for edge in self.edges:
            adjacency.setdefault(edge.source, []).append(edge.target)
        for values in adjacency.values():
            values.sort()
        found: list[list[GraphNode]] = []
        queue = deque((start, (start,)) for start in starts)
        while queue and len(found) < max_paths:
            current, path = queue.popleft()
            if current in targets and len(path) > 1:
                found.append([self.nodes[item] for item in path])
                continue
            if len(path) >= max_depth:
                continue
            for nxt in adjacency.get(current, []):
                if nxt not in path:
                    queue.append((nxt, path + (nxt,)))
        return found

    def to_dict(self) -> dict:
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "truncated": self.truncated,
            "nodes": [asdict(self.nodes[key]) for key in sorted(self.nodes)],
            "edges": [asdict(edge) for edge in sorted(
                self.edges, key=lambda item: (item.source, item.target, item.kind)
            )],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_source(node: ast.AST) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.Attribute) and item.attr in SOURCE_FIELDS:
            root = _name(item.value).lower()
            if "request" in root or root in {"req", "r"}:
                return True
        if isinstance(item, ast.Call) and _name(item.func).split(".")[-1] in SOURCE_HELPERS:
            return True
    return False


def _call_nodes(node: ast.AST):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)]


def build_python_graph(root: str | Path, *, max_files: int = DEFAULT_MAX_FILES,
                       max_nodes: int = DEFAULT_MAX_NODES,
                       max_edges: int = DEFAULT_MAX_EDGES) -> AnalysisGraph:
    """Build local Python source/assignment/sink facts without executing code.

    This first adapter tracks simple names inside each function. Other language
    adapters can add nodes and edges to the same AnalysisGraph using the public API.
    """
    graph = AnalysisGraph(max_nodes=max_nodes, max_edges=max_edges)
    root_path = Path(root).expanduser().resolve()
    if root_path.is_file():
        paths = [root_path] if root_path.suffix == ".py" else []
        root_path = root_path.parent
    elif root_path.is_dir():
        paths = sorted(
            path for path in root_path.rglob("*.py")
            if path.is_file() and not any(part in SKIP_DIRS for part in path.parts)
        )[:max_files]
    else:
        return graph

    for path in paths:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            continue
        relative = str(path.relative_to(root_path)) if path != root_path else path.name
        for function in (n for n in ast.walk(tree)
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            scope_nodes: dict[str, str] = {}
            statements = sorted(
                (n for n in ast.walk(function)
                 if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign, ast.Call))),
                key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0),
                               0 if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)) else 1),
            )
            for statement in statements:
                line = getattr(statement, "lineno", 0)
                column = getattr(statement, "col_offset", 0)
                if isinstance(statement, ast.Call):
                    called = _name(statement.func).split(".")[-1]
                    cwe = SINKS.get(called)
                    if cwe:
                        sink_id = graph.add_node("sink", called, path=relative, line=line,
                                                  column=column, language="python", cwe=cwe,
                                                  confidence=0.55)
                        for argument in statement.args:
                            for identifier in sorted({n.id for n in ast.walk(argument)
                                                       if isinstance(n, ast.Name)}):
                                if identifier in scope_nodes:
                                    graph.add_edge(scope_nodes[identifier], sink_id, "argument")
                        if _is_source(statement):
                            source_id = graph.add_node("source", "request-input", path=relative,
                                                       line=line, column=column, language="python",
                                                       confidence=0.45)
                            graph.add_edge(source_id, sink_id, "direct-argument", 0.45)
                    continue

                value = statement.value
                if value is None:
                    continue
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                names = sorted({item.id for target in targets for item in ast.walk(target)
                                if isinstance(item, ast.Name)})
                if not names:
                    continue
                expression_names = sorted({item.id for item in ast.walk(value)
                                           if isinstance(item, ast.Name)})
                source = _is_source(value)
                sanitizer = any(
                    _name(call.func).split(".")[-1] in SANITIZERS
                    for call in _call_nodes(value)
                )
                for name in names:
                    kind = "sanitizer" if sanitizer else "transform"
                    node_id = graph.add_node(kind, name, path=relative, line=line,
                                             column=column, language="python",
                                             confidence=0.65 if sanitizer else 0.5)
                    for dependency in expression_names:
                        if dependency in scope_nodes:
                            graph.add_edge(scope_nodes[dependency], node_id, "assignment")
                    if source:
                        source_id = graph.add_node("source", "request-input", path=relative,
                                                   line=line, column=column, language="python",
                                                   confidence=0.65)
                        graph.add_edge(source_id, node_id, "assignment")
                    scope_nodes[name] = node_id
    return graph
