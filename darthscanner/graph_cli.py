"""Command-line entry point for shared graph export."""
from __future__ import annotations

import argparse
from pathlib import Path

from .graph_adapters import build_project_graph


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="darth-graph",
        description="Build a bounded static provenance graph from local source files.",
    )
    parser.add_argument("--path", required=True, help="local source file or project directory")
    parser.add_argument("--max-files", type=int, default=1000)
    parser.add_argument("--max-nodes", type=int, default=50000)
    parser.add_argument("--max-edges", type=int, default=100000)
    parser.add_argument("--output", default="darth-analysis-graph.json")
    args = parser.parse_args(argv)
    if not 1 <= args.max_files <= 10000:
        parser.error("--max-files must be between 1 and 10000")
    if not 1 <= args.max_nodes <= 500000:
        parser.error("--max-nodes must be between 1 and 500000")
    if not 1 <= args.max_edges <= 1000000:
        parser.error("--max-edges must be between 1 and 1000000")

    graph = build_project_graph(
        args.path, max_files=args.max_files,
        max_nodes=args.max_nodes, max_edges=args.max_edges,
    )
    Path(args.output).write_text(graph.to_json() + "\n", encoding="utf-8")
    paths = graph.paths()
    print(f"Graph nodes: {len(graph.nodes)}; edges: {len(graph.edges)}; source-to-sink paths: {len(paths)}.")
    print(f"Languages: {', '.join(sorted({node.language for node in graph.nodes.values()})) or 'none'}.")
    print(f"Resource limit reached: {'yes' if graph.truncated else 'no'}.")
    print("Paths are static review candidates, not proof of exploitability.")
    print(f"JSON: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
