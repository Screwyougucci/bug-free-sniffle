# Shared analysis graph (2.5)

Darth Scanner 2.5 introduces `darthscanner.analysis_graph`, a common,
deterministic provenance representation for static-analysis engines.

## Model

- **Nodes:** source, transform, sanitizer, sink, and adapter-defined facts.
- **Edges:** assignments, arguments, returns, property/index flow, calls, and
  other provenance relationships supplied by an analyzer.
- **Locations:** repository-relative path, line, column, language, CWE, and
  bounded confidence metadata.
- **Limits:** configurable node/edge caps and bounded simple-path traversal.
  The graph marks itself `truncated` when a resource cap is reached.

## Python adapter

`build_python_graph(path)` builds an initial AST-backed graph for simple
request-input assignments and selected sensitive calls. It is intentionally
conservative and does not execute source code. The graph API is public so the
existing JavaScript/TypeScript/PHP/Java/Go analyzers can contribute structured
facts without each inventing a different report format.

## Example

```python
from darthscanner.analysis_graph import build_python_graph

graph = build_python_graph("./my_application")
for path in graph.paths():
    print(" -> ".join(f"{node.path}:{node.line} {node.label}" for node in path))
```

A path is a **review candidate**, not proof of a vulnerability. Sanitizer nodes
remain visible in paths rather than automatically erasing taint: whether a
transformation is safe depends on the destination context. Dynamic dispatch,
complex control flow, interprocedural aliasing, and framework-specific behavior
remain limitations. Use the graph alongside existing language-specific audits.
