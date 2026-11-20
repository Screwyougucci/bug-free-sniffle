# Darth Scanner 2.6 — multi-language graph adapters

2.6 connects the shared provenance graph to the existing language-specific
static review engines.

## Supported adapters

- Python: existing AST-backed graph producer.
- JavaScript and TypeScript: bounded line-oriented source/alias/sink adapter.
- PHP: bounded line-oriented source/alias/sink adapter.
- Java: bounded line-oriented source/alias/sink adapter.
- Go: bounded line-oriented source/alias/sink adapter.

The non-Python adapter deliberately models only simple same-file assignments.
It does not claim cross-function or cross-file flow for these languages. Its
confidence and provenance metadata identify the heuristic adapter.

## CLI

```powershell
darth-graph --path . --output darth-analysis-graph.json
```

Useful limits:

```powershell
darth-graph --path . --max-files 2000 --max-nodes 100000 --max-edges 200000
```

The JSON contains the shared graph schema, source-to-sink paths, language and
line locations, CWE labels, confidence values, and a `truncated` flag when a
resource cap or file limit is reached.

This command reads local source only. It does not execute scanned code or make
network requests. A path is a review lead, not a confirmed vulnerability.
