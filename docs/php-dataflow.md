# Darth Scanner 2.9 — PHP interprocedural dataflow

2.9 adds a bounded PHP source-text enrichment pass to the shared analysis graph.
It indexes named functions, parameters and returns, links same-file calls to
known local function parameters, and identifies parameter-to-sensitive-sink
relationships for common database, process, filesystem, include, and
outbound-request operations.

## Limits

This is not a PHP parser. Complex signatures, anonymous functions, closures,
traits, inheritance, dynamic calls, namespaces, cross-file imports, nested
argument expressions, branch-sensitive flow, and framework-specific sanitizer
semantics are not fully modeled. PHP findings remain conservative review leads.

The existing same-file taint adapter continues to provide request-source facts.
The new pass enriches function-level provenance; it does not establish runtime
reachability or exploitability.

All scanning is local and static. Scanned code is never executed and no network
requests are made. Graph paths are candidates for manual validation, not
confirmed vulnerabilities.
