# Darth Scanner 2.7 — deep dataflow analysis

2.7 enriches the shared graph with bounded Python call/return summaries,
local-import alias resolution, and object-property write tracking.

## New analysis

- **Call arguments:** resolved local function calls connect caller values to
  callee parameter nodes.
- **Return summaries:** values returned from local functions connect to the
  function summary and back to assignment sites at resolved call sites.
- **Local imports:** `from module import name as alias` and basic
  `import module as alias` forms are resolved only inside the scanned tree.
- **Object properties:** simple attribute writes are represented as explicit
  property nodes with dependency edges.
- **Sanitizer visibility:** sanitizer nodes remain in paths. A sanitizer is
  context-sensitive; its presence is evidence to review, not a blanket
  guarantee that every sink is safe.

## Scope and limitations

The deep adapter is AST-backed for Python. JavaScript, TypeScript, PHP, Java,
and Go retain the 2.6 same-file heuristic adapters; 2.7 does not claim
interprocedural analysis for those languages. Dynamic dispatch, reflection,
complex destructuring, control-flow joins, framework-specific sanitizers,
and full alias analysis are not solved. Unresolved external calls are not
treated as local functions.

All analysis is local and static: scanned code is not executed and no network
requests are made. Findings and graph paths remain review candidates, not
confirmed vulnerabilities.


## Evidence interpretation

The graph records possible propagation, not proof that a particular runtime
path is reachable. A parameter-to-sink or property-to-sink edge means the
static syntax links those values; branch conditions, dynamic dispatch, and
framework behavior may still change the actual flow. Review the full source
context before reporting a finding.
