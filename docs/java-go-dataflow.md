# Darth Scanner 3.0 — Java and Go interprocedural dataflow

3.0 adds bounded source-text adapters for Java methods and Go functions. The
adapters index simple named parameters and return values, link same-file calls
to known local parameters, and connect parameter identifiers to selected
database, process, filesystem, network-request, and deserialization sinks.

## Limits

These are conservative source-text adapters, not full Java or Go parsers.
Overloads, receiver and interface dispatch, generics, closures, callbacks,
goroutines, reflection, dynamic dispatch, cross-file symbol resolution,
framework-specific APIs, complex expressions, branch-sensitive flow, and
sanitizer semantics are not comprehensively modeled. Sink names can be
ambiguous. Findings are review candidates, not proof of reachability or
exploitability.

The adapters run locally, do not execute scanned code, and make no network
requests. Existing language-specific same-file heuristics remain in place.
