# Darth Scanner 2.8 — JavaScript/TypeScript dataflow

2.8 adds a bounded source-text enrichment pass for JavaScript and TypeScript.
It indexes basic named function declarations and arrow-function declarations,
tracks simple parameter-to-sink and parameter-to-return relationships, and
links same-file call arguments to known local function parameters.

The existing 2.6 line-oriented source/sink adapter remains the source of
request-input and sink nodes. The new pass adds higher-level provenance edges
to the shared graph.

## Limits

This is not a complete JavaScript or TypeScript parser. Complex signatures,
overloads, destructuring, nested closures, dynamic dispatch, cross-file module
resolution, promise/async propagation, and control-flow joins are not fully
modeled. Import aliases are indexed for future module resolution but are not
treated as proof of cross-file resolution. Unsupported or ambiguous cases
must remain unclassified rather than being presented as confirmed flows.

All scanning is local and static; source code is never executed and no network
requests are made. Graph paths are leads for manual review, not confirmed bugs.
