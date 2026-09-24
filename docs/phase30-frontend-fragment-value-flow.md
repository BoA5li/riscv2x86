# Phase 30: frontend fragment value-flow authority

The automatic frontend now exports compiler-owned, content-addressed value-flow
facts for each GNU asm fragment. It no longer creates `decl-value:<id>` nodes or
connects fragments merely because their declarations have the same spelling or
compiler-local identifier.

## Stable authority

Function, declaration, AST, value-node, candidate, use, and observation-sink
identities are derived from the source digest, stable source ranges, function
scope, node kind, declaration binding, and canonical type. Clang process-local
JSON IDs are used only to join nodes within one AST traversal and do not enter
persistent identities.

`compiler-fragment-boundary-candidate.v2` carries typed operand bindings,
compiler value nodes, downstream uses, and a content-bound fragment binding
key. Version 1 candidates are accepted only as explicit incomplete compatibility
input; no synthetic value node is created for them.

## Boundary closure

`fragment-operand-boundary.v2` records value-flow edges, observation sinks,
discarded outputs, and values covered by approved instrumentation. Every output
must reach a proved sink, feed a specifically bound consumer value node, be
authoritatively dead/discarded, or be covered by a complete instrumentation
proof. Unknown escapes and uncontracted call arguments remain incomplete.

The dependency graph records both producer and consumer value-node identities.
Declaration-name equality cannot create an edge.

## Instrumentation

Instrumentation proof and plan schemas are version 2. In addition to operand,
memory-clobber, control-flow, volatile-placement, escape, and observation-boundary
claims, a complete proof must independently establish flags preservation, memory
ordering preservation, alias preservation, and source/target observation-point
correspondence. Missing any claim keeps the fragment inconclusive.
