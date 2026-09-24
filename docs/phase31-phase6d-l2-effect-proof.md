# Phase 31: Phase-6D L2 effect proof closure

This change makes approved semantic effect relations a formal Phase-6D output.
The proof artifact is typed, content-addressed, and bound to the fragment,
Phase-6 plan, constraint model, and renderer semantic contract.

The L2 authority materializer no longer derives relations from a semantic
profile or the number of harness samples. It validates `L2EffectProofFacts`
and packages the already-approved source effects and relations. Missing,
stale, incomplete, or identity-mismatched facts fail closed.

Compiler shell preservation is explicit in `ShellRelationFact`: operand
modes, target constraints, early-clobber and tied bindings, memory and `cc`
clobbers, volatile placement, continuation, and compiler visibility are part
of the proof-owned payload.

Execution samples are separate from semantic authority. Observations use an
independent `sampleId` and reference a stable `effectRelationIdentity`.
Increasing the sample domain therefore does not change relation authority.
Memory and structured-control-flow comparators pair samples while validating
that every observation cites the proof-approved relation.

The legacy behavior that generated `relation:scalar:N`,
`relation:branch:N`, or `relation:memory:N` from sample cardinality has been
removed.
