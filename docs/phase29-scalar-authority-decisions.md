# Phase 29: auditable scalar L2 authority decisions

Scalar L2 authority materialization now has a typed, content-addressed decision
record. The decision is derived from the translated finding, its unique compiler
function binding, the fragment-specific operand boundary, and the approved
translation proof. It never infers bindings from assembly spelling or runtime
addresses.

Every scalar, branch, jump, or composite finding receives
`approvalArtifact.l2ScalarAuthorityDecision`, whether authority materialization
succeeds or fails. The record binds the fragment, semantic profile, operand
boundary, proof, canonical reason codes, and a SHA-256 decision identity.

The authority materializer and the automatic operand/effect providers recompute
the same decision. A modified, copied, stale, unknown-schema, or fragment-mismatched
record is rejected. Eligibility carries a valid decision into the requirement
artifact and reports its primary reason when materialization is impossible.

The implementation remains fail-closed. A successful decision does not itself
constitute L2 evidence: a complete approved effect relation and the normal
execution/observation evidence chain are still required. A rejected decision
does not reduce required dimensions.

Canonical rejection reasons distinguish missing/ambiguous fragment selection,
operand arity, value nodes, input/output bindings, live-out and observation
sinks, downstream ambiguity, proof identity, and approved effect relation.
