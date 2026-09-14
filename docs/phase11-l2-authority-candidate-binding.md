# Phase 11 L2 authority and candidate binding

L2 authority is transported by `riscv2x86.l2-authority-sidecar.v1`.  The
frontend/compiler or translation-proof boundary is the only permitted
producer.  Validators parse the envelope strictly and never reconstruct
operand, shell, memory-object, effect-relation, runtime-contract, or ignored
state authority from source text or physical registers.

The `authorityIdentity` is the canonical SHA-256 identity of every envelope
field except the identity itself.  `effectRelationSetIdentity` separately
binds the fragment and its ordered approved relation set.  Both identities are
archived on the terminal translation attempt, aggregated into the candidate
manifest, and copied to `TranslationArtifact`.  The latter fields participate
in `TranslationArtifact.identity` and are used directly by L2 dimension
evidence.

The candidate-level identities are content-addressed ordered sets, so one
candidate can safely contain multiple fragments without collapsing their
individual authority.  Candidate verification recomputes those sets from the
attempt archive.

An absent or `complete: false` envelope does not turn an infrastructure gap
into a translation-semantic failure.  The requirement-driven L2 gate records
`l2.authority.incomplete` and closes the affected dimension and fragment as
`inconclusive`.  A stale content digest, fragment mismatch, or shell-fact
mismatch is rejected before execution.
