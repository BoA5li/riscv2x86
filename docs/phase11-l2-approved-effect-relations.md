# Phase 11 approved L2 effect relations

Effect comparison accepts only proof-produced
`riscv2x86.effect-relation.v2` objects embedded in the unified L2 authority
sidecar.  Each relation has its own content-addressed `approvalIdentity`; the
complete ordered set remains bound by `effectRelationSetIdentity`.

The automatic effect runner does not inspect target routes, proof names,
translation outcomes, helper names, or runtime text to select `exact`,
`strengthened`, or `runtime_mediated`.  It reads and validates the approved
relation, checks the authority/proof/runtime/version bindings, records source
and target observations, and tests only the declared obligations.

Classification is fail-closed:

- missing, invalid, incomplete, stale, or binding-mismatched authority is
  `inconclusive`;
- a `runtime_mediated` relation without one matching versioned runtime
  contract is `inconclusive`;
- once complete authority names a target effect, an absent or non-conforming
  target observation is `failed`;
- `verified` is possible only when every declared source effect has one
  approved relation and the observations satisfy all value, coordinate,
  ordering, shell, and runtime obligations.

Ordering requirements are explicit `{before, after}` source-effect pairs.
The comparator maps both sides through their approved relations and verifies
the resulting target-event order; it does not assume that source program order
is automatically an approved observable relation.
