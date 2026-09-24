# Phase 32: unified L2 materialization closure

Phase 32 makes L2 eligibility, authority materialization, and provider
applicability consume one content-addressed, fail-closed decision:
`riscv2x86.fragment-l2-materialization-decision.v1`.

The decision binds the fragment, exact required dimensions, authority sidecar,
Phase 6D effect relations, and compiler-shell proof.  A fragment is executable
only when boundary, relation, and shell evidence are all complete and there are
no capability diagnostics.  Consequently:

- eligibility cannot report `eligible` before authority can be materialized;
- the materializer records the same decision in the approval artifact and does
  not publish a sidecar when closure fails;
- every provider validates the persisted decision and only resolves dimensions
  covered by it;
- copied, stale, malformed, or incomplete decisions fail closed before runner
  execution.

Legacy memory/scalar decisions remain diagnostic artifacts.  They no longer
form an independent applicability gate and cannot override the unified
decision.
