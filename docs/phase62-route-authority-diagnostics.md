# Bounded asm-goto/atomic authority corrections

Baseline: phase61-provider-evidence-audit,
4f659c825d2695d240325fffc302f30f00583f57.

This change is a foundation for the requested coverage expansion, **not a
completed asm-goto or atomic evaluation implementation**. In particular it does
not justify changing generated-suite 020/030 to verified.

## Implemented contracts

* Versioned `routeAuthorityDiagnostics` records bind a structured input snapshot,
  fragment, stage, stable rejection code and explanatory detail. Both input and
  decision identities can be recomputed. These records never grant proof authority.
* Asm-goto source construction records the first rejection instead of silently
  returning None. Successful bounded source construction is explicitly separate
  from target proof and L2 execution.
* Predicate normalization rejects future definitions and narrowing copies or
  extensions. The semantic-summary gate accepts a contiguous straight-line pure
  integer prefix followed by one direct conditional exit, rejecting gaps,
  overlap, internal cycles and unrelated effects. This is not a general CFG/SSA
  implementation and does not admit multi-exit regions.
* Atomic production join rejects wrong function binding, object schema, malformed
  provenance, non-power-of-two alignment, uncovered object bounds, unsupported
  address spaces, result carrier mismatches and AMO new-value/success-flag claims.
* v1 memory objects remain explicitly harness scoped. An arbitrary static object
  requires a new versioned object/environment contract. No harness allocation is
  presented as proof of arbitrary caller memory.
* Diagnostic-bearing attempts use `riscv2x86.translation-attempt.v3`; existing
  v2 attempts retain their exact shape and content identity. The existing archive
  container accepts validated v3 members. Diagnostics survive terminal archive
  roundtrip and evaluator attempt/linkage output. Unknown fields, missing
  diagnostics, different fragments and stale content identities are rejected.
* A lifecycle regression fixture now creates its source in tmp_path rather than
  relying on an unrelated working-directory source.c file.

## Remaining production obligations

| Work item | Status after this branch |
| --- | --- |
| First source/join failure diagnostics | Implemented; actual 020/030 must be rerun |
| General expression/lvalue/object authority | Not implemented |
| General CFG dominance and explicit source-label/ELF-target join | Not implemented |
| Actual asm-goto continuation observation provider | Not implemented |
| Explicit RV64 AMO.W input/result width relation through renderer and proof | Not implemented |
| Atomic L2 authority/provider and concurrent memory-model closure | Not implemented |
| LR/SC, compare-exchange and further decoder families | Not implemented |
| L3 experiment execution | Not implemented |

The existing control observer's return-selection shape is not reused as an
asm-goto continuation observation. Ordinary load/store observations are not used
to claim atomicity or memory-order equivalence. Missing provider/proof obligations
remain unsupported/inconclusive under the existing fail-closed contracts.

The RISC-V A specification distinguishes RV64 AMO.W's effective input width and
sign-extended register result:
https://docs.riscv.org/reference/isa/v20240411/unpriv/a-st-ext.html
No AMO.W width gate is relaxed by this patch.

## Local validation

Run the new `test_route_authority_diagnostics.py` plus existing asm-goto, atomic,
attempt lifecycle, evaluation and phase61 provider-audit regressions. Real
production tests require the frontend, Clang 10, cross compiler and QEMU. A skip
is not evidence of a successful production run.

For generated-suite, use a new output directory and collect per-finding
`routeAuthorityDiagnostics` from translated reports and terminal attempt archives,
as well as the existing L0-L3 counts and independent provider audit. Acceptance
does not require unsupported operations to become verified. Check that the
existing 24 supported cases remain verified and independently auditable.
