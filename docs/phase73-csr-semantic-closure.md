# Phase 73: CSR semantic closure and proof provenance

This revision fixes independently testable defects remaining after phase 72. It does not claim that cases 024/029 have completed architectural L2 validation.

## Changes

- Separate a potential trap obligation from a whole-function transformation requirement. Missing trap evidence still prevents approval.
- Resolve a decoder's potential counter-access trap only for one isolated decoded instruction under a complete, explicit execution/access policy and a valid CFG. Mixed regions retain the potential trap. ISA metadata alone never grants permission.
- Pass resolved access effects into CSR dataflow by instruction site, CSR identity and operation; retain immutable decoder facts.
- Content-address the full CSR source model and field-proof payload, including operands, access, dataflow, counter relation payload, registry and environment. A counter contract's declared identifier and relation must match its actual payload.
- Reject duplicate or mismatched effect/operand/constraint coverage.
- Select renderer expressions from proved GNU operand indices in the production entry. Sidecar expression spelling cannot redirect the output. Missing expressions reject rendering.
- Render the registered two-argument `rv2x86_read_counter` API correctly.
- Retain CSR and instruction-stream synchronization proof payloads and their recomputable identities in translation metadata. These hashes record contracts; they do not independently establish their truth.

## Validation

The route-contract regression list plus CSR analysis/dataflow/source-model tests: **625 passed, 38 skipped** locally. Skips require external production tools unavailable here. New mutation and negative tests cover payload changes, duplicate effects, unresolved traps, mixed regions, missing operand expressions and stale sidecar output spelling.

The entire Python suite was attempted, but collection was blocked by missing `z3`, `unicorn` and existing legacy module imports. This is not a full-suite pass. A frontend build and real generated-suite execution were not performed in this environment.

## Remaining acceptance work

- 024 needs an actual deployment-bound instruction visibility/publication/scope/completion contract and a provider that executes and observes that contract.
- 029 needs the explicit architecture and execution/access contracts, a justified counter-domain relation, shell transport, and architectural provider evidence.
- Runtime-specific approved effect facts, sidecar production and per-dimension observations must still be connected and verified end to end. This revision does not synthesize those from an `approved` flag, sample values or an opaque relation name.
- The existing strict rejection must remain when these facts are absent. Neither POSIX clock substitution nor local CPUID alone establishes the required source semantics. L3 remains independent.

Run the normal `experiment/verify_route_contracts.py` in a fresh directory on the production host. Keep the configuration directories used for the experiment and the provider audit. Compare individual case diagnostics and proof payloads rather than treating a nonzero batch exit as a runner crash.
