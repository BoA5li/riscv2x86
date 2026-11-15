# Phase188 local verification

Base: remote phase187-wide-integer-original,
27c4ebd50619b5fa53bb264d0775d9047cbf9783; local base tree
eeb7de7467e8571775a52dfce9e09690e5e494b5.

Final stable package source:

- `integration.log`: 12 passed, 211.77 s. New original evaluation/corpus tests.
- `regression.log`: 104 passed, 33.60 s. Existing original adapter, wide-integer,
  proof components, original evaluation, state separation, partial programs,
  verifier manifests, candidate materialization and batch evaluation tests.

The suites are disjoint: 116 selected tests passed. This is not a full-repository
test claim, a real Ghidra/GMP acceptance run, or program semantic approval.

The new integration suite executes actual pypcode, original Pipeline/6A--6F,
proof, renderer, physical materializer, original evaluator and consistency checks.
Compiler export, source assembler, and Ghidra startup use explicit test fixtures.
Copy-builds intentionally lack an L0 validator and must remain inconclusive;
actual target build failure must remain failed. No protocol fixture certifies
machine ABI, internal object accesses, canonical instruction coverage, or GMP.

Negative cases cover changed artifacts/contracts, added unrecorded evidence,
rehashed summary escalation, incomplete translation, unsupported outcomes kept
in the corpus denominator, bounded resume and reuse of checked translation
after an evaluation orchestration failure. Existing validators and proof gates
were not weakened to obtain these results.

Host instructions and remaining capabilities: `docs/phase188-original-evaluation-bridge.md`.
