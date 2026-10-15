# Zero-operand boundaries and scalar dependency observers

This branch builds on phase55. It does not change verdict thresholds or grant
ordering proofs from single-threaded runtime values.

## Changes

- Explicit, identity-bound empty operand arrays may close a boundary. Missing
  arrays, nonempty dangling live/value facts and producer reason codes reject.
  The compiler producer still checks candidate completeness, operand partition
  and enumeration. This does not close fence effect or shell obligations.
- Producer and consumer observation bindings reference the same canonical graph
  edge payload, instead of hashing two different edge DTOs.
- Clang exports a content-addressed scalar observer boundary in function facts.
  A program observation plan joins this boundary, typed value nodes, declaration
  identities, graph and approved fragment proofs. Names only render references
  after this join; they are never join keys.
- The observer records separate before/after events for all participating
  fragments. The bounded protocol requires every authorized point exactly once
  per sample, in compiler statement order. Producer post/consumer pre values
  must satisfy the direct edge relation. Both ISA traces are compared.
- One program-level plan is built for the function. The execution cache includes
  this plan and both instrumented source digests. Fragment projections may reuse
  the same source/target run records; their observation identities remain distinct.
- Dependency executions use a v3 runtime execution payload binding the static
  execution authority, observer plan and actual execution record. The central
  closer rehashes the supplied plan and run record. Legacy v2 payloads are retained
  for other routes; this is not an implicit migration of their identities.
- Requirement production failures retain a report-bound, hashed failure artifact;
  the evaluator preserves the producer stage/exception instead of replacing it
  with a secondary missing-marker exception.
- The regression driver rebuilds the frontend before production tests.

## Supported observation domain

The new automatic observer is deliberately bounded to direct statements in a
straight-line scalar function, direct declaration-reference operands, integer
carriers up to 64 bits and unconstrained register operands. All participating
fragment proofs must be approved with preserved architecture and shell semantics.
Clobbers, pointers, volatile/atomic C objects, calls, nested control flow,
macro/unmappable ranges and mixed internal-operation observer plans reject with
specific precondition reasons. Fan-out still requires extension of the existing
observation authority's one-consumer contract. No loop/branch events are guessed.

This is empirical L2 observation of authorized test variants under the existing
proof contract. It is not an unbounded equivalence proof and is not a concurrent
ordering or microarchitecture experiment. A provider can still return
inconclusive if another upstream authority or execution obligation is incomplete.

## Validation performed in the hosted environment

- Related regression matrix: 302 passed, 3 skipped.
- Includes a real host GCC compile/run of inserted producer/consumer observations,
  missing/duplicate/reordered event negatives, edge identity consistency, proof,
  constraint, extent and boundary mutations, runtime-record/plan tamper detection,
  zero-operand roundtrip and original requirement-error retention.
- The three real cross-ISA production tests (scalar/fence/dependency) skip here:
  Clang/RISC-V GCC/QEMU toolchain is unavailable. They must run locally.
- Full Python suite still stops with 13 collection errors (missing z3/unicorn and
  the pre-existing missing translate_function module). No full-suite pass claimed.
- No hosted generated-suite result is available.

## Local validation

Select Clang 10 on PATH, activate the existing environment, set PYTHONPATH to
pytools, rebuild `cmake --build build -j2`, and export
`RISCV2X86_TEST_FRONTEND=$PWD/build/riscv2x86`.

Run:

```
python3 -m pytest -q pytools/tests/test_dependency_observer_production.py \
  pytools/tests/test_l2_real_production_chain.py \
  pytools/tests/test_l2_fragment_execution_authority.py \
  pytools/tests/test_requirement_staging.py \
  pytools/tests/test_requirement_artifact_ingress.py \
  pytools/tests/test_l2_evidence_closure.py
```

Then use a fresh directory with automatic_batch_cli for diagnostic generated-suite
execution. Inspect each failure, the requirement-failure artifact, observer plan,
operand-observation and provider detail. Do not assume the two target seeds must
be verified before checking their actual compiler facts, proof and observations.
