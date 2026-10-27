# Phase113: LR/SC compiler/object binding

This change closes the compiler binding prerequisite for the finite LR, ALU,
SC, retry domain. It does not approve LR/SC translation or claim L3 completion.

## Contract

`lrsc_compiler_binding.bind` replays the byte sequence and the compiler
fragment authority (including source ranges and expression closure). It joins
machine roles to assembler-owned operand indexes, retaining the old, next and
SC-status outputs independently. It checks exact read/write dereference,
pointer/pointee types, access width, object bounds, alignment and the existing
harness environment provenance. Output/input slot order and physical register
allocation are not hard-coded. Ambiguous maps and unaccounted slots fail closed.
The initial domain requires explicit pointer/value inputs and XLEN early-clobber
outputs; other forms are unsupported rather than inferred.

The legacy declaration-only memory slot can remain incomplete: the replayed
closed expression authority supplies its memory role. No declaration identity
is fabricated for a dereference. No LR/SC sequence is put into the single-AMO
canonical operation field or converted into approved atomic runtime effects.

The normal pipeline now records `compilerBinding` or `compilerBindingFailure`
inside its `lrsc_sequence_ingress` diagnostic. Successful binding yields
`LRSC_COMPILER_BINDING_COMPLETE_SEMANTIC_PROOF_REQUIRED`; the route decision
remains rejected, with `semanticApproval: false`. A binding's identity identifies
its content, and is not a semantic proof. `replay_binding` reconstructs the join
from original authorities rather than trusting a rehashed result.

Existing direct-AMO validation uses extracted common envelope/object validators;
its validation predicates, accepted domain and serialized join payloads stay
unchanged. No backend regeneration is required for this Python-only stage.

## Verification

Run these checks in the project's Python environment:

```sh
set +e
python3 -m pytest -q -rs \
  pytools/tests/test_lrsc_compiler_binding.py \
  pytools/tests/test_lrsc_sequence_contract.py \
  pytools/tests/test_source_operand_coverage.py \
  pytools/tests/test_atomic_expression_consumer.py \
  pytools/tests/test_production_route_authority.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_pipeline_validation_entry.py
```

Rerun both original LR/SC inputs with unchanged mechanism selections, separate
input/output directories and new output directories. Return code 2 remains
expected until later proof stages are implemented. Inspect the new compiler
binding diagnostic before changing semantic gates. A rejected compiler join is
a blocker to investigate, not a reason to accept a partially modeled sequence.

## Remaining implementation

1. Establish a source sequence contract preserving all register outputs,
   memory effects and failure/retry transitions. For LR.W with ADD, retain
   XLEN arithmetic and sign-extended old value separately from the 32-bit store.
2. Prove a registered target implementation against that state contract,
   including output liveness, constraints/clobbers and ordering refinement.
   Failed SC is nonzero, not necessarily one. Progress is a separate assumption.
3. Produce L2 sequence authority and materialization only from successful proof.
4. Implement actual LR/SC invocation and success/failure observation, calibration,
   machine attribution, comparison and independent result replay/audit. Neither
   final object equality nor a reference interpreter substitutes for observation.
5. Extend normal CLI routing and generic production/negative tests, then rerun
   accepted AMO, fence, memory, control and scalar-program compatibility cases.

This is a completed prerequisite stage, not completion of those remaining tasks.
Local contract tests cannot replace the host's real compiler/QEMU validation.

Local validation for this change: 209 focused tests passed, with no skips
(including the new binding contract, sequence, operand-coverage, compiler
expression/object joins and direct-AMO/L2 regressions). `git diff --check` passed.
A larger regression attempt did not complete: it emitted
`fatal library error, lookup self` in this environment. It is not counted as a
successful regression. Real compiler/QEMU production validation remains pending.
