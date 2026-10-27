# Phase114: formal LR/SC source sequence ingress

Baseline: Phase113 remote commit 459a76e04961a4ada04288b7f1fe0e0a93d04ea1.
This is implementation batch A. It does not complete batches B/C/D or enable
LR/SC target emission, L2 approval or L3 acceptance.

## Implemented

- The normal pipeline constructs immutable `LrScRuntimeEvidence` directly from
  assembler bytes/maps, compiler authority and the current fragment. Diagnostic
  records cannot grant authority. Serialization replays the independent join;
  Phase6A additionally checks the current machine bytes, XLEN, shell, fragment
  authority, register map and widths. Rehashed substituted evidence is rejected.
- Phase6A constructs a normalized `SourceLrScSequenceModel` and all six source
  operands, including the genuine read/write memory slot. This path does not
  fabricate `AtomicMemoryObjectRuntimeFact` effect approval. Conflicting AMO
  authority is rejected. The normalized source DTO carries no raw machine bytes.
- Exact register effects and local negative facts are obtained from the decoded
  full region, instead of interpreting lifted reservation pseudostate as GNU
  operands. The input lifted summary remains unchanged. Alias normalization uses
  the already checked assembler/compiler join, not inferred operand positions.
- Widths, all output roles, raw LR/SC ordering bits and retry/success successors
  are retained. Reference transitions model success, arbitrary nonzero failure
  status, invalid reservations, retries with changed loaded values, and finite
  prefixes without success. SC clears the reservation on either outcome; a valid
  reservation does not force success. Reference results are explicitly not
  observations, and prove no termination or concurrent progress.
- The source compiler-address expression and memory lvalue remain different
  identities/types. No declaration is fabricated for the dereference. An x0
  calculation input requires a separate constant-slot contract and cannot stand
  for an arbitrary C argument.
- A normal translator-entry gate rejects LR/SC until a registered target proof,
  L2 authority and L3 route exist. It cannot fall through to legacy matchers or
  direct-AMO approval. Existing AMO routes have no LR/SC evidence and retain their
  prior path. Old runtime serialization omits the new field when unused.
- A compact read-only inspector reports source-stage results using the actual
  serialized `failureStage` field and refuses to overwrite an output file.

## Expected host results

Both original inputs should still return 2 / unsupported. This is not L3
acceptance. The new acceptance condition for batch A is:

- `lrsc_sequence_ingress`: compilerBindingComplete true;
- `lrsc_source_sequence`: sourceStateModelComplete true, semanticApproval false;
- all six modeled operands; operandShape.complete true;
- `LRSC_TARGET_SEQUENCE_PROOF_UNAVAILABLE` remains;
- no approval artifact and no target replacement;
- no `SOURCE_OPERAND_COVERAGE_INCOMPLETE` for these two supported source shapes.

The source model does not make the generic single-AMO model complete. No final
object equality, missing callback or completed source model is used to approve
an atomic implementation. Other incomplete semantic/profile fields may remain
until the target/effect/observation contracts are implemented.

## Local validation

Focused suite: 312 passed, no skips (100 new source-stage tests plus existing
sequence/compiler/object/operand/L2/pipeline checks).
Compatibility suite: 494 passed, no skips (existing L3 atomic retry/trace/
eligibility, automatic batch and translation-attempt tests).
`git diff --check` passed. Real Clang10/RISC-V compiler/QEMU production validation
is pending on the user's host; this environment cannot execute that full stack.

## Host verification

Use a new result directory; do not overwrite Phase113 evidence. The changes are
Python-only and require no C++ or backend rebuild for this source-stage check.

```sh
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export SELECT_CONFIG="$REPO/experiment/results/phase109-6KVjr8/acceptance-1LQ57K/mechanisms.json"
export PHASE114_ROOT="$(mktemp -d "$REPO/experiment/results/phase114-XXXXXX")"
hash -r
printf 'PHASE114_ROOT=%s\n' "$PHASE114_ROOT"
git rev-parse HEAD > "$PHASE114_ROOT/git-head.txt"

python3 -m pytest -q -rs \
  pytools/tests/test_lrsc_source.py \
  pytools/tests/test_lrsc_compiler_binding.py \
  pytools/tests/test_lrsc_sequence_contract.py \
  pytools/tests/test_source_operand_coverage.py \
  pytools/tests/test_atomic_expression_consumer.py \
  pytools/tests/test_production_route_authority.py \
  pytools/tests/test_l2_atomic_production.py \
  --junitxml="$PHASE114_ROOT/focused.xml" \
  > "$PHASE114_ROOT/focused.log" 2>&1
TEST_STATUS=$?
printf 'focused_status=%s\n' "$TEST_STATUS"
tail -n 80 "$PHASE114_ROOT/focused.log"

printf 'caseId\texitCode\n' > "$PHASE114_ROOT/exit-status.tsv"
for NAME in lrsc_add_32 lrsc_add_64
do
  python3 -m riscv2x86_py.automatic_batch_cli \
    --input "$REPO/experiment/results/phase112-yHGqbt/inputs/$NAME.c" \
    --frontend "$RISCV2X86_TEST_FRONTEND" \
    --output-directory "$PHASE114_ROOT/$NAME" \
    --jobs 1 --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
    --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
    > "$PHASE114_ROOT/$NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s\t%s\n' "$NAME" "$CASE_STATUS" >> "$PHASE114_ROOT/exit-status.tsv"
  printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
done

python3 experiment/inspect_lrsc_source.py \
  --root "$PHASE114_ROOT" --output "$PHASE114_ROOT/source-summary.json" \
  > "$PHASE114_ROOT/source-summary.log" 2>&1
INSPECT_STATUS=$?
printf 'inspect_status=%s\n' "$INSPECT_STATUS"
cat "$PHASE114_ROOT/source-summary.log"
```

The inspector's zero return means extraction succeeded, not that LR/SC was
accepted. Check the fields and remaining reason codes above.

## Remaining work, in dependency order

1. Prove abstraction/observation scope, including all live outputs and internal
   retry effects. Reservation validity cannot be replaced by value equality.
2. Register target contracts/constraints/proofs/rendering. A CAS or builtin RMW
   implementation is eligible only under an explicit proved refinement; it
   cannot preserve arbitrary reservation/attempt-count observations by default.
3. Introduce independent L2 sequence authority and effect/output relations; no
   single-AMO materializer may approve an unproved sequence collapse.
4. Add actual source LR/SC mechanism attribution, backend calibration, observed
   value/path contracts, comparison and independent audit. Existing control
   capture records PC paths and memory addresses/widths, not register values;
   target CAS retry observations are not source LR/SC observations. Required
   value evidence must be supplied by a separately validated capability or
   explicitly identified proof-based inference, never fabricated callbacks.
5. Extend normal mechanism planning and multi-fragment execution dependencies,
   then run generic width/operation/output/ordering/control/evidence matrices
   and existing mechanism compatibility cases.

Do not interpret source completeness or a successful sampled QEMU execution as
proof of all inputs, concurrent linearizability, physical ordering or progress.
