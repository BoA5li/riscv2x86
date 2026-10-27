# Phase111: LR/SC machine contract and compiler-boundary evidence

## Delivered and remaining scope

This stage adds a byte-decoded RV64 LR/ALU/SC/retry candidate and a pure reference
projection for all successful old/next/status/store outputs. It handles add,
AND, OR, XOR, 32/64-bit accesses, 64-bit ALU, ADDW for word accesses, and a standard
BNE or compressed C.BNEZ backedge. Register roles come from encoded instruction
fields, not filenames, source variable names, placeholder position or mnemonics.
Aliasing, extra instructions, other exits/operations and wider shapes are rejected.

A machine candidate is NOT compiler authority, translation proof, execution
observation, or semantic approval. Exact replay checks the entire reconstructed
payload. `semanticApproval=false` and `compilerBindingComplete=false` are invariant.
The pipeline records a content-bound, non-accepting route decision and preserves
all existing Phase6/L2/L3 gates. It does not inject an LR/SC candidate into the
single-AMO `atomic_semantics` slot or synthesize an L2 sidecar.

This is the first implementation stage, not end-to-end LR/SC support. Source-model
integration, full compiler object closure, approved target renderer, L2 authority,
SC failure observation/calibration, L3 comparison and independent result audit
remain required before any LR/SC sample may become verified. Compare-exchange,
concurrent progress and physical microarchitecture are not claimed.

## Why the compiler-boundary snapshot is necessary

Host input declares old/next/status and +A memory as four outputs, two inputs.
The uploaded *semantic profile* shows three outputs, no read/write operands and
an incomplete boundary. This does NOT establish that Classifier dropped memory:
we must compare preserved frontend-report.json, enriched raw_report.json,
compiler-candidates.json, compiler-fragment-joins.json and translated_report.json.
The read-only collector includes all these and exact compiler slot diagnostics.
It explicitly displays literal operand partitions alongside derived profile
counts. It never reconstructs source operands by regex or changes existing data.

## Host check 1: focused tests

Use the active .venv-l2. No C++ code changed; rebuilding the frontend or recalibrating
existing direct-AMO backends is not required just to collect this evidence.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PHASE111_ROOT="$(mktemp -d "$REPO/experiment/results/phase111-XXXXXX")"
printf 'PHASE111_ROOT=%s\n' "$PHASE111_ROOT"
git rev-parse HEAD > "$PHASE111_ROOT/git-head.txt"
python3 -m pytest -q -rs \
  pytools/tests/test_lrsc_sequence_contract.py \
  pytools/tests/test_atomic_phase5_closure.py \
  pytools/tests/test_canonical_atomic_operation.py \
  pytools/tests/test_production_route_authority.py \
  pytools/tests/test_compiler_expression_contracts.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_pipeline_validation_entry.py \
  --junitxml="$PHASE111_ROOT/focused.xml" \
  > "$PHASE111_ROOT/focused.log" 2>&1
TEST_STATUS=$?
printf 'focused_status=%s\n' "$TEST_STATUS"
tail -n 80 "$PHASE111_ROOT/focused.log"
```

Require no failures/errors. Report any skipped tests and their prerequisites.
These checks include pure-reference success outputs; no real source LR/SC/QEMU
execution or full semantic proof is inferred from these tests.

## Host check 2: inspect the already-existing reports without rerunning

```bash
export LRSC_ROOT="$REPO/experiment/results/lrsc-basis-5gKZJl"
python3 experiment/inspect_lrsc_basis.py \
  --root "$LRSC_ROOT" \
  --output "$PHASE111_ROOT/compiler-boundary-basis.json" \
  > "$PHASE111_ROOT/collect.log" 2>&1
COLLECT_STATUS=$?
printf 'collect_status=%s\n' "$COLLECT_STATUS"
cat "$PHASE111_ROOT/collect.log"
```

The output is created exclusively; use a new filename if repeating collection.
`collect_status=0` means diagnostics were read, not that translation was approved.
Send compiler-boundary-basis.json as text. To obtain a short preview first:

```bash
python3 - <<'PY_PREVIEW'
import json, os
from pathlib import Path
p = Path(os.environ['PHASE111_ROOT'])/'compiler-boundary-basis.json'
data = json.loads(p.read_text())
print('errors:', data['errors'])
print('sources:', [s['path'] for s in data['sources']])
for identity, snapshots in data['boundaryTransitions'].items():
    print('\nFRAGMENT:', identity)
    print(json.dumps(snapshots, ensure_ascii=False, indent=2))
PY_PREVIEW
```

Decision after this evidence:

* If frontend has four outputs and enriched raw has four, but the profile has
  three, trace the derived source model/closure. Do not modify Classifier by guess.
* If the preserved frontend itself has three, independently reproduce frontend
  extraction and examine source ranges, preprocessing and compiler diagnostics.
* If compiler slots include the memory expression but its carrier is incomplete,
  fix expression closure and object binding while preserving all slots.
* The canonical single-AMO decoder intentionally rejects LR/SC. It still needs
  explicit sequence-to-source-model integration even after the partition closes.

## Optional: exercise the new non-accepting pipeline diagnostic

Only if a fresh trace of the new code is needed, use a new output directory and
one existing input. Existing failed evidence is left unchanged. Restore Clang10
and SELECT_CONFIG as in Phase110; then run the normal automatic_batch_cli with
--require-l3 and the existing mechanism selections. Expected translation may
remain unsupported. Inspect routeAuthorityDiagnostics for failureStage
`lrsc_sequence_ingress`: `LRSC_SEQUENCE_MACHINE_CONTRACT_ONLY` means only the
closed machine contract decoded, NOT an approved candidate. Other LRSC_* reasons
identify an unsupported machine shape; report bytes rather than changing input.

## Development verification

The local runtime lacks Clang10 shared libraries, the RISC-V compiler and the real
QEMU experiment backend. It cannot independently reproduce the host's frontend
partition or execute end-to-end source LR/SC. Local native unit/reference and
existing contract checks are reported separately from those missing experiments.

Local related regression: **658 passed, 0 skipped**, including the new 80 sequence,
reference projection, non-approval and evidence-collection checks, and existing
atomic/compiler/L2/pipeline/target-CAS contract tests. This does not constitute
real source LR/SC production acceptance.
