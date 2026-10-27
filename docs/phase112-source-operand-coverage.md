# Phase112: authoritative coverage of every GNU operand

## Root cause and change

Host Phase111 snapshots establish that frontend, enriched raw, and final fragment
all retain four outputs (including +A) and two inputs. Only the normalized semantic
profile counted three outputs and zero read/write bindings with complete=true.
Do not change Classifier or relabel the memory slot from its constraint alone.

`source_model._build_operand_model` iterated only runtime bindings, so missing
GNU indexes were not checked. A fully modelled subset could claim completeness.
It now compares the complete declared index set against authoritative bindings,
reports missing and out-of-range indexes, preserves known facts, and returns an
incomplete model when any declared slot lacks its binding, semantics or width.
Shell slot enumeration is used solely for coverage, never to infer register maps.

`_runtime_operand_semantics` also refuses to turn +A/+m/=A/=m into scalar-register
semantics from a register map alone. A memory-lvalue runtime fact must have complete
object authority before this adapter consumes it. Existing complete AMO memory
facts retain their access/width/object roles. Nothing here manufactures LR/SC
atomicity or compiler authority.

`source_operand_coverage.py` records declared slots alongside modelled accesses,
widths and missing indexes/fact codes. The ordinary translation result publishes
an identity-bound, non-accepting `source_operand_coverage` decision when incomplete.
Its semanticApproval is always false. The L2 profile's counts remain counts of
modelled semantic roles, not a replacement for raw GNU slot counts. It must now
say complete=false for a missing-slot case, rather than faking an extra modelled
memory operand to make the numbers match.

## Scope

This fixes the false completeness error. It is not full LR/SC translation, L2 or
L3 support. Sequence/compiler binding, output and shell proof, target approval,
L2 sequence authority and actual source SC observation remain outstanding. The
Phase111 byte candidate still grants no approval. Unsupported remains expected
until those obligations are fulfilled. No build flags, validators, or source
programs are weakened. Source/target compilation and independent audit remain
mandatory for any future successful route.

## Host verification

Use .venv-l2; run blocks separately. No C++ changed. There is no need to rebuild
QEMU or repeat the 18-case production matrix for the diagnostic stage.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
hash -r
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export SELECT_CONFIG="$REPO/experiment/results/phase109-6KVjr8/acceptance-1LQ57K/mechanisms.json"
export LRSC_ROOT="$REPO/experiment/results/lrsc-basis-5gKZJl"
export PHASE112_ROOT="$(mktemp -d "$REPO/experiment/results/phase112-XXXXXX")"
printf 'PHASE112_ROOT=%s\n' "$PHASE112_ROOT"
git rev-parse HEAD > "$PHASE112_ROOT/git-head.txt"
python3 -m pytest -q -rs \
  pytools/tests/test_source_operand_coverage.py \
  pytools/tests/test_lrsc_sequence_contract.py \
  pytools/tests/test_source_memory_model_contract.py \
  pytools/tests/test_canonical_atomic_operation.py \
  pytools/tests/test_l2_atomic_production.py \
  pytools/tests/test_l2_semantic_profile.py \
  pytools/tests/test_atomic_expression_consumer.py \
  pytools/tests/test_atomic_memory_address_binding.py \
  pytools/tests/test_phase6_direct_memory_contract.py \
  pytools/tests/test_pipeline_validation_entry.py \
  --junitxml="$PHASE112_ROOT/focused.xml" \
  > "$PHASE112_ROOT/focused.log" 2>&1
TEST_STATUS=$?
printf 'focused_status=%s\n' "$TEST_STATUS"
tail -n 80 "$PHASE112_ROOT/focused.log"
```

Only after focused checks pass, copy the two original input bytes into a fresh
sibling input directory. The old source and all reports remain untouched.

```bash
python3 - <<'PY_INPUTS'
import os, shutil
from pathlib import Path
source = Path(os.environ['LRSC_ROOT'])/'inputs'
target = Path(os.environ['PHASE112_ROOT'])/'inputs'
target.mkdir()
for name in ('lrsc_add_32.c', 'lrsc_add_64.c'):
    shutil.copyfile(source/name, target/name)
    print('INPUT:', target/name)
PY_INPUTS
INPUT_STATUS=$?
printf 'input_status=%s\n' "$INPUT_STATUS"
```

After input_status=0:

```bash
printf 'caseId\texitCode\n' > "$PHASE112_ROOT/exit-status.tsv"
for NAME in lrsc_add_32 lrsc_add_64
do
  python3 -m riscv2x86_py.automatic_batch_cli \
    --input "$PHASE112_ROOT/inputs/$NAME.c" \
    --frontend "$RISCV2X86_TEST_FRONTEND" \
    --output-directory "$PHASE112_ROOT/$NAME" \
    --jobs 1 --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
    --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
    > "$PHASE112_ROOT/$NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s\t%s\n' "$NAME" "$CASE_STATUS" >> "$PHASE112_ROOT/exit-status.tsv"
  printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
done
python3 experiment/inspect_lrsc_basis.py \
  --root "$PHASE112_ROOT" \
  --output "$PHASE112_ROOT/compiler-boundary-basis.json" \
  > "$PHASE112_ROOT/collect.log" 2>&1
COLLECT_STATUS=$?
printf 'collect_status=%s\n' "$COLLECT_STATUS"
cat "$PHASE112_ROOT/collect.log"
```

Both cases may still return 2/unsupported. This stage requires preserved raw slots,
operandShape.complete=false when binding is incomplete, and an explicit coverage
decision explaining the missing index. It does not require four *modelled* outputs
before compiler object closure exists, nor an artificial L3 verified result.

Preview diagnostics, then send the full JSON (includes compiler candidates and
expression joins required for the next authority implementation):

```bash
python3 - <<'PY_PREVIEW'
import json, os
from pathlib import Path
p = Path(os.environ['PHASE112_ROOT'])/'compiler-boundary-basis.json'
data = json.loads(p.read_text())
print('errors:', data['errors'])
for fragment, snapshots in data['boundaryTransitions'].items():
    print('\nFRAGMENT:', fragment)
    print(json.dumps(snapshots, ensure_ascii=False, indent=2))
for record in data['records']:
    if not record['path'].endswith('/translated_report.json'):
        continue
    for finding in record.get('findings', []):
        for decision in finding.get('routeAuthorityDiagnostics') or []:
            if decision.get('failureStage') in ('source_operand_coverage', 'lrsc_sequence_ingress'):
                print(json.dumps(decision, ensure_ascii=False, indent=2))
PY_PREVIEW
```

## Development validation limits

The documented focused set passed **187 tests, no skips**. The local runtime
cannot execute the host Clang10 frontend or real RISC-V/QEMU acceptance. A wider
exploratory test selection also exposed six failures reproduced on unchanged
Phase111: five tests in test_phase6_pytest.py relying on removed legacy CFG/
translation entry points, and test_rv64_counter_csr_read_is_a_structured_runtime_route
expecting the earlier CSR fallback policy. They were not changed or reclassified.
That wider run later reported `fatal library error, lookup self` and was interrupted;
it has no completed all-suite acceptance claim. Use the completed focused and
contract regressions below as this change's local evidence.

Completed related contracts/L3 regression: **680 passed, no failures/errors/skips**
in 102.93 seconds. This set overlaps the 187 focused tests; do not add the counts.
It includes existing direct atomic proof/authority, compiler-expression, target
CAS retry, backend lifecycle and pipeline entry tests. The 22 new coverage tests
check both rejection of incomplete bindings and preservation of a complete direct
atomic model, including translation-result diagnostic propagation.
