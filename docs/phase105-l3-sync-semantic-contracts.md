# Phase105 — stage A: source fence semantics and synchronization obligations

Base: `254c9de4536cc45d06cb111275e0d354a6015624` (Phase104).
Branch: `phase105-l3-sync-semantic-contracts`.

## Delivered scope and remaining work

This is stage A of the agreed A/B/C rollout. It fixes semantic/proof foundations
and typed obligations. It does **not** supply a real fence/atomic observer, does
not register an uncalibrated backend and does not make 006/030 L3 verified.
Stage B is real fence capture/deployment/comparison/audit. Stage C is atomic
builtin machine attribution, object/outcome capture, comparison/audit. Controlled
environment, concurrency and mixed mechanisms remain further extensions.

The current support policy is bounded compiler-region architectural intent.
No physical timing/cache/prediction/speculation or empirical concurrent atomicity
claim is introduced. Backend availability never discharges proof obligations.

## Implementation

- Source full R/W fences now use `SourceFenceOrdering.RW_RW` (`rw_rw`), independent
  of `SourceMemoryOrdering` C abstract orders. The source type is produced only
  from complete Phase-5 predecessor/successor R/W masks. Directional/I/O/unknown
  and instruction-visibility fences retain strict refusal.
- New target contract `x86.gnu-att.mfence.ordinary-rw.v2` is used consistently by
  candidate generation, Phase6C, proof, default production catalog and renderer.
  Source and target match in the reviewed **ordinary coherent memory R/W pair**
  domain. `exact` here does not assert identical ISA memory models or global
  C sequential consistency. Compiler memory clobber remains independent.
- `fence_semantics.py` checks explicit refinement: required compiler/hardware
  guarantees, known order domain, and reviewed scope inclusion. Inequality alone
  is never strengthening. ISA R/W fences are never converted to C seq_cst.
- Fence proof facts v3 carry separately hashed source/target ordering contracts
  and explicit roles for proof-context anchors versus the actual fence operation.
  Old v2 facts must be regenerated; no hash patching/implicit migration.
- Proof and selection share one source model identity function. For barrier
  sources it includes the full barrier model, rejecting stale source semantics.
  Nonbarrier source identity format is preserved.
- `l3_sync_obligations.py` derives compiler, fence/atomic mechanism, ordering,
  atomic outcome, visibility/environment sub-obligations from existing approved
  facts and replays existing fence/atomic validators. Missing/compound bases keep
  explicit required obligations and diagnostics. Operation/anchor role changes,
  removed required properties, weakened evidence kinds and stale bindings reject.
- Synchronization sources use property-obligation schema v2; nonsync sources
  retain v1. Every producer manifest pins the new transitive semantic modules.
- Multi-scalar dispatch also requires the complete dimension set to be scalar
  access-only. A supplied capability named `unavailable` can never enable a route.
  Missing synchronization capabilities are reported individually.
- New tests are added to the selected route-contract regression list.

Immutable evidence, output-directory isolation and Phase104 atomic diagnostic
status remain unchanged. Existing memory/control/program backend builder and
plugin files are unchanged, so their calibrated manifests can be reused if their
normal validators still pass. New translation receipts and fence proofs must be
fresh because source/target contracts changed.

## Validation and limitations

Focused synchronization/fence tests: 65 passed. Related L3, Phase6 renderer,
automatic/batch and runner tests: **592 passed, 19 skipped**. The skips are
real QEMU production tests with no calibrated host backend selected. Counts overlap
with the focused tests and must not be added as independent coverage. Production
QEMU tests are opt-in and cannot be executed in this editing environment.

An exploratory glob over `test_phase6*.py` found six failures: five tests in
`test_phase6_pytest.py` reference old CFG/translation internals, plus
`test_phase6_rv64_add_contract.py::test_rv64_counter_csr_read_is_a_structured_runtime_route`.
All six reproduce in an untouched Phase104 archive. They were not modified or
weakened. The archive's two-file run also has an instruction-stream test failure;
that extraction lacks additional runtime assets and is not a complete baseline
suite. Do not report this exploratory glob as a clean full regression. The chosen
related suite is separate from these old tests.

## Safe host experiments

Use each block separately. Inspect outcomes before dependent steps. No `exit`,
`set -e`, deletion, hash modification or output-directory reuse is required.

### 1. Update/build

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase105-l3-sync-semantic-contracts
git switch --track origin/phase105-l3-sync-semantic-contracts
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
export CLANG10="/usr/lib/llvm-10/bin/clang"
export RV2X86_SYSTEM_CLANG="$CLANG10"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE105_ROOT="$(mktemp -d "$REPO/experiment/results/phase105-XXXXXX")"
export SELECT_CONFIG="$REPO/experiment/results/phase104-UqpwRG/selection-VCKufX/mechanisms.json"
hash -r
printf 'PHASE105_ROOT=%s\n' "$PHASE105_ROOT"
cmake --build build > "$PHASE105_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE105_ROOT/build.log"
```

Require delivered SHA and build return 0. Preserve local modifications if switching
reports a conflict. Do not rebuild the old calibrated backends just for this patch.

### 2. Focused stage-A verification

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_sync_semantics.py \
  pytools/tests/test_phase6_full_memory_fence_contract.py \
  pytools/tests/test_l2_fence_ordering_relations.py \
  pytools/tests/test_fence_execution_closure.py \
  --junitxml="$PHASE105_ROOT/focused.xml" \
  > "$PHASE105_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$PHASE105_ROOT/focused.log"
```

Require 65 passed, no skipped/errors/failures. This checks source/proof/renderer
and obligation rules, not real L3 synchronization observation.

### 3. Two targeted real frontend runs

```bash
python3 - <<'PY'
import os
from riscv2x86_py.l3_mechanism_selection import load
for name, backend in load(os.environ['SELECT_CONFIG']).items():
    print(name, backend['backendIdentity'])
PY
CONFIG_STATUS=$?
printf 'config_status=%s\n' "$CONFIG_STATUS"
```

Require return 0 before continuing.

```bash
for INDEX in 006 030
do
  for SOURCE in "$REPO"/experiment/generated-suite/case_${INDEX}_*.c
  do
    if [ -f "$SOURCE" ]; then
      CASE_NAME="$(basename "$SOURCE" .c)"
      python3 -m riscv2x86_py.automatic_batch_cli \
        --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
        --output-directory "$PHASE105_ROOT/$CASE_NAME" \
        --jobs 1 --timeout-seconds 240 \
        --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
        > "$PHASE105_ROOT/$CASE_NAME.log" 2>&1
      CASE_STATUS=$?
      printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
    fi
  done
done
```

Stage-A expected result: both emitted, L0/L1/L2 verified, L3 inconclusive and
CLI return 2. This is an expected **remaining mechanism gap**, not full acceptance.
006 should have the new renderer, v3 facts, source/target rw_rw ordinary domain,
explicit proof anchors and required typed synchronization subproperties. 030's
approved canonical atomic operation should remain intact; its typed mechanism,
outcome and ordering requirements must remain required. Neither may turn verified
merely because no observer exists.

Compact report extraction:

```bash
python3 - <<'PY' > "$PHASE105_ROOT/stage-a-summary.txt" 2>&1
import json, os
from pathlib import Path
from riscv2x86_py.l3_execution_plan import build
root = Path(os.environ['PHASE105_ROOT'])
for directory in sorted(root.glob('case_*')):
    if not directory.is_dir() or directory.name.endswith('-inventory'):
        continue
    print('\nCASE:', directory.name)
    for p in sorted(directory.rglob('evaluation-result.json')):
        d=json.loads(p.read_text())
        print('status:',d.get('status'))
        for a in d.get('attempts',[]):
            print('translation:',a.get('translationOutcome'))
            print('layers:',[(x.get('level'),x.get('status')) for x in (a.get('validation') or {}).get('layers',[])])
        if not d.get('attempts'):
            print('failure:',d.get('detail'),d.get('orchestrationFailure'))
    for p in sorted(directory.rglob('translated_report.json')):
        report=json.loads(p.read_text())
        snapshot=p.with_name('compiler-candidates.json')
        if not snapshot.is_file():
            print('snapshot missing:',snapshot)
            continue
        functions=json.loads(snapshot.read_text())['functions']
        plan=build(report['findings'],functions,{'memory','control','scalar-program'})
        for member in plan['members']:
            print('fragment:',member['fragmentId'])
            print('mechanism:',member['mechanism'],'ready:',member['status'])
            print(json.dumps(member['obligations'].get('synchronizationObligations'),ensure_ascii=False,indent=2))
PY
SUMMARY_STATUS=$?
printf 'summary_status=%s\n' "$SUMMARY_STATUS"
cat "$PHASE105_ROOT/stage-a-summary.txt"
```

If no reports were generated, provide the corresponding top-level case log tail.
If L0-L2 regresses, diagnose it before adding an observer.

### 4. Bounded dispatcher compatibility

After step 3 matches the expected refusal, run the same CLI from step 3 on original
000/002/018, using distinct fresh output directories. All three must return 0 with
full L0-L3 and independent acceptance. This checks the new obligation/dependency
versioning against existing three routes. Do not repeat the long full production
matrix after every semantic edit; final production compatibility and selected
no-skip regression follow real stage-B/C integration.

## Next implementation gates

B: calibrated instruction/region observation for actual fence mechanism, approved
ordering model comparison and independent binary/trace audit; no fake context
memory events. C: separately approved atomic builtin machine attribution and
object-relative value/mechanism evidence; ordinary R/W pairs never imply atomicity.
Both must distinguish static contract validation from measured execution evidence.

Reference semantic basis: RISC-V unprivileged manual / RVWMO explanatory material
(https://docs.riscv.org/reference/isa/unpriv/mm-eplan.html) describes predecessor /
successor fence ordering. QEMU plugin documentation
(https://www.qemu.org/docs/master/devel/tcg-plugins.html) distinguishes instruction
instrumentation from successful completion; future plugin implementation must use
the actual calibrated API-v1 header, not assume newer API features.
