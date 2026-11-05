# Phase156: complete captured-context batches and whole-AST asm discovery

Base: `0c6b746d03f698ab0fa3bea48a621688e40461e9` (Phase155).
Branch: `phase156-whole-ast-activation-batches`.

## What is added

The old pilot counts primary-file functions containing `GCCAsmStmt`. That is
useful acquisition evidence but not a whole-translation-unit asm inventory.
This opt-in extension enumerates `GCCAsmStmt`, `MSAsmStmt` and `FileScopeAsmDecl`
through the entire Clang JSON AST's structural `inner` tree, including header
bodies and locations expressed as macro spelling/expansion pairs. Referenced
declarations are not recursively followed as new occurrence nodes. Enumeration
is static compiler-AST occurrence discovery, not dynamic execution counts.

`--asm-inventory` acquires the AST through the same validated native context,
header search, dependency scans and compiler invocation as the existing check.
The new inventory is derived from that same AST; it does not execute an
unbound extra compiler scan. Raw AST allocation IDs are excluded from occurrence
records, while location records and unknown file bindings are preserved. Each
record binds context, dependencies, compiler, target and structural AST path.
Paths do not claim native instruction identity or universal stability across
compiler versions. Missing source files in Clang's location serialization are
not guessed to be the main file. A location record is not an authorized edit.

Opt-in observations use `project-context-inspection.v2`. Independent replay
reacquires and compares the whole asm inventory, as well as all original
components. Default inspection remains v1 and retains the Phase155 type fix.
The pilot binds report, summary and replay-log digests in its progress record.

The batch planner freezes **all captured compile contexts**, sorted by source
path with all variants for one source in the same batch. Unsupported contexts
are retained; derivation failures and unresolved build records are explicit.
The inspection compiler path and digest are frozen in the plan, too.
It does not filter by translation success, function type or presence of asm.
Duplicate/empty selections and altered plans are rejected. Run one batch at a
time; no native configure/make, source patching or frozen corpus policy changes.

The ledger verifies saved artifact hashes, plan membership and recorded replay
results. It explicitly reports `freshIndependentReplayPerformed: false`:
aggregation is not a new compiler replay or production audit. `not_run`,
`blocked`, `invalid` and `recorded_inspection_replayed` remain distinct. All
occurrences retain their translation-unit/context association; header occurrences
in multiple variants are not silently deduplicated into unique source sites.

## Claims that remain false

Even full captured-context inspection does not establish:

- GCC/Clang semantic equivalence or native-code activation of every occurrence;
- a complete macro definition/argument/expansion provenance graph;
- complete source-site binding, asm operand semantics or safe macro rewriting;
- reachable call/ABI/object/environment closure or end-to-end eligibility;
- L0--L3, semantic approval or production acceptance.

The output therefore keeps `nativeCompilerActivationConfirmed`,
`sourceInstanceBindingComplete`, `asmInstanceInventoryComplete`,
`endToEndEligibilityAssessed`, `semanticApproval` and
`productionAcceptanceComplete` false. `inspectionAstTraversalComplete` means
traversal of one successfully acquired inspection AST only. A zero count after
that traversal means no recognized asm occurrence in that AST; it does not prove
absence under other native configurations. Failed inspection is unknown, not zero.

## Host workflow

Reuse existing native capture records. Set `REPO`, `PREP_ROOT`, `VERIFY_ROOT` and
`CORPUS_CHECK_ROOT` to the existing paths; compiler variables must name installed
tools. Do not alter the protected main checkout or older output directories.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${VERIFY_ROOT:?}" "${CORPUS_CHECK_ROOT:?}"
: "${RV2X86_SYSTEM_CLANG:?}" "${RV2X86_TEST_RISCV_CC:?}"
cd "$REPO"
git fetch origin phase156-whole-ast-activation-batches
export TOOLING="$PREP_ROOT/tooling-phase156"
git worktree add --detach "$TOOLING" origin/phase156-whole-ast-activation-batches
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export ACT_ROOT="$(mktemp -d "$CORPUS_CHECK_ROOT/activation-full-XXXXXX")"
export ACT_PLAN="$ACT_ROOT/plan.json"
printf 'ACT_ROOT=%s\n' "$ACT_ROOT"
```

### 1. Tests, frozen plan and first batch

```bash
bash -e <<'STAGES'
python3 -m pytest -q -rs \
  "$TOOLING/pytools/tests/test_project_activation_inventory.py" \
  "$TOOLING/pytools/tests/test_project_type_replay.py" \
  "$TOOLING/pytools/tests/test_project_inspection_pilot.py" \
  "$TOOLING/pytools/tests/test_project_build_records.py" \
  "$TOOLING/pytools/tests/test_project_header_search.py" \
  --junitxml="$ACT_ROOT/focused.xml" > "$ACT_ROOT/focused.log" 2>&1
python3 "$TOOLING/experiment/inventory_project_activations.py" plan \
  --records "$VERIFY_ROOT/gmp-native/records.json" --batch-sources 16 \
  --clang "$RV2X86_SYSTEM_CLANG" \
  --output "$ACT_PLAN" > "$ACT_ROOT/plan.log" 2>&1
python3 "$TOOLING/experiment/inventory_project_activations.py" run \
  --plan "$ACT_PLAN" --batch-index 0 --tooling "$TOOLING" \
  --clang "$RV2X86_SYSTEM_CLANG" --output "$ACT_ROOT/batch-0000" \
  > "$ACT_ROOT/batch-0000.driver.log" 2>&1
STAGES
FIRST_STATUS=$?
printf 'first_batch_status=%s\n' "$FIRST_STATUS"
cat "$ACT_ROOT/focused.log"
for NAME in plan.log batch-0000.driver.log batch-0000/run-status.json batch-0000/summary.json; do
  if test -f "$ACT_ROOT/$NAME"; then cat "$ACT_ROOT/$NAME"; fi
done
```

The real Clang macro/header integration test must run when Clang is installed.
First-batch success requires exact planned membership and independent replay.
A zero whole-AST asm count is allowed; success is not defined by finding asm.
If it fails, return the failed stage log and status before launching more batches.

### 2. Remaining batches, stop at the first shared blocker

Run only after step 1 succeeds. This loop does not skip existing directories;
an existing destination requires review, not blind resume. To continue after a
known completed batch, set `NEXT_BATCH` to the first unrun index. Never overwrite
a failed batch; a repair requires a new result root/plan under the new tooling.

```bash
export NEXT_BATCH=1
bash -e <<'BATCHES'
TOTAL=$(python3 -c 'import json,os;print(len(json.load(open(os.environ["ACT_PLAN"]))["batches"]))')
for (( INDEX=NEXT_BATCH; INDEX<TOTAL; INDEX++ )); do
  NAME=$(printf 'batch-%04d' "$INDEX")
  printf 'RUNNING %s / %s\n' "$NAME" "$TOTAL"
  if test -e "$ACT_ROOT/$NAME" || test -e "$ACT_ROOT/$NAME.plan.json"; then
    printf 'EXISTING_BATCH_REQUIRES_REVIEW: %s\n' "$NAME"
    exit 2
  fi
  python3 "$TOOLING/experiment/inventory_project_activations.py" run \
    --plan "$ACT_PLAN" --batch-index "$INDEX" --tooling "$TOOLING" \
    --clang "$RV2X86_SYSTEM_CLANG" --output "$ACT_ROOT/$NAME" \
    > "$ACT_ROOT/$NAME.driver.log" 2>&1
done
BATCHES
ALL_STATUS=$?
printf 'remaining_batches_status=%s\n' "$ALL_STATUS"
```

### 3. Aggregate even a partial run

```bash
export LEDGER_FILE="$ACT_ROOT/ledger-first.json"
python3 "$TOOLING/experiment/inventory_project_activations.py" summarize \
  --plan "$ACT_PLAN" --result-root "$ACT_ROOT" --output "$LEDGER_FILE" \
  > "$ACT_ROOT/ledger-first.log" 2>&1
LEDGER_STATUS=$?
printf 'ledger_status=%s\n' "$LEDGER_STATUS"
cat "$ACT_ROOT/ledger-first.log"
```

Summary exits zero for a valid partial ledger; read the completion field and
batch statuses, not the exit code alone. A subsequent aggregation uses a new
filename. Print a bounded diagnostic view rather than copying the entire ledger:

```bash
python3 - <<'PY'
import json, os
from collections import Counter
data=json.load(open(os.environ['LEDGER_FILE']))
for key in ['sourceCount','contextCount','batchStatusCounts',
            'inspectionAstAsmOccurrenceCount','recordedInspectionAstCoverageComplete',
            'planningErrors','unresolvedBuildRecords']:
    print(key, data[key])
for batch in data['batches']:
    if batch['status'] not in {'not_run','recorded_inspection_replayed'}:
        print('BLOCKER',json.dumps(batch,ensure_ascii=False))
print('kinds',dict(Counter(r['instance']['kind'] for r in data['occurrences'])))
print('macroLocatedOccurrences',sum(r['instance']['macroLocationPresent'] for r in data['occurrences']))
for row in data['occurrences'][:20]:
    print('OCCURRENCE',json.dumps(row,ensure_ascii=False))
PY
```

## Proceeding to real translation experiments

Only after discovery, freeze representative observed occurrence/context pairs
before translation outcomes are known. Separate direct and macro/header sites;
record required source binding, operand contracts, caller/ABI/object/environment
closure and independent observation routes. Keep unsupported instances in the
denominator with explicit blockers. Directly editable, closed instances may
enter the project-aware translator and L0--L3/audit runner. Macro occurrences
cannot be made eligible by slicing a source line or replacing a header macro
without proving effects on all its uses. No generic synthetic harness is
substituted for the real project's calling and build conditions here.

## Local validation

Broader project/type/dependency regressions: 218 passed, 6 skipped because real
Clang/RISC-V tools are unavailable locally. The final activation-specific suite
also passes (18 passed, 1 real-Clang integration skip), including additional
negative tests that reject rehashed attempts to grant broader approval flags.
These suites overlap and their pass counts must not be added. Frozen corpus
regressions: 92 passed. Real header/macro AST integration must run on the host;
synthetic AST tests do not establish native compiler activation or L0--L3.
