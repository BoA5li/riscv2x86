# Phase119: L3 shared audit, refusal, provenance and persistence foundation

## Scope and remaining work

This change completes a shared prerequisite stage, **not the entire L3 coverage expansion**.
It does not enable mixed-mechanism execution or relax any source/target machine-code,
proof, calibration, required-property or independent-audit checks.

Implemented:

* Replace mechanism-selection fallback production with an incomplete, typed refusal.
  Missing selected backends are prerequisites; unsupported combinations remain unsupported.
  Independently reconstructed proof-bound properties survive refusal. A refusal grants no
  capability, execution boundary or approval. A known program cannot be accidentally
  approved by the fallback scalar producer after selection failed.
* Share structural audit readiness across control, scalar-program, fence, atomic and LR/SC.
  Incomplete upstream results are not audited; drivers preserve primary errors and mark
  independent audit not run. Completed counterexamples remain auditable: readiness accepts
  a completed failed L3 comparison as well as a verified one. Route-specific replay remains
  mandatory and this readiness check alone never approves semantics.
* Pin the complete Python implementation package, including nested modules and indirect
  helpers, in newly generated producer manifests and fence/atomic/LRSC backend manifests.
  Recompute package membership on validation; reject source symlinks. This conservative
  snapshot deliberately invalidates these manifests after even an unrelated package source
  edit. It avoids pretending a hand-maintained import list is a complete dependency graph.
  External compilers, executors, plugins and runtime assets retain their separate bindings;
  this is not a claim that every possible external dependency is newly captured.
* Extend JSON-native and type-sensitive persisted comparison checks to additional deployment,
  normalized observation, comparison and replay boundaries. Boolean/integer substitutions
  and tuple/list substitutions do not become equal evidence. Keep existing identity algorithms
  for semantic specifications and machine evidence.
* Use the established intent protocol hash for request/profile/disposition identities across
  all producers. Non-ASCII source paths and reasons now follow the same Unicode encoding
  as the ingress parser. ASCII protocol identities are unaffected.
* Add `experiment/inspect_l3_workflow.py`: a read-only report inventory with optional real
  independent audit. Declared success, audit success, upstream failures, malformed reports
  and incomplete layers remain separate. Report counts are not an independently recognized
  corpus coverage denominator. Inventory output always has `semanticApproval: false`.

Still outstanding, in dependency order:

1. A compiler-bound invocation/object/output contract: exact types, ABI, alias/extent/alignment,
   offset, integer conversion and output observability. Do not infer these from case names.
2. Calibrated 8/16/32-bit ordinary stores and generalized memory harnesses. Changing the
   `width == 8` gate alone is invalid: current store harness, object parser and calibration
   also encode eight-byte values.
3. Joint multi-fragment execution: one invocation identity, typed dependency graph, shared
   objects, execution-region order, control edges and full closure. Separate passing runs
   are insufficient. Keep `L3_MECHANISM_COMBINATION_NOT_YET_SUPPORTED` until this exists.
4. Control with memory, multiple exits, bounded loops and multiple regions, followed by
   memory/fence joint sequences and additional proof-supported fence forms.
5. General atomic signatures/offsets/outputs and further proof-supported operation families.
   `next/status` cannot be reported as runtime register observations by the current PC/memory
   callback plugin; add and calibrate the necessary observer, or explicitly limit the claim.
6. Instruction visibility and controlled environments: real execution, attribution,
   comparison and independent audit for each environmental contract.
7. Extend strict persistence boundaries and differential/mutation tests to every new route.
   Statistical/specialized experiment frameworks already exist; architectural-intent passing
   does not prove concurrent atomicity, physical memory ordering, timing or physical
   microarchitecture equivalence.

Every stage requires positive executions, negative controls (wrong operation/width/object/
order/path), changed evidence, missing/truncated observations and independent replay tests.
Unsupported semantics remain explicit, and must never become not-applicable or verified.

## Host validation

Use a new result root; preserve Phase118 artifacts as a baseline. No command below exits
the interactive shell. Run later blocks only after the preceding block succeeds.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE119_ROOT="$(mktemp -d "$REPO/experiment/results/phase119-XXXXXX")"
hash -r
printf 'PHASE119_ROOT=%s\n' "$PHASE119_ROOT"
git rev-parse HEAD > "$PHASE119_ROOT/git-head.txt"
cmake --build build > "$PHASE119_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE119_ROOT/build.log"
```

Focused checks, including rejection and evidence mutation tests:

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_l3_common_foundation.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_l3_lrsc_persistence.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_l3_program_regions.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_control_spec.py \
  pytools/tests/test_l3_fence_trace.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_automatic_batch_evaluation.py \
  pytools/tests/test_batch_evaluation_cli.py \
  --junitxml="$PHASE119_ROOT/focused.xml" \
  > "$PHASE119_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 90 "$PHASE119_ROOT/focused.log"
```

Fresh calibration is required for fence, atomic and LR/SC. Existing Phase118 wrapper
manifests have a smaller source dependency set and must not be edited to pass validation.
The unchanged base memory/control validators still validate their original manifest schemas;
actual source/tool changes can invalidate even those manifests and must be diagnosed.

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
export RV2X86_L3_CONTROL_BACKEND="$REPO/experiment/results/phase108-VWL1Ko/control-backend/backend.json"
python3 - <<'PY' > "$PHASE119_ROOT/base-preflight.log" 2>&1
import os
from riscv2x86_py.l3_qemu_backend import validate_backend
from riscv2x86_py.l3_control_backend import validate
for key, check in (("RV2X86_L3_TRACE_BACKEND", validate_backend),
                   ("RV2X86_L3_CONTROL_BACKEND", validate)):
    value = check(os.environ[key])
    print(key, value["backendIdentity"], flush=True)
PY
BASE_STATUS=$?
printf 'base_status=%s\n' "$BASE_STATUS"
tail -n 60 "$PHASE119_ROOT/base-preflight.log"
```

Only if base preflight succeeds:

```bash
for KIND in fence atomic lrsc
do
  python3 -m "riscv2x86_py.l3_${KIND}_backend" \
    --control-backend "$RV2X86_L3_CONTROL_BACKEND" \
    --output "$PHASE119_ROOT/$KIND-backend" \
    > "$PHASE119_ROOT/$KIND-backend.log" 2>&1
  PREPARE_STATUS=$?
  printf '%s_backend_status=%s\n' "$KIND" "$PREPARE_STATUS"
  tail -n 30 "$PHASE119_ROOT/$KIND-backend.log"
  if [ "$PREPARE_STATUS" -ne 0 ]; then
    printf '准备未完成，保留日志，暂不继续后续验收。\n'
    break
  fi
done
```

Copy the existing selections and replace only the three freshly calibrated manifests;
validate the entire resulting selection, including the existing scalar-program backend.
This script fails if any expected backend key was absent; it does not fabricate a selection.

```bash
export SELECT_CONFIG="$PHASE119_ROOT/mechanisms.json"
python3 - <<'PY' > "$PHASE119_ROOT/selection.log" 2>&1
import json
import os
from pathlib import Path
from riscv2x86_py.l3_mechanism_selection import load
repo = Path(os.environ["REPO"])
root = Path(os.environ["PHASE119_ROOT"])
old = repo / "experiment/results/phase109-6KVjr8/acceptance-1LQ57K/mechanisms.json"
data = json.loads(old.read_text())
data["backends"] = {key: str((Path(value) if Path(value).is_absolute()
    else old.parent / value).resolve()) for key, value in data["backends"].items()}
for kind in ("fence", "atomic", "lrsc"):
    if kind not in data["backends"] and kind != "lrsc":
        raise ValueError("expected existing selection missing: " + kind)
    data["backends"][kind] = str(root / (kind + "-backend/backend.json"))
with Path(os.environ["SELECT_CONFIG"]).open("x") as stream:
    json.dump(data, stream, indent=2)
for kind, backend in load(os.environ["SELECT_CONFIG"]).items():
    print(kind, backend["backendIdentity"], flush=True)
PY
SELECTION_STATUS=$?
printf 'selection_status=%s\n' "$SELECTION_STATUS"
tail -n 90 "$PHASE119_ROOT/selection.log"
```

If this fails, keep its complete traceback. Do not rerun into the same output path or
replace recorded identities. A new output root is needed for a fresh attempt.

First production check: retain the two LR/SC source inputs, use the freshly calibrated
backend, then independently audit the resulting complete batch reports.

```bash
export RV2X86_L3_LRSC_BACKEND="$PHASE119_ROOT/lrsc-backend/backend.json"
for NAME in lrsc_add_32 lrsc_add_64
do
  python3 experiment/run_l3_lrsc_trace.py \
    --input "$REPO/experiment/results/phase112-yHGqbt/inputs/$NAME.c" \
    --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_LRSC_BACKEND" \
    --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
    --output "$PHASE119_ROOT/$NAME" \
    > "$PHASE119_ROOT/$NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
done
python3 experiment/inspect_l3_workflow.py \
  --root "$PHASE119_ROOT" --audit \
  --output "$PHASE119_ROOT/workflow-audit.json" \
  > "$PHASE119_ROOT/workflow-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE119_ROOT/workflow-audit.log"
```

Expected: both driver exits zero; run-status complete with all three completion flags true;
two verified reports, two independently verified reports, no inspection errors. Read-only
inspection without `--audit` is useful for failures but never certifies production acceptance.
Exit two is a diagnostic result, not a passing experiment.

Then cross-route compatibility: use the new `SELECT_CONFIG` with automatic_batch_cli,
`--require-l3 --timeout-seconds 240 --l3-producer-timeout-seconds 600`, each with a fresh
output directory, for existing cases 000, 002, 006, 018, 030 and
`experiment/inputs/l3-bitwise-xor-discard.c`. Run the inventory with `--audit` on that new
compatibility root. All reports and independent audits must verify; two attempts for
case018 remain visible and must not be collapsed into one fragment.

```bash
export COMPAT_ROOT="$(mktemp -d "$PHASE119_ROOT/compatibility-XXXXXX")"
printf 'caseId\texitCode\n' > "$COMPAT_ROOT/exit-status.tsv"
for INDEX in 000 002 006 018 030
do
  for SOURCE in "$REPO"/experiment/generated-suite/case_${INDEX}_*.c
  do
    if [ -f "$SOURCE" ]; then
      CASE_NAME="$(basename "$SOURCE" .c)"
      python3 -m riscv2x86_py.automatic_batch_cli \
        --input "$SOURCE" --frontend "$RISCV2X86_TEST_FRONTEND" \
        --output-directory "$COMPAT_ROOT/$CASE_NAME" --jobs 1 \
        --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
        --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
        > "$COMPAT_ROOT/$CASE_NAME.log" 2>&1
      CASE_STATUS=$?
      printf '%s\t%s\n' "$CASE_NAME" "$CASE_STATUS" >> "$COMPAT_ROOT/exit-status.tsv"
      printf '%s status=%s\n' "$CASE_NAME" "$CASE_STATUS"
    else
      printf 'missing_source=%s\n' "$SOURCE"
    fi
  done
done
python3 -m riscv2x86_py.automatic_batch_cli \
  --input "$REPO/experiment/inputs/l3-bitwise-xor-discard.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output-directory "$COMPAT_ROOT/xor-discard" --jobs 1 \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
  > "$COMPAT_ROOT/xor-discard.log" 2>&1
CASE_STATUS=$?
printf 'xor-discard\t%s\n' "$CASE_STATUS" >> "$COMPAT_ROOT/exit-status.tsv"
python3 experiment/inspect_l3_workflow.py \
  --root "$COMPAT_ROOT" --audit --output "$COMPAT_ROOT/audit.json" \
  > "$COMPAT_ROOT/audit.log" 2>&1
AUDIT_STATUS=$?
printf 'compatibility_audit_status=%s\n' "$AUDIT_STATUS"
cat "$COMPAT_ROOT/exit-status.tsv"
cat "$COMPAT_ROOT/audit.log"
```

Also check that exactly six reports were inventoried. A missing input cannot be inferred
from existing report counts alone and is not a passing case.

After compatibility, run existing production matrices with fresh backend environment
variables: `test_l3_lrsc_production.py` (9), `test_l3_atomic_production.py` (18),
`test_l3_control_production.py` (6), `test_l3_memory_trace_production.py` (4), and fence
production tests as collected from the repository. Preserve JUnit files and check failures,
errors and skips; do not treat a skipped real production test as coverage.

Finally inventory a fresh full corpus run through explicit mechanism selections. Keep all
refused and inconclusive cases in the denominator. Group blockers by actual requirement,
compiler authority and unavailable observation capability. Use that evidence to implement
the outstanding invocation and joint-execution stages above; a successful Phase119
regression alone does not establish their completion.

## Local verification boundary

This environment lacks the RISC-V compiler, Clang and QEMU toolchain needed for real
dual-ISA production. Local unit/integration fixtures, native compiler checks and protocol
mutation tests are useful regression evidence but are not substituted for host production.
The final selected cross-route suite passed 1,323 tests in 89.81 seconds, with zero failures,
errors or skips. It includes 54 new shared-foundation test cases. The earlier dependency
basename assertion was corrected to compare complete relative paths; no acceptance
assertions were removed. Syntax parsing and `git diff --check` also passed.
