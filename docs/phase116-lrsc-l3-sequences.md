# Phase116: LR/SC L3 sequence observation and independent replay

Baseline: Phase115 c16ba9f9c33a04592273abbf949dec13382c7de4.
The production L0–L2 results for both original inputs are already verified on the
host. This change adds the missing L3 code path. Real QEMU calibration and host
production acceptance are required before calling the end-to-end task verified.

## Architecture and scope

- `l3_lrsc_spec.py`: dedicated LR/SC capability, not the direct-AMO capability.
  Replays sequence proof, compiler/function scope, complete sidecar and observable
  output bindings. Retains memory, synchronization AND internal-control-flow
  requirements. Never removes control obligations to fit the old AMO route.
- `l3_lrsc_machine.py`: reads final ELF bytes. Re-decodes LR/ALU/SC/backedge,
  compares widths, ALU and raw ordering bits, symbolically joins ABI inputs and
  old-value return through compiler stack/move code. Target proof checks a
  refreshed CAS accumulator over two epochs, locked CAS, recomputation, failure
  branch, object address, return projection and balanced stack. Unknown code
  rejects. No source/function name, fixed GNU slot or fixed allocated register
  selects approval. Source standard/compressed branch encodings are supported.
- `runtime/l3_qemu_lrsc_trace.c`: separately built loop observer. Re-executing
  region start while active is recorded as a loop step, not another invocation.
  Static machine proof excludes calls; every dynamic PC must then match its
  approved loop. Existing control plugin behavior is unchanged. Escape, partial
  traces, other CPUs and resource-limit violations reject.
- `l3_lrsc_backend.py`: separate immutable manifest with 68 mandatory probes:
  source widths 32/64, all 16 raw LR/SC ordering-bit combinations, success and
  controlled failure/retry; target widths 32/64, success and failure/retry.
  A calibration-only SC invalidates the reservation before the observed SC.
  It never modifies production programs. Every completed probe checks actual
  final data, exact executed PC paths and instruction-attributed callback shape.
  Missing/inconsistent calibration blocks backend publication. Failed callback
  patterns are measured, not guessed; a callback is not a committed store.
- `l3_lrsc_observation.py`: retains every attempt and raw callback. Outcomes come
  from proved branch semantics plus actual complete PC paths. No fabricated
  failed register values, synthetic R/W pairs or inferred reservation state.
- `l3_lrsc_compare.py`: checks each side separately, then compares actual inputs,
  returned old value, final object and sentinels under the approved completion
  abstraction. Raw access/attempt counts need not be equal. Control paths have
  their own dimension result. Atomicity/ordering evidence is approved contract
  plus attributed machine execution, not a concurrent measurement.
- `l3_lrsc_deployment.py`, `l3_lrsc_route.py`: preserve the established
  source/target artifact and independent-build checks. Audit reopens raw traces,
  command records, inputs, compiler snapshots, binaries and backend records;
  reconstructs machine regions, attempts, reports and comparisons; checks result
  identities and prior L0–L2 evidence. Stored verified booleans are not authority.
- `l3_execution_plan.py`, `l3_mechanism_selection.py`, `automatic_batch_cli.py`,
  `l3_source_eligibility.py`, `l3_production_acceptance.py`: normal production and
  independent acceptance dispatch through a new `lrsc` mechanism. Direct-AMO
  spec still refuses LR/SC. Existing direct AMO selection retains its own route.

The supported invocation domain remains an independently bound single-asm,
ordinary aligned object, pointer/value arguments and old-value return, with
compiler-proven dead next/status. ADD/AND/OR/XOR, 32/64-bit objects, 64-bit ALU and
32-bit ADDW are supported through the existing approved source/target domain.
Additional live output sinks, compound functions, other sequence instruction
families or concurrent observations require their own proof/observation joins;
they do not inherit a verified result from this route. Neither physical memory
order, concurrent linearizability, exact reservation histories nor termination
are claimed. Dynamic tests sample boundary values; they do not replace the
static all-input proof. Raw attempt histories are retained without claiming
cross-ISA equality of those histories.

## Diagnostics correction

The uploaded machine-basis log showed all four objdump commands failed because
the host's old objdump rejects `--disassemble=name`. This is a diagnostic command
compatibility error, not evidence of a translation failure. The new read-only
`experiment/inspect_lrsc_machine.py` extracts function bytes with the existing
bounds-checked ELF reader and runs the typed machine proof directly.

## Host verification

Run blocks sequentially. All shell blocks use `set +e`; none exits/resets the
interactive shell. Use fresh output directories and preserve previous evidence.
No C++ rebuild is required. The new plugin is built by backend preparation.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
git fetch origin phase116-lrsc-l3-sequence-observation
git switch --track origin/phase116-lrsc-l3-sequence-observation
git rev-parse HEAD
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE116_ROOT="$(mktemp -d "$REPO/experiment/results/phase116-XXXXXX")"
hash -r
printf 'PHASE116_ROOT=%s\n' "$PHASE116_ROOT"
git rev-parse HEAD > "$PHASE116_ROOT/git-head.txt"
python3 -m pytest -q -rs \
  pytools/tests/test_l3_lrsc_sequence.py \
  pytools/tests/test_lrsc_target.py \
  pytools/tests/test_l3_atomic_trace.py \
  pytools/tests/test_l3_atomic_retry.py \
  pytools/tests/test_l3_atomic_eligibility.py \
  pytools/tests/test_l3_control_backend.py \
  pytools/tests/test_l3_production_acceptance.py \
  --junitxml="$PHASE116_ROOT/focused.xml" \
  > "$PHASE116_ROOT/focused.log" 2>&1
TEST_STATUS=$?
printf 'focused_status=%s\n' "$TEST_STATUS"
tail -n 100 "$PHASE116_ROOT/focused.log"
```

If focused tests pass, first run the read-only final-machine preflight against
the already successful Phase115 binaries. Any REPORT_ERROR/BINARY_ERROR is an
implementation/domain issue to inspect before full production; raw bytes are
printed for diagnosis.

```bash
python3 experiment/inspect_lrsc_machine.py \
  --root "$REPO/experiment/results/phase115-BEXqoQ" \
  > "$PHASE116_ROOT/machine-preflight.txt" 2>&1
PREFLIGHT_STATUS=$?
printf 'machine_preflight_status=%s\n' "$PREFLIGHT_STATUS"
cat "$PHASE116_ROOT/machine-preflight.txt"
```

A zero collector exit code alone is not preflight acceptance: require both
source and target machine descriptions for both inputs, with no *_ERROR lines.

Then build and calibrate the dedicated backend. Do not substitute old AMO
manifests or modify their stored hashes.

```bash
python3 -m riscv2x86_py.l3_lrsc_backend \
  --control-backend "$REPO/experiment/results/phase108-VWL1Ko/control-backend/backend.json" \
  --output "$PHASE116_ROOT/lrsc-backend" \
  > "$PHASE116_ROOT/lrsc-backend.log" 2>&1
BACKEND_STATUS=$?
printf 'lrsc_backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$PHASE116_ROOT/lrsc-backend.log"
if [ -f "$PHASE116_ROOT/lrsc-backend/build-status.json" ]; then
  cat "$PHASE116_ROOT/lrsc-backend/build-status.json"
fi
```

Require exit0, stage=complete, complete=true, all 68 calibration records, and
backend.json. semanticApproval=false is expected: calibration grants observation
capability, not semantic approval. On failure retain build-status.json and the
calibrationCurrent directory's build/execute command records and guest-trace.log.
Do not start production with an incomplete backend.

```bash
export RV2X86_L3_LRSC_BACKEND="$PHASE116_ROOT/lrsc-backend/backend.json"
for NAME in lrsc_add_32 lrsc_add_64
do
  python3 experiment/run_l3_lrsc_trace.py \
    --input "$REPO/experiment/results/phase112-yHGqbt/inputs/$NAME.c" \
    --frontend "$RISCV2X86_TEST_FRONTEND" \
    --backend "$RV2X86_L3_LRSC_BACKEND" \
    --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
    --output "$PHASE116_ROOT/original-$NAME" \
    > "$PHASE116_ROOT/original-$NAME.log" 2>&1
  CASE_STATUS=$?
  printf '%s status=%s\n' "$NAME" "$CASE_STATUS"
done
python3 experiment/inspect_lrsc_evaluation.py --root "$PHASE116_ROOT" \
  > "$PHASE116_ROOT/evaluation-summary.txt" 2>&1
cat "$PHASE116_ROOT/evaluation-summary.txt"
```

Require both drivers exit0, L0/L1/L2/L3 all verified, three L3 dimensions covered,
executionComplete=true, independentResultAuditComplete=true,
productionAcceptanceComplete=true and blockers empty. The driver creates an
explicit mechanisms.json containing only the calibrated `lrsc` backend, and
calls ordinary automatic_batch_cli --require-l3. It does not manufacture an
acceptance report or disable preceding layers.

After both originals pass, run the unrelated-name production matrix (nine
cases), which also exercises independent-audit rejection of changed layer status
and modified raw traces. These tests are opt-in and must not be skipped during
host acceptance.

```bash
python3 -m pytest -vv -rs pytools/tests/test_l3_lrsc_production.py \
  --junitxml="$PHASE116_ROOT/production.xml" \
  > "$PHASE116_ROOT/production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'lrsc_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 120 "$PHASE116_ROOT/production.log"
```

Existing AMO manifests bind changed shared decoder/spec/eligibility files and
therefore need recalibration before AMO L3 compatibility experiments. The old
control backend is unchanged and may be reused only while its validator passes.
Mixed/multiple mechanism execution remains governed by the existing explicit
combination policy, not silently enabled by adding `lrsc` to a selection file.

## Development verification

806 related tests passed with zero failures, errors or skips. This includes
71 sequence-specific tests, actual native GCC function/probe execution and C
plugin callback execution against an API stub. The nine opt-in real production
cases were collected successfully but not executed in this environment.

## Development verification limits

The development environment can execute native GCC machine-proof/calibration
program tests and actual plugin callbacks against an API stub. These are not
QEMU calibration. Host RISC-V/QEMU production and all mandatory calibration
records remain pending until the commands above succeed. Tests with synthetic
traces validate rejection logic; they are never published as execution evidence.
