# Phase189: captured-project automation through the original evaluator

The Phase188 consumer required an EvaluationRequest which this experiment had
never produced. Manual object/link/loader/process diagnostics did not constitute
an original evaluation request or formal L0/L1 completion. This revision adds a
request producer and captured-project build/layer adapters, not another translator.

## What executes

`experiment/automate_native_project.py run` performs, in order:

1. Original input adaptation, Phase6 translation, original candidate materializer,
   and independent frontend/backend replay audit, using `native_original_pipeline`.
2. Structural selection of captured source executable, its shared-library inputs,
   and the actual library object producer matching the selected source digest.
   Target recipes come from the historical deployment plan and build records.
   The old candidate referenced by that plan supplies **no translation authority**.
3. A pinned project contract and a real, strictly parsed original EvaluationRequest.
4. Original `evaluation.run_evaluation` restaging and build commands. Each side
   compiles the current CPP bytes, replaces the exact recorded library object,
   and relinks the test executable. Duplicate library positions and link order
   remain intact; isolated library paths are explicitly added to original RPATHs.
5. Original L0 reference-manifest producer and original L0 checker, over the
   unchanged mandatory GCC/Clang x O0/O2/O3 x none/ASan/UBSan matrix. The candidate
   translation unit is rebuilt in each cell; the remaining captured project
   objects are frozen baseline dependencies. This is not an all-project sanitizer
   rebuild. Matrix reference objects/DSOs and full project executables have
   distinct scopes; no O2 executable is relabeled as all 18 matrix cells.
6. If original L0 verifies, the L1 adapter executes both project test programs for
   every declared case and invokes original `compare_l1_observations` for exact
   exit/stdout/stderr comparison. Empty stdout is a valid observation, not an
   assertion that the translated instance was executed.

The existing original orchestrator determines the final layer ordering and
status. The adapter returns L1 **inconclusive** until actual ABI, internal object
legality, same-input relation, natural-run image identity and canonical instance
coverage are proved. Observation mismatches remain visible but cannot become a
proved translation counterexample before input correspondence is established.
L2 is deliberately not manufactured; no L3/microarchitectural proof is requested
or claimed by this architectural campaign. No approval flags are changed.

## One command on the experiment host

Use a new worktree/output; old verifier-bound original-run receipts must be
regenerated under the current verifier. Historical build records are recipe
inputs and remain read-only. Set the exports below in the current terminal; exports made inside a child
`bash` do not propagate back to the next command block. The two existing discovery JSONs supply paths only;
the automation reads/checks the underlying captured records and actual bytes.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
export PHASE189_TOOLING="$PREP_ROOT/tooling-phase189"
export PYTHONPATH="$PHASE189_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
export PHASE189_PARENT="$(mktemp -d "$PHASE188_ROOT/phase189-XXXXXX")"
export PHASE189_CLI="$PHASE189_TOOLING/experiment/automate_native_project.py"
bash -e <<'VERIFY_PHASE189'
: "${REPO:?}" "${PHASE189_TOOLING:?}" "${PHASE189_PARENT:?}"
git -C "$REPO" fetch origin phase189-project-evaluation-automation
git -C "$REPO" worktree add --detach "$PHASE189_TOOLING" origin/phase189-project-evaluation-automation
git -C "$PHASE189_TOOLING" rev-parse HEAD
printf 'PHASE189_PARENT=%s\n' "$PHASE189_PARENT"
python3 -m pytest -q -rs \
 "$PHASE189_TOOLING/pytools/tests/test_native_project_evaluation.py" \
 "$PHASE189_TOOLING/pytools/tests/test_native_original_evaluation.py" \
 "$PHASE189_TOOLING/pytools/tests/test_native_original_pipeline.py" \
 "$PHASE189_TOOLING/pytools/tests/test_project_native_input.py" \
 "$PHASE189_TOOLING/pytools/tests/test_evaluation_runner.py" \
 "$PHASE189_TOOLING/pytools/tests/test_native_l0_materialization.py" \
 --basetemp="$PHASE189_PARENT/pytest" > "$PHASE189_PARENT/focused.log" 2>&1
cat "$PHASE189_PARENT/focused.log"
VERIFY_PHASE189
```

Then execute this single composed experiment. `run` owns its output directory;
do not pre-create `campaign` or overwrite an earlier attempt. The existing
runtime prefix was established from actual RISC-V loader/libc files, not the
compiler's `-print-sysroot` value `/`.

```bash
bash <<'RUN_PHASE189'
: "${PHASE189_CLI:?}" "${PHASE189_PARENT:?}" "${PHASE188_ROOT:?}" "${PHASE185_BUNDLE:?}"
python3 "$PHASE189_CLI" run \
 --bundle "$PHASE185_BUNDLE" \
 --target-inputs "$PHASE188_ROOT/evaluation-target-inputs.json" \
 --source-baseline-inputs "$PHASE188_ROOT/evaluation-source-baseline-inputs.json" \
 --source-entry-inputs "$PHASE188_ROOT/evaluation-source-entry-inputs.json" \
 --qemu /usr/local/bin/qemu-riscv64 \
 --runtime-prefix /usr/riscv64-linux-gnu \
 --gmp-seeds 42,43 --repetitions 1000 \
 --ghidra-install-dir /opt/ghidra_11.2_PUBLIC \
 --timeout-seconds 600 \
 --output "$PHASE189_PARENT/campaign" > "$PHASE189_PARENT/campaign.log" 2>&1
status=$?
printf 'campaign_status=%s\n' "$status"
cat "$PHASE189_PARENT/campaign.log"
RUN_PHASE189
```

`--source-records` (repeatable) and `--target-plan` accept original paths directly
instead of discovery JSONs. `--source-entry-action` resolves an explicitly chosen
captured entry if more than one is eligible; ambiguous selections otherwise fail.
For other test programs, `--cases /absolute/cases.json` replaces the GMP profile:

```json
[{"caseId":"default","arguments":[],"expectedExitCodes":[0],"environmentOverrides":{}}]
```

Cases explicitly declare their accepted process exit codes; the GMP profile
expects zero. A nonzero exit is retained as an observation and is not silently
relabeled a timeout. Cases cannot override `PATH`, loader or QEMU controls. The GMP profile supplies
explicit repetitions, `GMP_CHECK_REPFACTOR=1`, `LC_ALL=C`, and numeric fixed seeds
>=2. It does not assert equal random input sequences or iteration counts: those
also depend on generator behavior and compile-time thresholds. Repetitions are
the official test argument, not a claimed exact number of internal test cases.

## Read the result

Exit status:

- `0`: original evaluator verified its requested profile (not achievable merely
  from bounded process equality in the current adapter).
- `1`: original evaluation completed with failed/inconclusive evidence. Read its
  layer statuses; this is distinct from acquisition failure.
- `2`: an acquisition/configuration exception. `campaign/run-status.json` retains
  the primary stage and detail. Do not check/refine nonexistent child results.

After an evaluation result exists:

```bash
python3 "$PHASE189_CLI" check --input "$PHASE189_PARENT/campaign/evaluated/result.json"
```

This verifies retained records/content and source provenance bindings, not an
independent program-level proof or a second execution. Failures retain command,
cwd, explicit environment, return code and bounded stdout/stderr. No manual
relinking, log copying, boolean edits or EvaluationRequest heredoc is required.

Useful outputs (only children reached by the run will exist):

- `campaign/run-status.json`
- `campaign/original-run/result.json`
- `campaign/project.json`
- `campaign/contracts/request.json`
- `campaign/evaluated/result.json` and `evaluation-result.json`
- `campaign/evaluated/evaluation/replay/*-failure.json`
- `campaign/evaluated/evaluation/build/{source,target}.project/*/execution.json`
- `campaign/evaluated/evaluation/project-*-L0/{reference,verify}/`
- `campaign/evaluated/evaluation/project-*-L1/observations.json`

The actual layer directory includes the attempt identity before the layer name;
use `find campaign/evaluated/evaluation -name observations.json` if needed.

## Remaining proof work

The source selected CPP context, actual PIC producer context and target producer
context have not been proved equivalent. Replaying the existing CPP bytes under
producer flags does not redo macro selection or establish compatibility.
Canonical instance disposition may still be unknown or the branch may be
unreachable under the actual configuration. A function test is not instruction
coverage. Original macro/header edit authority remains false. Full dependency
and call closure, machine ABI, internal accesses/lifetimes/alias/effects and
program L2/L3 evidence require actual producers/checkers beyond this automation.
Unknown obligations remain reported; the fixed corpus denominator must retain
unsupported/eliminated/unobserved seeds. This revision does not purport to close
those proof gaps or restore the independent integer generation route.

## Local verification

139 distinct selected tests passed; 3 integrations were skipped for missing
real toolchains. Exact suites, overlap and fixture boundaries are recorded in
`experiment/baselines/phase189/README.md`. The actual host GMP campaign and full
18-cell matrix have not been executed in this workspace.
