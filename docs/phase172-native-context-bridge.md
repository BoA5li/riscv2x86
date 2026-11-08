# Native context bridge: implementation, limits and validation

This extends the existing project-input and instance-binding path. It does not
implement a second translator or grant another route to semantic approval.

## What changed

* `inspect-context` validates the captured deployment plan, candidate artifacts,
  binding bundle and original native-input receipt using existing validators.
* Candidate source-object stdin must match the bound native-expanded input.
  Reapplying the exact recorded edits must reproduce candidate CPP bytes.
* Each edit must identify exactly one existing instance binding with the same
  statement range and source digest. The bridge retains its enclosing function
  AST path, analysis-input identity, producer-context identity and plan identity.
  Matching a function spelling or definition signature does not establish this.
* The selected target object producer supplies the target context. Existing
  `project_native_input.acquire(target='x86_64')` performs native preprocessing,
  dependency snapshots, GCC frontend/specs capture, data-model checks and Clang
  inspection of the resulting bytes. Original inputs are never overwritten.
* Exact source/target dependency differences and preprocessing digests are
  retained. Different macro/header selections are obligations for a semantic
  relation, not authorization to reuse them or reject all cross-ISA inputs.
* Source, candidate-target and native-target AST declarations, parameters,
  attributes and call references are recorded with AST identities and paths.
  Type spelling equality does not establish native ABI or pointer legality.
* An optional observation must validate and belong to this exact deployment
  plan. Diagnostic event counts, unverified endpoint occurrences and unsupported
  relocations remain evidence, not natural-run identity or call coverage.
* `check` rederives the entire bridge report from bound artifacts. A rehashed
  edited report is rejected. As with existing integrity checks, this checks
  consistency with captured evidence, not the authenticity of an untrusted host.

Observation v3 also corrects unknown relocation timing to JSON `null`, including
when BIND_NOW is declared. Unsupported relocation semantics stay unsupported;
no symbol spelling whitelist resolves them. The inventory counts all unverified
endpoint occurrences, including files, labels and unresolved files. Events and
endpoint occurrences are not unique object counts. Existing v2 reports retain
v2 derivation for integrity checks; new acquisitions emit v3. This does not
silently change old receipts or promote any approval flag.

## What the uploaded receipts establish

The source native-expanded digest can be joined to candidate source-object
stdin. The recorded original C source digest can be joined to the target object
producer. These are narrow lineage facts. The candidate was compiled from
source-expanded CPP, whereas the target library producer uses its own target
headers, macros and code-generation options. A successful relink does not prove
that these contexts have the required semantic relationship. Appending PIC flags
or macro definitions after preprocessing cannot reconstruct an unselected branch.

The supplied file copies are sufficient to implement this general bridge and
correct the known diagnostic inference. They do not contain native ABI register
assignments, whole-program object lifetimes, full source/target behavior traces
or candidate-instance execution coverage. They are insufficient to assert that
all five experimental goals are complete. The bridge makes these gaps explicit.

## Remaining implementation and evidence plan

| Goal | Implemented evidence | Required before admission to the original framework |
| --- | --- | --- |
| Runtime bindings | Validated observation join; complete endpoint deficit counts; unknown relocation timing | Natural-run loaded-object identities, namespace/version resolution, applicable binding coverage and modeled special relocation behavior |
| Entry and ABI | Actual source/candidate/native-target declarations and reference paths; exact input and producer lineage | Native compiler ABI facts joined with machine facts; parameter/return/variadic/aggregate and external object representation contracts |
| Legal objects and inputs | Declaration and call-site inventory | Object initialization/lifetime, bounds/alignment, aliasing and function preconditions tied to exercised inputs |
| Output and termination | Existing natural-run output/return evidence retained separately | Explicit source/target observation relation including external effects, errors, protection failure and termination under that policy |
| Program validation | Stable candidate-instance-to-input/producer identities | Actual instance coverage, common L0–L3 admission and execution, independent program-level audit |

The existing `function_abi_sidecar` and machine-join modules are the intended ABI
consumers. Their variadic/aggregate exclusions must not be bypassed by converting
a Clang declaration into a purported native ABI certificate. The existing L2
memory-object, differential and L3 deployment/audit consumers remain the
acceptance authorities. The bridge uses their canonical status vocabulary but
does not manufacture their inputs or claim that they ran.

A future context relation must identify the relevant declarations, data models,
selected source macro semantics and target object representations. Unsupported
cases remain inconclusive. Original macro/header rewriting additionally requires
provenance/edit authorization; that requirement is separate from evaluating an
isolated frozen translation unit.

## Validation on the experiment host

Run the following steps separately in the original shell, where `REPO`,
`PREP_ROOT`, `PHASE171_ROOT` and `.venv-l2` are available. No path under `/` is
assumed for a plan or observation.

### 1. Fetch the new tooling without changing old experiments

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE171_ROOT:?}"
git -C "$REPO" fetch origin phase172-native-context-bridge
export PHASE172_TOOLING="$PREP_ROOT/tooling-phase172"
git -C "$REPO" worktree add --detach "$PHASE172_TOOLING" origin/phase172-native-context-bridge
export PHASE172_ROOT="$(mktemp -d "$PHASE171_ROOT/phase172-XXXXXX")"
: "${PHASE172_ROOT:?}"
export PYTHONPATH="$PHASE172_TOOLING/pytools"
export PYTHONDONTWRITEBYTECODE=1
git -C "$PHASE172_TOOLING" rev-parse HEAD
printf 'PHASE172_ROOT=%s\n' "$PHASE172_ROOT"
```

### 2. Run focused regression tests

```bash
python3 -m pytest -q -rs \
  "$PHASE172_TOOLING/pytools/tests/test_native_context_bridge.py" \
  "$PHASE172_TOOLING/pytools/tests/test_native_observation_integrity.py" \
  "$PHASE172_TOOLING/pytools/tests/test_native_captured_deployment.py" \
  "$PHASE172_TOOLING/pytools/tests/test_project_native_input.py" \
  "$PHASE172_TOOLING/pytools/tests/test_native_integer_translation.py" \
  --basetemp="$PHASE172_ROOT/pytest" \
  > "$PHASE172_ROOT/focused.log" 2>&1
PHASE172_TEST_STATUS=$?
printf 'phase172_test_status=%s\n' "$PHASE172_TEST_STATUS"
cat "$PHASE172_ROOT/focused.log"
```

These include real GCC/capture/relink/loader tests and explicitly mocked
inspection/binding boundary tests. Passing boundary tests is not GMP semantic
validation. Stop and investigate nonzero status before subsequent steps.

### 3. Acquire target-native context and join the existing v2 observation

Use the inspection compiler originally available on the host. The recorded
native target compiler is selected from the captured producer, not this variable.

```bash
export PHASE172_CLANG="$(command -v clang-10)"
: "${PHASE172_CLANG:?clang-10 unavailable}"
python3 "$PHASE172_TOOLING/experiment/advance_native_closure.py" inspect-context \
  --plan "$PHASE171_ROOT/deployment/plan.json" \
  --observation "$PHASE171_ROOT/observation/result.json" \
  --clang "$PHASE172_CLANG" --timeout-seconds 600 \
  --output "$PHASE172_ROOT/context-bridge" \
  > "$PHASE172_ROOT/context-bridge.log" 2>&1
PHASE172_CONTEXT_STATUS=$?
printf 'phase172_context_status=%s\n' "$PHASE172_CONTEXT_STATUS"
cat "$PHASE172_ROOT/context-bridge.log"
```

Do not change recorded tool paths or environment to suppress a validation error.
If the original capture environment differs, preserve the diagnostic and decide
whether to reproduce that environment or recapture the build context.

### 4. Independently rederive the saved bridge report

```bash
python3 "$PHASE172_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE172_ROOT/context-bridge/result.json"
```

Expected: `evidenceOperationComplete=true`, `targetNativeInputAcquired=true`.
For the supplied source lineage, `sourceContentLineageVerified` should be true;
this must be observed, not assumed. All ABI/object/behavior/coverage/L0–L3 and
semantic approval fields remain false. Inspect `obligations`,
`dependencyDifferences`, `preprocessingComparisons`, declaration inventories and
`runtimeObservationInventory` before implementing the next contract adapter.
A command exit status 0 means evidence acquisition/check succeeded, not that
those contracts were proved.

### 5. Reacquire corrected runtime diagnostics

```bash
python3 "$PHASE172_TOOLING/experiment/advance_native_closure.py" observe \
  --input "$PHASE171_ROOT/deployment/result.json" \
  --diagnostic --timeout-seconds 600 \
  --output "$PHASE172_ROOT/observation" \
  > "$PHASE172_ROOT/observation.log" 2>&1
PHASE172_OBSERVATION_STATUS=$?
printf 'phase172_observation_status=%s\n' "$PHASE172_OBSERVATION_STATUS"
cat "$PHASE172_ROOT/observation.log"
```

```bash
python3 "$PHASE172_TOOLING/experiment/advance_native_closure.py" check \
  --input "$PHASE172_ROOT/observation/result.json"
```

Expected schema is `riscv2x86.deployment-observation.v3`. Unsupported relocation
rows have unknown timing, and diagnostic event collection still cannot prove
natural-run binding identity or candidate execution.

The next useful evidence is the automatically generated bridge report and any
failed acquisition stage, not another sequence of individually copied files.
This code has not run against the user's GMP artifacts in the development
container; the experiment-host commands above are required for that validation.

## Development validation

The focused suite, including native validation CLI and compiler-configuration
regressions, completed with **111 passed, 3 skipped**. The skipped integrations
require real Clang; real RISC-V GCC plus Clang; and the full native translator
frontend/toolchain respectively. The development container lacks these tools.
The passing GCC/capture/relink/loader tests therefore do not establish the GMP
cross-ISA experiment result. `git diff --check` also passed.
