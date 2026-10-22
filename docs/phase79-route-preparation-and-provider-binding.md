# Phase 79: explicit input preparation and approved visibility provider binding

## Delivery and unresolved acceptance

This is a repair increment, not completed original 024/029 acceptance. It does
not implement a strict architectural TIME backend or fabricate a QEMU mechanism
contract. The supplied original TIME instruction is known; the QEMU binary
version/hash does not identify a verified source/build mechanism. That backend
remains a code-capability and environment-applicability gap. The absence of a
reviewed visibility-domain contract also remains a prerequisite for original024.
The old bare suite command is not a positive acceptance experiment for them.

## Implemented

* `prepare_route_environment` seals explicit source/ISA/directory declarations
  through the existing environment consumer. Required contract slots are checked
  by source-relative path and family, without case-specific rules. Missing slots
  produce `preparation.json` with `missing_inputs` and no usable environment
  manifest. Resolved files remain pending semantic validation: this tool does
  not approve malformed contracts, permissions, clocks or visibility properties.
* `prepare_instruction_visibility` provides a planning step and a binding step.
  Planning records exact observer commands and their identities without approval.
  Binding requires a replayable approved report, exact source/machine binding,
  compiler function scope and matching domain runner identities. It compares the
  canonical authority to the approved effect proof, then emits an explicit
  provider consumable by the existing inventory loader. The approval snapshot
  and relation identity stay bound; it never invents a missing proof.
* The shipped observer command identity now includes compiler and source runner
  executable bytes, not only Python and the harness. Executables are rechecked
  before/after execution. Existing domains for this shipped command must be
  re-bound to v2 command identities. Generic external harness identities retain
  their previous protocol. A changed identity is not silently repaired.
* A valid upstream needs_route rejection retains required L2 dimensions and its
  primary cause instead of adding sidecar/shell missing-field noise. An invalid,
  foreign, or tampered decision cannot suppress downstream validation. Existing
  approved artifacts still take the full proof-validation path.

## Local checks

Activate the project virtual environment first. These commands do not use
`set -e` or `exit`:

```bash
set +e
REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
python3 -m pytest -q pytools/tests/test_route_input_preparation.py pytools/tests/test_visibility_provider_preparation.py pytools/tests/test_l2_blocked_materialization.py pytools/tests/test_instruction_visibility_production.py pytools/tests/test_instruction_visibility_execution.py
TEST_STATUS=$?
printf 'targeted_status=%s\n' "$TEST_STATUS"
```

Selected route regression: **810 passed, 39 skipped**. Development has native
GCC/pypcode but lacks CMake/RISC-V GCC/QEMU. Source execution/frontend checks
skip explicitly; no original generated-suite success is claimed. New preparation
tests use serialized protocol fixtures, not claimed real ISA execution. Existing
native observation tests execute the real modified-code probe.

## Preparing a reviewed experiment

There are three distinct activities: select ISA facts, supply reviewed semantic
contracts, and bind executable observation. A hash envelope does not perform the
second activity.

Use existing reviewed directories. ISA options below must come from the actual
chosen source specification; do not infer them from a counter mnemonic:

```bash
python3 -m riscv2x86_py.prepare_route_environment --help
python3 -m riscv2x86_py.prepare_instruction_visibility --help
```

Example shape (replace variables with real declarations/paths):

```bash
python3 -m riscv2x86_py.prepare_route_environment --source "$SUITE" --output "$PREPARED" --environment-id "$REVIEWED_ENVIRONMENT_ID" --privilege-spec "$PRIVILEGE_SPEC" --xlen 64 --extensions $REVIEWED_EXTENSIONS --instruction-stream-sync-directory "$ISS_CONTRACTS" --csr-environment-contract-directory "$CSR_CONTRACTS" --l2-provider-directory "$PROVIDERS" --require-contract instruction_stream_sync=case_024_56593df85e.c --require-contract l2_provider=case_024_56593df85e.c --require-contract csr_environment=case_029_b2290047d8.c
PREP_STATUS=$?
printf 'preparation_status=%s\n' "$PREP_STATUS"
cat "$PREPARED/preparation.json"
```

The case names above are acceptance selections only, not implementation keys.
Missing or unreviewed directories must not be filled with invented true flags.
No environment.json is emitted when a required input is absent. Exit 0 means
input preparation, not semantic acceptance; real consumers validate every file.

## Visibility planning and binding sequence

1. Use the actual compiler-reported function symbol. Select a new fixed output
   location for the provider snapshot; moving it changes command identities.
2. Plan the observer commands:

```bash
python3 -m riscv2x86_py.prepare_instruction_visibility --output "$VISIBILITY_OUTPUT" --plan-symbol "$SYNC_SYMBOL" --source-compiler riscv64-linux-gnu-gcc --target-compiler gcc --source-runner-json '["qemu-riscv64","-L","/usr/riscv64-linux-gnu"]' > "$COMMAND_PLAN"
PLAN_STATUS=$?
printf 'plan_status=%s\n' "$PLAN_STATUS"
```

3. A reviewed domain must bind those sourceRunnerIdentity/targetRunnerIdentity
   values. Its scope, memory guarantees, hart and CPU facts require separate
   applicability evidence. Planning does not establish them.
4. Run translation with that source-bound sync registry. A bootstrap run can
   remain L2-inconclusive without a provider, but it must have an actual approved
   synchronization report and canonical sidecar. Never use a needs_route report.
5. Bind the report to the planned provider location:

```bash
python3 -m riscv2x86_py.prepare_instruction_visibility --output "$VISIBILITY_OUTPUT" --source "$SYNC_SOURCE" --source-root "$SUITE" --report "$APPROVED_REPORT" --fragment-id "$SYNC_FRAGMENT_ID" --execution-profile rv64gc-user-to-x86_64-user --source-compiler riscv64-linux-gnu-gcc --target-compiler gcc --source-runner-json '["qemu-riscv64","-L","/usr/riscv64-linux-gnu"]'
BIND_STATUS=$?
printf 'binding_status=%s\n' "$BIND_STATUS"
```

6. Supply `$VISIBILITY_OUTPUT/providers` as the L2 provider directory, or include
   it in the sealed environment. This removes the need to manually assemble
   relation hashes or weaken provider matching. A changed source, scope, helper,
   runner, compiler, report or relation must be revalidated, not silently reused.

## Formal rerun and logs

After applicable contracts and a prepared environment actually exist:

```bash
set +e
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase79-XXXXXX")
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$SUITE" --experiment-environment "$PREPARED/environment.json" --require-verified-case case_024_56593df85e --require-verified-case case_029_b2290047d8
RUN_STATUS=$?
printf 'runner_status=%s\nRESULT_ROOT=%s\n' "$RUN_STATUS" "$RESULT_ROOT"
cat "$RESULT_ROOT/run-status.json"
tail -n 100 "$RESULT_ROOT/regression.log"
cat "$RESULT_ROOT/summary.json"
cat "$RESULT_ROOT/route-goals.log"
cat "$RESULT_ROOT/provider-audit.log"
```

A missing downstream log after prerequisite failure is not experiment success.
029 remains unaccepted until an appropriate strict backend and its actual source
mechanism are implemented and verified. Monotonic sampling, independent clock
values, or a logical scratch-CSR array do not supply that missing equivalence.
