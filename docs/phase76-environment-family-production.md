# Phase 76: bound experiment inputs and CSR family production

This change is a verified increment, not completion of architectural TIME or
cross-hart instruction-visibility equivalence. No generated-suite verdict is
claimed from this development environment.

## Implemented

* `--experiment-environment` is shared by the regression runner and automatic
  batch inventory. It seals the source set and existing contract files, rejects
  stale inputs and conflicting directory overrides, and records resolution.
  Sealing configuration does not grant semantic approval.
* An explicitly selected CSR architecture template binds to the actual frontend
  fragment IDs and source digest after analysis. A registry supports multiple
  fragments. ISA selection grants neither CSR access nor runtime equivalence.
* CSR environment v2 distinguishes counter observation from logical CSR state.
  Logical state no longer requires a fabricated counter contract. Its checked
  runtime context is explicitly bound to a thread, cannot be nested, and must
  be unbound by the same pointer. Ownership and matching initial source/target
  state remain explicit experiment preconditions.
* The decoder catalog covers MSCRATCH/SSCRATCH for the supported privilege
  specifications. Isolated, explicitly permitted accesses can close source
  access classification; absent, denied or incomplete facts still reject.
* Ordinary RW fields no longer require a WARL policy. Decoder facts materialize
  before/after field value nodes. The concrete scratch implementation requires
  a full-width RW field without additional side effects.
* Proof v2 retains and replays logical-state backend bindings and environment
  snapshots. This is a conditional translation proof, not execution evidence
  that the initial states matched. L2 still requires its own observations.

## Validation and limits

The final selected route-contract regression passed 761 tests, with 38 skips. Native tests compile generated replacements
against the real runtime for all six CSR register/immediate forms; expected
old/new values are calculated independently. Context lifecycle tests exercise
missing/nested/wrong unbind rejection and thread isolation. Mutations reject
foreign backend objects, contexts and execution/environment snapshots.

No CMake, RISC-V compiler or QEMU is available here. Frontend/QEMU production
checks therefore remain skipped. The 24/29 case numbers are not used by code.

Architectural TIME cannot be replaced by CLOCK_MONOTONIC merely because both
increase. Source counter provenance, target clock implementation and an
applicable relation are still required. Likewise, a local clear-cache helper
is not evidence of cross-hart instruction visibility. The existing gates are
retained. A run with no reviewed contracts may correctly remain needs_route.

Contract files are content checked at inventory creation; this does not lock
external directories against concurrent modification. Keep inputs immutable
for a run and retain all resolution/proof artifacts.

## Local validation (Bash; nonzero verdicts do not close the terminal)

```bash
set +e
REPO="$PWD"
source "$REPO/.venv-l2/bin/activate"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
mkdir -p "$REPO/experiment/results"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase76-XXXXXX")
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$REPO/experiment/generated-suite"
RUN_STATUS=$?
printf 'runner_status=%s\nRESULT_ROOT=%s\n' "$RUN_STATUS" "$RESULT_ROOT"
cat "$RESULT_ROOT/run-status.json"
tail -n 100 "$RESULT_ROOT/regression.log"
cat "$RESULT_ROOT/generated-suite.log"
cat "$RESULT_ROOT/provider-audit.log"
```

For a configured run, first seal **existing reviewed** inputs:

```bash
python3 experiment/prepare_experiment_environment.py --help
```

Pass the real source via `--source`, a new path via `--output`, an explicit
`--environment-id`, and the applicable existing contract-directory options.
Optional `--privilege-spec`, `--xlen` and `--extensions` must be specified
together and must describe the real source ISA. Do not choose them only to
pass a gate. Add `--experiment-environment /absolute/path/environment.json`
to the same regression runner invocation. The template alone will not
materialize permissions, counter equivalence or instruction-visibility proof.

To continue strict 024/029 closure, retain actual sources, per-case route
rejections and contract-resolution files, source execution/privilege metadata,
QEMU binary/build provenance, target environment and clock/visibility contracts.
Do not infer those facts from a version string or from matching finite outputs.
