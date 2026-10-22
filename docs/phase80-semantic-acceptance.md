# Explicit semantic acceptance and regression execution coverage

## Delivery boundary

This branch includes the previously unpushed phase79 input-preparation/provider
binding increment and adds independently declared semantic acceptance checks.
It does **not** complete the seven-stage 024/029 plan. In particular it does not
implement a strict TIME backend, identify the user's QEMU TIME source mechanism,
or establish a missing instruction-visibility domain guarantee. No original
024/029 full-production success is claimed. Existing translation gates remain
unchanged. No tolerance-based TIME equivalence or functional fallback is added.

## Changes

`python3 -m riscv2x86_py.route_acceptance` consumes a reviewed matrix. It checks
source content and translation-command binding, all selected attempts (all
attempts for program validation), L0/L1/L2 and optionally L3, typed L2 fragment
results, layer/result identity agreement, required dimensions, claim scopes and
relation kinds. An additional required dimension cannot disappear because the
matrix omitted it. A functional claim cannot satisfy an architectural goal.
Unclaimed properties in results must be explicitly allowed in the goal.

This is an acceptance check of published claims, **not** a proof producer or a
replacement for central closure/provider audit. Content identities cannot prove
an environmental assumption. Serialized protocol fixtures are used for checker
tests and are not reported as real RISC-V execution.

`verify_route_contracts.py` now writes `regression.xml` and records test counts in
`run-status.json`. Optional `--require-no-regression-skips` stops before the suite
if regression execution was incomplete. Existing default diagnostic behavior is
preserved. `--acceptance-matrix` runs explicit semantic acceptance separately
from top-level case goals and provider audit; failure returns nonzero and is
recorded even if the suite process itself succeeded.

## Matrix format

Use actual source digests and reviewed dimension requirements. This example is
only a schema illustration; replace every placeholder and select appropriate
relation kinds. Do not derive the intended claim from the observed verdict.

```json
{
  "schemaVersion": "riscv2x86.route-acceptance-matrix.v1",
  "cases": [{
    "caseId": "chosen_case",
    "sourceRelativePath": "chosen_source.c",
    "sourceDigest": "sha256:<actual 64 lowercase hex characters>",
    "levels": ["L0", "L1", "L2"],
    "dimensions": {
      "memory_effects": {
        "relationKinds": ["runtime_mediated"],
        "claimScopes": ["architectural"]
      },
      "shell_semantics": {
        "relationKinds": ["exact"],
        "claimScopes": ["architectural"]
      }
    },
    "notClaimedProperties": ["arbitrary-cross-hart-publication"]
  }]
}
```

Matrices may include renamed sources/cases; there are no 024/029 name checks in
implementation. For heterogeneous fragments use separate case goals; the listed
dimensions are expected on every selected fragment, not a program-wide union.
L3 is not implicitly required or counted as passed.

## Testing without closing the shell

Run from the repository after activating the existing virtual environment. No
`set -e`, `exit`, pipeline status dependency, or interactive multi-line `if` is
required. The runner builds the frontend and records its failures.

```bash
set +e
REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase80-XXXXXX")
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$REPO/experiment/generated-suite"
RUN_STATUS=$?
printf 'runner_status=%s\nRESULT_ROOT=%s\n' "$RUN_STATUS" "$RESULT_ROOT"
cat "$RESULT_ROOT/run-status.json"
tail -n 100 "$RESULT_ROOT/regression.log"
cat "$RESULT_ROOT/summary.json"
cat "$RESULT_ROOT/provider-audit.log"
```

This bare run is a diagnostic baseline, not positive 024/029 acceptance. Missing
downstream logs mean the prerequisite or corresponding stage did not complete.
For a reviewed prepared environment and matrix add these arguments to the runner:

```text
--experiment-environment /actual/prepared/environment.json
--acceptance-matrix /actual/reviewed/acceptance.json
--require-no-regression-skips
```

Inspect `acceptance-matrix.log`, `regression.xml`, provider audit, and individual
`generated-suite-strict/cases/<caseId>/evaluation-result.json` in addition to the
summary. All nonzero codes remain visible without terminating the parent shell.

## Remaining implementation and external prerequisites

1. Obtain a reviewed 024 domain tied to the actual source mechanism and target
   helper. Preparation seals it; it does not manufacture its guarantees.
2. Obtain QEMU TIME source/build mechanism evidence (implementation source,
   build/patch provenance, configuration and its relation to the installed ELF).
   A binary version/hash alone does not supply this evidence.
3. Implement the applicable strict TIME backend and common external-time/state
   relation, including unit, epoch, wrap, availability, access/trap and ordering.
   Current registered monotonic runtime is explicitly functional only.
4. Supply complete CSR profile/access inputs through the prepared environment;
   execute original 024/029 with real frontend/decoder/runtime/providers/closer.
5. Complete the strict backend's negative/mutation tests and real positive
   production chain. Do not count skipped tests or input sealing as acceptance.

No arbitrary guessed environment contract should be checked in to make these
steps green. Further strict backend work depends on item 2; this branch is an
honest partial delivery rather than a claim that those steps are implemented.
