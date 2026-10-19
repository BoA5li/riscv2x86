# Phase 78: CSR normalization and runtime observation contracts

## Implemented repairs

The supplied evidence now includes the original 024 and 029 sources and their
machine bytes. The 029 CSRRS TIME read (`732510c0`) suppresses the write through
x0. Older SLEIGH versions expand this into a constant conditional transfer over
an unreachable state write. This is a valid lifting representation, but treating
its unreachable tail as an ordinary fragment branch/write produces false source
requirements.

Canonicalization now performs bounded, replayable constant control reduction for
single decoder-owned CSR instructions. Unknown predicates, unknown reachable
user operations, overlapping temporary writes and unsupported control targets
retain the original operations. No access or trap permission is inferred.
Only complete read-only CSR copies with catalogue-declared register aliases and
a decoder-matched result carrier are removed from the ordinary GNU GPR-input
ledger. CSR state remains represented by typed privileged effects.

The normalization proof retains original/normalized operations, branch decisions,
removed indexes, decoder metadata and a recomputable identity. Findings retain
this record. When used for a runtime approval it enters the v3 CSR proof; both
production and replay validate the record against the actual decoded instruction.
Existing v1/v2 approvals remain accepted through their existing validation.

L1 and L2 now consume one closed functional observation registry. It includes the
already shipped checked monotonic implementation ID; registration does not
establish architectural TIME equivalence. The special counter comparator is
restricted to functional preservation mode. Architectural artifacts cannot obtain
a functional counter verdict through this dispatch.

Evidence collection preserves experiment-time run records and explicitly marks
current executable information as collection-time provenance. A collector's PATH
or Clang version cannot retrospectively identify the experiment compiler.

## Remaining production acceptance

This change does not claim original 024/029 verification. A bare suite invocation
still does not supply the environment contracts that the earlier evidence showed
as not_provided. The 024 executable observer exists, but its approved visibility
contract, applicable domain and explicit provider must be bound to the actual
run. The 029 strict backend still lacks verified clock-domain applicability to
the user's QEMU binary. A binary version/digest alone does not establish that
contract. CLOCK_MONOTONIC sampling is not an architecture-equivalent replacement
for an unspecified TIME backend, and no such downgrade is performed.

The current development environment lacks CMake, the RISC-V compiler and QEMU.
Native runtime execution and real pypcode lifting are tested; frontend/QEMU
production tests skip explicitly. Local generated-suite acceptance is necessary.

## Development checks

Selected route regression: **793 passed, 39 skipped**. Additional batch/CSR
checks: **57 passed** (overlapping checks, not an additive test count). Coverage
includes real native runtime execution, real pypcode TIME lifting, replay of
legacy constant-control regions, unknown/overlapping temporary mutations, and
approval replay against decoded bytes. No frontend/QEMU acceptance is inferred
from skipped tests.

## Local verification (does not terminate the interactive shell)

After switching to this branch, execute from the repository:

```bash
set +e
REPO="$PWD"
source "$REPO/.venv-l2/bin/activate"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
mkdir -p "$REPO/experiment/results"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase78-XXXXXX")
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$REPO/experiment/generated-suite" --require-verified-case case_024_56593df85e --require-verified-case case_029_b2290047d8
RUN_STATUS=$?
printf 'runner_status=%s\nRESULT_ROOT=%s\n' "$RUN_STATUS" "$RESULT_ROOT"
```

Use `--experiment-environment /absolute/path/reviewed-environment.json` only when
an actual applicable contract bundle is available. Do not manufacture permission,
clock or coherence claims to pass acceptance. A remaining needs_route is evidence
of an unfinished production route, not a successful case repair.

```bash
cat "$RESULT_ROOT/run-status.json"
tail -n 100 "$RESULT_ROOT/regression.log"
cat "$RESULT_ROOT/generated-suite.log"
cat "$RESULT_ROOT/summary.json"
cat "$RESULT_ROOT/route-goals.log"
cat "$RESULT_ROOT/provider-audit.log"
python3 experiment/collect_route_evidence.py --results "$RESULT_ROOT" --output "$RESULT_ROOT/route-evidence.zip"
COLLECT_STATUS=$?
printf 'collect_status=%s\n' "$COLLECT_STATUS"
```

Missing downstream logs after a prerequisite failure mean that stage did not run.
A nonzero suite/goal result is retained and never coerced to success.
