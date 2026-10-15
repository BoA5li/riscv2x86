# Phase 43 L2 repair baseline

This baseline freezes the evidence immediately before the operand-authority v3
and fence-staging repairs. It is an experiment fixture only; production
translation and validation code must not import it.

## What is separated

The baseline verifies two independent failure classes:

1. Nineteen scalar programs reach the logical-operand provider but fail the
   compiler-value-node/sidecar join with
   `L2_OPERAND_OBSERVATION_BINDING_MISMATCH`.
2. The no-operand fence program `case_006_61dfdddddc` fails evaluation
   orchestration because its withheld translation did not produce the L2
   requirements artifact.

The fence case is explicitly excluded from the scalar mismatch set.

## Archive an existing Phase 43 run

Run this from the repository root after selecting the same Clang 10 executable
used for the experiment:

```bash
REPO=/root/src/poc_trans/path_b/riscv2x86
STRICT_OUT=/root/src/poc_trans/path_b/riscv2x86/experiment/results/phase43-generated-suite-20261015T061105Z/generated-suite-strict
ARCHIVE_ROOT="$REPO/experiment/results/phase43-l2-repair-baseline-$(date -u +%Y%m%dT%H%M%SZ)"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"

cd "$REPO"
source "$REPO/.venv-l2/bin/activate"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"

python3 pytools/archive_l2_repair_baseline.py \
  --strict-out "$STRICT_OUT" \
  --output "$ARCHIVE_ROOT" \
  --frontend "$REPO/build/riscv2x86" \
  --clang "$CLANG10"
```

The command fails closed if the case set, root reasons, Clang major version,
fence structured failure, or representative operand authority differs from the
frozen contract. It refuses to overwrite an existing archive.

`provenance.json` distinguishes the frozen experiment commit from the commit
containing the archive tool. This prevents a later checkout from being
misrepresented as the code that produced the Phase 43 results.

## Verify the repository-side contract

```bash
python3 -m pytest -q pytools/tests/test_l2_repair_baseline.py
```

After each repair phase, compare the new batch with the archived
`baseline-verification.json`. Expected reductions must result from closed
authority/evidence production; the baseline must never be read by production
classification, provider resolution, or verdict code.
