# Automatic corpus translation and evaluation

`automatic_batch_cli` is the user-facing entry point when the input is one C
file or a directory of independent C programs.  It creates and retains the
inventory, target-environment contract, per-program validation plan, translation
command, candidate staging tree, typed translation bindings, L0 matrix evidence,
L1 replay evidence, and corpus summaries.

```bash
REPO=/path/to/riscv2x86
RUN="$REPO/experiment/runs/round1-$(date -u +%Y%m%dT%H%M%SZ)"

PYTHONPATH="$REPO/pytools" python3 -m riscv2x86_py.automatic_batch_cli \
  --input "$REPO/experiment/corpus-round1" \
  --frontend "$REPO/build/riscv2x86" \
  --output-directory "$RUN" \
  --jobs 1 \
  --timeout-seconds 60
```

Add `--allow-functional-fallbacks` only when the experiment intentionally
permits registered functional-only routes.  The flag does not turn unsupported
instructions into successful translations and does not upgrade an L1 result to
L2.

The sibling directory `${RUN}-inventory` is part of the replay record.  It
contains `automatic-inventory.json`, the generated environment contract, and a
descriptor/plan for every program.  The run directory contains each translated
report, attempt archive, candidate manifest, compiler commands, L0 cell results,
L1 observations and the batch JSON/CSV summary.  Existing directories are never
overwritten.

## Entry and harness policy

The command asks Clang's RV64 AST whether the translation unit defines `main`.
Programs with `main` are executed under QEMU and natively; exit code, stdout and
stderr are compared byte-for-byte.  A translation unit without `main` receives
an automatically generated replayable harness only when every selected public
function uses zero to three scalar integer arguments and a scalar integer return
type.  The harness exercises deterministic RV64 boundary values.  Pointer,
aggregate, floating-point, variadic, stateful or ambiguous APIs require an
explicit user-authored validation case; automatic L1 then remains unavailable
rather than inventing an input contract.

## Meaning of results

- L0 uses RV64GC/LP64D source objects and all 18 GCC/Clang × O0/O2/O3 ×
  none/ASan/UBSan target cells.  Every cell is compiled, linked, ELF/ABI checked,
  loaded or executed, and compared with the generated versioned artifact
  manifest.
- L1 is a program-level observation.  It is counted once per program cluster,
  even when a program contains several translated fragments.
- Translation coverage remains fragment-level.  Unsupported and needs-route
  attempts remain in the denominator.
- L2 is never synthesized by this command.  It can be registered only when the
  frontend/compiler supplied authoritative operand, shell and semantic-event
  sidecars.  A run that has only L0/L1 evidence must not be reported as L2
  verified.

Inspect the program-level and fragment-level denominators separately:

```bash
jq '{statusCounts, programValidationCounts, translationOutcomeCounts,
     statisticalUnits, reasonCodeCounts}' "$RUN/batch-evaluation.json"
```
