# Stage 12 layered regression

Run from the repository root in the configured Python environment:

```bash
python3 experiment/run_layered_regression.py \
  --suite "$PWD/experiment/generated-suite" \
  --frontend "$PWD/build/riscv2x86" \
  --clang10 /absolute/path/to/clang10-toolchain/clang \
  --output "$PWD/experiment/results/stage12-$(date -u +%Y%m%dT%H%M%SZ)"
```

The output directory must not exist. The driver selects clang through PATH,
requires version 10, records the Python module, Git state and frontend digest,
and runs static checks, targeted tests, full Python tests and the frontend build.
Any failed prerequisite blocks the batch. A nonzero batch exit is preserved;
it does not prevent diagnostic extraction. No test failure is converted to a skip.

All original per-case artifacts remain under `strict/cases`, including staging
manifests, attempts, requirements, dimensions, provider dispositions and stderr.
`summary.json` is read only from this run's batch file. `evidence-records.jsonl`
retains full records and JSON paths without interpreting identity presence as
verification. Inspect case count (expected 32 for generated-suite), per-case
evaluation results and the fence staging manifest before comparing verdicts.
The runner is generic and does not encode seed IDs or expected verified counts.

## Execution in the hosted environment, 2026-10-15

- Five requested Python modules compile successfully.
- Driver targeted set: 136 passed, 2 skipped (production toolchain unavailable).
- Full Python regression: interrupted by 13 collection errors; missing z3 and
  unicorn dependencies, and missing riscv2x86_py.translate_function import.
- Frontend rebuild: blocked, cmake executable unavailable.
- Clang 10 selection: blocked, clang executable unavailable.
- generated-suite: not executed; source suite directory unavailable here.

These are blocked acceptance steps, not a passing L2 experiment. This commit
adds a reproducible execution/reporting entry point; it does not alter translator
semantics, evidence checks or verdict thresholds. Resolve dependency/import and
toolchain prerequisites before claiming full regression or 32-seed acceptance.
