# Generated-suite baseline workflow

`experiment/baselines/generated-suite-phase16.json` freezes the 32-program
result at commit `9f26c3591d1521b6d8ede1e33fd08d33344dbfcc`.

The baseline is deliberately program-scoped. It does not use the exit status of
`riscv2x86-auto-evaluate` as evidence that every case succeeded or failed. The
comparison command reads `batch-evaluation.json/cases` and accounts for every
stable `case_NNN` identity independently:

```sh
python3 -m riscv2x86_py.generated_suite_baseline \
  --baseline experiment/baselines/generated-suite-phase16.json \
  --batch-result "$RESULT_ROOT/batch-evaluation.json" \
  --mode exact \
  --output "$RESULT_ROOT/generated-suite-baseline-comparison.json"
```

Use `--mode exact` to reproduce the frozen Phase 16 result. Use
`--mode progress-aware` after a capability change: transitions explicitly
listed in `allowedFutureStatuses` are accepted, while missing/unexpected cases,
regressions of already verified cases, and acceptance of the two invalid source
programs remain failures.

`case_023` and `case_026` remain in the 32-case denominator as frontend
rejection tests, but their `coverageDisposition` excludes them from translation
coverage. Their invalid immediate operands must never become accepted merely to
increase translation coverage.

`primaryCapabilityGap` records the audit classification used to plan future
work. `observedReasonCodes`, when present, records exact diagnostics emitted by
the implementation. Keeping those fields separate prevents an audit conclusion
from being represented as runtime evidence.
