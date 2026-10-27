# Phase110: strict atomic acceptance input naming

The Phase109 host build and 540 focused tests passed, and the atomic v2 backend
completed 138/138 calibration probes. Clean alpha/beta inputs passed L0-L3 and
independent acceptance. Gamma failed both source and target compilation because
its C symbol `gamma` conflicts with GCC's built-in declaration. This is a sample
naming error, not evidence of an XOR observer/comparator failure.

This change separates case labels from C symbols in the Phase109 generator,
adds a corrected standalone XOR input, prints failed command records during
acceptance diagnosis, and documents read-only configuration revalidation.
No translator, build flags, proof gate, backend dependency, or audit policy changes.
Existing Phase109 calibrated backends remain usable if normal validation succeeds.
No new calibration is needed for these documentation/input changes.

## Recover the failed sample without overwriting evidence

Use the active `.venv-l2` and run blocks separately. Do not rerun configuration
creation, rewrite previous input/report hashes, or remove the failed directory.
All original atomic semantics, constraints, types and clobbers are retained.
The corrected function has a project-specific external symbol; the translator
must continue to preserve user symbols rather than silently renaming them.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
case "$PATH" in
  /usr/lib/llvm-10/bin:*) ;;
  *) export PATH="/usr/lib/llvm-10/bin:$PATH" ;;
esac
hash -r
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export RV2X86_L3_ATOMIC_BACKEND="$REPO/experiment/results/phase109-6KVjr8/atomic-backend/backend.json"
export SELECT_CONFIG="$REPO/experiment/results/phase109-6KVjr8/acceptance-1LQ57K/mechanisms.json"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase110-XXXXXX")"
printf 'CHECK_ROOT=%s\n' "$CHECK_ROOT"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"

python3 - <<'PY_CONFIG' > "$CHECK_ROOT/selection-check.log" 2>&1
import os
from riscv2x86_py.l3_mechanism_selection import load
for name, backend in load(os.environ['SELECT_CONFIG']).items():
    print(name, backend['backendIdentity'], flush=True)
PY_CONFIG
CONFIG_STATUS=$?
printf 'config_status=%s\n' "$CONFIG_STATUS"
cat "$CHECK_ROOT/selection-check.log"
```

Only after config_status=0:

```bash
python3 -m riscv2x86_py.automatic_batch_cli \
  --input "$REPO/experiment/inputs/l3-bitwise-xor-discard.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --output-directory "$CHECK_ROOT/xor-discard" \
  --jobs 1 --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --l3-mechanism-selections "$SELECT_CONFIG" --require-l3 \
  > "$CHECK_ROOT/xor-discard.log" 2>&1
CASE_STATUS=$?
printf 'xor_discard_status=%s\n' "$CASE_STATUS"
tail -n 80 "$CHECK_ROOT/xor-discard.log"
```

Inspect the original result, including failed compiler commands, and independently
replay acceptance. Script status 0 requires a verified evaluation and audit.

```bash
python3 - <<'PY_AUDIT' > "$CHECK_ROOT/xor-audit.log" 2>&1
import json, os
from pathlib import Path
from riscv2x86_py.l3_production_acceptance import audit_evaluation
paths = sorted((Path(os.environ['CHECK_ROOT'])/'xor-discard').glob('cases/*/evaluation-result.json'))
print('report_count:', len(paths), flush=True)
if len(paths) != 1:
    raise SystemExit('Missing or duplicate report; read xor-discard.log')
report = json.loads(paths[0].read_text())
print('REPORT:', paths[0])
print('status:', report.get('status'))
print('reasonCodes:', report.get('reasonCodes'))
for key in ('detail', 'orchestrationFailure', 'requirementStagingFailure'):
    if report.get(key):
        print(key+':', json.dumps(report[key], ensure_ascii=False, indent=2))
for command in report.get('commands', []):
    print('COMMAND:', command.get('phase'), command.get('status'))
    if command.get('status') != 'verified':
        print(json.dumps(command, ensure_ascii=False, indent=2))
for attempt in report.get('attempts', []):
    print('translationOutcome:', attempt.get('translationOutcome'))
    for layer in (attempt.get('validation') or {}).get('layers', []):
        print('LAYER:', layer.get('level'), layer.get('status'))
        if layer.get('status') != 'verified':
            print('DETAIL:', layer.get('detail'))
if report.get('status') != 'verified':
    raise SystemExit('Evaluation failed; no acceptance claimed')
audit = audit_evaluation(report)
print('AUDIT:', json.dumps(audit, ensure_ascii=False, indent=2), flush=True)
if audit.get('status') != 'verified':
    raise SystemExit('Independent audit failed')
PY_AUDIT
AUDIT_STATUS=$?
printf 'xor_audit_status=%s\n' "$AUDIT_STATUS"
cat "$CHECK_ROOT/xor-audit.log"
```

Expected source/target builds verified, emitted, L0-L3 verified, independent audit
verified. Keep -Werror and do not add -fno-builtin or warning exemptions. Successful
alpha/beta reports remain evidence for their original inputs; they do not count as
new runs of renamed examples. Failed gamma remains a failed build, never relabeled.

After corrected XOR passes, run the full 18-case atomic production matrix once
with RV2X86_L3_ATOMIC_BACKEND above and fresh JUnit/log paths under CHECK_ROOT.
Require 18 passed, no skips/failures/errors. Those tests intentionally mutate some
artifacts after successful audits; retain the clean XOR run for later replay.
Then execute Phase109 guide section 4 for 030/006/000/002/018 with fresh output
paths (use CHECK_ROOT for the guide's result root while keeping SELECT_CONFIG).
Require all five normal evaluations and independent audits verified.

Acceptance remains bounded architectural intent: no physical concurrency,
physical memory-order, full-corpus coverage, or source LR/SC capability is inferred.
