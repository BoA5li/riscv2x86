# Phase 77: executable visibility observation and explicit route acceptance

## Delivery status

This is a tested repair increment. It does **not** claim that the original
024/029 cases now verify. Their exact source files are absent from the GitHub
branch (both content requests returned 404), and no applicable environment
contracts have been supplied. This environment also lacks the real frontend
build toolchain and RISC-V/QEMU execution tools. Strict architectural counter
translation is still an unsupported backend domain; no flag or generated
boolean in this change overrides that limitation.

## Implemented behavior

* CSR instructions without an explicit/derived ISA profile stop before
  privileged source-model collection. The primary reason, structured blocked
  stages and needs_route attempt are retained. No downstream permission,
  trap/dataflow or proof failure is manufactured from the absent profile.
* Runtime authority materialization now retains the original typed join
  exception, source/fragment/proof binding and failure identity. A stale
  machine-code join no longer gets collapsed to a generic boundary error.
* A new `instruction_visibility_harness` executable tool can be used by the
  existing explicit instruction-visibility provider. It compiles a small
  observer, loads the **actual built shared library**, calls its exported sync
  function, then executes code written with two different versions. Values
  are read from execution output, not predicted from the input code.
* A compiler AST scope allows function-entry observation only for void,
  zero-parameter functions consisting solely of the asm and optional void
  return. Conditionals, declarations, calls, extra asm and value returns do
  not receive this scope. The observation joins the source/function and asm
  range to compiler fragment authority. The original Phase 6D contract,
  source digest, CPU pinning and two-side execution identities remain required.
* `--require-verified-case` checks explicit acceptance goals independently of
  regression success. It never changes an evaluator verdict. It checks final
  case status; it does not replace provider audit or proof checking.
* A read-only collector packages exact blocked-case sources, reports and tool
  digests. It refuses stale source files and existing output paths. A version
  string or digest records provenance, not a semantic platform guarantee.

## Observer applicability and configuration

The tool is a concrete producer for the existing explicit harness protocol;
its command can be selected in a reviewed L2 provider manifest:

```
python3 -m riscv2x86_py.instruction_visibility_harness --side target --function-symbol SYMBOL --approval REPORT --compiler gcc
python3 -m riscv2x86_py.instruction_visibility_harness --side source --function-symbol SYMBOL --approval REPORT --compiler riscv64-linux-gnu-gcc --runner qemu-riscv64 -L /usr/riscv64-linux-gnu
```

These commands read the provider's execution request on stdin. They are not
standalone semantic approval commands. The manifest must identify the module
file as the harness source, bind both commands and their digests, and reference
the approved relation set. The instruction-stream domain must bind the same
runner identities. `REPORT` must contain a replayable approval and the compiler
function scope. The normal provider applies taskset; the harness checks actual
CPU observations. Both program artifacts must be 64-bit little-endian ELF
shared libraries of the correct ISA. Finite probes test observed local fetch
behavior; they do not alone prove arbitrary instruction visibility.

There is no automatic contract or permission generator in this change. A
plain generated-suite run without applicable environment inputs will continue
to reject the unsupported route. In particular this tool does not implement
architectural TIME, privilege emulation or cross-hart synchronization.

## Local checks without terminating the shell

Run from the repository with the Python environment already activated:

```bash
set +e
REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
python3 -m pytest -q pytools/tests/test_instruction_visibility_execution.py pytools/tests/test_compiler_instruction_sync_scope.py pytools/tests/test_route_precondition_lifecycle.py pytools/tests/test_route_goals_and_collection.py
TEST_STATUS=$?
printf 'targeted_status=%s\n' "$TEST_STATUS"
```

Full selected regression and generated-suite, with explicit target acceptance:

```bash
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
mkdir -p "$REPO/experiment/results"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase77-XXXXXX")
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$REPO/experiment/generated-suite" --require-verified-case case_024_56593df85e --require-verified-case case_029_b2290047d8
RUN_STATUS=$?
printf 'runner_status=%s\nRESULT_ROOT=%s\n' "$RUN_STATUS" "$RESULT_ROOT"
cat "$RESULT_ROOT/run-status.json"
tail -n 100 "$RESULT_ROOT/regression.log"
cat "$RESULT_ROOT/generated-suite.log"
cat "$RESULT_ROOT/route-goals.log"
cat "$RESULT_ROOT/provider-audit.log"
```

Add `--experiment-environment /absolute/path/reviewed-environment.json` only
when actual applicable contracts exist. Do not fill the file with invented
privilege, counter or cache-coherence claims to obtain a passing result.

The existing phase76 run can be collected **without another suite run**:

```bash
python3 experiment/collect_route_evidence.py --results "$REPO/experiment/results/phase76-e4e9B9" --output "$REPO/experiment/results/phase76-route-evidence.zip"
COLLECT_STATUS=$?
printf 'collect_status=%s\n' "$COLLECT_STATUS"
```

This captures the exact source and actual report needed to develop and verify
an applicable counter backend, not merely a summary of reason counts.

## Development verification

Selected regression: 776 passed, 39 skipped. Tests include
real native shared-library loading, execution of two modified code versions,
AST scope mutations, stale observed values, terminal attempt lifecycle,
original materialization exception retention, goal-failure reporting, and
source evidence staleness/overwrite rejection. Source ISA execution has an
explicit real-tool test and skips when unavailable. No generated-suite or
original 024/029 acceptance is claimed from mocked or skipped execution.
