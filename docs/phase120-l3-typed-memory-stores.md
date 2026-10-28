# Phase120: typed ordinary-store invocation and width-calibrated observation

## Delivered scope

This change implements a vertical store route, not all outstanding L3 expansion.
It adds compiler-resolved LP64 call facts and a proof-bound consumer for ordinary
unsigned stores with one pointer and one unsigned input in either parameter order.
The observed width can be 1, 2, 4 or 8 bytes. Supported shells are a sole asm with
void return, or a sole asm followed by a constant-index read of the same stored
element. Unsigned exact-width and widening returns are supported. The input
carrier may be wider than the access; the expected stored value is its low bits.

The source and target function bytes, source materialization, approved effect
relations, L0-L2 prerequisites, raw callback evidence, observed object bytes and
independent replay remain mandatory. A compiler signature describes types; it
does not grant semantic approval or execution permission.

The implementation includes:

* `compiler_memory_signature.py`: compiler-resolved integer/pointer/void type
  facts, declaration identities, ABI and signature identity.
* `compiler_continuation_sites.py`: store-shell facts retain actual pointer
  position and constant return element, including unsigned widening and void.
* `l3_memory_call.py`: bind parameter roles, unsigned widths, declarations,
  source/function identity, region and return to the actual proof/compiler facts.
* `l3_trace_deployment.py`: exact-pointee-type C object allocation (avoids
  incompatible typed array aliasing), typed calls, actual return/null for void,
  and full object post-state outside the traced asm region.
* `l3_qemu_memory_route.py`: explicit v5 typed-store contract, version-downgrade
  rejection, width-correct truncation, full object and actual return comparison.
  The generic experiment parser and provider dispatcher also recognize v5.
* `l3_memory_backend.py`: an optional wrapper over the unchanged reviewed QEMU
  base. It calibrates actual 1/2/4/8-byte store callbacks on both ISAs (8 probes),
  checks machine bytes, complete captures, exact commands and successful probe
  outcomes, and independently rebuilds probe executable load images. It pins
  all package Python implementations and the immutable base manifest.

Legacy load/scalar backends and the original 8-byte store contract remain
supported. A legacy backend cannot authorize a narrow store: it produces
`L3_MEMORY_STORE_WIDTH_CALIBRATION_REQUIRED`, not a passing result. No calibration
record or manifest identity should be edited to bypass this requirement.

## Remaining gaps

More than two call parameters, multiple objects, signed store-return semantics,
arbitrary external typedef admission, general expressions and arbitrary C shells
are not newly enabled. Mixed mechanisms, multi-region memory/control execution,
additional atomic signatures/outputs and environment-specific mechanisms remain
pending. Their existing refusal gates are retained. This branch must not be
described as completing the whole L3 coverage objective.

The supplied user log confirms 32 one-function exports without inspection errors;
it does not include the contents of `seed-and-call-basis.json`. That file is still
needed for per-seed source/signature/environment classification. Counts alone do
not establish that a seed has complete proofs, suitable observation or passing L3.

## Local validation boundary

`test_l3_typed_memory.py` contains 53 unit/native checks, including real native
typed C calls, exact object bytes, adjacent-byte mutation, wrong type/declaration/
region/return bindings, schema downgrade, exact native probe machine bytes,
probe image rebuild and synthetic transcript negative controls. Synthetic callback
records are tests of replay logic, never QEMU production evidence.

`test_l3_typed_store_production.py` contains 17 opt-in real frontend/L0-L3/QEMU/
independent-audit checks: 4 widths x 2 parameter orders x 2 return modes, plus a
widened return. Each verifies an altered raw capture is rejected after acceptance.
These tests require the actual host toolchain and a freshly calibrated wrapper.
Local collection of their test IDs is not a production pass. This execution
environment has no working RISC-V/Clang/QEMU production toolchain.

The final selected cross-route regression passed 1,466 tests in 147.21 seconds,
with zero failures, errors or skips. It includes the 53 new unit/native tests,
legacy memory/control/fence/atomic/LRSC routes, generic experiment/provider
parsing, production ingress/acceptance fixtures and batch evaluation. Changed
Python syntax parsing and `git diff --check` also passed. The 17 real production
tests were collected separately and remain unexecuted here.

## Host validation commands

All blocks use `set +e`; none exits the interactive shell. Use new output paths
and proceed only after reviewing the preceding result.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
export PHASE120_ROOT="$(mktemp -d "$REPO/experiment/results/phase120-XXXXXX")"
hash -r
printf 'PHASE120_ROOT=%s\n' "$PHASE120_ROOT"
git rev-parse HEAD > "$PHASE120_ROOT/git-head.txt"
cmake --build build > "$PHASE120_ROOT/build.log" 2>&1
BUILD_STATUS=$?
printf 'build_status=%s\n' "$BUILD_STATUS"
tail -n 40 "$PHASE120_ROOT/build.log"

python3 -m pytest -q -rs \
  pytools/tests/test_l3_typed_memory.py \
  pytools/tests/test_l3_memory_trace.py \
  pytools/tests/test_l3_route_applicability.py \
  pytools/tests/test_l3_backend_validation.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_l3_common_foundation.py \
  pytools/tests/test_l3_experiment_runner.py \
  pytools/tests/test_l3_provider_resolution.py \
  --junitxml="$PHASE120_ROOT/focused.xml" \
  > "$PHASE120_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 100 "$PHASE120_ROOT/focused.log"
```

After build and focused checks succeed, build the new wrapper. This reuses the
reviewed base and plugin; it does not rebuild QEMU or alter the base manifest.

```bash
export RV2X86_L3_TRACE_BACKEND="$REPO/experiment/results/phase95-92qksg/trace-backend/backend.json"
python3 -m riscv2x86_py.l3_memory_backend \
  --base-backend "$RV2X86_L3_TRACE_BACKEND" \
  --output "$PHASE120_ROOT/typed-memory-backend" \
  > "$PHASE120_ROOT/backend.log" 2>&1
BACKEND_STATUS=$?
printf 'backend_status=%s\n' "$BACKEND_STATUS"
tail -n 100 "$PHASE120_ROOT/backend.log"
if [ -f "$PHASE120_ROOT/typed-memory-backend/build-status.json" ]; then
  cat "$PHASE120_ROOT/typed-memory-backend/build-status.json"
fi
```

Expected: zero exit, complete true, stage complete, all 8 calibration cases;
`semanticApproval` remains false. Any missing case, changed dependency, wrong
machine bytes, unsuccessful execution or incomplete capture must refuse output.

Create a standalone positive input, preserving its evidence for independent audit:

```bash
mkdir "$PHASE120_ROOT/inputs"
cat > "$PHASE120_ROOT/inputs/narrow-store.c" <<'C'
#include <stdint.h>
uint32_t rv2x86_probe_typed_store(uint32_t *address, uint64_t input) {
    __asm__ volatile("sw %[value],12(%[base])"
        :: [base] "r"(address), [value] "r"(input) : "memory");
    return address[3];
}
C
export RV2X86_L3_TYPED_MEMORY_BACKEND="$PHASE120_ROOT/typed-memory-backend/backend.json"
python3 experiment/run_l3_memory_trace.py \
  --input "$PHASE120_ROOT/inputs/narrow-store.c" \
  --frontend "$RISCV2X86_TEST_FRONTEND" \
  --backend "$RV2X86_L3_TYPED_MEMORY_BACKEND" \
  --timeout-seconds 240 --l3-producer-timeout-seconds 600 \
  --output "$PHASE120_ROOT/narrow-store" \
  > "$PHASE120_ROOT/narrow-store.log" 2>&1
CASE_STATUS=$?
printf 'narrow_store_status=%s\n' "$CASE_STATUS"
tail -n 80 "$PHASE120_ROOT/narrow-store.log"
python3 experiment/inspect_l3_workflow.py \
  --root "$PHASE120_ROOT/narrow-store" --audit \
  --output "$PHASE120_ROOT/narrow-store-audit.json" \
  > "$PHASE120_ROOT/narrow-store-audit.log" 2>&1
AUDIT_STATUS=$?
printf 'audit_status=%s\n' "$AUDIT_STATUS"
cat "$PHASE120_ROOT/narrow-store-audit.log"
```

Expected: full L0-L3 verified, driver acceptance complete, one independently
verified report, no blockers or inspection errors. If this fails, keep all logs
and audit JSON. A translation/L2 failure is not repaired by waiving its checks.

After the standalone case passes, run the real matrix:

```bash
python3 -m pytest -vv -rs \
  pytools/tests/test_l3_typed_store_production.py \
  --basetemp="$PHASE120_ROOT/typed-production-pytest" \
  --junitxml="$PHASE120_ROOT/typed-production.xml" \
  > "$PHASE120_ROOT/typed-production.log" 2>&1
PRODUCTION_STATUS=$?
printf 'typed_production_status=%s\n' "$PRODUCTION_STATUS"
tail -n 130 "$PHASE120_ROOT/typed-production.log"
```

Expected: 17 passed, no failures/errors/skips. The tests deliberately alter a
capture at the end to check rejection; do not audit their mutated pytest artifacts
again as positive runs. The standalone case above retains untouched evidence.

Finally run the existing four memory production tests with the unchanged legacy
base in `RV2X86_L3_TRACE_BACKEND` to verify compatibility. For a selected mechanism
configuration, `memory` may point at the new wrapper. Other Phase119 full-package-
pinned atomic/fence/LRSC wrappers become stale after these source changes and
require fresh calibration before combined acceptance. Do not reuse a stale
selection or edit its identities. Control/program/legacy base validators must
still perform their own original checks.

Only after the new production route passes should a fresh full-corpus run be
used to measure remaining coverage; the Phase100 report counts are historical.
