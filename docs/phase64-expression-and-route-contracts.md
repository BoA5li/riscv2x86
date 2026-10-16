# Phase 64: expression ingress and route observation contracts

Base: phase63-cbranch-and-atomic-type-contracts, remote commit
826b8410e699278095b87aee77a9028e9cc3cee4.

## Implemented

* Compiler candidates now preserve a separate, versioned expression-slot
  artifact. It records AST operations, conversions, value category, canonical
  type, source extent, stable declaration references and recursively hashed
  children. Calls, modifying operators and unknown conversions are rejected
  with field-specific reasons. An expression is never given a fake declaration.
* The automatic command joins these expressions with compiler API types and GNU
  output/input/read-write roles **before** legacy declaration closure. A memory
  lvalue therefore remains visible in `fragment.compilerExpressionJoin` even
  when no legacy scalar carrier can represent it. This field survives Python
  fragment/report serialization. It is identity/evaluation authority only;
  `semanticRouteApproved` is deliberately false.
* Numeric/pointer conversions no longer silently alias their source declaration.
  Legacy declaration closure remains conservative. Type-preserving loads need
  explicit cast-kind and equal canonical types. C integer recognition uses an
  exact supported type set instead of substrings such as `long` in `long double`.
* Phase 6D exports a complete supported atomic operation as
  `AtomicReadModifyWrite`, not ordinary `WriteMemory`. Its relation includes
  atomicity, read-modify-write, ordering and result-extension obligations. Atomic
  L2 cannot be closed with an ordinary memory-object sidecar alone.
* A continuation trace reader consumes actual compiler-site-bound exit markers.
  It never predicts exits from predicate inputs or final return values. It
  checks side-specific site maps, sample arity, duplicate exits, ordinal,
  execution/relation bindings and content identities. This API is an observation
  reader, **not** an installed automatic provider or an instrumentation producer.
* Missing automatic asm-goto/atomic observation authority receives an additional
  route-specific materialization reason.

## Deliberately still incomplete

This branch is a prerequisite/safety-contract revision, not completion of the
entire asm-goto/atomic implementation plan. In particular:

1. Expression facts do not prove object offset, bounds, alignment or aliasing.
   A complex expression is preserved, but is not inserted into a declaration-only
   canonical authority under a fabricated declaration ID.
2. The new continuation reader is not yet connected to a compiler-generated,
   semantics-preserving source/target edge instrumentation plan, an automatic
   provider, or a new asm-goto sidecar. The existing `UNKNOWN` gate remains.
3. Atomic expression-aware compiler/decoder/object join, atomic sidecar and a
   dedicated provider remain necessary. A single-thread old/new-value trace is
   insufficient for atomicity or ordering evidence.
4. Machine exits still need an explicit symbol/relocation-to-source-continuation
   proof. A unique frontend label alone is not that proof.

Consequently this branch does **not** claim that original cases 020/030 become
L2 verified. It should be used to validate the prerequisites and collect exact
remaining production slots. No unsupported gate was weakened to meet a count.

## Validation

The implementation has targeted unit, mutation and report-retention tests.
Real frontend tests additionally cover memory lvalues, arithmetic operands and
narrowing casts before legacy closure. Those tests require the real frontend,
Clang 10 and cross tools; a skipped test is not production-chain evidence.

The current development environment lacks Unicorn and z3, preventing a clean
full-suite collection. It also lacks the real RISC-V frontend/toolchain, so no
local generated-suite success is claimed. See the change report for the exact
selected regression counts.

## Local verification without multiline shell conditionals

Run each command separately in the existing terminal. `set +e` avoids an
expected nonzero batch verdict closing the interactive shell.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
source .venv-l2/bin/activate
REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase64-XXXXXX")
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$REPO/experiment/generated-suite"
RUN_STATUS=$?
printf 'runner_status=%s\n' "$RUN_STATUS"
cat "$RESULT_ROOT/run-status.json"
```

The Python runner records commands/statuses, builds before real regression tests,
checks Clang 10, blocks the suite after prerequisite failures and runs the
provider audit after a produced batch. A batch return code of 1 is preserved,
not converted to success. Inspect `summary.json`, `regression.log`,
`generated-suite.log` and `provider-audit.log`. An existing nonempty result
folder is refused rather than overwritten.

For cases 020/030 inspect `fragment.compilerExpressionJoin` and
`fragment.compilerFragmentJoin` in `work/translation-work/raw_report.json`
(and the translated report when produced). Preserve the complete AST expression
slots and first route rejection before implementing further consumers.

Selected final regression: **377 passed, 10 skipped**. Static compilation and
`git diff --check` passed. Full collection reports 13 errors (missing Unicorn,
z3, angr-related dependencies and the legacy `translate_function` import).
An attempted continued run was interrupted; its three observed test failures
were subsequently isolated to `test_assemble`/`test_cfg`, all reporting
`llvm-mc not found in PATH`. This is not a full-regression pass.
