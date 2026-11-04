# Phase149: preprocessing and operand type integrity

Base: Phase148 remote commit `f064947679431b47e6d0e56e5832452167d55462`.

This is a correctness repair and type acquisition extension. **The full real-project
translation/evaluation plan is not complete.** Passing the checks below does not
establish production acceptance for musl floating routines, macro/header entries,
or the whole corpus. No filtering or original corpus bytes change in this branch.

## Implemented behavior

1. Replace the over-escaped preprocessing token regex with a spelling-preserving
   scanner. Multi-character punctuators use maximal munch; prefixed/escaped
   literals, preprocessing numbers, identifiers and GNU `$` identifiers keep
   their token boundaries. `a++` cannot compare equal to `a + +`; literal escape
   sequences are not interpreted or normalized. Unknown or malformed input is
   rejected rather than silently discarded.
2. Preserve directive line endings. `#pragma pack(1)` followed by a declaration
   is not equivalent to a single directive containing that declaration. Ordinary
   C layout differences remain irrelevant. Both `#` and `%:` directive prefixes
   retain this boundary; a directive at EOF receives the same boundary as one
   ending with a newline.
3. Both source-inspector and source-target preprocessing receipts use version 2
   and include the tokenization algorithm version. Existing version 1 receipts
   must be regenerated and replayed. Merely rehashing an old receipt cannot make
   it pass independent acquisition.
4. The linked Clang frontend exports real floating operand types from ASTContext
   rather than returning an empty type. Binary32/binary64 format recognition uses
   Clang's actual `fltSemantics`, not a type-name or instruction-text match. Other
   real floating formats remain `unmodelled`.
5. Floating operands have a separate `clang-operand-type.v2` schema. JSON output,
   input validation and Python reading retain format, width, alignment,
   qualifiers and expression properties. Integer/pointer V1 serialization is
   unchanged; integer-only consumers continue to reject floating V2. These facts
   do not grant translation, ABI, proof, or execution authority.

## Tests and their limits

The added tests cover maximal-munch counterexamples, escaped literals, directive
boundaries, native GCC preprocessing, actual compiled C++ report serialization,
strict JSON types, old receipt rejection, and floating/integer class isolation.
Four additional tests invoke a rebuilt real frontend on binary32/binary64 fabs
and sqrt operands. They assert compiler facts only, without claiming those
operations have production translation routes.

Local checks cannot replace a full LLVM10 frontend build or calibrated RV64 and
x86 execution. A skip due to an absent frontend is an unperformed integration
check, not a pass. Do not reuse a previous frontend binary: this branch changes
C++ frontend and report reader code.

Local checks: 455 passed and 10 skipped in the context/route suite; 92 passed
in the corpus suite. The skipped checks require real Clang or the rebuilt
frontend, which are absent in the current workspace. Native GCC preprocessing
and native C++ report serialization ran successfully. All 391 package Python
files parsed; patch whitespace checks passed. No full frontend build, RV64
execution, new FP proof or whole-corpus acceptance is claimed.

## Host verification

Run from the repository root in the existing `.venv-l2`. Keep original project
sources, native build logs and corpus inventories unchanged.

```bash
export REPO="$PWD"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1
export PATH="/usr/lib/llvm-10/bin:$PATH"
export RV2X86_SYSTEM_CLANG="/usr/lib/llvm-10/bin/clang"
export CHECK_ROOT="$(mktemp -d "$REPO/experiment/results/phase149-XXXXXX")"
git rev-parse HEAD > "$CHECK_ROOT/git-head.txt"

cmake -S "$REPO" -B "$REPO/build-phase149" \
  -DLLVM_DIR=/usr/lib/llvm-10/lib/cmake/llvm \
  -DClang_DIR=/usr/lib/llvm-10/lib/cmake/clang \
  > "$CHECK_ROOT/configure.log" 2>&1
```

Check the configure command's exit code before building; stop and retain its log
if it failed. Then run:

```bash
cmake --build "$REPO/build-phase149" --parallel 4 \
  > "$CHECK_ROOT/build.log" 2>&1
```

After a successful build:

```bash
export RISCV2X86_TEST_FRONTEND="$REPO/build-phase149/riscv2x86"
python3 -m pytest -q -rs \
  pytools/tests/test_c_preprocessing_tokens.py \
  pytools/tests/test_compiler_floating_type.py \
  pytools/tests/test_project_build_contract.py \
  pytools/tests/test_project_build_records.py \
  pytools/tests/test_project_archive_acquisition.py \
  pytools/tests/test_compiler_function_types.py \
  pytools/tests/test_compiler_call_dependencies.py \
  pytools/tests/test_l3_joint_program.py \
  pytools/tests/test_source_operand_coverage.py \
  pytools/tests/test_production_route_authority.py \
  pytools/tests/test_atomic_expression_consumer.py \
  pytools/tests/test_l3_protocol_resolution.py \
  pytools/tests/test_l3_lrsc_persistence.py \
  --junitxml="$CHECK_ROOT/regression.xml" \
  > "$CHECK_ROOT/regression.log" 2>&1
REGRESSION_STATUS=$?
printf 'regression_status=%s\n' "$REGRESSION_STATUS"
tail -n 60 "$CHECK_ROOT/regression.log"
```

The four `test_real_clang_frontend_exports_floating_operands` parameter cases
must pass on the rebuilt host frontend. Any skip needs an explicit missing-tool
explanation. Preserve failures; do not alter the tests or source inputs to force
acceptance.

Check immutable corpus selection separately:

```bash
python3 -m pytest -q -rs \
  pytools/tests/test_real_project_corpus.py \
  pytools/tests/test_whole_project_corpus.py \
  pytools/tests/test_filter_rv64_c_corpus.py \
  --junitxml="$CHECK_ROOT/corpus.xml" \
  > "$CHECK_ROOT/corpus.log" 2>&1
CORPUS_STATUS=$?
printf 'corpus_status=%s\n' "$CORPUS_STATUS"
tail -n 40 "$CHECK_ROOT/corpus.log"
```

These are revision checks, not the deferred final full-corpus experiment.
Project receipts from before this branch must be reacquired under the same
selected variant and original options; do not change options to evade a mismatch.
The formal project invocation remains documented in Phase148.

## Outstanding implementation, not additional host-data requests

| Remaining capability | Required closure before claiming support |
|---|---|
| Floating operations | Source semantics, NaN/signaling/rounding/exception-state contracts, correct target refinement, L2 proof, actual machine attribution, FP-state L3 observations and independent audit |
| Floating/mixed ABI and outputs | Compiler-derived source/target ABI, typed harnesses, register/state observations, return conversion and all observable outputs |
| GCC/Clang differences | Proven feature-specific compatibility or native-preprocessed AST acquisition with exact source-expansion mapping; no token deletion/normalization |
| Macro and header entries | Real TU instantiation, expansion/spelling provenance, safe edits, entry adapters and complete reachable effects |
| External/runtime/environment closure | Explicit legitimate call inputs, reachable callees, runtime/link/TLS/syscall effects and applicable observation authority |
| Final corpus results | Fixed denominator/configuration matrix, all planned variants retained, actual toolchains/backends, L0–L3 plus fresh independent audit |

The available host details suffice to continue implementing these capabilities.
Their absence is not repaired by requesting another identical host inventory or
by calling conservative blockers a completed coverage extension.
