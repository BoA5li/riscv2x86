# Phase160: native instance and call context binding

Base: Phase159, `bfbe07e3f63f624511f71fa08660967265f2c31f`.
Branch: `phase160-native-instance-and-call-context-binding`.

**This is not completion of the entire GMP translation/evaluation plan.** It
implements physical-domain instance/operand binding and collects the missing
compiler/call/build facts. Instruction/C-context composition proofs, original
macro provenance, authorized target generation, general call/object/link
closure and production L0--L3 integration are still required. Additional logs
alone cannot implement those missing contracts. No final acceptance is granted.

## Implemented behavior

`compiler_native_instance_binding.derive()` joins each emitted native-input
`GCCAsmStmt` to the existing Clang Tooling frontend's structured export using
exact physical byte ranges. Every occurrence must appear exactly once in both
views. It does not search for asm text or use project, macro, function, file or
line names to select an implementation. Unicode offsets remain byte offsets.
Other asm node kinds fail explicitly rather than disappearing from coverage.

For each occurrence it retains the complete frontend fragment, compiler types,
raw template, constraints/clobbers, operand expression ASTs, declaration
references, surrounding AST ancestry and nearest compound statement. Statement
and operand byte slices must match the compiler-selected ranges. An asm range
cannot absorb a neighboring C statement. Only trivia and a terminating
semicolon may extend the compiler AST range. No original-source edit is made.

The finite typed-operand validators and whole-asm GNU operand relation parser
are consumed. Unsupported type/constraint contracts remain explicit blockers
without removing their occurrences. `%r` is retained as a relation requiring a
semantic permutation proof. Merely recognizing the modifier does not approve
commutativity, operand expression reordering or a helper call.

`call_contexts()` exports function declarations, parameters, body AST paths,
syntax kinds, direct call targets and asm-owning function contexts. Definition
joins follow declaration IDs and redeclaration chains, not matching names.
External/indirect calls and recursion retain unresolved obligations. Unrelated
functions remain in the inventory; global startup/effect candidates are retained.
Resolved static call targets never imply effects, object validity or ABI closure.

`project_native_binding.acquire()` independently replays the Phase159 input
before running the existing C++ frontend with `--analysis-only`,
`--no-builtin-rules` and `-x cpp-output` against the exact stored CPP artifact.
All commands, input bytes, tool/report/output identities are bound. Output
directories are exclusive; accidental top-level destinations caused by an empty
shell prefix are rejected. A compiler failure preserves its true exit status,
stderr and partial report and produces no complete binding bundle.

`replay()` repeats input acquisition and compiler export in a separate directory,
then compares the complete binding/context inventories. Stored-evidence
validation independently rederives these inventories and checks the original
and fresh native input evidence using the same Phase159 comparison policy.
Rehashed edits to type facts, commands, inventories and approval flags fail.
Inspection of saved evidence is labeled separately from fresh replay.

`build-basis` checks a captured build-record inventory and binds the selected
native compile action. It retains link/archive observations and unresolved
records; a command classified as `link` is not automatically an executable test
entry. No captured command is executed by this inspection operation.

## Claims and domains

| Field | Meaning |
| --- | --- |
| `derivedInputInstanceBindingComplete=true` | All recognized emitted AST occurrences are joined to compiler operand exports in the frozen CPP byte domain |
| `typedOperandContractsComplete` | Per occurrence, exported types pass the existing finite type validators; still not a translation proof |
| `originalSourceInstanceBindingComplete=false` | No complete original macro definition/argument/expansion binding |
| `editAuthorizationComplete=false` | No source or target rewrite is approved |
| `formalEvaluationEntrySelected=false` | Owning functions are candidates, not authorized executable entries |
| `effectClosureVerified=false`, `abiClosureVerified=false` | Static calls and type spellings do not prove these properties |
| `semanticApproval=false`, `productionAcceptanceComplete=false` | No GMP L0--L3 acceptance |

No production route consumes this bundle as approval. Existing semantic,
source-range, target preprocessing, build and independent audit gates remain
unchanged. A synthetic wrapper or the helper's unit test cannot stand in for a
real GMP function or project evaluation. Frozen corpus sources and denominators
are unchanged.

## Host workflow

Keep existing source/build/tooling/result directories. Phase159 receipts contain
their paths and digests; do not move or rewrite them. Set `NATIVE_INPUT_RECEIPT`
to the **existing successful** `native-analysis/native-input.json`, including
the previous top-level result if that is where the successful run was saved.
Do not set it to an empty newly created results directory.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${CORPUS_CHECK_ROOT:?}"
: "${NATIVE_INPUT_RECEIPT:?set the existing successful native-input.json path}"
test -f "$NATIVE_INPUT_RECEIPT"
cd "$REPO"
git fetch origin phase160-native-instance-and-call-context-binding
export BIND_TOOLING="$PREP_ROOT/tooling-phase160"
git worktree add --detach "$BIND_TOOLING" origin/phase160-native-instance-and-call-context-binding
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$BIND_TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export RV2X86_TEST_RISCV_CC=/usr/bin/riscv64-linux-gnu-gcc-7
export RISCV2X86_TEST_FRONTEND="$REPO/build/riscv2x86"
test -x "$RISCV2X86_TEST_FRONTEND"
BIND_ROOT="$(mktemp -d "$CORPUS_CHECK_ROOT/native-binding-phase160-XXXXXX")"
export BIND_ROOT
: "${BIND_ROOT:?result directory creation failed}"
printf 'BIND_ROOT=%s\n' "$BIND_ROOT"
git -C "$BIND_TOOLING" rev-parse HEAD
```

The frontend sources are unchanged in this branch; a compatible existing binary
can export the required fields. If the real integration fails because the binary
does not implement that export, preserve the error rather than weakening checks.
Do not repeat worktree creation over an existing directory.

### 1. Regressions, including real tool integrations

```bash
bash -e <<'TESTS'
: "${BIND_ROOT:?}" "${BIND_TOOLING:?}"
python3 -m pytest -q -rs \
  "$BIND_TOOLING/pytools/tests/test_native_instance_binding.py" \
  "$BIND_TOOLING/pytools/tests/test_project_native_input.py" \
  "$BIND_TOOLING/pytools/tests/test_project_macro_preflight.py" \
  "$BIND_TOOLING/pytools/tests/test_project_build_contract.py" \
  "$BIND_TOOLING/pytools/tests/test_project_type_replay.py" \
  "$BIND_TOOLING/pytools/tests/test_project_instance_eligibility.py" \
  --basetemp="$BIND_ROOT/pytest" --junitxml="$BIND_ROOT/focused.xml" \
  > "$BIND_ROOT/focused.log" 2>&1
TESTS
BIND_TEST_STATUS=$?
printf 'binding_test_status=%s\n' "$BIND_TEST_STATUS"
cat "$BIND_ROOT/focused.log"
```

Require pass; the real RISC-V/compiler API binding test must run on this host.
Local protocol mocks do not establish that the host frontend matches Clang's
actual JSON AST. A missing-tool skip is not a pass for that obligation.

### 2. Bind the same GMP context and independently replay

```bash
bash -e <<'STAGES'
: "${BIND_ROOT:?}" "${BIND_TOOLING:?}" "${NATIVE_INPUT_RECEIPT:?}" "${RISCV2X86_TEST_FRONTEND:?}"
python3 "$BIND_TOOLING/experiment/preflight_project_macros.py" bind-native \
  --native-input-receipt "$NATIVE_INPUT_RECEIPT" \
  --frontend "$RISCV2X86_TEST_FRONTEND" --output "$BIND_ROOT/first" \
  --timeout-seconds 300 > "$BIND_ROOT/binding.log" 2>&1
python3 "$BIND_TOOLING/experiment/preflight_project_macros.py" replay-bindings \
  --bundle "$BIND_ROOT/first/binding-bundle.json" \
  --output "$BIND_ROOT/replay" --timeout-seconds 300 \
  > "$BIND_ROOT/binding-replay.log" 2>&1
python3 "$BIND_TOOLING/experiment/preflight_project_macros.py" inspect-bindings \
  --bundle "$BIND_ROOT/first/binding-bundle.json" --include-context --limit 12 \
  > "$BIND_ROOT/binding-details.txt" 2>&1
STAGES
BIND_STATUS=$?
printf 'native_binding_status=%s\n' "$BIND_STATUS"
for NAME in binding.log binding-replay.log binding-details.txt first/run-status.json; do
  if test -f "$BIND_ROOT/$NAME"; then cat "$BIND_ROOT/$NAME"; fi
done
```

Expected for this domain: exact occurrence coverage, typed operands and GNU
relation facts retained, fresh binding replay complete. Inspect the actual count;
do not hardcode an expected one occurrence into implementation or approval.
Original macro/edit/semantic/production claims stay false.

On failure return `first/run-status.json`, `binding.log` and
`first/frontend.stderr` when present. Do not patch the official source, discard
an occurrence, clear a clobber or suppress a frontend diagnostic to proceed.

### 3. Existing build and remaining entry evidence

Set `GMP_BUILD_RECORDS` to the captured GMP `records.json` used for the current
context, not a reconstructed compile database or an unrelated build variant.

```bash
bash -e <<'BASIS'
: "${BIND_ROOT:?}" "${BIND_TOOLING:?}"
: "${GMP_BUILD_RECORDS:?set the existing captured GMP records.json path}"
python3 "$BIND_TOOLING/experiment/preflight_project_macros.py" build-basis \
  --bundle "$BIND_ROOT/first/binding-bundle.json" --records "$GMP_BUILD_RECORDS" \
  --output "$BIND_ROOT/build-entry-basis.json" \
  > "$BIND_ROOT/build-entry-basis.log" 2>&1
BASIS
BASIS_STATUS=$?
printf 'build_entry_basis_status=%s\n' "$BASIS_STATUS"
cat "$BIND_ROOT/build-entry-basis.log"
```

Return `focused.log`, `binding-details.txt`, `binding-replay.log` and
`build-entry-basis.log` as text. No archive upload or repeat full corpus discovery
is needed. Function identities, typed signatures, surrounding C AST and unresolved
callee records guide the next proof/ABI implementation. The build basis tells
whether an actual linked test driver has been observed, without guessing one.

For formal execution, the remaining necessary evidence is the selected official
test/API entry and its actual legal input/object requirements, plus source/target
test/library build and link dependencies. Pointer lengths, alias permissions,
initialization/lifetime and required outputs cannot be inferred from a pointer's
type alone. Prefer captured official test drivers or a separately justified call
contract; do not invent a toy wrapper and report whole-project acceptance.

Do not start full-corpus L3 while common proof/materialization/entry contracts
are unresolved. These are implementation obligations, not labels to flip after
an acquisition command returns zero.

## Validation

Tests cover renamed locations and UTF-8 byte offsets, exact coverage, wrong
operands/ranges/roles, missing type/constraint contracts, redeclarations,
recursive calls, command changes, real exit codes, rehashed forgeries and CLI
integration. A separate unmocked test runs RISC-V GCC, Clang, the built C++
frontend and independent replay. The local implementation environment lacks
that real toolchain, so its skip must be reported and completed on the host.

Local final regression: **435 passed, 7 skipped** in 46.37 seconds. This covers
the project acquisition/context/build suites, the new binding tests, native CPP
replay, GNU operand/lexer tests and frozen corpus/filter/generated-suite checks.
The seven skips require real Clang, RISC-V GCC and/or the built frontend; they
are not counted as successful integrations. No real GMP production result is
claimed from the local mock/protocol tests.
