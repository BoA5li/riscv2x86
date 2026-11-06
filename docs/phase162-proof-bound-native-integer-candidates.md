# Phase162: proof-bound native integer candidates and captured test entry metadata

Base commit: `28beddfa1606792fbc0fca0f222e46f4b28c75cd` (Phase161).

This revision goes beyond inventory: it generates target preprocessed C and
source/target objects for a finite proved local integer domain. It does NOT
complete the six outstanding whole-program/macro requirements. Do not report a
candidate-generation exit code as GMP translation acceptance or L0--L3 success.
Existing production proof and acceptance gates are unchanged.

## Implemented

* A dedicated, explicit native-input candidate entry point consumes validated
  binding bundles. It independently replays the input binding first. It never
  re-preprocesses the original C with Clang, spoofs preprocessing equality or
  modifies an original source/header. The legacy direct-source entry is separate.
* The route materializes operands with the existing assembler materializer,
  invokes the captured RV64 compiler to assemble the fragment, and independently
  decodes the resulting four-byte word. It joins actual rd/rs1/rs2 to the
  materializer's operand bindings. Names, macro locations and mnemonic strings
  do not select the semantic rule. Extra instructions, relocations, allocated
  sections, source assembler directives/labels and unbound registers fail closed.
* The current rule is a nonvolatile unsigned-64, single-output/two-input register
  MULHU with no clobbers, symbols, control transfer or environment obligation.
  The full GNU relation is checked, including the permitted commutative input
  pair. Pure, repeatable declaration carriers are required; memory expressions,
  volatile effects, unsupported constraints/types and other instruction families
  are not silently accepted.
* The generated statement uses explicitly unsigned 128-bit multiplication,
  shift and truncation. A fresh target Clang AST is normalized with actual type
  conversions and declaration identities. The normal form must exactly equal
  the decoded source operation's expression. The identity is for all unsigned
  64-bit operands under the stated C/toolchain contracts, not inferred from
  numerical test samples. Multi-declarator identifier locations are kept distinct.
* Source and target code-generation compilers also compile in-scope static type
  witnesses for each operand (integer class, width and unsignedness). Inspection
  AST type facts alone do not authorize a mismatched backend type. All source
  asm replacements are hash-bound, disjoint and leave other bytes unchanged.
* Every reachable builtin is accounted for. Integer-literal constant queries
  have source AND target compiler static witnesses for constant classification,
  type width, signedness and value. Values are not a lookup list. Runtime queries
  remain unsupported. Branch-expectation calls are preserved, with their pure
  typed predicate/conversion/hint contract checked against the target AST.
  Unknown or side-effecting forms and unproved implementation-defined signed
  conversions stop this route. Physical branch-prediction equivalence is not
  claimed. Other external/indirect-call obligations are not discharged here.
* Both original frozen CPP and candidate CPP are compiled to real objects. Source
  options are preserved; only the explicit target architecture/ABI retargeting
  projection and captured plain-char model adaptation are used. Integer data
  models must match. The inspection-only projection can omit the recorded
  excess-precision option unsupported by older Clang, but no FP equivalence or
  whole-function proof is granted. Unsupported target compiler diagnostics fail.
* Independent candidate audit reruns binding, decoding, target parsing, witnesses
  and builds in a new directory. It compares proof content, command recipes,
  artifact bytes and all claim flags. Rehashing a false acceptance flag or editing
  an object/AST/assembly/witness/candidate does not approve it.
* Explicit test-entry metadata selection replays compiler-exec capture, verifies
  the captured output's digest, resolved path and ELF header, and reads the ELF
  interpreter, DT_NEEDED and RPATH/RUNPATH. It does not select tests by basename
  or claim that a listed library was actually loaded. No test executes in this
  metadata command.

## Still not implemented

* Whole-function C/data/memory/control composition and external effect summaries.
* Original GCC macro expansion/argument provenance and authorized original-header
  rewriting. CPP byte offsets are never original-source edit permissions.
* Eight-parameter object/ABI/input/output contracts and observed instance coverage.
* Source/target library graph retargeting, runtime loader closure, linked execution
  and full native-route L1--L3/independent program acceptance integration.

`localIntegerProofComplete`, `compilerOperandTypeWitnessesComplete`,
`derivedTargetMaterializationComplete` and `objectBuildsComplete` refer to their
bounded scopes. `wholeFunctionCompositionVerified`, `formalEntryVerified`,
`semanticApproval` and `productionAcceptanceComplete` remain false. The local
statement proof assumes the surrounding C execution/object domain is legal; it
neither ignores nor proves the `mp[0]` initializer and low-product consumers.

A candidate may preserve that surrounding C text while still requiring these
program contracts. Linking an ordinary native x86 GMP library and passing an
upstream test is not proof that this translator generated or validated it.

## Host validation

Keep existing receipts at their hash-bound paths. Use the existing venv and
frontend. No frontend rebuild is required by these Python-only changes.
Use a new worktree/output directory; never delete or overwrite older evidence.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${BIND_ROOT:?}" "${PHASE161_ROOT:?}"
git -C "$REPO" fetch origin phase162-proof-bound-native-integer-candidates
export PHASE162_TOOLING="$PREP_ROOT/tooling-phase162"
git -C "$REPO" worktree add --detach "$PHASE162_TOOLING" origin/phase162-proof-bound-native-integer-candidates
export PHASE162_ROOT="$(mktemp -d "$BIND_ROOT/phase162-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
export NATIVE_BUNDLE="$PHASE161_ROOT/fresh/binding-bundle.json"
export ENTRY_RECORDS="$PHASE161_ROOT/official-test-records.json"
export RV2X86_NATIVE_TARGET_CC=/usr/bin/x86_64-linux-gnu-gcc-7
printf 'PHASE162_ROOT=%s\n' "$PHASE162_ROOT"
```

1. Focused regression, including the real compiler route. Supply the already
   used RV2X86_SYSTEM_CLANG, RV2X86_TEST_RISCV_CC and RISCV2X86_TEST_FRONTEND.
   A skipped real integration does not count as its validation.

```bash
bash -e <<'TEST'
: "${PHASE162_TOOLING:?}" "${PHASE162_ROOT:?}"
export PYTHONPATH="$PHASE162_TOOLING/pytools"
python3 -m pytest -q -rs \
  "$PHASE162_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE162_TOOLING/pytools/tests/test_native_test_entry.py" \
  "$PHASE162_TOOLING/pytools/tests/test_native_call_obligations.py" \
  "$PHASE162_TOOLING/pytools/tests/test_native_instance_binding.py" \
  "$PHASE162_TOOLING/pytools/tests/test_project_native_input.py" \
  --basetemp="$PHASE162_ROOT/pytest" --junitxml="$PHASE162_ROOT/focused.xml" \
  > "$PHASE162_ROOT/focused.log" 2>&1
TEST
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
cat "$PHASE162_ROOT/focused.log"
```

2. Bind the official test output. The known captured stage has one link action;
   assert this explicitly rather than guessing a binary from its name. If more
   links are present, select the intended recorded identity after inspection.

```bash
bash -e <<'ENTRY'
: "${PHASE162_TOOLING:?}" "${PHASE162_ROOT:?}" "${ENTRY_RECORDS:?}"
export PYTHONPATH="$PHASE162_TOOLING/pytools"
ENTRY_ACTION="$(python3 - <<'PY'
import json,os
with open(os.environ['ENTRY_RECORDS']) as stream:
    data=json.load(stream)
links=[a for a in data['actions'] if a['kind']=='link']
if len(links)!=1:
    raise SystemExit('Select one recorded link action explicitly; count='+str(len(links)))
print(links[0]['actionIdentity'])
PY
)"
python3 "$PHASE162_TOOLING/experiment/translate_native_project.py" entry-metadata \
  --records "$ENTRY_RECORDS" --action-identity "$ENTRY_ACTION" \
  --output "$PHASE162_ROOT/entry.json" > "$PHASE162_ROOT/entry.log" 2>&1
python3 "$PHASE162_TOOLING/experiment/translate_native_project.py" replay-entry-metadata \
  --input "$PHASE162_ROOT/entry.json" > "$PHASE162_ROOT/entry-replay.log" 2>&1
ENTRY
ENTRY_STATUS=$?
printf 'entry_status=%s\n' "$ENTRY_STATUS"
cat "$PHASE162_ROOT/entry.log" "$PHASE162_ROOT/entry-replay.log"
```

3. Generate actual candidate C and source/target objects; then independently audit.
   These commands are candidate-generation tests, not the old batch L0--L3
   command. Do not feed candidate.json to the legacy evaluation-result parser.

```bash
bash -e <<'CANDIDATE'
: "${PHASE162_TOOLING:?}" "${PHASE162_ROOT:?}" "${NATIVE_BUNDLE:?}" "${RV2X86_NATIVE_TARGET_CC:?}"
export PYTHONPATH="$PHASE162_TOOLING/pytools"
test -f "$NATIVE_BUNDLE"
python3 "$PHASE162_TOOLING/experiment/translate_native_project.py" create \
  --bundle "$NATIVE_BUNDLE" --target-compiler "$RV2X86_NATIVE_TARGET_CC" \
  --output "$PHASE162_ROOT/candidate" --timeout-seconds 300 \
  > "$PHASE162_ROOT/candidate.log" 2>&1
python3 "$PHASE162_TOOLING/experiment/translate_native_project.py" audit \
  --candidate "$PHASE162_ROOT/candidate/candidate.json" \
  --output "$PHASE162_ROOT/independent-audit" --timeout-seconds 300 \
  > "$PHASE162_ROOT/audit.log" 2>&1
CANDIDATE
CANDIDATE_STATUS=$?
printf 'candidate_status=%s\n' "$CANDIDATE_STATUS"
cat "$PHASE162_ROOT/candidate.log" "$PHASE162_ROOT/audit.log"
```

For the currently bound one-asm GMP unit, success should produce `candidate.i`,
`source.o`, `target.o`, witness files, target AST and candidate.json, followed by
`nativeCandidateIndependentAuditComplete=true`. It should NOT claim whole-program
or production success. A stage failure leaves run-status.json and command stderr;
there is no complete manifest. Keep it; do not remove blockers or force approval.

4. Return focused.log, entry.log, entry-replay.log, candidate.log and audit.log.
   On failure also provide the failing run-status.json and corresponding *.stderr.
   entry.json supplies the interpreter and dynamic dependency facts needed to
   choose a source runtime prefix without guessing. No all-corpus rerun is needed.

## Original macro exporter prerequisite information

The remaining macro route needs a compiler-owned expansion exporter, not more
copies of the current Clang AST. Before implementing a GCC plugin adapter,
obtain the matching plugin-header availability. These commands only inspect;
they do not install packages or modify the compiler.

```bash
: "${RV2X86_TEST_RISCV_CC:?}" "${PHASE162_ROOT:?}"
"$RV2X86_TEST_RISCV_CC" -v > "$PHASE162_ROOT/source-compiler-version.txt" 2>&1
"$RV2X86_TEST_RISCV_CC" -print-file-name=plugin > "$PHASE162_ROOT/source-plugin-directory.txt"
python3 - <<'PY'
import os,json
from pathlib import Path
root=Path(os.environ['PHASE162_ROOT'])
requested=(root/'source-plugin-directory.txt').read_text().strip()
p=Path(requested)
print(json.dumps({'pluginDirectoryReported':requested,'absolute':p.is_absolute(),
 'headers':{name:p.is_absolute() and (p/'include'/name).is_file()
            for name in ['gcc-plugin.h','plugin-version.h','cpplib.h','line-map.h']}}))
PY
```

This is evidence for the still-unimplemented source macro adapter, not a reason
for further changing source preprocessing or weakening proof requirements.

## Implementation validation

Scoped regression: 366 passed, 10 skipped. The missing integrations require
Clang, real RV64 GCC and/or the built frontend. Native GCC executes the generated
128-bit C expression regression and operand type witnesses. Protocol tests use
explicitly synthetic cross-ELF/AST fixtures; these are not advertised as real
cross-ISA execution. A separate unmocked compiler/frontend/candidate/audit test
is included for the host environment.

Negative coverage includes signed/volatile/computed operands, memory/control
constraints, similar opcodes and extra instructions, wrong machine register
bindings, unsafe signed conversions, changed shifts, changed input slices,
overlapping edits, declaration identity collisions, changed object bytes,
rehashed program-acceptance claims, stale entry artifacts and host-ISA images.
