# Phase159: native preprocessed analysis input

Base: Phase158, `9281e154bfbc223cb00bcb83942dedf6950e4cfa`.
Branch: `phase159-native-preprocessed-analysis-input`.

## Problem and resulting behavior

The native GCC and inspection Clang can expand the same original C differently.
Compiler built-ins and header feature tests affect declarations and attributes,
even with matching include search paths. Literal spellings can differ too.
The original strict token comparison correctly blocks this difference; it is
not an arithmetic translation failure. Deleting attributes, substituting macro
values or impersonating GCC in Clang would not close the input boundary.

An explicit `capture --mode native-input` now runs the original native CPP
recipe and feeds its unchanged bytes to Clang using `-x cpp-output` and stdin.
The original `-D/-U`, include paths and forced includes are not applied a second
time. Semantic inspection options retain their order. Unknown or ignored
attributes and other Clang warnings are errors. No warning suppression or
literal normalization is introduced. Native GCC frontend `cc1`, native driver,
inspection compiler, source and dependencies are content-bound; native driver
expansion, specs, macro definitions and effective macro outputs are preserved.
The first version requires a native GCC with a resolvable `cc1` and `-dumpspecs`.
Other native drivers need an explicit tool identity adapter, not guessed flags.

Native and inspection integer data models must match, including plain-char,
wchar, endian and language-version facts. This is a limited acquisition check,
not complete ABI or floating-point equivalence. Flags whose effects require
additional contracts retain those obligations.

The raw AST and a whole emitted-tree asm/attribute inventory are saved. All AST
fields, attributes, types, literal values and reference relationships participate
in independent replay. Only known process-local AST reference fields undergo
bijective alpha-renaming; hexadecimal literals and arbitrary fields are not
stripped. Raw AST pointer bytes are retained but are not expected to match
across processes. Other command stdout and stderr bytes remain exact.

The old exact mode remains the default and still refuses mismatching tokens.
Its failure now reports `preprocessing-comparison` rather than the last native
dependency command. Old receipts and old corpus records are never upgraded.

## What this does not authorize

This is a new analysis-input contract, not a production translation route.
`nativeInputConsumed` means Clang consumed native CPP bytes. It does not mean
the compiler retained every asm in optimized machine code or that GCC and Clang
interpret every extension identically. Unsupported constructs fail, rather than
being changed or ignored.

The inventory uses **physical preprocessed-input locations**. Original macro
argument provenance, expansion/source edit binding, side-effect contracts and
safe target materialization remain separate requirements. Clang presumed line
locations are not silently converted into original-source byte edit ranges.
The old discovery ledger is selection evidence only; `originalDiscoveryRebound`
stays false. Counts from these two AST domains are not automatically equated.

`compilerEquivalenceVerified`, `sourceInstanceBindingComplete`,
`editAuthorizationComplete`, `semanticApproval` and
`productionAcceptanceComplete` remain false. The old source/target production
compatibility gates are unchanged and do not accept this receipt as a bypass.
The target still needs its own header/type/ABI and translation contracts.
In particular, a successful acquisition is not GMP L0--L3 acceptance. Do not
launch the whole corpus through expensive L3 based on this acquisition alone.

## Update without changing the original checkout or earlier results

Keep the Phase156/158 tooling and evidence directories: frozen records bind
those paths. Reuse `REPO`, `PREP_ROOT`, `CORPUS_CHECK_ROOT` and `MACRO_ROOT` from
the previous run. `MACRO_ROOT` must contain the old `eligibility.json` and
`native-first/preflight.json`, including the original failed comparison.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${CORPUS_CHECK_ROOT:?}" "${MACRO_ROOT:?}"
cd "$REPO"
git fetch origin phase159-native-preprocessed-analysis-input
export INPUT_TOOLING="$PREP_ROOT/tooling-phase159"
git worktree add --detach "$INPUT_TOOLING" origin/phase159-native-preprocessed-analysis-input
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$INPUT_TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export RV2X86_TEST_RISCV_CC=/usr/bin/riscv64-linux-gnu-gcc-7
export INPUT_CHECK_ROOT="$(mktemp -d "$CORPUS_CHECK_ROOT/native-input-phase159-XXXXXX")"
export MACRO_CONTEXT="$(python3 -c 'import json,os;from pathlib import Path;p=Path(os.environ["MACRO_ROOT"])/"native-first/preflight.json";print(json.loads(p.read_text())["contextIdentity"])')"
printf 'INPUT_CHECK_ROOT=%s\n' "$INPUT_CHECK_ROOT"
git -C "$INPUT_TOOLING" rev-parse HEAD
```

Run the worktree creation once. Existing destinations require review; do not
delete them or use reset/clean to force these commands to succeed.

## 1. Focused regressions with real host tools

```bash
python3 -m pytest -q -rs \
  "$INPUT_TOOLING/pytools/tests/test_project_native_input.py" \
  "$INPUT_TOOLING/pytools/tests/test_project_macro_preflight.py" \
  "$INPUT_TOOLING/pytools/tests/test_project_build_contract.py" \
  "$INPUT_TOOLING/pytools/tests/test_project_type_replay.py" \
  "$INPUT_TOOLING/pytools/tests/test_project_activation_inventory.py" \
  "$INPUT_TOOLING/pytools/tests/test_project_instance_eligibility.py" \
  "$INPUT_TOOLING/pytools/tests/test_gnu_operand_relations.py" \
  --basetemp="$INPUT_CHECK_ROOT/pytest" \
  --junitxml="$INPUT_CHECK_ROOT/focused.xml" \
  > "$INPUT_CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
cat "$INPUT_CHECK_ROOT/focused.log"
```

Require all tests to pass. The real native/Clang and real RISC-V/Clang tests
must run on the configured host; a missing-tool skip is not integration proof.
If this step fails, retain logs before proceeding.

## 2. Same failing context, native-input capture and independent replay

```bash
bash -e <<'STAGES'
python3 "$INPUT_TOOLING/experiment/preflight_project_macros.py" capture \
  --mode native-input --eligibility "$MACRO_ROOT/eligibility.json" \
  --context-identity "$MACRO_CONTEXT" --timeout-seconds 300 \
  --output "$INPUT_CHECK_ROOT/native-first" \
  > "$INPUT_CHECK_ROOT/native-first.log" 2>&1
python3 "$INPUT_TOOLING/experiment/preflight_project_macros.py" replay \
  --eligibility "$MACRO_ROOT/eligibility.json" \
  --receipt "$INPUT_CHECK_ROOT/native-first/preflight.json" \
  --timeout-seconds 300 --output "$INPUT_CHECK_ROOT/native-replay" \
  > "$INPUT_CHECK_ROOT/native-replay.log" 2>&1
STAGES
INPUT_STATUS=$?
printf 'native_input_status=%s\n' "$INPUT_STATUS"
for NAME in native-first.log native-replay.log native-first/run-status.json \
  native-first/native-analysis/run-status.json; do
  if test -f "$INPUT_CHECK_ROOT/$NAME"; then cat "$INPUT_CHECK_ROOT/$NAME"; fi
done
```

Expected: capture reports `nativeInputConsumed: true` and
`inspectionParsingComplete: true`; independent replay reports
`nativeInputReplayComplete: true`. Production/semantic claims stay false.
The failed Phase158 exact comparison is still valid historical evidence.
It is not relabeled as a preprocessing match.

If Clang cannot interpret native CPP constructs or attributes, the exact
failed command, stderr and return code are preserved under `native-analysis`.
Provide that stderr together with both run status files. Do not remove the
attribute, change the header, disable fortify or suppress the diagnostic.

## 3. Inspect native-domain occurrences before expanding the experiment

```bash
python3 - <<'PY'
import json, os
from collections import Counter
from pathlib import Path
root = Path(os.environ['INPUT_CHECK_ROOT'])/'native-first/native-analysis'
receipt = json.loads((root/'native-input.json').read_text())
inventory = json.loads(Path(receipt['inventoryPath']).read_text())
print('analysisInputIdentity', receipt['analysisInputIdentity'])
print('instances', len(inventory['instances']))
print('attributes', dict(Counter(r['kind'] for r in inventory['attributes'])))
for key in ('sourceInstanceBindingComplete', 'editAuthorizationComplete',
            'endToEndEligibilityAssessed', 'semanticApproval',
            'productionAcceptanceComplete'):
    print(key, inventory[key])
PY
```

First review this same preselected context, not a success-selected replacement.
Native-source instance binding and the remaining Phase157 B--G macro/call/target
contracts must close before formal GMP translation/evaluation. This branch does
not claim those broader requirements have been implemented.

## Validation scope

Protocol tests execute a real host GCC and simulate inspection responses;
they cover exact stdin bytes, preserved literals/attributes, model mismatch,
reference-edge mutation, source/dependency changes, timeouts, real exit codes,
artifact tampering, rehashed approval forgery and exclusive output directories.
Separate unmocked tests exercise host GCC/Clang and RISC-V GCC/Clang acquisition
and replay. Their missing-tool skips must be reported, not counted as passes.
No original corpus source, frozen filter, translation proof, runtime helper,
L0--L3 comparator or production acceptance rule is relaxed.

Local final regression: **408 passed, 6 skipped** in 68.89 seconds. This includes
the project acquisition/context/contract suites, native-input adversarial tests,
CPP lexer and operand suites, and frozen corpus/filter/generated-suite tests.
All six skips require real Clang and/or the RISC-V cross compiler, unavailable
in this implementation environment. The two new unmocked integrations must run
on the experiment host before claiming this route works with its GCC/Clang pair.
