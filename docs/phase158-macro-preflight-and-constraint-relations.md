# Phase158: source-bound macro preflight and whole-asm constraint relations

Base: Phase157, `98c5e3baefcb8c09a5f6a4d23bec965255a227e9`.
Branch: `phase158-macro-preflight-and-constraint-relations`.

## Delivery and explicit limits

This implements executable parts of the Phase157 plan, not the whole A--G
production closure. It does not enable macro translation, authorize edits or
approve arbitrary project calls. Existing production parsers, renderers, proof
checks, target preprocessing checks and acceptance gates are unchanged.

| Plan item | Delivered here | Still required |
|---|---|---|
| A | Reconstructed discovery ledger, occurrence/context preservation, dependency-content-bound definition slices and expansion-token anchors, blockers and replay | Complete eligibility assessment after missing authorities exist |
| B | Real native and inspection preprocessing capture; native definitions/macros, dependency closure checks, exact tokens and independent recapture | Compiler macro definition/argument/expansion graph and native instruction attribution |
| C | Whole-asm commutative input pairs, allowed permutations, retained original constraints and exact replay | Semantic permutation proof and integration with closed operand authority |
| D | Native regression of the existing high-half helper against wide-integer reference | Macro C-shell effects, alias/output ordering and full candidate/L2 consumption |
| E | Read-only source evidence and preserved expanded C artifacts | Authorized macro/expanded-TU editing and proved target adaptation |
| F | Explicit typed-call/object/dependency prerequisites per occurrence | Real caller input-domain, ABI, object and link-graph closure |
| G | Tamper/negative regressions; conservative status propagation | New macro production execution and full independent L0--L3 audit |

These limits are executable flags, not just prose: acquisition and relation
records retain false semantic/production approval, and macro/ABI/edit obligations
remain blockers. This branch must not be reported as completing all Phase157
coverage gaps or as accepting the real project corpus.

## Implemented interfaces

`project_instance_eligibility.acquire()` reconstructs the Phase156 aggregate
from its frozen plan and batch artifacts, compares the entire discovery ledger,
and preserves every occurrence and source/context denominator. Missing or
changed evidence cannot be repaired by deleting records or rehashing labels.

Each source slice requires explicit non-virtual filenames, byte offsets/token
lengths, and a dependency snapshot whose digest matches the actual file. Definition
and expansion-token evidence are separate. A token anchor (often just the macro
name) is never treated as the full invocation or replacement range. Missing
Clang location files remain blocked. AST ordinals are not declared cross-version
source identities. The output is a new ledger; old artifacts are not rewritten.

`gnu_operand_relations.derive(outputs, inputs)` parses the entire operand list,
checks the read-only adjacent commutative pair, tied-output indices and unsupported
modifier/alternative combinations, and records original constraints and allowed
permutations. A `%r` constraint is no longer opaque to this **analysis** interface.
However, `semanticCommutativityProofRequired` is true and semantic approval stays
false. Legacy `parse_riscv_operand()` still rejects `%r`: existing consumers must
not silently discard the new relation before a complete proof consumer exists.

`project_native_macro_preflight.acquire()` validates qualification, selected
report/context and dependencies, then runs original native compiler arguments
and the checked inspection recipe. It captures native `-E -P`, inspection `-E -P`,
native `-E -dD`, native `-E -dM` and dependency scans surrounding acquisition.
Output bytes, stderr, commands, files and tools are bound. Exact preprocessing
tokens are compared without deleting attributes or changing literals. Difference
or compiler failure stops the workflow and preserves its evidence. Native
preprocessing does not prove that an asm reached optimized machine code.

`replay()` checks old artifact digests and independently repeats acquisition in
a new directory. Only new artifact path fields are excluded from comparison;
bytes, compiler commands, dependency/context binding and claims remain exact.
The capsule is not a new translation TU build contract and cannot bypass the
existing target compatibility gate. Expanded source is evidence, not an
approved translation.

## Host workflow: no repeat native build or whole-corpus discovery

Use existing `REPO`, `PREP_ROOT`, `CORPUS_CHECK_ROOT`, `ACT_ROOT`, `ACT_PLAN` and
`LEDGER_FILE` from the completed Phase156 run. Keep the old tooling directory:
old input hashes refer to it. Add the new worktree only once.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${CORPUS_CHECK_ROOT:?}"
: "${ACT_ROOT:?}" "${ACT_PLAN:?}" "${LEDGER_FILE:?}"
cd "$REPO"
git fetch origin phase158-macro-preflight-and-constraint-relations
export MACRO_TOOLING="$PREP_ROOT/tooling-phase158"
git worktree add --detach "$MACRO_TOOLING" origin/phase158-macro-preflight-and-constraint-relations
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$MACRO_TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export MACRO_ROOT="$(mktemp -d "$CORPUS_CHECK_ROOT/macro-preflight-XXXXXX")"
printf 'MACRO_ROOT=%s\n' "$MACRO_ROOT"
```

### 1. Regressions, qualification and qualification replay

```bash
bash -e <<'STAGES'
python3 -m pytest -q -rs \
  "$MACRO_TOOLING/pytools/tests/test_gnu_operand_relations.py" \
  "$MACRO_TOOLING/pytools/tests/test_project_instance_eligibility.py" \
  "$MACRO_TOOLING/pytools/tests/test_project_macro_preflight.py" \
  "$MACRO_TOOLING/pytools/tests/test_gnu_operand_contract.py" \
  "$MACRO_TOOLING/pytools/tests/test_project_activation_inventory.py" \
  --junitxml="$MACRO_ROOT/focused.xml" > "$MACRO_ROOT/focused.log" 2>&1
python3 "$MACRO_TOOLING/experiment/preflight_project_macros.py" eligibility \
  --plan "$ACT_PLAN" --result-root "$ACT_ROOT" --ledger "$LEDGER_FILE" \
  --output "$MACRO_ROOT/eligibility.json" > "$MACRO_ROOT/eligibility.log" 2>&1
python3 "$MACRO_TOOLING/experiment/preflight_project_macros.py" verify-eligibility \
  --input "$MACRO_ROOT/eligibility.json" > "$MACRO_ROOT/eligibility-replay.log" 2>&1
STAGES
QUALIFICATION_STATUS=$?
printf 'qualification_status=%s\n' "$QUALIFICATION_STATUS"
cat "$MACRO_ROOT/focused.log"
for NAME in eligibility.log eligibility-replay.log; do
  if test -f "$MACRO_ROOT/$NAME"; then cat "$MACRO_ROOT/$NAME"; fi
done
```

Expected: counts preserve the existing occurrence ledger; all records remain
blocked on unimplemented macro/semantic/edit/call authorities. A bound source
slice is progress, not a safe-edit claim. A zero CLI exit means that this
qualification report was generated and replayed correctly, not that blockers
were resolved. If discovery reconstruction differs, stop before capture.

### 2. First deterministic native preprocessing capsule and independent repeat

This chooses the first context by stable context identity before any native
capture outcome is known; it is an acquisition smoke test, not representative
sampling for paper results. Both destination directories must be absent.

```bash
export MACRO_CONTEXT="$(python3 -c 'import json,os;d=json.load(open(os.environ["MACRO_ROOT"]+"/eligibility.json"));print(sorted({r["contextIdentity"] for r in d["records"]})[0])')"
bash -e <<'STAGES'
python3 "$MACRO_TOOLING/experiment/preflight_project_macros.py" capture \
  --eligibility "$MACRO_ROOT/eligibility.json" --context-identity "$MACRO_CONTEXT" \
  --output "$MACRO_ROOT/native-first" \
  > "$MACRO_ROOT/native-first.log" 2>&1
python3 "$MACRO_TOOLING/experiment/preflight_project_macros.py" replay \
  --eligibility "$MACRO_ROOT/eligibility.json" \
  --receipt "$MACRO_ROOT/native-first/preflight.json" \
  --output "$MACRO_ROOT/native-replay" \
  > "$MACRO_ROOT/native-replay.log" 2>&1
STAGES
NATIVE_STATUS=$?
printf 'native_preflight_status=%s\n' "$NATIVE_STATUS"
for NAME in native-first.log native-replay.log native-first/run-status.json; do
  if test -f "$MACRO_ROOT/$NAME"; then cat "$MACRO_ROOT/$NAME"; fi
done
```

On token mismatch the complete receipt is preserved in `native-first/preflight.json`;
return its `firstDifference`, token counts and run status. Do not weaken token
comparison to proceed. On compiler failure return the recorded stderr file. On
success, native preprocessing is replayed but edit/ABI/semantic flags stay false.
Do not run every context through expensive L3 while these common prerequisites
are unresolved. Preserve the expanded C/definitions for compiler provenance and
proved adaptation work; do not manually patch them and call it corpus acceptance.

## Local checks

New tests cover whole-asm modifiers/permutations, old-parser conservatism,
rehashed tampering and missing records, preserved variants/denominators,
explicit source locations, file changes, exact CPP differences, real exit codes,
timeouts, artifact mutation and independent acquisition protocol. CPP protocol
unit tests use mocked subprocess outputs and are not native GCC/Clang evidence.
A separate test compiles and executes the existing runtime helper with native
GCC, checking boundary and fixed-seed inputs against Python wide multiplication;
finite testing is not a universal equivalence proof.

Broader project/constraint/type/helper tests: 206 passed, 6 real-tool integration
skips in the local environment. Final new-feature suite: 29 passed (overlaps
with the broader suite). Frozen corpus regressions: 92 passed. Host CPP capture
and compiler integrations are still required. The branch changes no existing
production code or frozen corpus policy.
