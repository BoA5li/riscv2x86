# Phase163: canonical target AST audit and independent audit lifecycle

Base: Phase162, `5eb21c6716e0f5adb986fa675d4c80c9fa2dca8e`.

## Failure and repair

The host produced different raw target-AST stdout digests but the same complete
canonical target AST identity. Candidate generation, integer proofs and objects
had passed; command replay incorrectly required the raw compiler-process AST
bytes to match. This revision separates two contracts:

1. Each run's raw stdout/stderr files must match their own recorded digests.
2. Across independent runs, target-ast stdout is parsed again and compared as the
   full canonical declaration/reference graph, using the existing versioned
   alpha-renaming policy. It must also agree with target-ast.json and the saved
   targetAstIdentity. Cached identity strings alone are not authority.

All fields other than registered process-local reference identities are retained,
including literals, types, attributes, operators, ordering and reference edges.
No general hexadecimal-string replacement or source-text matching is used.
Unknown semantic fields remain part of the comparison. Duplicate JSON keys,
nonfinite JSON numbers, malformed reference identities and non-TU roots fail.
Other stages' stdout, all stderr, commands, return codes, inputs, proof artifacts
and completion flags remain strict. The original files and tools are checked
again at audit closing. No compiler/toolchain or source semantics gate is relaxed.

The audit now has its own exclusive output root, run-status.json and audit.json.
Candidate reconstruction lives in `rebuild/`. A successful rebuild is not a
successful outer audit. Comparison or build failure keeps the outer audit failed
and emits no success receipt. Source/target program acceptance remains false.

## Compatibility and scope

Existing Phase162 candidate.json is supported unchanged, so the host can audit
its existing GMP candidate. Do not edit its hashes or move its bound files.
This repair does not implement original macro rewriting, whole-function object
and external-call closure, source/target library linking or complete program
L1--L3 acceptance. The audited claim is still local integer statements and the
supported preserved builtin contracts.

## Host verification

Keep the same venv and toolchain. No frontend rebuild, GMP configure/make,
archive download or plugin header installation is needed for this audit repair.
If the proposed worktree already exists, inspect its HEAD rather than deleting
it; otherwise use a new path.

```bash
: "${REPO:?}" "${PREP_ROOT:?}" "${PHASE162_ROOT:?}"
git -C "$REPO" fetch origin phase163-canonical-native-audit
export PHASE163_TOOLING="$PREP_ROOT/tooling-phase163"
git -C "$REPO" worktree add --detach "$PHASE163_TOOLING" origin/phase163-canonical-native-audit
export PHASE163_ROOT="$(mktemp -d "$PHASE162_ROOT/phase163-XXXXXX")"
export PYTHONDONTWRITEBYTECODE=1
printf 'PHASE163_ROOT=%s\n' "$PHASE163_ROOT"
```

Run regression first, then re-audit the existing real GMP candidate in a NEW
output directory. The block stops on any failure. Supply the previously used
RV2X86_SYSTEM_CLANG, RV2X86_TEST_RISCV_CC and RISCV2X86_TEST_FRONTEND so the real
integration runs; a skip is not its verification.

```bash
bash -e <<'VERIFY'
: "${PHASE163_TOOLING:?}" "${PHASE163_ROOT:?}" "${PHASE162_ROOT:?}"
export PYTHONPATH="$PHASE163_TOOLING/pytools"
test -f "$PHASE162_ROOT/candidate/candidate.json"
python3 -m pytest -q -rs \
  "$PHASE163_TOOLING/pytools/tests/test_native_audit_evidence.py" \
  "$PHASE163_TOOLING/pytools/tests/test_native_integer_translation.py" \
  "$PHASE163_TOOLING/pytools/tests/test_native_test_entry.py" \
  "$PHASE163_TOOLING/pytools/tests/test_native_instance_binding.py" \
  "$PHASE163_TOOLING/pytools/tests/test_project_native_input.py" \
  --basetemp="$PHASE163_ROOT/pytest" --junitxml="$PHASE163_ROOT/focused.xml" \
  > "$PHASE163_ROOT/focused.log" 2>&1
python3 "$PHASE163_TOOLING/experiment/translate_native_project.py" audit \
  --candidate "$PHASE162_ROOT/candidate/candidate.json" \
  --output "$PHASE163_ROOT/gmp-audit" --timeout-seconds 300 \
  > "$PHASE163_ROOT/gmp-audit.log" 2>&1
VERIFY
VERIFY_STATUS=$?
printf 'phase163_status=%s\n' "$VERIFY_STATUS"
for NAME in focused.log gmp-audit.log gmp-audit/run-status.json gmp-audit/audit.json; do
  if test -f "$PHASE163_ROOT/$NAME"; then
    printf '\nFILE: %s\n' "$NAME"
    cat "$PHASE163_ROOT/$NAME"
  fi
done
```

Expected: the real compiler integration test passes; gmp-audit/run-status.json
has status complete and nativeCandidateIndependentAuditComplete true; audit.json
records the canonical target-AST comparison policy. semanticApproval and
productionAcceptanceComplete remain false. The temporary rebuild status alone
is insufficient. On failure preserve the outer primaryFailure, rebuild status,
corresponding *.stderr and gmp-audit.log. Never rerun into an existing directory.

## Next gap: source runtime and program closure

After the bounded audit passes, continue with actual loader/library selection,
execution inputs, object domains, target-library builds and program observations.
The existing entry metadata already identifies the interpreter and DT_NEEDED;
it does not prove which library is loaded during execution. Do not substitute
an unmodified native x86 GMP build for translator-generated target artifacts.

The following optional, read-only query supplies actual source runtime locations
for the next adapter; a returned bare filename or `/` is not an approved runtime
prefix. Do not guess QEMU -L from that value alone.

```bash
: "${RV2X86_TEST_RISCV_CC:?}" "${PHASE163_ROOT:?}"
"$RV2X86_TEST_RISCV_CC" -print-sysroot > "$PHASE163_ROOT/source-sysroot.txt"
"$RV2X86_TEST_RISCV_CC" -print-file-name=ld-linux-riscv64-lp64d.so.1 > "$PHASE163_ROOT/source-loader.txt"
"$RV2X86_TEST_RISCV_CC" -print-file-name=libc.so.6 > "$PHASE163_ROOT/source-libc.txt"
cat "$PHASE163_ROOT/source-sysroot.txt" "$PHASE163_ROOT/source-loader.txt" "$PHASE163_ROOT/source-libc.txt"
```

The separately reported missing GCC plugin headers affect future compiler-owned
macro expansion provenance, not this audit path. An exporter needs headers/API
matching the actual cross compiler; copying unrelated host headers or replacing
GCC expansion provenance with Clang preprocessing is not a valid repair.

## Tests

Scoped native/project/contract regression: 386 passed, 10 skipped locally.
Focused audit and candidate tests: 60 passed, 1 skipped locally. The missing
integration requires real RV64 GCC, Clang and the built frontend; it remains
included for the host. The protocol fixture now deliberately changes all raw
reference IDs every AST-producing invocation. Native GCC executes the existing
C expression and type-witness regressions; synthetic cross-ELF/AST protocol
fixtures are not claimed as real cross-ISA runs.

Negative cases retain rejection of changed literal/type/attribute/operator,
reference redirection or identity collisions, changed opaque hex strings,
unknown added fields, reordered declarations, raw-output tampering, stale cached
canonical AST, duplicate/malformed JSON, changed non-AST stdout/stderr, altered
objects and rehashed false acceptance flags. Tests also cover outer failure after
successful rebuild and propagation of nested compiler failure.
