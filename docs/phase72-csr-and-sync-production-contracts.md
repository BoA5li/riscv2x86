# Phase 72: CSR static production bindings and auditable sync rejection

Base remote: bffb0d1a99f17393bf34333f476447989afec06d (phase71).
This is a staged correction, not completion of strict instruction-visibility
and cross-environment counter equivalence. It must not be reported as 024/029
architectural L2 acceptance.

## Changes implemented

* Add an explicit, source/fragment/XLEN-bound CSR architecture profile distinct
  from execution permission. Profile fields and content identity are checked;
  a profile cannot grant CSR access. Conflicts with an execution-sidecar
  architecture profile reject the fragment with a retained decision.
* Add a production compiler/assembler/decoder CSR join for a standalone CSR
  instruction with integer register GNU operands. It validates the closed
  compiler envelope, value nodes, types, access, width, decoder effect and
  assembler materialization, and records a content-bound witness. READ,
  WRITE and read/write roles follow decoder suppression rules; read/write
  carriers retain both decoder nodes. Early-clobber, alternatives, memory
  operands and mixed regions remain rejected by this initial producer.
* Keep the explicit CSR bundle path and its existing validator. The new join
  is used when the bundle is absent; neither path grants permission, removes
  traps, creates a target time-domain relation, or waives downstream proof.
* A standalone, typed instruction fence can close only control-absence facts
  when its canonical carrier is finite and contains no register/memory effect
  or additional operation. Cache/speculation/visibility contracts remain
  separate. Ordinary fences, atomics and scalar proof predicates are retained.
* CSR/ISS needs-route records carry the specific nested contract/proof reason,
  stage, bound inputs and precondition disposition through existing reports,
  attempts and evaluator route diagnostics. ASM-goto diagnostics append rather
  than replace other route decisions.
* Extend the experiment runner to forward CSR architecture/authority/environment
  and instruction-stream registry directories, retaining actual command lines.
  Existing command semantics and no-contract fail-closed behavior remain.

## Profile ingress

Automatic batch accepts `--csr-architecture-directory DIR`. For a source
`path/probe.c`, its file is `DIR/path/probe.c.csr-architecture.json`.
Automatic translation/backend accept `--csr-architecture-profile FILE`.
The exact JSON fields are:

```
schemaVersion = riscv2x86.csr-architecture-profile.v1
sourceDigest = sha256:<actual source bytes>
fragmentId = <exact frontend fragment ID>
privilegeSpecVersion = riscv-privileged-1.12 | riscv-privileged-1.13
xlenBits = 32 | 64
extensions = <sorted, unique, lowercase extension IDs>
profileIdentity = sha256:<canonical JSON of all other fields>
```

Canonical JSON uses sorted keys, separators `(',', ':')`, UTF-8 and
`ensure_ascii=False`. Select the specification/extensions from the actual
supported source deployment, not to bypass rejection. RV32 does not imply
full RV32 production-route acceptance: the compiler-envelope consumer still
requires a supported triple and all independent contracts.

## Validation

Local selected route regression plus CSR, summary and execution-sidecar tests:
**638 passed, 38 skipped**. Changed Python files compile and `git diff --check`
passes. This is not the complete Python test suite. The editing host lacks
linked frontend/Ghidra/RISC-V compiler/QEMU production tools. The two new real
production tests, among the skips, are NOT end-to-end acceptance.

The new production tests independently parse source with the real frontend,
then execute automatic batch. The sync case requires a specific
`ISS_RUNTIME_CONTRACT_MISSING` diagnostic; the CSR case supplies only an
architecture profile, requires a successful static CSR join and still requires
`needs_route` without an execution/target contract. Mutation tests cover source,
profile identity/schema/XLEN, register binding, decoder effect, width,
constraint, compiler identity and mixed regions. No case ID is used by runtime.

## Remaining obligations (not implemented by this patch)

1. Static CSR external-state versus ordinary-register/control summaries still
   need their complete dedicated effect-coverage contract; no `time` register
   is silently dropped from the generic summary in this patch.
2. Strict ISS platform-authority provenance must replace reliance on caller
   booleans/opaque relation IDs. A void fence function supplies no code range;
   use a real caller/platform scope, never a fabricated nonempty code object.
3. A real counter access policy and source-target clock/counter domain mapping
   are required. A monotonic clock/TSC substitution is not exact rdtime proof.
4. Strict ISS/CSR Phase-6D approval artifacts and dedicated automatic L2
   materializers/providers/observations still need a complete production
   implementation and real-tool validation. The existing functional fallback
   validator does not establish these architectural properties.
5. L3 requires independent configuration and execution.

Without those obligations, expect 024/029 to remain needs_route, with more
precise diagnostics; no extra verified count is promised. This limitation is
intentional and does not mean the overall requested expansion is complete.

## Local retest without terminal-closing shell assertions

Run in the existing checkout after fetching/switching this branch. Do not reset
tracked builds or clean local experiment directories. `set +e` prevents a
nonzero test or batch result from terminating an interactive shell.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
REPO="$PWD"
source "$REPO/.venv-l2/bin/activate"
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
mkdir -p "$REPO/experiment/results"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase72-XXXXXX")
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$REPO/experiment/generated-suite"
RUN_STATUS=$?
printf 'runner_status=%s\nRESULT_ROOT=%s\n' "$RUN_STATUS" "$RESULT_ROOT"
cat "$RESULT_ROOT/run-status.json"
tail -n 80 "$RESULT_ROOT/regression.log"
```

Only when independently justified configuration directories exist, append the
runner's `--csr-architecture-directory`, `--csr-authority-directory`,
`--csr-environment-contract-directory`, `--instruction-stream-sync-directory`.
Do not create approved dummy contracts. A nonzero batch verdict is expected
when invalid inputs/unconfigured routes remain. The runner records whether the
suite actually executed; missing tools or failing regression are blockers.
