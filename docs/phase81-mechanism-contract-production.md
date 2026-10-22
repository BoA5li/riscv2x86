# Mechanism-backed local synchronization and controlled TIME production

Base: `19b324654676f59cacd2028abc637ea508731609` (phase80).

Development validation: the selected `verify_route_contracts.TESTS` regression
set completed with **852 passed, 40 skipped**. Thirty-nine skips require the
real production toolchain/frontend; one requires source ISA tools. Native x86
runtime execution and protocol/proof mutation tests ran. The separate QEMU
build and original 024/029 full production runs have **not** been executed in
this development environment. Those are required local acceptance steps below.

## Supported claims

The original QEMU 7.2 linux-user x86-64 TIME implementation calls RDTSC.
Two independent executions do not read the same TSC value merely because they
use that implementation. Native TSC is **not** newly registered as strict
equivalence. The existing monotonic adapter remains functional only.

The new strict route is an **explicit controlled external TIME environment**.
A separate QEMU worktree replaces the user-mode `read_time` implementation,
while the target uses a registered checked reader of the same event trajectory.
Actual source read events, their sites, returned values, event counts and
termination are observed. This does not rewrite the source asm or postprocess
the source result. It does not claim unmodified QEMU/TSC, wall-clock timing,
arbitrary enclosing-function equivalence or L3 microarchitecture equivalence.
The reserved trajectory/event files and their resources must not be aliased or
observed by the tested program. The target reader preserves errno.

TIME observation currently supports an AST-proved unsigned 64-bit function
with no parameters, one uninitialized local, one volatile output-only asm and
a direct return of that local. Other placements remain needs_route. Source
execution facts are complete for this isolated user TIME operation only: no
machine-mode delegation, VM or trap-handler facts are fabricated. The selected
privileged specification is 1.12 for this QEMU backend. TIMEH/RV32 and composite
CSR operations do not acquire this implementation.

Local instruction synchronization reuses the shipped CPUID helper, v3 approval
replay, command planning/binding and actual modified-code observer. New v2
domains bind mechanically collected QEMU evidence and explicit reviewed
assumptions: one thread, local pinned execution, private ordinary coherent
memory, same mapping, no external writers/aliases or active-code overwrite.
Cross-hart publication remains a different unsupported protocol. A successful
finite probe does not establish these external assumptions.

The 4096-byte `probe-code-object` range is an **observer object**, not proof of
coverage over every application code object. New proof obligations distinguish
the observed range from the reviewed mechanism's supported domain. QEMU may
detect modified code even without fence.i, so a deletion mutation need not
produce a dynamic mismatch. Proof/runtime/build binding is independently
required. Existing legacy synchronization schemas are not silently migrated or
given the new reviewed-mechanism claim.

## Implementation

* `mechanism_evidence` checks the independent QEMU source root/commit, clean
  tracked files, x86-64 ELF, installed-versus-build bytes, build target/source
  path, and records implementation/config digests. Collection never approves
  semantics. This is traceability evidence, not a reproducible-build theorem.
* `prepare_instruction_visibility_contract` consumes an actual compiler snapshot,
  decoded source encoding, collected mechanism evidence, reviewed domain and a
  fixed observer output plan. It produces a registry for normal Phase 6D.
* `prepare_controlled_time_backend` builds a separate QEMU at the reviewed commit
  and records commands, patched source/header and binary identities. It never
  installs over `/usr/local/bin/qemu-riscv64`. Each consumed TIME event is
  emitted by the real read implementation. Missing/exhausted/malformed input
  and transport failure abort instead of becoming a counter value.
* CSR environment schema v3 carries the controlled external-time relation.
  Runtime registration, source access refinement, Phase 6D, renderer, approval
  replay and build provenance all consume it. Legacy exact-epoch/scale checks
  and functional fallback policies are unchanged.
* `prepare_time_trace contract` uses the production compiler/decoder join;
  `bind` consumes an existing approved report. An approval is not created by
  provider preparation. TIME's L1 runs the same actual observation mechanism
  in a separate fresh execution; L2 remains requirement-driven and centrally
  audited. The observations retain explicit unclaimed properties.
* Actual observer routes build a source shared library rather than attempting
  to dlopen the previous source `.o`. Other source build paths are unchanged.
* Both observer runners accept the canonical serialized target environment
  passed by validation orchestration, as well as typed environments.
* `contract-consumption.json` distinguishes validated-but-unused contracts from
  contracts consumed by replayed approvals. It is not itself semantic evidence.

## Local update and regression

Activate the existing project virtual environment. Use a fresh result directory
for every run. These commands do not use `set -e`, `exit`, assertions, or pipe
status as a shell control-flow condition.

```bash
set +e
cd /root/src/poc_trans/path_b/riscv2x86
REPO="$PWD"
git status --short
git fetch origin phase81-mechanism-contract-production
git switch --track origin/phase81-mechanism-contract-production
export PYTHONPATH="$REPO/pytools${PYTHONPATH:+:$PYTHONPATH}"
RESULT_ROOT=$(mktemp -d "$REPO/experiment/results/phase81-regression-XXXXXX")
CLANG10="$REPO/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain/clang"
python3 experiment/verify_route_contracts.py --frontend "$REPO/build/riscv2x86" --clang10 "$CLANG10" --output "$RESULT_ROOT" --suite "$REPO/experiment/generated-suite"
RUN_STATUS=$?
printf 'runner_status=%s\nRESULT_ROOT=%s\n' "$RUN_STATUS" "$RESULT_ROOT"
cat "$RESULT_ROOT/run-status.json"
tail -n 100 "$RESULT_ROOT/regression.log"
cat "$RESULT_ROOT/summary.json"
cat "$RESULT_ROOT/provider-audit.log"
```

If local edits exist, keep them before switching; the commands never reset,
clean, stash or overwrite them. If the branch already exists locally, use
`git switch phase81-mechanism-contract-production` followed by
`git pull --ff-only origin phase81-mechanism-contract-production`.

The bare suite is a baseline, not positive TIME/synchronization acceptance.
Without the controlled backend environment variables, its explicit production
test skips. Do not report a skip as a pass or demand zero skips before preparing
the corresponding environment. Once all required tools/environments are
selected, `--require-no-regression-skips` is available for acceptance.

## Explicit declarations

Create `architecture.json` using the actually selected specification, XLEN and
extensions; its schema is `riscv2x86.csr-architecture-template.v1`. Example shape:

```json
{
  "schemaVersion": "riscv2x86.csr-architecture-template.v1",
  "privilegeSpecVersion": "riscv-privileged-1.12",
  "xlenBits": 64,
  "extensions": ["i", "zicsr", "zifencei"],
  "templateIdentity": "sha256:<canonical unsigned payload digest>"
}
```

Use `semantic_identity` to seal the unsigned payload; it binds a declaration,
not its truth. For example, after saving the selected payload without
`templateIdentity` to `/actual/architecture.json`, seal it once:

```bash
python3 - /actual/architecture.json <<'PY'
import json, sys
from pathlib import Path
from riscv2x86_py.semantic_content import semantic_identity
p = Path(sys.argv[1])
value = json.loads(p.read_text())
value.pop('templateIdentity', None)
value['templateIdentity'] = semantic_identity(value)
p.write_text(json.dumps(value, indent=2) + '\n')
PY
```

A TIME review JSON has exactly these fields:

```json
{
  "owner": "<experiment owner>",
  "basis": "explicit-controlled-environment-selection",
  "evidenceIdentity": "sha256:<reviewed controlled-environment basis>"
}
```

A synchronization selection JSON has exactly this shape. Select available CPUs
from `taskset -pc $$` / the effective affinity mask, not a guessed CPU 0:

```json
{
  "schemaVersion": "riscv2x86.local-sync-selection.v1",
  "sourceCpu": 0,
  "targetCpu": 0,
  "logicalHartIdentity": "<declared logical context correspondence>",
  "modifiedCodeRange": {
    "objectIdentity": "probe-code-object", "offsetBytes": 0,
    "lengthBytes": 4096, "addressSpaceIdentity": "observer.private.anonymous"
  },
  "assumptions": {
    "writerPolicy": "one-thread-same-mapping-no-external-writers",
    "mappingPolicy": "private-anonymous-no-alias-no-mmio",
    "executionPolicy": "local-pinned-hart-no-active-code-overwrite",
    "targetProtocolBasis": "x86-local-serializing-smc-v1",
    "rangeRole": "observer-probe-only-domain-guarantee-from-reviewed-mechanism",
    "reviewer": "<experiment owner>",
    "basisIdentity": "sha256:<reviewed source and target mechanism basis>"
  }
}
```

The target-protocol basis must include the applicable processor's local SMC
serialization guarantees and availability. Hashing the selection is not that
review. If these assumptions do not describe the intended experiment, select a
different protocol; do not fill them with convenient assertions.

## Build the separate controlled backend

Only run this when explicitly choosing the controlled TIME experiment:

```bash
set +e
TIME_BACKEND_ROOT="$REPO/experiment/toolchains/controlled-time-$(date -u +%Y%m%dT%H%M%SZ)"
python3 -m riscv2x86_py.prepare_controlled_time_backend --qemu-source "$REPO/qemu" --output "$TIME_BACKEND_ROOT" --jobs 2
BACKEND_STATUS=$?
printf 'backend_status=%s\nTIME_BACKEND_ROOT=%s\n' "$BACKEND_STATUS" "$TIME_BACKEND_ROOT"
cat "$TIME_BACKEND_ROOT/build-status.json"
tail -n 80 "$TIME_BACKEND_ROOT/compile.log"
```

An unsuccessful build has no usable backend.json. The original installed QEMU
and source checkout are retained. The new worktree/output is a checkpoint and
is not silently deleted/reused after failure. Building requires the project's
existing QEMU development dependencies; submodules may need network access.

## Run real preparation and acceptance

After rebuilding the frontend/runtime, pass existing reviewed declarations:

```bash
set +e
cmake --build build -j2
BUILD_STATUS=$?
printf 'frontend_runtime_build_status=%s\n' "$BUILD_STATUS"
MECHANISM_RUN="$REPO/experiment/results/phase81-mechanism-$(date -u +%Y%m%dT%H%M%SZ)"
python3 experiment/run_mechanism_routes.py --frontend "$REPO/build/riscv2x86" --output "$MECHANISM_RUN" --architecture-template /actual/architecture.json --sync-source "$REPO/experiment/generated-suite/case_024_56593df85e.c" --sync-declaration /actual/sync-selection.json --qemu-source "$REPO/qemu" --qemu-build "$REPO/qemu/build" --native-runner-json '["/usr/local/bin/qemu-riscv64","-L","/usr/riscv64-linux-gnu"]' --time-source "$REPO/experiment/generated-suite/case_029_b2290047d8.c" --time-review /actual/time-review.json --time-backend "$TIME_BACKEND_ROOT/backend.json" --time-runner-json "[\"$TIME_BACKEND_ROOT/build/qemu-riscv64\",\"-L\",\"/usr/riscv64-linux-gnu\"]" --suite "$REPO/experiment/generated-suite"
MECHANISM_STATUS=$?
printf 'mechanism_status=%s\nMECHANISM_RUN=%s\n' "$MECHANISM_STATUS" "$MECHANISM_RUN"
cat "$MECHANISM_RUN/run-status.json"
cat "$MECHANISM_RUN/sync-provider-audit.log"
cat "$MECHANISM_RUN/time-provider-audit.log"
```

For independent experiments supply only the sync inputs or only the TIME inputs.
The script uses the selected source paths as inputs, not as implementation keys.
It performs bootstrap -> contract -> approval -> provider binding -> configured
execution, retaining expected bootstrap failures and requiring final verified
L0/L1/L2 plus provider audit. The optional full suite runs a separate bare baseline
and checks that its verified cases do not regress under the configured run.
It never turns failed stages into green summaries. Nested suite layouts can use
the individual preparation tools with their explicit source-root mapping.

For the optional production regression, select the existing built backend:

```bash
export RV2X86_CONTROLLED_QEMU_MANIFEST="$TIME_BACKEND_ROOT/backend.json"
export RV2X86_CONTROLLED_QEMU_RUNNER_JSON="[\"$TIME_BACKEND_ROOT/build/qemu-riscv64\",\"-L\",\"/usr/riscv64-linux-gnu\"]"
python3 -m pytest -q pytools/tests/test_controlled_time_production.py
PRODUCTION_STATUS=$?
printf 'controlled_production_status=%s\n' "$PRODUCTION_STATUS"
```

## Logs and acceptance boundary

* `run-status.json`: every subprocess status, selected/completed routes, blockers.
* `*-bootstrap.log`, `*-approval.log`: expected missing prerequisites versus real
  compilation/decoder/proof failures. Missing reports stop preparation.
* `*-binding.json`: consumption of an existing approval, not new approval.
* `<route>-configured/cases/<case>/work/translation-work/contract-consumption.json`:
  actual replayed semantic contract consumption.
* `<route>-configured/cases/<case>/evaluation-result.json`: L0/L1/L2 verdicts.
* `<route>-provider-audit.log`: central persisted observation/provider audit.
* `full-strict-suite/` and `full-configured-suite/`: independent coverage runs.

Query errors without shell termination:

```bash
find "$MECHANISM_RUN" -name evaluation-result.json -o -name contract-consumption.json
grep -RInE 'TIME_|ISS_|reasonCode|failureStage|not_produced|partial' "$MECHANISM_RUN" --include='*.json' --include='*.log'
```

Do not claim original 024/029 acceptance until their real toolchain runs and
central audits complete. Protocol fixtures/native x86 tests alone do not supply
that result. Full historical Python collection also contains a pre-existing
`test_cross_asm.py` import of absent `translate_function`; do not hide it or
describe the targeted route regression as the entire historical suite.

The controlled source patch is reviewed against
[`target/riscv/csr.c` at the pinned QEMU commit](https://github.com/qemu/qemu/blob/b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56/target/riscv/csr.c).
The registered patched file has a fixed digest checked independently of the
manifest's self-hash. Binary/build identities remain build provenance under
the declared review, not proof that an arbitrary binary implements a hash.
