# Phase153: native compiler header search for project inspection

Base: `a8d2db7ac7ef6a731ed68b36ea1e8db51000558f` (Phase152).

## Root cause and delivered scope

The reported GCC7 cross compiler preprocesses stdio successfully with sysroot
`/`, using its configured RISC-V include tree before `/usr/include`. Clang10
identifies a GCC installation but does not add that target include tree to its
actual search list. Cross libc/kernel development packages are already present.
Do not copy headers, install host multiarch headers as RISC-V substitutes, change
GCC's native sysroot, or infer a sysroot from GCC version-directory names.

This branch repairs inspection header acquisition and binding. It does not add
macro rewriting, `%r` proofs, floating-point semantics, general ABI or Linux
execution support, nor fix Linux's unsupported compiler-option projection.

## Implementation

- `project_header_search` runs the recorded native compiler with the original
  semantic options and working directory, querying its C search list with a
  fixed diagnostic locale. Bind source/compiler/context identities, arguments,
  environment, ordered quote/angle paths and resolved symlink targets. Reject
  incomplete/ambiguous protocols, nonexistent paths, unsupported framework
  entries and failed native probes; never fall back to guessed host directories.
- Keep explicit project `-I`, `-iquote`, `-isystem` and include-environment
  paths in their existing categories. Add `-nostdinc` and only missing native
  paths to the Clang inspection recipe. The native compilation is unchanged.
  This deliberately mirrors GCC headers, including private/fixed headers. If
  Clang cannot parse a GCC-specific header, report that remaining compatibility
  gap; do not rewrite the header or silently switch to different declarations.
- Independently probe Clang's effective projected search list and require the
  same resolved ordering/categories as the native list. New dependency manifests
  use v2 with both search records and original inspection arguments. Replay
  native search, Clang search, dependencies and derived AST inventories.
- No projection is permitted to inject native outputs, plugins or a second
  source into a header probe. Rehashed receipts must still match fresh compiler
  queries and, in project snapshots, the exact bound build context.
- Project contextual inspection now uses this path automatically. Legacy
  project-aware entry/candidate discovery can opt in through an explicit exact
  context table (`RV2X86_PROJECT_HEADER_CONTEXTS`); no match/ambiguous match is an
  error. Report-bound operations and independent snapshot audits use the bound
  contract context, not a process-global include path guess.
- Source GCC/Clang CPP comparison uses the same projection and a new v3 receipt.
  It retains exact token comparison and now includes the inspector's integer
  data model in comparison. Headers being found or AST parsing are never
  compiler-equivalence or translation approval.
- Existing standalone v1 dependency records retain their unprojected replay
  route. Old project compatibility v2 receipts need regeneration; changing only
  hashes/version labels cannot make them valid v3 evidence. Old raw build
  records/contexts remain reusable. Frozen corpus files/policies are unchanged.

## Host experiment: reuse captured builds, no configure/make rerun

```bash
cd /root/src/poc_trans/path_b/riscv2x86
export REPO="$PWD"
export PREP_ROOT="$REPO/experiment/results/gmp-linux-prepare-Q0FqGS"
export TOOLING="$PREP_ROOT/tooling-phase153"
export VERIFY_ROOT="$REPO/experiment/results/project-build-phase152-CtODca/verification-TCA4lE"
export CORPUS_CHECK_ROOT="$VERIFY_ROOT/corpus-analysis-fzAdqI"
git fetch origin phase153-native-header-search-binding
git worktree add --detach "$TOOLING" origin/phase153-native-header-search-binding
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$TOOLING/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RV2X86_SYSTEM_CLANG=/usr/lib/llvm-10/bin/clang
export RV2X86_TEST_RISCV_CC=/usr/bin/riscv64-linux-gnu-gcc-7
export HEADER_CHECK_ROOT="$(mktemp -d "$CORPUS_CHECK_ROOT/phase153-XXXXXX")"
printf 'HEADER_CHECK_ROOT=%s\n' "$HEADER_CHECK_ROOT"
```

Only create a worktree once; inspect an existing path rather than deleting it.
Do not alter the old tooling worktrees: their bytes are bound by capture records.

### 1. Focused regression

```bash
python3 -m pytest -q -rs \
  "$TOOLING/pytools/tests/test_project_header_search.py" \
  "$TOOLING/pytools/tests/test_compiler_call_dependencies.py" \
  "$TOOLING/pytools/tests/test_project_build_contract.py" \
  "$TOOLING/pytools/tests/test_project_build_records.py" \
  --junitxml="$HEADER_CHECK_ROOT/focused.xml" > "$HEADER_CHECK_ROOT/focused.log" 2>&1
FOCUSED_STATUS=$?
printf 'focused_status=%s\n' "$FOCUSED_STATUS"
tail -n 80 "$HEADER_CHECK_ROOT/focused.log"
```

The real RISC-V/Clang stdio test should run on the reported host. A failure must
be analyzed, not converted into a skip. Local absence of a compiler is explicitly
reported by pytest; mock protocol tests do not establish actual Clang10 behavior.

### 2. Rerun the SAME pilot sources and preserve ALL captured variants

Run only after step 1 succeeds. Old pilot errors remain untouched.

```bash
python3 - <<'PY'
import json, os, subprocess, sys
from pathlib import Path
out=Path(os.environ['HEADER_CHECK_ROOT'])
tooling=Path(os.environ['TOOLING'])
old=Path(os.environ['CORPUS_CHECK_ROOT'])
plan=json.loads((old/'gmp-pilot-plan.json').read_text())
sources=plan['sourcePaths']
command=[sys.executable,str(tooling/'experiment/prepare_real_project_experiment.py'),
 'inspect','--records',str(Path(os.environ['VERIFY_ROOT'])/'gmp-native/records.json'),
 '--clang',os.environ['RV2X86_SYSTEM_CLANG'],'--target','riscv64',
 '--output',str(out/'gmp-pilot-contexts.json')]
for source in sources:command+=['--source',source]
with (out/'command.json').open('x') as stream:json.dump(command,stream,indent=2)
with (out/'gmp-pilot.log').open('x') as log:
 result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=False)
print('pilot_status:',result.returncode)
path=out/'gmp-pilot-contexts.json'
if path.is_file():
 data=json.loads(path.read_text())
 print('statusCounts:',data['statusCounts']);print('errors:',data['errors'])
 for row in data['records']:
  print('SOURCE:',row['context']['sourcePath'],'STATUS:',row['status'])
  print('FAILURE:',row.get('inspectionFailure'))
  observation=row.get('inspection')
  if observation is None:
   print('functions/asm: unknown (acquisition failed)');continue
  manifest=observation['snapshot']['dependencyManifest']
  print('dependencySchema:',manifest['schemaVersion'])
  print('nativeHeaderSearchIdentity:',manifest['nativeHeaderSearch']['headerSearchIdentity'])
  print('functionCount:',len(observation['functions']))
else:print((out/'gmp-pilot.log').read_text(errors='replace'))
PY
```

Expected: original bits-header error resolved and projected dependency v2
recorded. A GCC-header parser incompatibility or later call-inventory failure
is a new, separately retained blocker. Neither success nor failure establishes
that the selected assert/compat files contain eligible asm instances.

### 3. Independent pilot replay, only after all pilot inspections succeeded

```bash
python3 "$TOOLING/experiment/prepare_real_project_experiment.py" replay \
  --report "$HEADER_CHECK_ROOT/gmp-pilot-contexts.json" \
  > "$HEADER_CHECK_ROOT/replay.log" 2>&1
REPLAY_STATUS=$?
printf 'replay_status=%s\n' "$REPLAY_STATUS"
cat "$HEADER_CHECK_ROOT/replay.log"
```

Replay performs fresh header/dependency/AST acquisition. It is not L3 or an
independent production acceptance audit. If failure occurs, return focused/pilot/
replay status and the corresponding log. Do not rerun native project builds.

## Explicit bridge for a future approved project plan

`experiment/inspect_project_headers.py --contexts CONTEXT_REPORT --source FILE
[--source FILE] --clang CLANG --output NEW_REPORT --profile-output NEW_PROFILE`
exports an exact selected-context table only when all selected header searches
match. Set `RV2X86_PROJECT_HEADER_CONTEXTS` to this profile for initial legacy
project-aware entry/candidate acquisition. Scope it to the planned variants;
never use it as a global header injection for unrelated sources or x86 targets.
A missing/ambiguous exact source/argument/cwd match blocks execution. Header
matches do not satisfy macro, ABI, FP, environment or L0–L3 obligations.

## Acceptance boundaries and next work

After pilot/replay succeeds, discover actual active asm/headers/call scopes and
freeze a typed end-to-end plan. Existing Linux /dev/null probe classification
and kernel-option projection gaps remain; preserve records instead of deleting
probe failures or dropping original compiler flags. No corpus denominator is
selected by passing results. Do not launch all 1008 GMP contexts merely to
repeat a common unresolved semantic/ABI/header blocker.

## Local validation

- Project/header/dependency/type/compiler regressions: 240 passed, 7 skipped
  because real Clang/RISC-V GCC or the rebuilt frontend is absent locally.
- Additional production-evidence/chain checks: 37 passed, 29 skipped (includes
  the header tests; skips require the actual production toolchain).
- Immutable corpus regressions: 92 passed; no frozen corpus policy file changed.
- Real native GCC search probing and independent replay ran locally. Mocked
  tests cover the acquisition protocol, not actual RISC-V semantic acceptance.
- Tests reject changed order, rehashed directory/receipt tampering, native probe
  failure, output injection, absent profile matches and inspector data-model
  disagreement despite identical CPP tokens. No evaluation threshold was reduced.
