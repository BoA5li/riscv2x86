# Phase148: project context consumption and artifact binding

Base: Phase147 remote commit `7740e024005d10a61e7d415716fc11229bda5675`.

**This branch does not complete the entire real-project coverage plan.** It
implements project recipe consumption across the existing bounded routes. It
adds no floating-point lowering/L2 proof or floating-state L3 observer, no generic
header-entry adapters, and no new syscall/TLS/relocation environment authority.
No full-corpus translation rate or completed-all-capabilities claim is justified.

## Implemented changes

| Component | Project-mode behavior |
|---|---|
| Build contract | Explicit source context, inspection compiler, target profile and separate driver profiles. Source/target options are not silently copied or dropped. Body language, overflow, aliasing, builtin and floating-evaluation semantic options must match explicitly. |
| Compiler compatibility | Native/target/driver integer data models and ABI-affecting options are checked; body language profiles must match, while driver language versions may differ. Native compiler and Clang preprocess with their bound options. Maximal-munch token equality is a conservative prerequisite; differences are retained with the first differing token window. This is not a proof of arbitrary compiler equivalence. |
| Entry discovery | Project cwd/semantic options and dependency acquisition replace default inspection flags. Function identities bind contract and dependency identities. Legacy mode retains its original identity contract. |
| Translation frontend | Project mode uses the bound options/cwd and no default sysroot probe. Source inventories and preprocessing diagnostics are preserved. |
| Compiler snapshot | Version 2 binds context, dependency manifest, type inventory and preprocessing receipt. Consumers replay the used AST function facts under the exact acquisition command. Version 1 remains accepted for legacy inputs. |
| Program build | The materialized target TU is preprocessed under original and migrated recipes to detect target-only branch/header changes. Bound recipes build separate program objects and link outputs; build receipts bind actual command, source/object/output digests and contract. Fresh outputs are required. |
| L0 | Independently rebuild actual project artifacts, inspect ELF/ABI and retain the existing complete compiler/optimization/sanitizer matrix as additional cells. The default O0 matrix artifact is not mislabeled as the project artifact. |
| L1/L2 execution | Explicit per-validator context scope; harnesses and program TUs compile separately. Instrumented effect/operand/atomic/joint observations use the same body profile. |
| L3 | Bounded scalar/memory/control/fence/atomic/LRSC/program/joint deployment entry points consume report-bound recipes. Backend compiler mismatches fail; existing exact function-byte, mechanism, event and independent-rebuild checks remain. |
| Independent acceptance | Evaluation binding joins contract, report and both actual artifacts. Audit replays compiler provenance and rebuilds both artifacts before the existing L3-specific audit. Missing project bindings are rejected. |
| Corpus orchestration | Immutable explicit variant plans retain every planned row, including configuration failures. A verified evaluation without nonempty independently audited L3 fragments cannot be counted as accepted. |

## What is still not solved

1. **Compiler compatibility beyond exact preprocessing equality.** Legitimate
   GCC/Clang differences, such as compiler-specific declarations/attributes, are
   conservatively blocked. They need verified, feature-specific compatibility
   rules or native-preprocessed AST acquisition with source-expansion mapping;
   dropping differing tokens is not a repair. The same restriction applies to target-only runtime/header differences exposed after materialization.
2. **Unsupported driver/ABI classes.** Discovery of static, floating, variadic or
   aggregate entries is not execution eligibility. New calling conventions and
   entry adapters require actual compiler-derived layout and output contracts.
3. **Floating semantics and execution.** No FSGNJX/FSQRT production proof,
   rounding refinement, NaN/exception-state contract or calibrated floating L3
   backend has been added. Existing integer-register ABI contracts are unchanged.
4. **Macro/header rewrite closure.** Existing exact source-range gates remain.
   No expansion offset is reinterpreted as an editable original-file offset.
   Header-only routines need real TU instantiation and reviewed entry adapters.
5. **Broader runtime/link/environment closure.** Project recipes do not infer
   legitimate arguments, reachable external effects, whole-library ABI closure,
   TLS state, syscall environments or controlled-system authority. Special
   time/visibility/system provider combinations need explicit project adapters.
6. **Full host production validation.** Local contract/regression checks are not
   a substitute for running the actual RV64 toolchain/QEMU/observation backends.
   No host production run is claimed by this branch.

The supported domain is the intersection of an existing proved route, a valid
entry/observation contract, source preprocessing compatibility, a representable
project recipe and available actual backend capabilities. Conservative blockers
inside an intended but not yet implemented domain remain outstanding work; this
list is not an assertion that identifying those blockers completes the plan.

## Interfaces (deferred verification, not a request to run now)

`experiment/prepare_real_project_experiment.py make-contract` consumes a
Phase147 context or one explicitly selected context from a preflight report:

```
--context-file CONTEXT_OR_PREFLIGHT.json
--context-identity sha256:...       # required if selection is not unique
--profile EXPLICIT_PROFILE.json
--output NEW_CONTRACT.json
```

The profile has exactly these keys:

| Key | Value |
|---|---|
| `clang` | Inspection compiler path |
| `targetCompiler` | Target compiler path |
| `targetArguments` | Target program-body argument array |
| `targetDirectory` | Target compilation working directory |
| `sourceDriverArguments` | Source driver argument array |
| `targetDriverArguments` | Target driver and link argument array |

All three argument collections are JSON string arrays. `targetArguments` are
program-body options, not a native-library link command. Driver ABI options must match the program ABI (including plain-char
signedness); language versions may differ. Driver profiles are
separate and explicit; unreviewed driver `-D`/`-U`/include-path/forced-header overrides are rejected. A typed harness adapter is required when such context is necessary; project-local `-nostdinc`/feature macros must not leak into
an unrelated stdio harness. Runtime library dependencies selected by the approved
translation are still independently resolved and bound. Target architecture
options may not contain source RV ISA/ABI options.

The formal single-variant entry is:

```
python3 -m riscv2x86_py.automatic_batch_cli \
  --input ORIGINAL_SOURCE.c \
  --project-build-contract CONTRACT.json \
  --frontend FRONTEND \
  --l3-mechanism-selections CALIBRATED_SELECTIONS.json \
  --require-l3 \
  --output-directory FRESH_OUTPUT
```

There is no implicit choice between `.o` and `.lo`: select and bind the intended
build variant. A new project configuration requires a new contract and proofs;
it is not a retry under more convenient flags.

`python3 -m riscv2x86_py.project_corpus_evaluation --plan PLAN.json --output NEW_DIR`
executes a sealed `riscv2x86.project-corpus-plan.v1`. Each `variants` row has exactly
`variantId`, `projectBuildContract`, `frontend`, `mechanismSelections` and
`harnessDirectory` (the last two may be null). `planIdentity` is the canonical
content identity of the body without that field. Every row is retained. This
plan must be determined from the declared corpus/build selection, not from which
entries translated successfully.

Do not schedule the final full-corpus experiment until the intended entry and
semantic domains above have been implemented and its expected-outcome matrix has
been fixed. The interfaces are documented so subsequent implementation does not
need another incompatible experiment wrapper.

## Candidate-view provenance migration

The immutable Phase146/147 `real-projects-rv64-c-v1` directory is unchanged.
Because that view also pins automatic-entry implementation bytes, the new default
is `real-projects-rv64-c-v2`, with a new policy/view identity. Original source
archives, all candidate/review/excluded decisions and counts are identical.

The verifier can check the old view only under its exact historical view/policy
pins, reports `implementationProvenance=archived-exact-phase146-pins`, and still
replays its source partition. It does not pretend the old snapshot was created
by the new entry code. Arbitrarily rehashed historical policies are not trusted.

## Local development checks

- Core/context/legacy-route checks: 326 passed, 6 skipped.
- Original and versioned corpus integrity/replay checks: 92 passed.
- All package Python sources parsed; whitespace patch checks passed.
- No host production matrix, new floating proof, real calibrated project L3
  execution or full-corpus acceptance is claimed by these checks.
