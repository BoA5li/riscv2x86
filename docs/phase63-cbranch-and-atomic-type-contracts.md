# CBRANCH roles and production atomic type authority

Baseline: phase62-route-authority-diagnostics,
8fbefc3e49aa86626b6e309ade93bca2f7034f66.

## Corrections

`conditional_transfer_from_op` applies the CBRANCH opcode input contract instead
of identifying the condition by filtering out CONST varnodes. It distinguishes
machine code references (MEM/ram) from p-code-relative CONST targets, validates
boolean width and rejects unknown target spaces. Predicate normalization consumes
the resulting explicit condition. Machine targets must agree with the canonical
instruction target. Relative offsets are never silently treated as absolute
machine addresses. This fixes the actual compressed-branch shape in case020.

Atomic join diagnostics retain `compilerFragmentJoin` including upstream missing
or rejected candidate/slot/closure diagnostics. The primary reason is the existing
compiler rejection when available, rather than always authority-missing.

The Clang tooling frontend exports versioned `compilerType` facts for each GNU
operand, using ASTContext/QualType APIs: canonical value and pointee types, target
width and alignment, qualifiers, side-effect freedom and modifiable lvalue status.
Repeatability is deliberately limited to side-effect-free declaration references;
it is not inferred from side-effect freedom alone. No asm text/type-name pattern
is used to infer the pointee type.

The wrapper binds these facts to the exact operand index/value node in an explicit
`riscv2x86.compiler-fragment-authority.v2` envelope. The provenance consumer accepts
v1/v2 and checks v2 type bindings. The shell retains typed facts; the model uses
their C type identities for the bound atomic route, without enabling unrelated
scalar C lowering paths. Atomic object ingress now requires a true pointer/pointee type
binding; `valueNodeIdentity` is never substituted for a C type. Pointee width must
match the atomic access. Qualified pointees remain rejected until an explicit
qualifier/shell contract is implemented. A v1 envelope is still readable but cannot
grant absent atomic pointee authority; rebuild/re-export instead of filling gaps.

## Scope and limits

This branch fixes the confirmed input-role and type-domain errors and improves
upstream diagnosis. It does **not** implement general expression/lvalue closure,
source-label/ELF continuation join, an asm-goto continuation observer, or an atomic
concurrency L2 provider. Existing public atomic builtin routes are retained; the
seq_cst/read-write-only lock contract is not relaxed. No unsupported dimension is
changed to verified, and L3 remains a separate experiment.

The actual case030 compiler-candidate rejection must be read from its new retained
upstream decision. A missing/rejected expression candidate is not manufactured
as a complete declaration binding by this patch.

## Validation

Selected Python regression: 398 passed, 7 skipped for missing real toolchain.
Python compile checks and diff checks pass. The real Clang exporter/join test is
`test_real_compiler_operand_types.py`; it must run on the user host after rebuilding
the frontend. The C++ changes have not been built in this environment (Clang SDK
and production cross-toolchain are unavailable). A skipped test is not validation
of those C++ changes or a successful generated-suite execution.

Acceptance on the production host: build succeeds; the new exporter test passes;
the actual MEM/ram branch reaches predicate normalization correctly; compiler
pointer/pointee identities are distinct from value-node identities; phase61 audit
and existing supported-case results do not regress. Further route/provider gaps
must remain explicit instead of being counted as successful equivalence proofs.
