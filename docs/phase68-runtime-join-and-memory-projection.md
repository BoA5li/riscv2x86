# Phase 68: preserve production authority and project memory addresses

Parent: phase67-asmgoto-expression-production, remote commit
6a8750daee05e301cf0488c49323c18cc0bcc4cf.

## Changes

1. Phase 4 facts normalization preserves assembler-owned machine join and
   atomic object facts. Existing frontend no-op certificates remain separate.
2. The lift invocation explicitly binds its base and exact machine image to a
   versioned layout. Source proof compares absolute addresses only after this
   checked conversion; source continuation identity stays layout-independent.
3. A shared bounded RISC-V GNU constraint contract recognizes memory `m` and
   address-in-register memory `A`. Alternatives and unapproved fixed-register
   combinations remain rejected. Closure propagates the precise leaf reason.
4. The linked Clang frontend exports a separate compilerAddressType for exact
   dereference bases. Python and C++ report ingress/egress retain it. Missing
   facts remain rejected; do not run this route with an old frontend binary.
5. A content-addressed memory-address projection joins the dereference, its
   base declaration, compiler pointer/pointee types and evaluation node. It
   does not manufacture an extra GNU operand or a declaration for the lvalue.
   Object bounds/alignment, address space and decoder AMO facts are still
   independently checked by atomic ingress.
6. Source models, builtin constraints/proof, rendering, L2 sidecars and the
   atomic wrapper consume that same projection. Rendering uses an approved
   address-of-lvalue; word truncation/extension stays independently checked.
7. Atomic proof facts are versioned v2. Old generated artifacts must be
   regenerated rather than silently relabelled with their old identities.
8. Compiler AST typedef declarations resolve type sugar, including pointer
   types. No handwritten variable/type alias table supplies semantic facts;
   conflicting/cyclic aliases do not authorize a join.
9. The stale memory-lvalue rejection assertion now validates the closed typed
   carrier and keeps semanticRouteApproved false. Scalar expressions outside
   the closed domain still require their own value-flow authority.

## Verification

Tests cover Phase-4 facts transport, three lift bases, machine digest mutation,
GNU role rejection, the memory-only address route through object ingress,
Phase 6D, L2 sidecar and actual native renderer execution. Real AMO fixtures
cover both extra-pointer/+m and memory-only/+A forms for five AMOs at 32/64
bits. The runner regression timeout is 1800 seconds for the expanded matrix.

The current build environment lacks Clang/LLVM development headers, the linked
frontend, llvm-mc, RISC-V GCC and QEMU. Full frontend and RISC-V production
verification must run on the production host. Native test success is not
RISC-V end-to-end acceptance. Report.cpp is separately syntax-checked by GCC.

Run verify_route_contracts.py with --frontend, --clang10, --output (a new empty
directory), and --suite experiment/generated-suite. Inspect regression.log,
run-status.json, summary.json and provider-audit.log. Nonzero results remain
recorded; never weaken proof or skip required dimensions to pass this matrix.
Existing 24 verified cases must not regress. Invalid sources and configured
runtime/environment routes remain separately classified. L3 is independent.

## Limits

Exact, side-effect-free pointer dereferences are supported. General indexed
lvalues, offsets, pointer casts, ambiguous aliases and side-effectful address
expressions need additional address/evaluation contracts. asm-goto remains a
single taken/fallthrough, closed zero/nonzero predicate region with no outputs.
Single-thread atomic observations do not establish concurrent memory-model
equivalence; approved static atomic/order contracts remain necessary.

Local verification: exact route-runner selection 480 passed / 32 skipped;
broader related regression 758 passed / 28 skipped. Skipped tests require
the unavailable production toolchain. Changed Python sources compile, no NUL
bytes were found, git diff --check passed, and Report.cpp passed the native
GCC C++17 syntax check. Classifier/ReportLoad and the full frontend build were
not executable here due to missing Clang/LLVM development dependencies.
