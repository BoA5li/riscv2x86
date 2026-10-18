# Phase 71: distinct memory contents and pointer carrier bindings

Parent remote: f680b4761a75ad9306baf66a7fa0d91be5ee88ed
(phase70-register-views-and-memory-profile).

## Defect and correction

Phase 70's memory-only profile correction required every atomic memory operand
index to equal the atomic machine-address operand index. This is valid for a
memory-only address projection but wrong for a GNU memory contents operand
with an independent pointer carrier. Actual 32/64-bit separate-pointer tests
therefore stopped at requirement_classification, before L2 execution. The local
expression fixture incorrectly omitted that GNU memory operand from its source
model and did not exercise the faulty branch.

The compiler/decoder join now emits a strict, versioned atomic-memory-access
binding for each validated expression memory operand. It records both operand
indices, expression/evaluation identities, both compiler value-node identities,
object, offset, access width/mode and read/write effect identities. The new
compiler/decoder join v2 includes the pre-binding payloads in its content hash;
each final binding retains that join payload and validates membership and its
hash. Rehashing a modified binding alone cannot retain the old join authority.
No relation is inferred from variable names, assembly strings or execution values.

Atomic runtime records carrying the new binding explicitly use
atomic-memory-object-runtime.v2. Unknown/missing versioned fields are rejected;
serialization and parsing preserve the binding. Legacy records retain their
existing format. SourceAddressBinding carries the same relation into the source
model. A missing separate-carrier relation is not manufactured from shared
object/declaration identities.

Profile classification validates the actual memory access and the selected
address participant separately. Different operand indices are permitted only
through the closed relation; object, offset, width, address space, effects and
join identity must agree. Every memory operand is checked, including additional
unbound accesses. Scalar read_write operands are not treated as memory addresses.
Pointer-only handling and the explicit legacy same-operand memory-only projection
contract remain; no old identity is silently upgraded.

A content-bound decision retains specific profile binding failures. For such
failures classification rejects before materialization/provider execution, and
keeps the binding root reason rather than derived missing-sidecar noise. The
ordinary non-atomic classifier and independent proof/evidence gates are retained.

## Tests

Fixtures now preserve all GNU operands and their widths/types before closure.
Tests cover pointer-only, separate-memory/pointer and memory-only at 32/64 bits;
runtime semantic propagation; object/range/width/carrier/effect/identity mutation;
versioned snapshot roundtrips; additional uncovered accesses; legacy projection
compatibility; and precise classification diagnostics. The actual 20-AMO tests
also inspect the produced relation, memory profile and production decision.

Local related regression: 614 passed, 36 skipped. Changed Python modules compile;
git diff --check passes. The linked frontend, actual Ghidra pythonRun, llvm-mc,
RISC-V compiler and QEMU are unavailable on the editing host. Skipped production
tests are not successful end-to-end acceptance. Rebuild/run verify_route_contracts.py
on the production host, then inspect run-status.json, regression.log, generated-suite
summary and provider audit. Existing phase69/70 generated artifacts must be
regenerated to obtain the new join/association identities. No verdict is forced
to verified, single-thread output does not waive atomicity/order contracts, and
L3 remains independently configured.
