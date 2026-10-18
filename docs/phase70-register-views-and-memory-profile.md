# Phase 70: backend register read views and memory-lvalue L2 profiles

Parent remote: bfa7b1d6a20b7b7d7ef0c6d1bd5122f266b020eb
(phase69-fragment-source-range-contract).

## Confirmed defects

Actual RV64 word-AMO p-code reads a four-byte register varnode. The pythonRun
resolver indexed only exact (space, offset, size) register definitions. A parent
register defined at eight bytes was therefore unavailable for this low read.
The actual failures stopped at phase5.authoritative_register_name_unavailable,
not atomic proof or result extension. The old terminal archive omitted that
root reason while retaining it only in verificationDetail/notes.

Memory-only atomic operands keep read_write access and have a separate, closed
address projection. L2 profile construction filtered only access=address and
therefore discarded this existing address fact, producing an incomplete memory
profile before provider execution. The v3 compiler authority upgrade also left
one real-toolchain test asserting v2.

## Implementation and safety boundaries

* The Ghidra query exports a versioned v2 database snapshot with base-register
  metadata and explicit endianness. The bridge locates its query script relative
  to the repository instead of an installation-specific /root path.
* Read-view resolution uses database-defined names, base offsets, sizes and
  bit lengths, with a unique parent and explicitly little-endian layout. No
  numeric offset-to-ABI-name table, inferred XLEN width or test-case ID is used.
* Only same-start low reads may use this fallback. Interior slices, ambiguous
  parents, context registers, unknown/big endianness and partial writes remain
  unapproved. Existing exact register lookup remains unchanged.
* The adapted varnode and canonical Var retain the actual narrow size and a
  frozen, content-addressable RegisterReadView. Canonical ingress rejects a
  view disagreeing with its name, offset or width. No write extension is
  invented; full result extension remains decoder/proof-owned.
* The direct Ghidra API adapter and pythonRun snapshot adapter both consume the
  same bounded view logic. Old unversioned snapshots get exact lookup only.
* L2 profile construction recognizes typed memory operands with address facts
  without relabelling contents access. Atomic memory-lvalue operands must match
  the atomic address index, object identity, join identity and content-addressed
  projection. Missing or inconsistent addresses still make the profile incomplete.
* Pre-candidate terminal rejection records now preserve rule/stage/detail and
  the not-produced/precondition-rejected disposition before attempt archival.
* The real compiler type test requires v3 and validates its range witness while
  retaining pointer/pointee/value-node checks. A test fixture's 32-bit memory
  type is now produced before closure; changing an identity-covered pointer
  type after closure is no longer used to construct that matrix member.

## Validation

Related regression (including the exact route-runner selection): 590 passed,
36 skipped. Tests include actual pypcode decoding/lifting of a word-AMO machine
image using backend-database locations, read versus write boundaries, ambiguity,
endianness, canonical-view mutations, terminal diagnostics, and the 32/64-bit x
pointer/memory-only profile-to-materializer matrix. Python compilation and
`git diff --check` pass.

The editing host lacks llvm-mc, the linked Clang frontend, Ghidra pythonRun and
RISC-V GCC/QEMU. The legacy test_lift.py assembly test cannot execute here due
to missing llvm-mc; it was not changed or reported as passing. The 36 skipped
production tests are not end-to-end acceptance. Run the updated regression
runner on the production host to exercise the actual Ghidra snapshot, frontend,
20 AMO production tests, generated suite and provider audit. New downstream
failures must retain their own reasons; L0/L1 output equality does not waive L2
atomicity/order proof, and L2 does not establish L3.
