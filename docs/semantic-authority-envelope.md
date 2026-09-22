# Semantic authority envelope

`riscv2x86_py.semantic_authority` is the common fail-closed ingress contract
for authoritative frontend/decoder facts.  It does not make a Phase 6 route
applicable by itself.  A route must explicitly consume a validated payload and
retain its authority identity in its proof artifacts.

Every envelope binds one fact to all of the following:

- the exact source digest;
- the exact fragment identity;
- a registered producer and producer version;
- one of the seven typed fact kinds;
- a content-derived authority identity;
- an explicit completeness decision and canonical reason codes.

Callers load a bundle with `semantic_authority_bundle_from_dict`.  They must
provide the expected source digest and fragment identity, a closed producer
registry, and the decoder/value-node identities produced for that fragment.
The loader rejects stale bindings, unsupported schemas, unregistered
producers, unknown node references, altered content identities, duplicates,
and conflicting claims for the same semantic object.

The typed payload families are:

- `MemoryOperandBoundaryFacts`;
- `OperandValueFlowFacts`;
- `StructuredControlFlowFacts`;
- `AtomicOperationFacts`;
- `PrivilegedOperationFacts`;
- `InstructionStreamSyncFacts`;
- `CsrOperationFacts`.

`make_semantic_authority_envelope` derives completeness from required fields.
A missing field produces an incomplete envelope with a precise reason code. A
serialized artifact that claims `complete=true` while omitting a required
field is malformed and is rejected rather than silently downgraded.

`adapt_legacy_authority` is the only compatibility bridge. It deliberately
does not reverse-map registers, p-code text, mnemonics, or legacy field names
to decoder nodes. Its result is always incomplete and carries both the legacy
schema identity and missing-field diagnostics. Consequently, compatibility
keeps old pipelines inspectable without granting them new semantic authority.
