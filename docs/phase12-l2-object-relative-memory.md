# Phase 12 L2-E4: object-relative memory evidence

The automatic memory route is proof-driven and fail-closed.  Phase 6A exports
`riscv2x86.l2-memory-proof-facts.v1` from its structured source model.  The
facts identify one address operand, one scalar value operand, a proven byte
offset and width, natural alignment, non-atomic ordering, and a finite alias
class.  No filename, function name, assembly text, mnemonic, or runtime
address participates in this classification.

Before candidate staging, the frontend/compiler boundary binds those facts to
typed operand declarations and one `L2MemoryObjectAuthority`.  The authority
sidecar owns the object identity, bounds, readable/writable range, lifetime,
alias class, and exact approved effect relations.  Missing or ambiguous
bindings leave the dimension inconclusive; the validator does not repair or
infer them.

The automatic harness creates an aligned logical byte object sized by the
authority, runs a bounded canonical value domain, and reports only the value
at the approved object-relative coordinate plus whether any byte outside the
approved effect changed.  `riscv2x86.l2-memory-observation.v1` contains no raw
pointer, stack address, ASLR address, spill, or helper-internal access.

The exact comparator checks the complete approved source/target event sets and
then compares event kind, logical object, offset, width, canonical value,
alignment, atomicity, memory order, execution order, and predecessor list.
Split or merged target accesses require an explicit relation/harness and are
not accepted by the automatic route.

The capability provider `automatic-l2-memory-object-v1` jointly supplies
`logical_operands`, `memory_effects`, and `shell_semantics` for `memory_load`
and `memory_store`.  This prevents a second generic operand provider from
ambiguously claiming pointer-bearing fragments.  Explicit providers retain
the resolver's normal precedence for shapes outside the automatic contract.
