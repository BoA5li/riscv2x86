# L2 memory operand boundary authority

Automatic L2 memory validation is enabled only after one content-bound
`AuthorityMaterializationDecision` proves all of the following for the same
fragment:

- the translation proof preserves architecture and compiler-shell semantics;
- a compiler declaration identifies the base pointer and stored/loaded value;
- a compiler parameter-object or harness contract supplies the logical object
  identity, finite size, alignment, alias domain, and address space;
- the object-relative offset and access width are within those bounds;
- the source value width and operand value-flow binding agree; and
- the semantic profile and memory access kind agree.

Runtime pointer values are never accepted as object identities. The automatic
aligned-memory harness declares a 32-byte parameter object explicitly in the
compiler boundary metadata; the materializer no longer invents that size from
the observed offset.

The same decision is consumed by the authority materializer, eligibility
classifier, and requirement-driven provider resolver. Its identity covers the
complete decision payload. A missing, stale, cross-fragment, or incomplete
decision therefore remains `inconclusive`/`not_run` and cannot select a memory
provider.

Stable primary diagnostics include:

- `L2_MEMORY_OBJECT_IDENTITY_MISSING`
- `L2_MEMORY_ADDRESS_BINDING_MISSING`
- `L2_MEMORY_BOUNDS_UNPROVED`
- `L2_MEMORY_ALIGNMENT_UNPROVED`
- `L2_MEMORY_VALUE_FLOW_UNPROVED`
- `L2_FRAGMENT_IDENTITY_MISMATCH`

Materialized authority records carry the logical object, base and value-node
bindings, offset, width, required/proven alignment, bounds relation, alias
domain, address space, exact source/target effect relation, and shell-facts
identity. Removing any required coordinate invalidates materialization rather
than weakening the relation.
