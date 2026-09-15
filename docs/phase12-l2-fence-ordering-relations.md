# Phase 12 L2-E5: fence ordering relations

Automatic fence validation is based on a finite logical ordering domain, not
on successful process termination.  Phase 6 emits
`riscv2x86.l2-fence-proof-facts.v1` only when the normalized source barrier is
complete, is not an instruction-visibility operation, and the proof-selected
renderer contract is in the registered fence contract set.

The authority materializer creates three source effects (`before:read`,
`fence:0`, and `after:write`), one typed ordering edge from the read anchor to
the write anchor, and exact or strengthened approved relations for all three
effects.  Contract ID and renderer version are bound into the proof facts.
Missing anchors, stale identities, unknown contracts, and version mismatches
remain inconclusive rather than being inferred from the replacement text.

The source and target observations use
`riscv2x86.l2-fence-ordering-observation.v1`.  Each contains a ReadMemory,
Fence, and WriteMemory event with explicit execution order and predecessor
identities.  The fence payload declares the compiler-ordering, hardware-
ordering, ordering-strength, scope, and contract identity supplied by proof
authority.  The process `completed` marker is only an execution prerequisite;
it cannot itself satisfy L2.

The comparator requires a complete approved event set, validates the source
and target ordering graphs, and checks every approved required edge.  An exact
relation requires equal ordering semantics.  A strengthened relation requires
the target to retain every source compiler/hardware property and to cover the
source ordering and scope.  A missing target edge is a semantic failure.

The automatic provider `automatic-l2-fence-ordering-v1` supports only the
`fence` pattern.  `instruction_visibility_fence` instead requires the distinct
`instruction_visibility` capability and a versioned explicit provider/runtime
contract.  Thus `fence.i`, self-modifying code, device I/O, non-coherent
memory, and platform-specific or multi-thread ordering experiments cannot be
silently claimed by the ordinary fence route.
