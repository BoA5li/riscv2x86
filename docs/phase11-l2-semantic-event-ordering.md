# Phase L2-C5: semantic events and ordering

This phase replaces the flat semantic-event wire format with
`riscv2x86.semantic-event.v2`. Each event carries a fragment identity, a
logical subject, a kind-specific payload, a unique execution order, explicit
ordering predecessors, and a source location bound by file identity.

## Closed validation boundary

`ExecutionObservation` validates the complete event graph without changing
producer output. Event IDs and execution orders are unique, execution order is
the canonical tuple order, predecessor references must resolve, and the graph
must be acyclic. Predecessor arrays retain their original order; neither the
parser nor the explicit observation canonicalizer sorts or deduplicates them.

Memory events use object-relative coordinates and explicitly record value,
offset, width, alignment, atomicity, and memory order. Raw process addresses
are rejected. Branch payloads contain condition, taken state, and continuation;
trap payloads contain cause, continuation, and termination.

## Comparison boundary

Exact memory comparison includes the logical object coordinates and ordering,
so equal bytes at different offsets do not verify. Strengthened fence ordering
is accepted only through an approved `effect-relation.v2` relation. Branch and
trap relations must declare and compare their complete observable payloads.
Runtime-mediated effects still require the approved runtime contract introduced
in L2-C4.

Runtime-helper internal accesses are excluded only by the producer-side
`materialize_observable_semantic_events` operation. A persisted observation is
never silently filtered, repaired, renumbered, sorted, or deduplicated.

## Regression coverage

The phase includes negative tests for duplicate event IDs, unresolved
predecessors, cycles, noncanonical execution order, raw addresses, and equal
memory values at different object offsets. It also covers approved versus
unapproved strengthened fences and undeclared versus explicitly declared
runtime-helper internal events.
