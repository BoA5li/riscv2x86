# Per-fragment L2 value-flow and execution authority

Phase 20 closes the authority gap after the fragment-capable provider is
registered.  It does not relax provider applicability or infer value flow from
operand spelling.

## Authority model

Each compiler `GCCAsmStmt` exports a source-range candidate and its ordered
declaration identities.  A translated fragment is joined to exactly one
candidate by its source range.  The resulting `FragmentOperandBoundary`
contains fragment-local input/output bindings and live-in/live-out value-node
identities.  Declaration identity, rather than symbolic operand name, is the
only basis for a value-flow edge.

All boundaries in a function form a `FragmentDependencyGraph`:

- no internal edge selects `shared_independent` execution;
- an acyclic internal edge selects a `composite` observation contract;
- an incomplete boundary or cycle selects `inconclusive`.

The graph creates one `ProgramExecutionAuthority` shared by its member
fragments.  Runtime execution evidence binds that authority to the source and
target trace digests, harness digest, seed and input domain.  Therefore all
fragments observed in the same program execution share an execution identity,
while observation identities remain scoped by fragment, dimension and side.

## Fail-closed rules

No L2 verification is emitted when any of the following occurs:

- a boundary is attached to a different fragment;
- an output has no proven live-out binding;
- the dependency graph is cyclic;
- source-range binding is absent or ambiguous;
- an operand declaration/value node is missing;
- identically named operands have different compiler declaration identities.

Legacy single-fragment input remains on its existing authority path.  The new
path is selected only when compiler-owned fragment candidates are present.

## Regression coverage

`test_l2_fragment_execution_authority.py` covers the successful two-fragment
composite case and the swapped-boundary, missing-live-out, cyclic-dependency,
and same-name/different-identity negative cases.
