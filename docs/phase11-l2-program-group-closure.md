# Phase L2-C6: program-group evidence closure

This phase separates one program execution from the L2 decisions made for its
member fragments. `ProgramExecutionEvidence` records the source and target
observation identities, their sample-set identity, the execution identity, and
the complete canonical member-fragment set. It is not inferred from an L1
layer evidence hash.

Each L2 layer must contain a valid `L2FragmentResult`. The evaluation linkage
checks its content identity, fragment identity, requirement identity, and exact
required-dimension list before it can enter the program gate. A stale manifest,
an unstructured L2 layer, or a missing required dimension therefore closes as
inconclusive rather than verified.

`ProgramL2GroupResult` verifies only required members. Every required member
must exist, have a closed fragment result at the required claim scope, reference
one available execution identity from every required dimension, and have no
uncovered observable effects. Non-required diagnostic members are retained but
do not change the gate.

Execution samples are deduplicated exclusively by:

```
programId + executionIdentity + sampleSetIdentity
```

The same execution referenced by three fragments therefore contributes one
program execution sample. Conflicting evidence with the same key is rejected.
The batch and paper aggregation paths use the same key instead of summing
fragment-level references.

The translation/evaluation linkage and validation-group schemas advance to v3;
the program execution evidence and closed group result use their own v1
schemas and content identities.
