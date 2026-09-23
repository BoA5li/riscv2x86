# Phase 27: L2 execution and observation evidence closure

An L2 provider may close a required dimension only when it emits a complete,
content-addressed evidence chain.  The requirement-driven registry no longer
creates an execution identity from two observations and no longer substitutes
an artifact-level relation for a relation omitted by the provider.

## Execution-plan authority

`riscv2x86.l2-execution-plan.v1` binds:

- the approved translation proof;
- the target environment/route declaration;
- the semantic/operand/memory authority;
- the approved effect-relation set;
- the registered runtime contract and version;
- the exact harness identity; and
- the selected provider and fragment.

Declared environment and runtime names are domain-separated and hashed.  They
are not treated as pre-existing authority hashes.  Changing the environment,
runtime, provider, fragment, or harness changes the execution-plan identity.

## Provider evidence

Registered providers return `riscv2x86.l2-provider-evidence.v1` with explicit
authority, relation, plan, environment, runtime, harness, execution, source
observation, and target observation identities.  The central closer checks the
authority and relation against the translation artifact.  A missing field,
unknown evidence schema, or mismatched authority produces an `inconclusive`
dimension with a precise `l2.provider-evidence.*` reason.

The five identities published by every verified required dimension remain:

- `authorityIdentity`;
- `effectRelationIdentity`;
- `executionIdentity`;
- `sourceObservationIdentity`; and
- `targetObservationIdentity`.

No required dimension is weakened to optional.  Provider selection failures
remain `not_run`; incomplete authority or evidence remains `inconclusive`.

## Negative guarantees

Tests remove each identity independently, exchange authority/relation bindings,
and vary harness and environment inputs.  None of these cases can produce a
verified dimension.  Compatibility providers that have not adopted the v1
evidence schema remain callable, but their positive result cannot close a
required dimension.
