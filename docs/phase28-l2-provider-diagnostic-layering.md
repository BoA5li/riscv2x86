# Phase 28: L2 provider diagnostic layering

This phase separates an L2 provider's execution progress from its semantic
verdict.  It changes diagnostics only: requirements, authority gates, and
verified/failed comparison semantics remain unchanged.

Providers use `L2ProviderExecutionDisposition` to report one of:

- `precondition_rejected`: authority or applicability failed before execution;
- `not_executed`: no comparison was attempted;
- `executed_inconclusive`: execution began but observations are incomplete;
- `executed_failed`: a complete evidenced comparison found a mismatch; or
- `executed_verified`: a complete evidenced comparison matched.

Precondition rejection preserves the provider's primary reason and does not
expand the expected absence of execution evidence into a list of missing
identities.  Executed inconclusive results retain valid partial identities and
report only missing observation evidence.  Executed failed and verified
results both require the total evidence chain; a missing identity demotes either
result to inconclusive.  Consequently, an unauthorised mismatch cannot be
reported as a semantic translation failure.

Automatic operand and effect providers explicitly mark authority/finding
rejections before execution.  Providers that emit evidence mark their actual
executed disposition.  Legacy inconclusive results with a primary reason and no
execution identities are conservatively treated as precondition rejections;
legacy positive or failed claims remain incomplete until they adopt the typed
disposition and evidence schema.
