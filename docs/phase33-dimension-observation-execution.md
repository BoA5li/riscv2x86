# Phase 33: provider execution and dimension observations

Phase 33 separates a program execution from the observations derived for each
required L2 dimension.

One provider invocation produces one content-addressed `executionIdentity`.
Its result contains a `dimensionObservations` map whose source and target
identities bind the execution, fragment, exact dimension, side, and underlying
observation evidence.  The central closer selects only the entry associated
with the current resolved binding.  It cannot reuse a logical-operand
observation as shell, memory, or control-flow evidence.

Provider evidence now carries the complete `executionPlan` as well as its
identity.  The closer parses and re-hashes the plan and checks its fragment,
provider, translation proof, environment, semantic operand/memory authority,
effect relation, runtime adapter, and harness bindings against the translation
artifact and provider selection.

The provider evidence schema is `riscv2x86.l2-provider-evidence.v2`.
Execution disposition is mandatory.  A missing or status-incompatible value
is not inferred from incidental fields and fails closed as not executed or
inconclusive.  Precondition rejection, non-execution, executed inconclusive,
executed failure, and executed verification therefore remain distinguishable.
