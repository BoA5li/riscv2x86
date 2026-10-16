# Phase 58: typed privileged presence in effect production

Baseline: remote phase57-observer-cc-shell-compatibility,
3e18de3a9fac13800efcf95d3a460262a42c3d96.

The Phase-6 source model carries a privileged adapter even when Phase 5 has
proved that no privileged state is present. Testing adapter object existence
therefore mislabeled ordinary scalar fragments as PrivilegedOperation. The
scalar observer correctly rejected these effects; its gate is unchanged.

The adapter now exposes tri-state semantic_presence. Proven absence requires
complete typed classification, no effects/classes/counter binding, and
state.present=False. Missing or contradictory classification is unknown and
cannot produce complete effect facts. Actual privileged presence remains true.
For legacy source models with no adapter, the existing absence convention is
retained; a privileged operation without matching typed state is rejected.
Phase-6D reports effect_classification failures with the fragment ID and detail.

The production regression runs the Phase-5 analyzer, source model builder,
candidate planner, constraint derivation, and Phase-6D proof with a nonempty
fragment ID. It covers scalar GNU cc clobbers, serialization round trips,
unknown classification, and real counter presence. No case ID, variable name,
assembly-text heuristic, or runtime sample determines the classification.

Validation here: 94 passed, 6 cross-toolchain tests skipped. One existing counter
functional-fallback test fails with both the baseline and revised effect
producer and was separately reproduced, then excluded from this targeted run.
No generated-suite execution is claimed: Clang/RISC-V gcc/QEMU are unavailable.

Rerun in a fresh directory with Clang 10. Never edit old proof JSON. Normal
production recomputes proof facts, authority and observation identities from
the new payload. For the scalar multi-fragment example, inspect both source
and target effect kinds, relation identities, provider dispositions and final
L2 verdict; a correct scalar classification alone does not establish L2 success.
