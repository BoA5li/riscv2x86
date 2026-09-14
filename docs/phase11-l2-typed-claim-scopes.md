# Phase 11 L2 typed claim scopes

L2 results publish a typed conclusion derived from both status and claim scope.
`verified` is therefore not, by itself, an architectural claim. Dimension result v2
also records the approved relation kind, verified properties, and properties that are
explicitly outside the claim.

The supported verified boundaries are:

- `architectural` -> `l2_architectural_verified`;
- `approved_functional_relation` -> `l2_approved_functional_relation_verified`;
- `diagnostic_only` -> `l2_diagnostic_passed`.

An approved functional relation must identify a `runtime_mediated` relation and carry
non-empty verified and not-claimed property sets. Runtime contract version mismatch is
inconclusive. Privileged fallback remains unable to verify when ignored state is absent
from its contract or is declared to escape.

Paper report v3 counts only verified architectural dimensions in the architectural L2
numerator and dimension metrics. It reports approved functional-relation verification
and diagnostic execution separately. Missing required dimension evidence closes the
architectural result as unverified even if an untyped outer L2 layer says `verified`.
