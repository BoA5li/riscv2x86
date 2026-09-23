# Explicit privileged environment routes

ECALL and WFI remain unsupported in the default automatic translation mode.
They become candidates only when `--privileged-config-directory` contains a
content-bound `<source>.privileged-environment.json` manifest using
`riscv2x86.privileged-environment.v1`.

The manifest is an envelope over the existing versioned execution, runtime,
functional-observability, and ignored-state authorities. It does not infer
facts from assembly text. The loader verifies the source digest, frontend
fragment identity, execution profile, runtime contract-set identity, route
kind, and registered adapter identity before invoking the backend.

Required top-level fields are:

- `schemaVersion`, `sourceDigest`, `fragmentId`, `operation`, and
  `relationKind`;
- `sourceExecutionProfile`, `runtimeContractSet`, and `targetProfile`;
- an operation-specific `routeContract`;
- `pipelineInputs` referring to files below the configuration directory.

An ECALL route must describe its trap handler, source service ABI, service and
call-number identities, argument/result/error mappings, memory effects,
clobbers, continuation, and address-space relation. Its target mechanism must
be a registered runtime adapter. A direct x86 `syscall` declaration is rejected
because ABI equivalence cannot be inferred.

A WFI architectural route must describe interrupt enable/pending state,
delegation, virtualization, trap/wakeup continuation, spurious wakeup policy,
the target wait adapter, and scheduler interaction. Architectural contracts
cannot list any unpreserved semantics.

A WFI `pause`, yield, or sleep route is accepted only with
`relationKind: functional_fallback`, the command-line functional policy flag,
and a registered functional contract. It must explicitly record
`waiting_intent` as preserved and both `architectural_interrupt_wakeup` and
`architectural_state_transition` as not preserved. Such a route is proved and
reported as functional equivalence only; it cannot enter the strict runtime
registry or receive an architectural verdict.

Malformed, stale, incomplete, or conflicting manifests fail closed with a
`PRIV_ENV_*` reason code. Missing manifests do not change default behavior.
