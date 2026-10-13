# Explicit environment contracts for environment-dependent routes

The automatic translator remains fail-closed when an operation depends on
facts outside the source program.  A route is enabled only by a configuration
file bound to the exact source digest and frontend fragment identity.  Merely
passing `--allow-functional-fallbacks` never creates missing environment
facts.

## Batch configuration

For a source path `case.c`, a configured run may supply:

| Route | Batch option | File |
| --- | --- | --- |
| ECALL/WFI | `--privileged-config-directory DIR` | `DIR/case.c.privileged-environment.json` |
| instruction-stream synchronization | `--instruction-stream-sync-directory DIR` | `DIR/case.c.instruction-stream-sync.json` |
| CSR frontend facts | `--csr-authority-directory DIR` | `DIR/case.c.csr-authority.json` |
| CSR runtime/counter contract | `--csr-environment-contract-directory DIR` | `DIR/case.c.csr-environment.json` |

The corresponding source-relative layout is preserved for recursive corpus
inputs.  Missing files are not synthesized: the ordinary strict run keeps the
existing `needs_route` or `unsupported` result.

## ECALL and WFI

The privileged environment envelope is the authority for the execution
profile, runtime contract set, target profile, and operation-specific route.
It is checked against the Phase-4 privileged execution sidecar and the exact
registered adapter.  ECALL cannot be mapped directly to x86 `syscall` without
an ABI-, service-, address-space-, error-, and continuation-equivalent
contract.  WFI architectural translation requires the interrupt, delegation,
virtualization, wakeup, scheduler, and spurious-wakeup relations.  A
pause/yield/sleep contract is only a functional wait-intent relation and also
requires `--allow-functional-fallbacks`.

## Instruction-stream synchronization

The independent v2 registry binds a finite modified-code range to data-write
publication, instruction-fetch visibility, scope, coherence, invalidation,
CPU-profile, runtime-adapter, and completion relations.  A data-cache flush is
insufficient.  A no-op is accepted only when the contract contains a positive
environment visibility guarantee.

## CSR counter observations

`riscv2x86.csr-environment-contract.v1` contains one content-addressed,
source- and fragment-bound route.  It packages the Phase-6C effect mapping,
the complete counter relation, and the registered Phase-6F recipe.  The
counter relation explicitly records epoch, frequency/scale, monotonicity,
wraparound, scope, migration, serialization, target mechanism, error bound,
availability, and trap policy.

An `architectural-equivalence` contract requires identical epoch, unit scale,
and zero error.  A `functional-monotonic-observation` contract is usable only
under the functional fallback policy and cannot receive an architectural
claim.  The source effect identity must match the independently supplied CSR
authority; the renderer target operation and runtime version must match the
Phase-6C mapping.  Any mismatch therefore remains a route/proof failure rather
than being repaired from the CSR name or inline-assembly text.
