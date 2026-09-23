# Independent instruction-stream synchronization route

RISC-V `fence.i` is not an ordinary memory-ordering fence. Its relevant
relation begins with writes to a code range and ends when later instruction
fetches are guaranteed to observe those writes. The translator therefore does
not lower this semantic family through `mfence`, a generic compiler barrier,
or the ordinary fence candidate catalogue.

## Registry ingress

Automatic runs accept a content-bound registry from
`--instruction-stream-sync-directory`. For source `case.c`, the file name is
`case.c.instruction-stream-sync.json` and its schema is
`riscv2x86.instruction-stream-sync-registry.v2`. The automatic translation
command verifies `sourceDigest` before forwarding the registry to the backend.
Contracts are resolved by exact `(sourceFragmentId, targetEnvironmentId)`.

Every contract records:

- a finite modified-code object, offset, length, and address-space identity;
- data-write publication and instruction-fetch visibility relations;
- local-hart or multi-hart scope;
- the cache/coherence model and, for multi-hart scope, an invalidation or
  shootdown relation;
- the target CPU profile;
- a registered runtime adapter or cache-maintenance API;
- a completion/acknowledgement relation;
- compiler volatile, memory-ordering, and `cc` shell preservation.

## Closed lowering alternatives

The registry may select a registered runtime helper, a registered platform
cache-maintenance API, or a proved no-op. Executable routes must match a shipped
runtime manifest, including symbol, header, and library. A helper that only
flushes data cache but does not prove instruction-fetch visibility is rejected.

A no-op contract requires a positive `environmentNoopGuaranteeId`; general x86
coherence is not treated as such a proof. The emitted no-op route still retains
the GNU compiler `memory` barrier needed to preserve the original inline-asm
shell. The compiler barrier is not used as evidence for architectural
instruction visibility.

## Phase boundaries

The route is represented independently in its approval artifact:

- Phase 6B identifies the registered lowering kind;
- Phase 6C binds the exact contract and target profile;
- Phase 6D checks code range, publication, fetch visibility, scope, coherence,
  invalidation, CPU profile, adapter identity, completion, and compiler shell;
- Phase 6F renders only an approved helper/API call or proof-backed no-op.

Missing contracts and failed obligations remain `needs_route` with a precise
`ISS_*` reason. `--allow-functional-fallbacks` does not authorize this route.
The former capability-triggered local helper and two-field no-op shortcut are
not consulted.
