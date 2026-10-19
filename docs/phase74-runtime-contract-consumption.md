# Phase 74: runtime contract consumption and evidence boundaries

## Implemented

* Record per-source contract resolution and content identities without treating file discovery as semantic approval. Forward CSR, instruction-sync, privileged and provider directories through the regression runner.
* Separate unknown CSR control flow from proven whole-function requirements. Preserve the original failure stage and reasons.
* Validate the actual runtime ABI, source implementation, approved operation and counter domain before rendering. Bind compiler operand indexes and source/fragment identity. Use an opaque separate-translation-unit call with explicit source shell barriers and no LTO.
* Emit and replay canonical CSR approval artifacts. A failed runtime artifact cannot fall through into a weaker scalar materializer.
* Add instruction-sync registry v3 with explicit local-hart execution/domain assumptions, replayable approval and a dedicated zero-operand L2 materializer.
* Add an explicit instruction-visibility provider with pinned execution, program/runner identities, execution plan, raw trace retention and per-dimension observations. It consumes actual harness events. Its probe language is bounded; passing finite probes does not prove arbitrary concurrent instruction visibility.
* Prevent privileged state traces from claiming shell semantics they do not observe.
* Generate build/riscv2x86-runtime-build.json after runtime compilation. New runtime routes verify archive, compiler, source/header and build-contract identities before consuming the library. Legacy routes retain their previous behavior.

## Scope and remaining work

This is conditional support, not a declaration that cases 024/029 now verify by default. Missing platform contracts must still yield a route requirement. Contracts are externally supplied assumptions and must describe the actual experiment.

The checked CLOCK_MONOTONIC helper implements a functional monotonic-nanosecond observation only. It aborts on unavailable execution rather than returning a fabricated zero. It does not implement exact architectural rdtime/cycle/instret equivalence. A strict CSR counter EEI backend with matching clock, privilege/access/trap and scheduling semantics, plus corresponding L2 observations, remains necessary for strict architectural counter verification.

Instruction-sync v3 currently supports the explicitly bound local-hart, ordinary coherent memory domain and the shipped x86 local serializing protocol. It does not cover remote harts, arbitrary memory types or arbitrary generated code. The harness remains a trusted explicit observation producer whose applicability/noninterference must be justified. Existing v2 contracts do not acquire v3 approval implicitly.

L3 remains separate and must not inherit an L2 verdict.

## Configuration

The runner accepts --csr-architecture-directory, --csr-authority-directory,
--csr-environment-contract-directory, --instruction-stream-sync-directory,
--privileged-config-directory, --l2-provider-directory, --l3-provider-directory,
--harness-directory and --atomic-authority-directory. Supply only real manifests;
no permissive platform fixture is installed automatically.

Per-source inventory contract-resolution.json distinguishes missing files from
resolved-but-not-yet-validated files. Inspect this together with route decisions,
preflight, requirement staging, dimension results and provider audit.

Instruction visibility providers use validatorType l2-instruction-visibility-harness,
config schema riscv2x86.instruction-visibility-runner.v1 and observation schema
riscv2x86.instruction-visibility-observation.v1. They provide only memory_effects
and shell_semantics. See test_instruction_visibility_production.py for protocol
fixtures: mocked protocol tests are not real RISC-V execution evidence.

## Validation

Local selected regression: 731 passed, 38 skipped (Python 3.12). Tests include
actual native compilation/execution of checked clock and x86 self-modifying-code
probes, runtime archive provenance, rejection mutations, approval replay and
provider persistence. The skipped tests require unavailable production tools.
CMake, the real frontend, RISC-V compiler and QEMU were unavailable here; no
claim is made that frontend rebuild or generated-suite completed locally.

Run experiment/verify_route_contracts.py in the production toolchain. Its output
directory must be new and empty. A nonzero generated-suite status is a batch
verdict, not by itself proof of an orchestration failure. Read summary.json and
case-level reasons. Preserve raw artifacts and separately inspect L3 coverage.
