# Phase 75: typed CSR result flow and checked value-shell contracts

## Changes delivered

* Production CSR joins consume the compiler candidate's complete downstream-use enumeration, value nodes and closure identity. They no longer fabricate `output_escape_facts=False` for every operand. Legacy/manual joins retain their previous conservative boolean gate.
* A returned scalar, expression result, branch condition, downstream asm input or discarded value is distinct from hidden architectural-state escape. Unknown uses remain incomplete. Current compiler memory-store uses that lack complete object authority remain rejected; this change does not declare them supported.
* Source-model identity v3 includes explicit state-escape facts and whole-function requirement provenance. Missing escape evidence is not converted into a proven escape by matching a diagnostic string. Existing conservative semantic-class/dataflow restrictions remain.
* Runtime approval replay checks compiler result-flow snapshots. A rehashed proof cannot remove a result flow, redirect a recipe input, or inject an unused immediate input.
* Runtime shell v2 supports one unsigned 64-bit scalar result/input with separate `=r`/`r`, a `+r` carrier, or a discarded result. It requires a valid compiler envelope, direct integer carriers, side-effect-free unqualified types, exact access/index coverage and one opaque call. Multiple effects, arbitrary expressions, narrow conversions, matching constraints and memory operands retain their explicit gates.
* Checked scratch-state ABI functions implement read/write/set/clear with old-value returns. Invalid context/version/profile/token aborts as an execution precondition failure rather than returning a fabricated zero. Unchecked legacy functions remain ABI-compatible, but cannot receive new production logical-state approval.
* A suppressed CSR result no longer requires a nonexistent output value node. This does not suppress the actual CSR operation, access permission or trap obligation.
* `experiment/summarize_route_run.py` reads case-level route decisions, embedded L2 dimensions, execution identities, contract discovery and artifact errors. Optional baseline comparison detects previously verified case/dimension status regressions. It never edits verdicts.

## Supported boundaries and unfinished work

These are general fact/ABI fixes, not a claim that cases 024/029 now verify.
The checked scratch ABI is a bounded logical-state implementation, not automatic privileged hardware emulation. Its context ownership/lifetime, permission/trap and surrounding state relations still need an approved source model. No incomplete ISA catalog entry is bypassed to reach it.

Still required for the larger plan:

* Real source-compatible counter EEI backend and observations for strict time/cycle/instret claims. CLOCK_MONOTONIC remains functional-only.
* Actual platform instruction-sync harness and applicable code-object mapping; cross-hart/migration and dynamically generated source ISA code need independent mechanisms.
* Complete source facts for memory sinks, expression conversions, RV32, multiple CSR effects and broader GNU constraints.
* General write/RMW production-chain verification through real frontend, source runner, Phase 6D, L2 and publication. Native ABI tests do not establish this.

Do not fill those gaps by granting permission from the ISA profile, copying a target value into source evidence, widening comparison tolerances or setting proof booleans.

## Reproduction

Use the existing `experiment/verify_route_contracts.py` with a new empty output directory and the explicit Clang 10 path. New tests are included in its selected regression list. Supply platform/provider directories only when they contain actual applicable contracts.

After execution:

```
python3 experiment/summarize_route_run.py --results "$RESULT_ROOT" --output "$RESULT_ROOT/route-summary.json"
```

To compare against a previous production run, add `--compare /absolute/path/to/previous/run` and use a new output filename. Status preservation is checked separately from identity/semantic validation. Generated-suite nonzero verdicts are recorded data; they do not close an interactive shell.

The runtime library must be rebuilt because the ABI implementation source changed. The CMake provenance hook will regenerate its source/archive/compiler identities. New approvals and requirement artifacts must be regenerated; stale approvals are not silently migrated.

## Local validation record

Selected runner regression plus CSR value-flow/model/field/plan/catalog/environment,
automatic batch and privileged-runner tests: 793 passed, 38 skipped. Native tests
compile and execute the actual checked C runtime at -O2 with separate objects
and no LTO. Protocol/proof fixtures are identified as such and are not claimed
as frontend or RISC-V execution. Static Python compilation and diff whitespace
checks passed. CMake, RISC-V GCC and QEMU were unavailable in this environment,
so real frontend rebuild and generated-suite were not executed here.
