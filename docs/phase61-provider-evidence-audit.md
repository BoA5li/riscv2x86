# Provider invocation evidence and audit

Baseline: phase60-preflight-terminal-diagnostics,
f501e9d536f81ad00d9863eae68d37206040569e.

The requirement-driven registry previously consumed child provider summaries
in memory and returned only a closed fragment result. Reading evaluation JSON
could not recover those summaries. The registry now captures the exact child
result, normalized ingress result, exceptions, provider definition and
per-dimension central assessments once per actual invocation. Declared replay
observations are copied into content-bound snapshots at provider return time,
before another invocation can replace the original filename.

A unique invocation group binds fragment, requirement, resolved plan and full
translation context. It is distinct from the execution identity: multiple
invocations may share one program execution. Results are atomically written,
read back, and committed by an index. A v3 fragment result references this
index and includes the reference in its evidence identity. Persistence or
immediate audit failure returns inconclusive with precise persistence-stage
information; captured raw results are retained in that diagnostic when possible.
No provider execution disposition is fabricated when an invocation throws.

Schemas:
- riscv2x86.l2-provider-invocation-result.v1
- riscv2x86.l2-provider-invocation-index.v1
- riscv2x86.l2-provider-index-reference.v1
- riscv2x86.l2-fragment-result.v3
- riscv2x86.auto-logical-operand-observation.v2
- riscv2x86.l2-coverage-diagnostics.v3

Legacy fragment-result v2 remains parseable, but cannot satisfy the new provider
audit. It is never upgraded by inventing records. Paper and L3 typed consumers
recognize v3; paper/aggregate artifact reload also audits v3 provider references.
The outer translation-validation layer schema is unchanged: its detail carries
the independently versioned fragment result.

The reader follows exact references inside the case root, rechecks hashes and
plan/context/provider bindings, replays evidence validation according to
not_produced/partial/complete, and compares each central dimension result and
its five identities. It separately preserves provider-reported status and
central acceptance. Built-in operand snapshots retain the boundary/internal/
dependency trace payloads needed to recompute trace digests. Effect snapshots
rebuild dimension projections from saved events and approved relation authority.
Other registered providers retain their original result contract; this layer
cannot invent missing experimental observations for them.

Coverage now adds providerInvocationCounts, auditedProviderExecutionCounts and
providerArtifactAuditCounts. Existing providerExecutionCounts is explicitly
labelled legacy inference for compatibility. Audited execution counts group
provider-reported execution dispositions by binding kind, provider ID and
execution identity; central verified/nonverified invocation counts are separate.
They must not be described as a count of dimensions or independent samples.

Run the real scalar/fence/downstream production tests on the experiment host.
Then use a fresh generated-suite directory and run:
python3 -m riscv2x86_py.l2_provider_artifacts --batch PATH/batch-evaluation.json
Capture nonzero exit codes in shell if/else; do not enable set -e for expected
negative experiments. A missing or altered committed provider artifact must
make the independent audit fail even if a stored summary says verified.

This change does not extend asm-goto, atomic, runtime-environment or L3 semantic
capability. No real cross-ISA experiment is claimed from skipped tests here.

Local validation: 353 related Python tests passed; 6 real cross-toolchain tests
skipped. Additional targeted artifact/registry checks passed after final hash
binding review. Empty audits return not_applicable (exit 2), not a passing
experiment. These are targeted regressions, not a claim of a full Python suite
or an executed generated-suite on this host.
