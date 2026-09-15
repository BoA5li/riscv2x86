# Phase 10 paper evaluation contract

The paper path deliberately separates three statistical objects:

1. an independently curated oracle fragment is the denominator for translation coverage;
2. a declared program, single-candidate, or group execution is one validation unit;
3. a source program is the resampling cluster for confidence intervals.

An oracle must be created before translating the corpus. Its `sourceIdentity`, source-slice
digests, paths, byte ranges, categories, and required semantic dimensions are checked again
when aggregation runs. Attempt IDs are not oracle IDs and must never define recognition
coverage.

## Execution

Run every declared evaluation, archive source and attempt evidence, generate the corpus
manifest, and render the paper report with one command:

```bash
PYTHONPATH=pytools python -m riscv2x86_py.corpus_evaluation_cli \
  --execution-plan experiment/paper-corpus-execution.json \
  --output-directory experiment/run-001
```

The destination must not exist. Keep the complete directory; it contains generated requests,
per-evaluation work/replay artifacts, immutable source and attempt evidence, the generated
paper corpus manifest, and the report.

To re-render an already completed, integrity-checked corpus manifest:

```bash
PYTHONPATH=pytools python -m riscv2x86_py.paper_evaluation \
  --corpus-manifest experiment/run-001/paper-corpus-manifest.json \
  --output-directory experiment/report-replay
```

## Attribution modes

- `program`: one result for the complete candidate program; it is never copied into fragment
  correctness rows.
- `single_candidate`: exactly one selected attempt is materialized and exactly one oracle
  fragment is named.
- `group`: only the explicitly sorted attempt set is materialized and the group is one
  validation sample.

Every non-program evaluation request must contain `validationUnit`, `validationGroupId`, and
the canonical `selectedAttemptIds`. The paper manifest separately names the matching
`oracleFragmentIds`. The aggregator rejects mismatched attribution.

## Metrics

Coverage stages are recognition, modeling, routing, candidate generation, proof approval,
and rendering. Validation reports unconditional and predecessor-conditional L0/L1/L2/L3
rates. Canonical L2 dimensions are `logical_operands`, `memory_effects`, `control_flow`,
`shell_semantics`, `trap_semantics`, `privileged_state`, and `atomic_memory_order`;
L3 uses experiment contract. A dimension is verified only when a named composite validator
produces its own evidence. A generic L2 success is not expanded into dimension successes.
The current `riscv2x86.paper-metrics.v2` policy closes L2 denominators over
oracle fragments and records every denominator in JSON and Markdown; see
`phase11-l2-paper-metric-closure.md`.

The automatic path does not choose a fixed L2 mode before translation.  It consumes the
versioned requirement manifest after translation and resolves providers per fragment:

```json
{
  "L2": {
    "type": "requirement-driven",
    "config": {
      "schemaVersion": "riscv2x86.l2-requirement-driven-registry.v1",
      "requirementManifestPath": "${TRANSLATED_REPORT}.l2-requirements.json",
      "fragmentId": "${FRAGMENT_ID}",
      "executionProfile": "rv64gc-user-to-x86_64-user",
      "resolvedPlanPath": "${REPLAY_DIR}/${ATTEMPT_ID}-l2-resolved-plan.json",
      "providers": []
    }
  }
}
```

Providers declare canonical dimensions, a registered validator type, and one of
`explicit`, `automatic`, or `runtime_adapter`.  Resolution priority is in that order.
Every eligible fragment receives a content-addressed
`riscv2x86.l2-resolved-execution-plan.v1`; missing or ambiguous bindings remain in the plan
as `not_run`/`inconclusive` and prevent L2 verification.  A provider may cover multiple
dimensions and is executed once per attempt.  Additional providers can be registered without
changing the evaluator or paper aggregator.  Source-bound explicit provider manifests may be
supplied to the automatic CLI with `--l2-provider-directory`; they use schema
`riscv2x86.explicit-l2-providers.v1` and override automatic providers for their dimensions.

Real provider `config` objects contain the corresponding versioned sidecars and runner
contracts. Dimension names must be unique and sorted. Registry schema v2 rejects legacy aliases such as
`operand`, `operands`, `effects`, and `shell`. Requirement-manifest v1 data must be converted
with the explicit `migrate_l2_requirement_v1_to_v2()` API; normal parsing never migrates or
repairs it. Each execution is closed into content-addressed
`riscv2x86.l2-dimension-result.v2` members and one
`riscv2x86.l2-fragment-result.v2`. A verified dimension binds the authority, source and
target observations, approved effect relation, and execution identities. The fragment result
retains both `requiredDimensions` and typed `dimensionResults`; a missing required member,
an invalid content hash, or an incomplete identity chain cannot verify. Additional diagnostic
members do not change the required set. The aggregate claim is `architectural` only when
every required verified member has architectural scope. A child failure fails the layer,
while unavailable child tooling makes it inconclusive and an unexecuted required binding is
retained as `not_run` in the fragment result.

All intervals use program-cluster bootstrap. The JSON and CSV outputs retain numerators,
denominators, cluster counts, confidence level, resample count, and the bootstrap unit.

## Real corpus workflow

`.github/workflows/phase10-paper-evaluation.yml` keeps fixture tests and real corpus execution
in different jobs. Configure a self-hosted runner with the `paper-corpus` label and repository
variables:

- `PAPER_CORPUS_RUNNER_ENABLED=true`
- `PAPER_CORPUS_EXECUTION_PLAN_PATH=/absolute/path/to/paper-corpus-execution.json`
- `PAPER_CORPUS_CONTAINER_IMAGE_DIGEST=sha256:...`

If the runner is not configured, the workflow publishes an explicit inconclusive capability
record. Real runs retain all evidence for 90 days even when validation fails.
