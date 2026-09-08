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
rates. L2 dimensions are shell, operand, memory, control flow, trap, atomic, and privileged;
L3 uses experiment contract. A dimension is verified only when a named composite validator
produces its own evidence. A generic L2 success is not expanded into dimension successes.

An L2 registry composes applicable validators explicitly, for example:

```json
{
  "L2": {
    "type": "composite",
    "validators": [
      {"dimension": "operand", "type": "l2-logical-operand-differential", "config": {}},
      {"dimension": "shell", "type": "l2-effect-trace-differential", "config": {}}
    ]
  }
}
```

Real `config` objects contain the corresponding versioned sidecars and runner contracts.
Dimension names must be unique and sorted. A child failure fails the layer, while unavailable
child tooling makes it inconclusive.

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
