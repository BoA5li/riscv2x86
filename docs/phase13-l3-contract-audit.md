# L3-0: experiment-contract audit and conclusion boundary

This audit describes the repository at the start of Phase 13. A registered
validator is an execution capability, not evidence that an experiment ran.

| Contract or field | Existing declaration | Actual producer in repository | Consumer | Gap |
| --- | --- | --- | --- | --- |
| `experimentContractId` and `microarch` profile | `translation_validation.ValidationPlan` | Explicit evaluation requests; the automatic batch plan writes an empty ID and chooses `build` or `functional`/`architectural` | Profile gate and L3 runner | No automatic per-fragment L3 classification or contract selection |
| `l3-experiment-contract` registration | `validation_runtime_registry` | Registered factory | Validation orchestration | Registration alone never schedules a layer |
| Experiment identity, proof, target strategy, sample protocol and environment constraints | `l3_experiment_runner.ExperimentContract` v1 | User-supplied JSON contract | L3 runner | No translator-produced L3 intent/requirement or automatic contract binding |
| `memory_access` / `logicalAccesses` | Contract's object-relative access events; report protocol | Constructed by `test_l3_experiment_runner.py`; no general source/target platform report producer in this repository | `_logical_checks` | No attributable real-execution access-trace producer |
| `control_flow` / `controlFlow` | Contract's control events; report protocol | Constructed by `test_l3_experiment_runner.py`; no general source/target platform report producer in this repository | `_logical_checks` | No attributable real-execution control-trace producer |
| `statistical` / `metricSamples` | Metric and calibration contract; source/target report schema | Constructed by `test_l3_experiment_runner.py`; no general source/target calibrated measurement producer in this repository | `_metric_summary` | No reproducible real-hardware campaign producer |
| Source/target runner commands and environment | `ExperimentRunnerConfig`, `PlatformReport` | External commands supplied by explicit runner configuration; synthetic subprocess in tests | L3 runner | External controlled runner is a deployment prerequisite, not bundled evidence |
| L3 in paper output | `paper_evaluation` level and `experiment_contract` dimension | Evaluation results when supplied | Paper aggregation | No dedicated L3 eligibility, execution coverage, claim scope or campaign denominators |
| L3 nightly job | `phase10-evaluation-nightly.yml` | Optional self-hosted request path and controlled runner | Evaluation CLI | Job is conditional; its existence does not certify corpus L3 execution |

The repository contains a subprocess protocol test; its script returns
synthetic access, branch and metric reports. It establishes parser and runner
integration, not an RV64-to-x86 experimental result. An external runner might
be configured in a private deployment, but that cannot be inferred from this
repository. The automatic round1/round2 inventory does not configure L3, so
its `L3: not_run` must remain `not_run`; it is not `verified` or
`not_applicable`. A formal `not_applicable` conclusion requires a future
complete intent classifier, not absence of an experiment contract.

## Outcome boundary at L3-0

- `verified`: valid reports and complete evidence satisfy the predeclared
  contract. This proves only the declared experimental conclusion, not
  cross-ISA identity of hardware state, raw counters, or timing.
- `failed`: valid, complete reports demonstrate a contradiction of the
  declared logical or statistical criterion.
- `inconclusive`: contract/configuration/proof binding is stale or invalid,
  runner or capability unavailable, execution fails or times out, report
  missing/malformed, or controlled environment does not match. Such an
  infrastructure failure is not a demonstrated translation mismatch.
- `not_run`: an experiment was required but not called; the batch default
  currently falls here.
- `not_applicable`: explicitly established by a complete applicability
  classifier; it must not be inferred from a blank contract ID.
- `needs_route` and `unsupported`: translation/experiment route conclusions
  require a declared target mechanism and environment; the L3 runner cannot
  infer either from a command failure.

L3-0 changes the L3 runner's infrastructure classification only. It does not
silently schedule L3, invent source/target reports, broaden its verified
claims, or alter already executed L2 semantic comparisons. More detailed
claim scopes, real report producers and campaign aggregation are subsequent
Phase 13 work.
