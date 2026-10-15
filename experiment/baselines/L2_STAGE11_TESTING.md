# L2 repair acceptance tests

The component matrix and the real production tests are separate acceptance
levels. A passing fixture-based test does not establish that the production
frontend emitted a fact or that a cross-ISA executable ran successfully.

| Contract | Tests |
| --- | --- |
| v3 parse, required value node, SHA format, stale identity, migration | `test_l2_typed_authority.py`, `test_l2_stage11_contract_matrix.py` |
| input/output/read-write and all eleven source/sink routes | `test_canonical_l2_operand.py`, `test_l2_stage11_contract_matrix.py` |
| operand field, sink, dependency edge and proof mutation | `test_l2_operand_join_preconditions.py` |
| trace arity, samples, internal values and dependency observations | `test_canonical_observation_materializer.py`, `test_l2_operand_observation_authority.py` |
| emitted/published, pending validation, terminal outcomes, crash, malformed report, classification failure | `test_requirement_staging.py`, `test_l2_stage11_lifecycle.py`, `test_evaluation_runner.py` |
| missing/stale requirements and staging manifest | `test_requirement_artifact_ingress.py` |
| operand-free fence, shell obligations, missing ordering relation, strengthening, real native witness | `test_fence_execution_closure.py`, `test_l2_fence_ordering_relations.py` |
| per-dimension closure, execution payload, partial evidence, precondition noise | `test_l2_evidence_closure.py`, `test_l2_requirement_driven_registry.py` |
| actual compiler candidate through Phase 6D, authority, requirements, resolver, execution and closer | `test_l2_real_production_chain.py` |

## Real production acceptance

Use a freshly rebuilt frontend from this branch, activate the project Python
environment, and select the Clang version used for the experiment on PATH.
The following example assumes the toolchain directory used in earlier runs:

```bash
cd /root/src/poc_trans/path_b/riscv2x86
source .venv-l2/bin/activate
export PYTHONPATH="$PWD/pytools${PYTHONPATH:+:$PYTHONPATH}"
export RISCV2X86_TEST_FRONTEND="$PWD/build/riscv2x86"
export PATH="$PWD/experiment/results/phase33-generated-suite-20261010T093538Z/clang10-toolchain:$PATH"
clang --version
python3 -m pytest -vv -rs pytools/tests/test_l2_real_production_chain.py
```

These tests invoke the actual batch CLI on independent scalar and fence C
sources. They do not inject compiler facts, approve a proof, replace a provider,
or fabricate observations. Installed tool failures fail the test. Missing
frontend/toolchain executables produce explicit skips. **A skipped test does
not satisfy production-chain acceptance.** Use `--basetemp` to retain the chosen
test work location when examining a failure.

The fence execution witness is a before/after call witness combined with the
approved Phase 6D ordering relation. It is not a hardware concurrency litmus
test. Internal scalar values without a registered observer remain inconclusive.

Known unrelated historical test-contract failures must be reported separately;
they must not be converted to xfail merely to make this acceptance suite green.
