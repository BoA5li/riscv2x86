#!/usr/bin/env python3
"""Record route-contract regressions without shell control-flow/pipeline state.

The runner never changes a checkout or removes results. A failed prerequisite
prevents the suite and is recorded; nonzero suite verdicts remain visible.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

TESTS = (
    'test_l3_qemu_dependencies.py',
    'test_l3_memory_trace.py',
    'test_l3_route_applicability.py',
    'test_l3_scalar_trace.py',
    'test_l3_scalar_trace_production.py',
    'test_static_operand_production.py',
    'test_static_operand_real_production.py',
    'test_l3_trace_driver.py',
    'test_l3_memory_trace_production.py',
    'test_l3_production_ingress.py',
    'test_l3_production_acceptance.py',
    'test_l3_authoritative_consumption.py',
    'test_l3_intent_requirements.py',
    'test_l3_provider_resolution.py',
    'test_l3_experiment_runner.py',
    'test_l3_evidence_closure.py',
    'test_l3_attributed_traces.py',
    'test_l3_concurrency_campaign.py',
    'test_l3_statistical_experiment.py',
    'test_l3_specialized_experiment.py',
    'test_l3_batch_coverage.py',
    'test_paper_evaluation.py',
    'test_system_build_profile.py',
    'test_system_build_reproducibility.py',
    'test_privileged_source_completion.py',
    'test_controlled_system.py',
    'test_controlled_system_scope.py',
    'test_controlled_system_production.py',
    'test_system_instruction_ingress.py',
    'test_system_deployment.py',
    'test_l2_system_routes.py',
    'test_system_preparation.py',
    'test_privileged_environment_manifest.py',
    'test_privileged_environment_routes.py',
    'test_phase8_privileged_differential_validation.py',
    'test_csr_access_coverage.py',
    'test_privileged_state_analysis.py',
    'test_csr_state_dataflow.py',
    'test_source_csr_semantic_model.py',
    'test_execution_environment_closure.py',
    'test_mechanism_source_dso_l0.py',
    'test_mechanism_retained_execution.py',
    'test_l0_build_matrix.py',
    'test_mechanism_route_closure.py',
    'test_mechanism_experiment_driver.py',
    'test_local_sync_production.py',
    'test_controlled_time.py',
    'test_mechanism_preparation.py',
    'test_controlled_time_production.py',
    'test_route_acceptance.py',
    'test_route_input_preparation.py',
    'test_visibility_provider_preparation.py',
    'test_l2_blocked_materialization.py',
    'test_csr_pcode_normalization.py',
    'test_automatic_l2_functional_relation.py',
    'test_instruction_visibility_execution.py',
    'test_compiler_instruction_sync_scope.py',
    'test_route_precondition_lifecycle.py',
    'test_route_goals_and_collection.py',
    'test_experiment_environment.py',
    'test_csr_architecture_registry.py',
    'test_csr_family_environment.py',
    'test_csr_context_lifecycle.py',
    'test_csr_environment_contract.py',
    'test_csr_typed_result_flow.py',
    'test_csr_runtime_value_shell.py',
    'test_route_run_summary.py',
    'test_runtime_build_provenance.py',
    'test_instruction_visibility_production.py',
    'test_runtime_contract_consumption.py',
    'test_route_contract_regression_runner.py',
    'test_csr_semantic_closure.py',
    'test_csr_sync_production_contracts.py',
    'test_csr_metadata_ingress.py', 'test_csr_value_flow.py',
    'test_csr_translation_pipeline.py', 'test_instruction_stream_sync_contracts.py',
    'test_atomic_memory_address_binding.py',
    'test_register_read_views.py',
    'test_fragment_source_range.py',
    'test_gnu_operand_contract.py',
    'test_compiler_expression_evaluation.py', 'test_atomic_expression_consumer.py',
    'test_l2_atomic_production.py', 'test_atomic_native_observation.py',
    'test_asm_goto_machine_join.py', 'test_asm_goto_region_closure.py',
    'test_l2_asm_goto_authority.py', 'test_continuation_instrumentation.py',
    'test_l2_precondition_obligations.py', 'test_l2_semantic_profile.py',
    'test_l2_dimension_results.py', 'test_l2_requirement_driven_registry.py',
    'test_batch_evaluation_cli.py', 'test_production_evidence_contract.py',
    'test_compiler_expression_contracts.py', 'test_l2_continuation_trace.py',
    'test_translation_preflight.py', 'test_scalar_fragment_candidate_binding.py',
    'test_production_route_authority.py', 'test_cbranch_and_compiler_type_contracts.py',
    'test_canonical_atomic_operation.py', 'test_atomic_phase5_closure.py',
    'test_l2_materialization_closure.py', 'test_l2_effect_proof_facts.py',
    'test_real_compiler_operand_types.py', 'test_l2_real_production_chain.py',
    'test_asm_goto_structured_authority.py', 'test_asm_goto_contract_guards.py',
    'test_l2_evidence_closure.py', 'test_l2_provider_artifacts.py',
    'test_requirement_staging.py', 'test_requirement_artifact_ingress.py',
    'test_fence_execution_closure.py', 'test_dependency_observer_production.py',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frontend', required=True, type=Path)
    parser.add_argument('--clang10', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--suite', type=Path)
    parser.add_argument('--privileged-config-directory', type=Path)
    parser.add_argument('--l2-provider-directory', type=Path)
    parser.add_argument('--l3-provider-directory', type=Path)
    parser.add_argument('--harness-directory', type=Path)
    parser.add_argument('--atomic-authority-directory', type=Path)
    parser.add_argument('--csr-architecture-directory', type=Path)
    parser.add_argument('--csr-authority-directory', type=Path)
    parser.add_argument('--csr-environment-contract-directory', type=Path)
    parser.add_argument('--instruction-stream-sync-directory', type=Path)
    parser.add_argument('--experiment-environment',type=Path)
    parser.add_argument('--require-verified-case',action='append',default=[])
    parser.add_argument('--acceptance-matrix', type=Path)
    parser.add_argument('--require-no-regression-skips', action='store_true')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        print('Output directory must be empty; existing results were preserved.', file=sys.stderr)
        return 2
    env = dict(os.environ)
    env['PYTHONPATH'] = str(repo/'pytools') + os.pathsep + env.get('PYTHONPATH','')
    clang_directory = str(args.clang10.absolute().parent)
    # Preserve an already selected search environment exactly. Backend build
    # profiles bind PATH; duplicating its first directory invalidates them.
    if env.get('PATH', '').split(os.pathsep)[0] != clang_directory:
        env['PATH'] = clang_directory + os.pathsep + env.get('PATH','')
    env['RISCV2X86_TEST_FRONTEND'] = str(args.frontend.absolute())
    status = {'schemaVersion':'riscv2x86.route-contract-regression.v1',
        'steps':[], 'generatedSuiteExecuted':False, 'generatedSuiteExitCode':None,
        'blockers':[], 'python':sys.executable, 'repository':str(repo)}

    def save():
        (output/'run-status.json').write_text(json.dumps(status, indent=2)+'\n')

    def run(stage, argv, timeout):
        step = {'stage':stage, 'command':argv, 'returnCode':None}
        status['steps'].append(step)
        try:
            with (output/(stage+'.log')).open('w') as log:
                result = subprocess.run(argv, cwd=repo, env=env, stdout=log,
                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
            step['returnCode'] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            step.update(exceptionType=type(exc).__name__, detail=str(exc))
        save()
        print(stage + ': ' + str(step['returnCode']), flush=True)
        return step['returnCode'] == 0

    if args.acceptance_matrix is not None and args.suite is None:
        status['blockers'].append('acceptance-matrix-requires-suite')
    if args.require_verified_case and args.suite is None:
        status['blockers'].append('route-goals-require-suite')
    run('git-head', ['git','rev-parse','HEAD'], 30)
    run('git-branch', ['git','branch','--show-current'], 30)
    if not run('clang-version',[str(args.clang10.absolute()),'--version'],30):
        status['blockers'].append('clang-version')
    elif re.search(r'clang version 10\.', (output/'clang-version.log').read_text()) is None:
        status['blockers'].append('clang-major-version-is-not-10')
    if not status['blockers']:
        tools = {name:shutil.which(name,path=env['PATH']) for name in
                 ('llvm-mc','riscv64-linux-gnu-gcc','qemu-riscv64','gcc')}
        (output/'production-tools.log').write_text(json.dumps(tools,indent=2)+'\n')
        status['productionTools'] = tools
        if any(value is None for value in tools.values()):
            status['blockers'].append('production-tools')
    if args.experiment_environment is not None and not status['blockers']:
        if args.suite is None:
            status['blockers'].append('experiment-environment-requires-suite')
        elif not run('experiment-environment',[sys.executable,'-m','riscv2x86_py.experiment_environment',
                '--manifest',str(args.experiment_environment.absolute()),'--source',str(args.suite.absolute()),
                '--output',str(output/'experiment-environment.json')],60):
            status['blockers'].append('experiment-environment')
    if not status['blockers']:
        if not run('frontend-build',['cmake','--build','build','-j2'],600):
            status['blockers'].append('frontend-build')
        if not status['blockers'] and not run('regression', [sys.executable,'-m','pytest','-q',
                '--junitxml='+str(output/'regression.xml'),
                *['pytools/tests/'+name for name in TESTS]],1800):
            status['blockers'].append('regression')
    regression_xml = output/'regression.xml'
    if regression_xml.is_file():
        try:
            suites = list(ET.parse(regression_xml).getroot().iter('testsuite'))
            coverage = {key:sum(int(x.get(key, '0')) for x in suites)
                        for key in ('tests', 'failures', 'errors', 'skipped')}
            status['regressionCoverage'] = coverage
            if args.require_no_regression_skips and coverage['skipped']:
                status['blockers'].append('regression-skipped')
        except (OSError, ValueError, ET.ParseError) as exc:
            status['blockers'].append('regression-report-invalid')
            status['regressionReportFailure'] = str(exc)
    elif args.require_no_regression_skips and not status['blockers']:
        status['blockers'].append('regression-report-missing')
    if args.suite is not None and not status['blockers']:
        status['generatedSuiteExecuted'] = True
        suite_command = [sys.executable,'-m','riscv2x86_py.automatic_batch_cli',
            '--input',str(args.suite.absolute()), '--frontend',str(args.frontend.absolute()),
            '--output-directory',str(output/'generated-suite-strict'), '--jobs','1',
            '--timeout-seconds','120']
        if args.experiment_environment is not None:
            suite_command.extend(('--experiment-environment',str(args.experiment_environment.absolute())))
        for name in ('privileged_config_directory', 'l2_provider_directory',
                     'l3_provider_directory', 'harness_directory', 'atomic_authority_directory',
                     'csr_architecture_directory', 'csr_authority_directory',
                     'csr_environment_contract_directory', 'instruction_stream_sync_directory'):
            value = getattr(args, name)
            if value is not None:
                suite_command.extend(('--' + name.replace('_','-'), str(value.absolute())))
        run('generated-suite', suite_command, 7200)
        status['generatedSuiteExitCode'] = status['steps'][-1]['returnCode']
        batch = output/'generated-suite-strict'/'batch-evaluation.json'
        if batch.is_file():
            try:
                data = json.loads(batch.read_text())
                summary = {k:data.get(k) for k in ('batchIdentity','caseCount','statusCounts',
                    'programValidationCounts','reasonCodeCounts','l2CoverageDiagnostics')}
                (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
                if args.require_verified_case:
                    status['routeGoalsSatisfied']=run('route-goals',[sys.executable,'experiment/check_route_goals.py',
                        '--results',str(batch.parent),*[a for c in args.require_verified_case for a in ('--case',c)]],60)
                if args.acceptance_matrix is not None:
                    status['acceptanceMatrixSatisfied']=run('acceptance-matrix', [sys.executable,
                        '-m', 'riscv2x86_py.route_acceptance', '--matrix', str(args.acceptance_matrix.absolute()),
                        '--results', str(batch.parent), '--source-root', str(args.suite.absolute())],60)
                if not run('provider-audit',[sys.executable,'-m','riscv2x86_py.l2_provider_artifacts',
                        '--batch',str(batch)],120):
                    status['blockers'].append('provider-audit')
            except (OSError,ValueError) as exc:
                status['blockers'].append('batch-artifact-invalid')
                status['batchArtifactFailure'] = {'exceptionType':type(exc).__name__,'detail':str(exc),'artifactPath':str(batch)}
        else:
            status['blockers'].append('batch-artifact-missing')
    save()
    print('run-status: '+str(output/'run-status.json'))
    if status['blockers']:
        return 2
    return 0 if status['generatedSuiteExitCode'] in (None,0) and status.get('routeGoalsSatisfied',True) and status.get('acceptanceMatrixSatisfied',True) else 1


if __name__ == '__main__':
    sys.exit(main())
