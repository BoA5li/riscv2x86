#!/usr/bin/env python3
"""Captured object replacement, isolated relinks and conservative observations.

Exit 0 means the requested evidence operation completed, not semantic approval.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py import native_captured_deployment as deployment
from riscv2x86_py import native_deployment_observation as observation
from riscv2x86_py.native_external_providers import checked
from riscv2x86_py.project_acquisition import StageFailure


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='operation', required=True)
    prepare = sub.add_parser('prepare')
    for name in ('requirements', 'library-records', 'test-records', 'output'):
        prepare.add_argument('--'+name, required=True)
    for name in ('candidate', 'library-action', 'entry-action'):
        prepare.add_argument('--'+name)
    deploy = sub.add_parser('deploy'); deploy.add_argument('--plan', required=True)
    mode = deploy.add_mutually_exclusive_group(required=True)
    mode.add_argument('--audit', help='artifact-bound deployment-audit.json prerequisite')
    mode.add_argument('--diagnostic-only', action='store_true', help='no audit prerequisite; never formal acceptance')
    replay = sub.add_parser('replay'); replay.add_argument('--input', required=True)
    source = sub.add_parser('inspect-source'); source.add_argument('--requirements', required=True)
    source.add_argument('--objdump', required=True)
    run = sub.add_parser('observe'); run.add_argument('--input', required=True)
    run.add_argument('--arg', action='append', default=[])
    run.add_argument('--diagnostic', action='store_true')
    audit = sub.add_parser('audit-candidate'); audit.add_argument('--plan', required=True)
    repeat = sub.add_parser('replay-observation'); repeat.add_argument('--input', required=True)
    context = sub.add_parser('inspect-context'); context.add_argument('--plan', required=True)
    context.add_argument('--clang', required=True)
    context.add_argument('--reuse-native-input')
    context.add_argument('--observation', help='validated observation from this exact deployment plan')
    runtime = sub.add_parser('capture-runtime'); runtime.add_argument('--observation', required=True)
    entry_probe = sub.add_parser('capture-entry')
    entry_probe.add_argument('--contracts', required=True)
    api_prepare=sub.add_parser('prepare-api');api_prepare.add_argument('--contracts',required=True)
    api_run=sub.add_parser('run-api');api_run.add_argument('--contracts',required=True)
    api_run.add_argument('--domain',required=True);api_run.add_argument('--source-library',required=True)
    api_run.add_argument('--source-launcher',required=True);api_run.add_argument('--launcher-arg',action='append',default=[])
    statements=sub.add_parser('capture-statements');statements.add_argument('--api-experiment',required=True)
    framework_export=sub.add_parser('export-framework');framework_export.add_argument('--contracts',required=True)
    framework_run=sub.add_parser('run-framework');framework_run.add_argument('--contracts',required=True)
    framework_run.add_argument('--request',required=True)
    native_l0=sub.add_parser('materialize-native-l0');native_l0.add_argument('--contracts',required=True)
    native_l0.add_argument('--instance',required=True)
    native_request=sub.add_parser('prepare-native-l0-request');native_request.add_argument('--native-build',required=True)
    native_request.add_argument('--framework-output',required=True);native_request.add_argument('--qemu',required=True)
    native_request.add_argument('--source-isa',required=True)
    contracts = sub.add_parser('inspect-contracts')
    contracts.add_argument('--context', required=True); contracts.add_argument('--observation', required=True)
    contracts.add_argument('--clang', required=True); contracts.add_argument('--runtime')
    contracts.add_argument('--comparison')
    contracts.add_argument('--reuse-entry-receipt',action='append',default=[])
    batch=sub.add_parser('acquire-context-batch')
    batch.add_argument('--contracts',required=True);batch.add_argument('--clang',required=True)
    batch.add_argument('--start-index',type=int,default=0);batch.add_argument('--count',type=int,default=4)
    batch.add_argument('--reuse-receipt',action='append',default=[])
    batch.add_argument('--context-index',type=int,action='append')
    priority=sub.add_parser('acquire-priority-contexts')
    priority.add_argument('--resolution',required=True);priority.add_argument('--clang',required=True)
    priority.add_argument('--count',type=int,default=4)
    archive_audit=sub.add_parser('audit-archive-selection')
    archive_audit.add_argument('--deployment',required=True)
    summary=sub.add_parser('summarize-contracts')
    summary.add_argument('--input',required=True);summary.add_argument('--output',required=True)
    resolution=sub.add_parser('resolve-contexts')
    resolution.add_argument('--contracts',required=True)
    resolution.add_argument('--context-batch',action='append',required=True)
    resolution.add_argument('--output',required=True)
    refinement=sub.add_parser('refine-contracts')
    refinement.add_argument('--input',required=True);refinement.add_argument('--output',required=True)
    refinement.add_argument('--runtime');refinement.add_argument('--comparison')
    refinement.add_argument('--context-resolution')
    refinement.add_argument('--archive-audit')
    refinement.add_argument('--entry-coverage')
    refinement.add_argument('--api-experiment');refinement.add_argument('--statement-probe');refinement.add_argument('--framework-execution')
    prepare_comparison=sub.add_parser('prepare-comparison')
    for name in ('deployment','source-program','domain','output'):
        prepare_comparison.add_argument('--'+name,required=True)
    prepare_comparison.add_argument('--source-machine',type=int,required=True)
    prepare_comparison.add_argument('--source-launcher')
    prepare_comparison.add_argument('--launcher-arg',action='append',default=[])
    prepare_comparison.add_argument('--timeout-seconds',type=int,default=300)
    comparison = sub.add_parser('compare-programs'); comparison.add_argument('--plan', required=True)
    comparison.add_argument('--output', required=True)
    for parser in (deploy, replay, source, run, audit, repeat, context, runtime, entry_probe, api_prepare, api_run, statements, framework_export, framework_run, native_l0, native_request, contracts, batch, priority,archive_audit):
        parser.add_argument('--output', required=True)
        parser.add_argument('--timeout-seconds', type=int, default=300)
    check = sub.add_parser('check'); check.add_argument('--input', required=True)
    audit_check = sub.add_parser('check-audit')
    audit_check.add_argument('--plan', required=True)
    audit_check.add_argument('--input', required=True)
    args = p.parse_args(argv)
    try:
        for name in ('plan', 'context', 'contracts', 'observation', 'runtime', 'comparison', 'deployment', 'domain', 'source_program', 'source_launcher','context_resolution','archive_audit','resolution','entry_coverage','source_library','api_experiment','statement_probe','framework_execution','request','native_build','qemu'):
            value = getattr(args, name, None)
            if value is not None and (not value or not Path(value).is_file()):
                raise ValueError('CLOSURE_INPUT_REGULAR_FILE_REQUIRED:' + name)
        if hasattr(args, 'output'):
            from riscv2x86_py.native_deployment_prerequisites import output_path
            output_path(args.output)
        if hasattr(args, 'timeout_seconds') and not 1 <= args.timeout_seconds <= 86400:
            raise ValueError('CLOSURE_TIMEOUT_INVALID')
        if args.operation == 'prepare':
            candidate = args.candidate
            if candidate is None:
                req = deployment.read(args.requirements); checked(req, 'requirementsIdentity')
                if deployment.digest(req['providerPath']) != req['providerDigest']:
                    raise ValueError('CLOSURE_PROVIDER_CHANGED')
                provider = deployment.read(req['providerPath']); checked(provider, 'inventoryIdentity')
                for path, sha in provider['inputDigests'].items():
                    if deployment.digest(path) != sha:
                        raise ValueError('CLOSURE_PROVIDER_INPUT_CHANGED')
                deps = deployment.read(provider['dependencyPath']); checked(deps, 'inventoryIdentity')
                if deps['inventoryIdentity'] != provider['dependencyInventoryIdentity']:
                    raise ValueError('CLOSURE_DEPENDENCIES_CHANGED')
                candidate = deps['candidatePath']
            value = deployment.prepare(candidate, args.library_records, args.test_records,
                                       args.requirements, library_action=args.library_action,
                                       entry_action=args.entry_action)
            with Path(args.output).open('x') as f:
                json.dump(value, f, indent=2); f.write('\n')
        elif args.operation == 'deploy':
            value = deployment.execute(deployment.read(args.plan), args.output, args.timeout_seconds,
                                       audit_path=args.audit, diagnostic_only=args.diagnostic_only)
        elif args.operation == 'replay':
            value = deployment.replay(args.input, args.output, args.timeout_seconds)
        elif args.operation == 'inspect-source':
            from riscv2x86_py.native_reference_inspection import acquire
            value = acquire(args.requirements, args.output, args.objdump, timeout=args.timeout_seconds)
        elif args.operation == 'audit-candidate':
            from riscv2x86_py.native_deployment_prerequisites import audit as candidate_audit
            plan = deployment.read(args.plan); deployment.validate(plan)
            value = candidate_audit(plan, args.output, timeout=args.timeout_seconds)
        elif args.operation == 'check-audit':
            from riscv2x86_py.native_deployment_prerequisites import check as check_audit
            plan = deployment.read(args.plan); deployment.validate(plan)
            check_audit(plan, args.input)
            value = {'auditPrerequisiteIntegrityChecked': True}
        elif args.operation == 'refine-contracts':
            from riscv2x86_py.native_contract_evidence import refine as refine_contracts
            value=refine_contracts(args.input,args.output,runtime_path=args.runtime,
                comparison_path=args.comparison,resolution_path=args.context_resolution,
                archive_audit_path=args.archive_audit,entry_coverage_path=args.entry_coverage,api_path=args.api_experiment,
                statement_path=args.statement_probe,framework_path=args.framework_execution)
        elif args.operation == 'audit-archive-selection':
            from riscv2x86_py.native_archive_audit import acquire as audit_archive
            value=audit_archive(args.deployment,args.output,timeout=args.timeout_seconds)
        elif args.operation == 'summarize-contracts':
            from riscv2x86_py.native_validation_progress import summary as contract_summary
            value=contract_summary(args.input)
            with Path(args.output).open('x') as stream:
                json.dump(value,stream,indent=2,ensure_ascii=False);stream.write('\n')
        elif args.operation == 'prepare-comparison':
            from riscv2x86_py.native_program_comparison import prepare as prepare_comparison
            value=prepare_comparison(args.deployment,args.source_program,args.source_machine,args.domain,args.output,
                source_launcher=args.source_launcher,launcher_arguments=args.launcher_arg,timeout=args.timeout_seconds)
        elif args.operation == 'compare-programs':
            from riscv2x86_py.native_program_comparison import acquire as compare_programs
            value = compare_programs(args.plan, args.output)
        elif args.operation == 'materialize-native-l0':
            from riscv2x86_py.native_l0_materialization import acquire as materialize_l0
            value=materialize_l0(args.contracts,args.instance,args.output,timeout=args.timeout_seconds)
        elif args.operation == 'prepare-native-l0-request':
            from riscv2x86_py.native_l0_materialization import prepare_request
            value=prepare_request(args.native_build,args.output,args.framework_output,args.qemu,source_isa=args.source_isa)
        elif args.operation == 'prepare-api':
            from riscv2x86_py.native_api_experiment import prepare as prepare_api
            value=prepare_api(args.contracts,args.output)
        elif args.operation == 'run-api':
            from riscv2x86_py.native_api_experiment import acquire as run_api,context
            domain=deployment.read(args.domain);report=context(args.contracts)[0]
            matches=[f for f in report['graphs']['candidate']['functionDefinitions']
                     if f['functionEvidenceIdentity']==domain.get('functionEvidenceIdentity')]
            if len(matches)!=1:raise ValueError('API_DOMAIN_FUNCTION_REQUIRED')
            value=run_api(args.contracts,args.domain,matches[0]['astPath'],args.source_library,args.output,
                source_launcher=args.source_launcher,launcher_arguments=args.launcher_arg,timeout=args.timeout_seconds)
        elif args.operation == 'capture-statements':
            from riscv2x86_py.native_statement_probe import acquire as capture_statements
            value=capture_statements(args.api_experiment,args.output,timeout=args.timeout_seconds)
        elif args.operation == 'export-framework':
            from riscv2x86_py.native_framework_admission import export as export_framework
            value=export_framework(args.contracts,args.output)
        elif args.operation == 'run-framework':
            from riscv2x86_py.native_framework_admission import acquire as run_framework
            value=run_framework(args.contracts,args.request,args.output)
        elif args.operation == 'capture-entry':
            from riscv2x86_py.native_entry_probe import acquire as acquire_entry
            value = acquire_entry(args.contracts, args.output, timeout=args.timeout_seconds)
        elif args.operation == 'capture-runtime':
            from riscv2x86_py.native_runtime_identity import acquire as acquire_runtime
            value = acquire_runtime(args.observation, args.output, timeout=args.timeout_seconds)
        elif args.operation == 'acquire-context-batch':
            from riscv2x86_py.native_context_batch import acquire as acquire_batch
            value=acquire_batch(args.contracts,args.output,clang=args.clang,start=args.start_index,
                                count=args.count,timeout=args.timeout_seconds,reuse_paths=args.reuse_receipt,
                                indices=args.context_index)
        elif args.operation == 'acquire-priority-contexts':
            from riscv2x86_py.native_context_resolution import acquire_priority
            value=acquire_priority(args.resolution,args.output,clang=args.clang,
                                   count=args.count,timeout=args.timeout_seconds)
        elif args.operation == 'resolve-contexts':
            from riscv2x86_py.native_context_resolution import acquire as resolve_contexts
            value=resolve_contexts(args.contracts,args.context_batch,args.output)
        elif args.operation == 'inspect-contracts':
            from riscv2x86_py.native_contract_evidence import acquire as acquire_contracts
            value = acquire_contracts(args.context, args.observation, args.output, clang=args.clang,
                                      timeout=args.timeout_seconds, runtime_path=args.runtime, comparison_path=args.comparison,
                                      reuse_receipts=args.reuse_entry_receipt)
        elif args.operation == 'inspect-context':
            from riscv2x86_py.native_context_bridge import acquire as bridge
            value = bridge(args.plan, args.output, clang=args.clang, timeout=args.timeout_seconds,
                           observation_path=args.observation,reuse_receipt=args.reuse_native_input)
        elif args.operation == 'replay-observation':
            value = observation.replay_observation(args.input, args.output, args.timeout_seconds)
        elif args.operation == 'observe':
            value = observation.observe(args.input, args.output, arguments=args.arg,
                                        timeout=args.timeout_seconds, diagnostic=args.diagnostic)
        else:
            value = deployment.read(args.input)
            if value.get('schemaVersion') == 'riscv2x86.native-l0-materialization.v1':
                from riscv2x86_py.native_l0_materialization import check as check_native_l0
                check_native_l0(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-api-experiment.v1':
                from riscv2x86_py.native_api_experiment import check as check_api
                check_api(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-statement-probe.v1':
                from riscv2x86_py.native_statement_probe import check as check_statements
                check_statements(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-framework-execution.v1':
                from riscv2x86_py.native_framework_admission import check as check_framework
                check_framework(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.candidate-function-entry.v1':
                from riscv2x86_py.native_entry_probe import check as check_entry
                check_entry(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-archive-selection-audit.v1':
                from riscv2x86_py.native_archive_audit import check as check_archive_audit
                check_archive_audit(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-context-resolution.v1':
                from riscv2x86_py.native_context_resolution import check as check_resolution
                check_resolution(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-context-batch.v1':
                from riscv2x86_py.native_context_batch import check as check_batch
                check_batch(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-process-comparison.v1':
                from riscv2x86_py.native_program_comparison import check as check_comparison
                check_comparison(args.input)
            elif value.get('schemaVersion') in ('riscv2x86.diagnostic-map-bindings.v1', 'riscv2x86.diagnostic-map-bindings.v2', 'riscv2x86.diagnostic-map-bindings.v3'):
                from riscv2x86_py.native_runtime_identity import check as check_runtime
                check_runtime(args.input)
            elif value.get('schemaVersion') in ('riscv2x86.native-contract-evidence.v1', 'riscv2x86.native-contract-evidence.v2', 'riscv2x86.native-contract-evidence.v3','riscv2x86.native-contract-evidence.v4'):
                from riscv2x86_py.native_contract_evidence import check as check_contracts
                check_contracts(args.input)
            elif value.get('schemaVersion') == 'riscv2x86.native-context-bridge.v1':
                from riscv2x86_py.native_context_bridge import check as check_bridge
                check_bridge(args.input)
            elif value.get('schemaVersion', '').startswith('riscv2x86.deployment-observation.'):
                observation.check_observation(args.input)
            else:
                deployment.check_result(args.input)
        result = {k: value[k] for k in ('schemaVersion', 'deploymentMode', 'deploymentPlanIdentity', 'deploymentIdentity',
                   'independentDeploymentRebuildComplete', 'capturedInputReplacementVerified',
                   'candidateDefinitionAttributionVerified', 'capturedBaselineBytesReproduced',
                   'derivedLibraryBuildComplete', 'derivedEntryBuildComplete', 'loaderListSelectionVerified',
                   'testExecutionPerformed', 'observedReturnCode',
                   'compilerDeclarationWitnessesComplete','processObservationStatus','harnessObservationProtocolComplete',
                   'instrumentedStatementCoverageComplete','instrumentedOutputMatchesApiRun','canonicalInstructionCoverageVerified',
                   'originalFrameworkInvoked','frameworkResult',
                   'candidateFunctionEntriesObserved', 'observedFunctionCount', 'expectedFunctionCount',
                   'traceFailureReason', 'candidateInstructionExecutionCoverageVerified',
                   'nativeAbiClosureVerified', 'legalObjectDomainVerified', 'untracedRunCoverageVerified',
                   'tracedReturnCodeMatchesReference', 'tracedStdoutMatchesReference', 'parentObligationCount', 'referenceCount',
                   'naturalRunCompletedWithinBudget', 'diagnosticRunCompletedWithinBudget', 'runtimeBindingClosureComplete',
                   'targetDependencyLinkClosureComplete', 'externalContractClosureComplete',
                   'sourceContentLineageVerified', 'targetNativeInputAcquired', 'targetContextCompatibilityVerified',
                   'entryAbiContractComplete', 'legalObjectInputContractComplete',
                   'outputTerminationContractComplete', 'translatedInstanceExecutionVerified',
                   'l0L3AcceptanceComplete', 'mappedEndpointOccurrencesVerified', 'requiredMappedImagesVerified',
                   'bindingEventCount', 'mappingCaptureFailureCount', 'endpointOccurrenceCount',
                   'streamHeaderReplayVerified', 'fragmentedBindingEventCount',
                   'unverifiedEndpointOccurrenceCount', 'diagnosticEndpointMappingComplete',
                   'endpointFailureReasonCounts', 'metadataFailureReasonCounts',
                   'metadataCompatibleProviderEvents', 'diagnosticReturnCode',
                   'tracedRunReturnCodeMatchesReference', 'tracedRunStdoutMatchesReference',
                   'diagnosticMappedEndpointOccurrencesVerified',
                   'entryDirectObjectContextAcquisitionComplete', 'entryAbiClosureVerified',
                   'processObservableComparisonStatus', 'sourceReturnCode', 'targetReturnCode',
                   'l1EligibilityVerified','startIndex','nextIndex','totalContextCount',
                   'selectedContextAcquisitionComplete','selectedContextIndices') if k in value}
        for key in ('naturalObservationReproduced', 'auditPrerequisitePath', 'diagnosticObservedReturnCode',
                    'auditPrerequisiteIntegrityChecked'):
            if key in value: result[key] = value[key]
        if 'nativeCandidateIndependentAuditComplete' in value:
            result['nativeCandidateIndependentAuditComplete'] = value['nativeCandidateIndependentAuditComplete']
        if 'coverageInventory' in value:
            coverage=value['coverageInventory']
            result['runtimeEvidenceState']=coverage['runtimeEvidenceState']
            result['entryInputGapReasonCounts']=coverage['entryInputGapReasonCounts']
            result['relocationContractKindCounts']=coverage['relocationContractKindCounts']
            result['contractStageStatuses']={k:v['status'] for k,v in value['stages'].items()}
        if 'producerContextClosure' in value:
            from collections import Counter
            producers=value['producerContextClosure']
            result['capturedProducerClosureComplete']=producers['capturedProducerClosureComplete']
            result['producerNodeCount']=len(producers['nodes'])
            result['producerCompileContextCount']=len(producers['compileContexts'])
            result['producerGapReasonCounts']=dict(sorted(Counter(g['reasonCode'] for g in producers['inputGaps']).items()))
            result['explicitPICArgumentsEqual']=value['programScope']['explicitPICArgumentsEqual']
        if 'contextResolutionIdentity' in value and 'resolution' in value:
            for key in ('consumedContextCount','producerCompileContextCount','remainingWorkReasonCounts'):
                result[key]=value[key]
            result['callReasonCounts']=value['resolution']['callReasonCounts']
            result['uniqueStrongFunctionCandidateCallCount']=value['resolution']['uniqueStrongFunctionCandidateCallCount']
        if 'archiveSelectionAuditIdentity' in value:
            for key in ('artifactBytesReproduced','archiveContributionRelationsReproduced',
                        'independentObservedArchiveContributionsVerified','verifiedObservedArchiveMemberCount'):
                result[key]=value[key]
        if 'archiveMemberSelectionEvidence' in value:
            result['observedArchiveMemberCount']=value['archiveMemberSelectionEvidence']['observedArchiveMemberCount']
        if 'validationProgress' in value:
            result['verifiedSubgoals']=[k for k,v in value['validationProgress']['subgoals'].items()
                                       if v['status']=='verified']
        result.update(operation=args.operation, evidenceOperationComplete=True,
                      semanticApproval=False, productionAcceptanceComplete=False)
        if hasattr(args, 'output'):
            result['output'] = str(Path(args.output).absolute())
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration, StageFailure, subprocess.SubprocessError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc),
                          'evidenceOperationComplete': False, 'semanticApproval': False,
                          'productionAcceptanceComplete': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
