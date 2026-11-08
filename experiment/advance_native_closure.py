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
    context.add_argument('--observation', help='validated observation from this exact deployment plan')
    for parser in (deploy, replay, source, run, audit, repeat, context):
        parser.add_argument('--output', required=True)
        parser.add_argument('--timeout-seconds', type=int, default=300)
    check = sub.add_parser('check'); check.add_argument('--input', required=True)
    args = p.parse_args(argv)
    try:
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
        elif args.operation == 'inspect-context':
            from riscv2x86_py.native_context_bridge import acquire as bridge
            value = bridge(args.plan, args.output, clang=args.clang, timeout=args.timeout_seconds, observation_path=args.observation)
        elif args.operation == 'replay-observation':
            value = observation.replay_observation(args.input, args.output, args.timeout_seconds)
        elif args.operation == 'observe':
            value = observation.observe(args.input, args.output, arguments=args.arg,
                                        timeout=args.timeout_seconds, diagnostic=args.diagnostic)
        else:
            value = deployment.read(args.input)
            if value.get('schemaVersion') == 'riscv2x86.native-context-bridge.v1':
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
                   'testExecutionPerformed', 'observedReturnCode', 'parentObligationCount', 'referenceCount',
                   'naturalRunCompletedWithinBudget', 'diagnosticRunCompletedWithinBudget', 'runtimeBindingClosureComplete',
                   'targetDependencyLinkClosureComplete', 'externalContractClosureComplete',
                   'sourceContentLineageVerified', 'targetNativeInputAcquired', 'targetContextCompatibilityVerified',
                   'entryAbiContractComplete', 'legalObjectInputContractComplete',
                   'outputTerminationContractComplete', 'translatedInstanceExecutionVerified',
                   'l0L3AcceptanceComplete') if k in value}
        for key in ('naturalObservationReproduced', 'auditPrerequisitePath', 'diagnosticObservedReturnCode'):
            if key in value: result[key] = value[key]
        if 'nativeCandidateIndependentAuditComplete' in value:
            result['nativeCandidateIndependentAuditComplete'] = value['nativeCandidateIndependentAuditComplete']
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
