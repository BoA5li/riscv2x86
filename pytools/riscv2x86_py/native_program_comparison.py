"""Bounded process-observation adapter to the existing L1 comparison function.

No harness return values/objects/assertions are invented. No process comparison
is promoted to L1 eligibility or whole-program translation approval.
"""
import base64
import json
from pathlib import Path

from . import native_captured_deployment as deployment
from .native_external_providers import checked
from .native_experiment_driver import command
from .native_elf_runtime import parse
from .project_compile_context import digest
from .l1_differential import HarnessObservation, ProcessObservation, compare_l1_observations
from .validation_case import ComparisonContract
from .validation_status import ValidationStatus

SCHEMA='riscv2x86.native-process-comparison-plan.v1'
POLICY='exit-code-stdout-stderr-exact-bytes.v1'


def validate(plan):
    checked(plan,'processComparisonPlanIdentity')
    if (set(plan)!={'schemaVersion','deployment','source','arguments','inputDomainIdentity',
                    'sourceMachine','expectedExitCodes','policy','timeoutSeconds','maxLogBytes',
                    'inputFiles','processComparisonPlanIdentity'}
            or plan['schemaVersion']!=SCHEMA or plan['policy']!=POLICY
            or type(plan['sourceMachine']) is not int
            or type(plan['timeoutSeconds']) is not int or not 1<=plan['timeoutSeconds']<=86400
            or type(plan['maxLogBytes']) is not int or not 1024<=plan['maxLogBytes']<=2**30
            or not isinstance(plan['arguments'],list) or any(not isinstance(v,str) or '\0' in v for v in plan['arguments'])
            or not isinstance(plan['expectedExitCodes'],list) or not plan['expectedExitCodes']
            or any(type(v) is not int or not -64 <= v <= 255 for v in plan['expectedExitCodes'])
            or not isinstance(plan['inputFiles'],list)
            or not isinstance(plan['inputDomainIdentity'],str) or not plan['inputDomainIdentity']):
        raise ValueError('PROCESS_COMPARISON_PLAN_INVALID')
    deployment.verify_snapshot(plan['deployment'])
    deployed=deployment.check_result(plan['deployment']['path'])
    source=plan['source']
    if set(source)!={'program','launcher','launcherArguments','environment','directory'}:
        raise ValueError('PROCESS_COMPARISON_SOURCE_PROFILE_INVALID')
    deployment.verify_snapshot(source['program'])
    if parse(Path(source['program']['path']).read_bytes())['machine']!=plan['sourceMachine']:
        raise ValueError('PROCESS_COMPARISON_SOURCE_MACHINE_MISMATCH')
    if (not Path(source['directory']).is_dir() or not isinstance(source['environment'],dict)
            or 'PATH' not in source['environment']
            or any(not isinstance(k,str) or not isinstance(v,str) or '\0' in k+v for k,v in source['environment'].items())
            or not isinstance(source['launcherArguments'],list)
            or any(not isinstance(v,str) or '\0' in v for v in source['launcherArguments'])):
        raise ValueError('PROCESS_COMPARISON_SOURCE_PROFILE_INVALID')
    if source['launcher'] is not None: deployment.verify_snapshot(source['launcher'])
    elif source['launcherArguments']: raise ValueError('PROCESS_COMPARISON_LAUNCHER_REQUIRED')
    for row in plan['inputFiles']: deployment.verify_snapshot(row)
    return deployed


def process_observation(root, execution):
    return ProcessObservation(HarnessObservation(None,(),(),(),()),execution['returnCode'],
        base64.b64encode((root/'stdout.log').read_bytes()).decode('ascii'),
        base64.b64encode((root/'stderr.log').read_bytes()).decode('ascii'),())


def derive(plan, root):
    deployed=validate(plan)
    source_profile=plan['source']; target=next(a for a in deployed['artifacts'] if a['stage']=='derived-entry')
    deployment_plan=deployment.read(deployed['planPath'])
    expected_source=([source_profile['launcher']['path'],*source_profile['launcherArguments']]
                     if source_profile['launcher'] else [])+[source_profile['program']['path'],*plan['arguments']]
    profiles={'source':(expected_source,source_profile['directory'],source_profile['environment']),
              'target':([target['path'],*plan['arguments']],str(root),deployment_plan['environment'])}
    observations={}; executions={}
    for side,(argv,cwd,env) in profiles.items():
        value=deployment.read(root/side/'execution.json');checked(value,'processExecutionIdentity')
        if (set(value)!={'schemaVersion','planIdentity','arguments','directory','environment','returnCode',
                          'failureReason','stdoutDigest','stderrDigest','timeoutSeconds','maxLogBytes','processExecutionIdentity'}
                or value['schemaVersion']!='riscv2x86.native-process-execution.v1'
                or type(value['returnCode']) is not int
                or value['failureReason'] not in (None,'TIMEOUT','LOG_BUDGET_EXCEEDED')
                or value['timeoutSeconds']!=plan['timeoutSeconds'] or value['maxLogBytes']!=plan['maxLogBytes']
                or value['arguments']!=argv or value['directory']!=cwd or value['environment']!=env
                or value['planIdentity']!=plan['processComparisonPlanIdentity']):
            raise ValueError('PROCESS_COMPARISON_EXECUTION_PROFILE_MISMATCH')
        for stream in ('stdout','stderr'):
            if digest(root/side/(stream+'.log'))!=value[stream+'Digest']:
                raise ValueError('PROCESS_COMPARISON_OUTPUT_CHANGED')
        observations[side]=process_observation(root/side,value);executions[side]=value
    contract=ComparisonContract(False,True,True,True,False,(),(),(),())
    mismatches=compare_l1_observations(observations['source'],observations['target'],contract)
    unavailable=any(v['failureReason'] is not None for v in executions.values())
    source_outside_domain=executions['source']['returnCode'] not in plan['expectedExitCodes']
    status=(ValidationStatus.INCONCLUSIVE if unavailable or source_outside_domain
            else ValidationStatus.FAILED if mismatches else ValidationStatus.VERIFIED)
    return deployment.seal({'schemaVersion':'riscv2x86.native-process-comparison.v1',
        'processComparisonPlanIdentity':plan['processComparisonPlanIdentity'],
        'deploymentIdentity':deployed['deploymentIdentity'],'inputDomainIdentity':plan['inputDomainIdentity'],
        'sourceMachine':plan['sourceMachine'],'targetMachine':target['elf']['machine'],
        'sourceExecutionRouteVerified':False,
        'sourceExitOutsideDeclaredDomain':source_outside_domain,
        'executionBudgetFailed':unavailable,
        'policy':POLICY,'transport':'base64-exact-bytes-no-normalization',
        'processObservableComparisonStatus':status.value,'mismatches':list(mismatches),
        'sourceReturnCode':executions['source']['returnCode'],'targetReturnCode':executions['target']['returnCode'],
        'sourceTargetObjectLegalityVerified':False,'candidateExecutionCoverageVerified':False,
        'scope':'declared-arguments-exit-code-and-output-bytes-only',
        'l1EligibilityVerified':False,'semanticApproval':False,'productionAcceptanceComplete':False},'processComparisonIdentity')


def acquire(plan_path, output):
    from .native_deployment_prerequisites import output_path
    plan=deployment.read(plan_path);deployed=validate(plan)
    root=output_path(output);root.mkdir()
    inputs=deployment.seal({'schemaVersion':'riscv2x86.native-process-comparison-inputs.v1',
                            'plan':deployment.snapshot(plan_path)},'processComparisonInputsIdentity')
    (root/'inputs.json').write_text(json.dumps(inputs,indent=2))
    source=plan['source'];target=next(a for a in deployed['artifacts'] if a['stage']=='derived-entry')
    source_argv=([source['launcher']['path'],*source['launcherArguments']] if source['launcher'] else [])+[source['program']['path'],*plan['arguments']]
    profiles={'source':(source_argv,source['directory'],source['environment']),
              'target':([target['path'],*plan['arguments']],str(root),deployment.read(deployed['planPath'])['environment'])}
    for side,(argv,cwd,env) in profiles.items():
        folder=root/side;folder.mkdir()
        code,reason=command(argv,cwd,env,folder,plan['timeoutSeconds'],plan['maxLogBytes'])
        value=deployment.seal({'schemaVersion':'riscv2x86.native-process-execution.v1',
            'timeoutSeconds':plan['timeoutSeconds'],'maxLogBytes':plan['maxLogBytes'],
            'planIdentity':plan['processComparisonPlanIdentity'],'arguments':argv,
            'directory':cwd,'environment':env,'returnCode':code,'failureReason':reason,
            'stdoutDigest':digest(folder/'stdout.log'),'stderrDigest':digest(folder/'stderr.log')},'processExecutionIdentity')
        (folder/'execution.json').write_text(json.dumps(value,indent=2))
        validate(plan)
        if reason is not None: break
    # Keep failure evidence without manufacturing a missing target execution.
    if not (root/'target/execution.json').is_file():
        raise ValueError('PROCESS_COMPARISON_SOURCE_EXECUTION_BUDGET_FAILED')
    result=derive(plan,root);(root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    check(root/'result.json');return result


def check(path):
    path=Path(path).resolve(strict=True);root=path.parent
    value=deployment.read(path);checked(value,'processComparisonIdentity')
    inputs=deployment.read(root/'inputs.json');checked(inputs,'processComparisonInputsIdentity')
    if (set(inputs)!={'schemaVersion','plan','processComparisonInputsIdentity'}
            or inputs['schemaVersion']!='riscv2x86.native-process-comparison-inputs.v1'):
        raise ValueError('PROCESS_COMPARISON_INPUT_SCHEMA_INVALID')
    deployment.verify_snapshot(inputs['plan']);plan=deployment.read(inputs['plan']['path'])
    if derive(plan,root)!=value:raise ValueError('PROCESS_COMPARISON_REDERIVATION_MISMATCH')
    return value


def prepare(deployment_path, source_program, source_machine, domain_path, output, *,
            source_launcher=None, launcher_arguments=(), timeout=300, max_log_bytes=16*1024*1024):
    """Create a reviewable pinned invocation plan; never infer the source runner."""
    from .native_deployment_prerequisites import output_path
    domain=deployment.read(domain_path)
    if (set(domain)!={'schemaVersion','sourceDirectory','sourceEnvironment','arguments',
                      'expectedExitCodes','inputFiles'}
            or domain['schemaVersion']!='riscv2x86.native-process-input-domain.v1'
            or not isinstance(domain['inputFiles'],list)
            or any(not isinstance(p,str) for p in domain['inputFiles'])):
        raise ValueError('PROCESS_COMPARISON_DOMAIN_INVALID')
    body={'schemaVersion':SCHEMA,'deployment':deployment.snapshot(deployment_path),
          'source':{'program':deployment.snapshot(source_program),
                    'launcher':deployment.snapshot(source_launcher) if source_launcher else None,
                    'launcherArguments':list(launcher_arguments),
                    'environment':domain['sourceEnvironment'],'directory':domain['sourceDirectory']},
          'sourceMachine':source_machine,'arguments':domain['arguments'],
          'inputDomainIdentity':digest(domain_path),'expectedExitCodes':domain['expectedExitCodes'],
          'policy':POLICY,'timeoutSeconds':timeout,'maxLogBytes':max_log_bytes,
          'inputFiles':[deployment.snapshot(domain_path),*[deployment.snapshot(p,domain['sourceDirectory']) for p in domain['inputFiles']]]}
    plan=deployment.seal(body,'processComparisonPlanIdentity');validate(plan)
    path=output_path(output)
    with path.open('x') as stream:json.dump(plan,stream,indent=2);stream.write('\n')
    return plan
