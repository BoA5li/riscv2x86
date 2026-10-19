"""Explicit, execution-bound instruction-visibility provider.

Harness code remains an explicit trusted observation producer. This runner
never predicts an observation. It checks actual reported fetch results against
an independently decoded, deliberately bounded return-u32 code probe.
"""
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
from types import SimpleNamespace
from uuid import uuid4
from .semantic_content import semantic_identity
from .l2_explicit_harness import (load_explicit_l2_harness_runner_config,
    load_explicit_l2_harness_manifest, validate_explicit_l2_harness_provider, _file_digest)
from .l2_instruction_stream import validate_instruction_stream_approval
from .l2_evidence_closure import execution_plan_for_provider, provider_evidence_fields, L2DimensionEvidence, L2ProviderExecutionDisposition
from .l2_dimensions import L2Dimension
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus

SCHEMA='riscv2x86.instruction-visibility-runner.v1'
OBSERVATION='riscv2x86.instruction-visibility-observation.v1'
DIMENSIONS=(L2Dimension.MEMORY_EFFECTS,L2Dimension.SHELL_SEMANTICS)
PROPERTIES={L2Dimension.MEMORY_EFFECTS:('compiler_ordering','external_detail','hardware_ordering','kind','subject','value'),
            L2Dimension.SHELL_SEMANTICS:('clobbers','compiler_visibility','continuation','volatile_placement')}


def load_config(raw):
    value=dict(raw)
    if value.get('schemaVersion')!=SCHEMA or not isinstance(value.get('approvalPath'),str) or not value['approvalPath']:
        raise ValueError('ISS_PROVIDER_CONFIG_INVALID')
    approval=value.pop('approvalPath'); value['schemaVersion']='riscv2x86.explicit-l2-harness-runner.v1'
    return load_explicit_l2_harness_runner_config(value),approval


def validate_provider(provider):
    config,_=load_config(provider.config)
    fields=vars(config).copy()
    raw={'schemaVersion':'riscv2x86.explicit-l2-harness-runner.v1','manifestPath':fields['manifest_path'],
        'sourceHarnessPath':fields['source_harness_path'],'targetHarnessPath':fields['target_harness_path'],
        'sourceCommand':list(config.source_command),'targetCommand':list(config.target_command),
        'contractId':config.contract_id,'timeoutSeconds':config.timeout_seconds}
    validate_explicit_l2_harness_provider(SimpleNamespace(config=raw,supported_dimensions=provider.supported_dimensions,
        execution_profiles=provider.execution_profiles,fragment_ids=provider.fragment_ids,semantic_profile_ids=provider.semantic_profile_ids))
    manifest=load_explicit_l2_harness_manifest(config.manifest_path)
    if manifest.provided_dimensions!=DIMENSIONS or manifest.observation_schema_version!=OBSERVATION:
        raise ValueError('ISS_PROVIDER_CAPABILITY_MISMATCH')


def runner_identity(command,harness_digest):
    executable=Path(shutil.which(command[0]) or command[0])
    return semantic_identity({'command':list(command),'harnessDigest':harness_digest,
        'executableDigest':_file_digest(executable)})


def decode_probe(code_hex,side):
    code=bytes.fromhex(code_hex)
    if side=='source':
        if len(code)!=8 or code[4:]!=bytes.fromhex('67800000'):
            raise ValueError('ISS_PROBE_PROGRAM_UNSUPPORTED')
        instruction=int.from_bytes(code[:4],'little')
        if instruction & 0xfffff != 0x00513: raise ValueError('ISS_PROBE_PROGRAM_UNSUPPORTED')
        value=instruction>>20
        if value>=2048: raise ValueError('ISS_PROBE_PROGRAM_UNSUPPORTED')
    else:
        if len(code)!=6 or code[0]!=0xb8 or code[-1]!=0xc3:
            raise ValueError('ISS_PROBE_PROGRAM_UNSUPPORTED')
        value=int.from_bytes(code[1:5],'little')
        if value>=2048: raise ValueError('ISS_PROBE_PROGRAM_UNSUPPORTED')
    return value


def validate_observation(value,request,side,domain):
    expected={'schemaVersion','fragmentId','executionIdentity','executionPlanIdentity','side',
        'programDigest','executionContext','events','termination'}
    if (not isinstance(value,dict) or set(value)!=expected or value['schemaVersion']!=OBSERVATION
            or value['fragmentId']!=request['fragmentId'] or value['side']!=side
            or value['executionIdentity']!=request['executionIdentity']
            or value['executionPlanIdentity']!=request['executionPlanIdentity']
            or value['programDigest']!=request[side+'Program']['digest']
            or value['termination']!='normal'
            or value['executionContext']!=domain[side+'Execution']):
        raise ValueError('ISS_OBSERVATION_EXECUTION_BINDING_INVALID')
    events=value['events']; projection=[]; current=None; object_id=None; synchronized=False
    visited=0; fetched=[]; source_valid=True
    if not isinstance(events,list) or len(events)<6: raise ValueError('ISS_OBSERVATION_TRACE_INCOMPLETE')
    for index,event in enumerate(events):
        if not isinstance(event,dict) or event.get('eventIndex')!=index:
            raise ValueError('ISS_OBSERVATION_EVENT_INDEX_INVALID')
        kind=event.get('kind')
        if kind=='code_write':
            if set(event)!={'eventIndex','kind','objectIdentity','codeHex'} or current is not None:
                raise ValueError('ISS_OBSERVATION_EVENT_ORDER_INVALID')
            if not isinstance(event['objectIdentity'],str) or not event['objectIdentity']:
                raise ValueError('ISS_OBSERVATION_OBJECT_INVALID')
            object_id=event['objectIdentity']; current=decode_probe(event['codeHex'],side); synchronized=False
            projection.append(('code_write',current))
        elif kind=='synchronize':
            if (set(event)!={'eventIndex','kind','fragmentId','traceRecord'} or current is None or synchronized
                    or event['fragmentId']!=request['fragmentId']):
                raise ValueError('ISS_OBSERVATION_SYNC_BINDING_INVALID')
            trace=event['traceRecord']
            if (not isinstance(trace,dict) or set(trace)!={'origin','executionSiteIdentity','recordPayload','recordIdentity'}
                    or trace['origin']!='execution_trace' or not isinstance(trace['recordPayload'],dict)
                    or not trace['recordPayload'] or trace['recordIdentity']!=semantic_identity(trace['recordPayload'])
                    or not isinstance(trace['executionSiteIdentity'],str) or not trace['executionSiteIdentity']):
                raise ValueError('ISS_OBSERVATION_ACTUAL_TRACE_REQUIRED')
            synchronized=True; visited+=1; projection.append(('synchronize',request['fragmentId']))
        elif kind=='instruction_fetch':
            if (set(event)!={'eventIndex','kind','objectIdentity','observedValue'} or not synchronized
                    or event['objectIdentity']!=object_id or type(event['observedValue']) is not int):
                raise ValueError('ISS_OBSERVATION_FETCH_BINDING_INVALID')
            source_valid &= event['observedValue']==current
            projection.append(('instruction_fetch',event['observedValue']))
            fetched.append(current); current=None; synchronized=False
        else: raise ValueError('ISS_OBSERVATION_EVENT_UNSUPPORTED')
    if current is not None or visited<2 or len(set(fetched))<2:
        raise ValueError('ISS_OBSERVATION_VERSION_COVERAGE_INCOMPLETE')
    return projection,source_valid


def _reject(code,stage,**extra):
    return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,
        detail=json.dumps({'reasonCode':code,'failureStage':stage,'evidenceProductionDisposition':'not_produced',**extra},sort_keys=True))


def run(config,approval_path,**kwargs):
    try:
        manifest=load_explicit_l2_harness_manifest(config.manifest_path)
        environment=kwargs.get('target_environment')
        if (environment is None or getattr(environment,'target_isa','')!='x86_64'
                or not getattr(environment,'source_isa','').startswith('rv64')
                or tuple(kwargs.get('l2_provider_dimensions',DIMENSIONS))!=DIMENSIONS):
            raise ValueError('ISS_PROVIDER_ENVIRONMENT_OR_DIMENSIONS_UNSUPPORTED')
        artifact=kwargs['translation_artifact']; fid=artifact.fragment_id
        if (not manifest.complete or manifest.provided_dimensions!=DIMENSIONS
                or manifest.observation_schema_version!=OBSERVATION or config.contract_id!=manifest.contract_id
                or manifest.relation_set_identity!=artifact.effect_relation_set_identity
                or (manifest.supported_fragment_identities and fid not in manifest.supported_fragment_identities)
                or (manifest.supported_semantic_profiles and artifact.l2_semantic_profile_identity not in manifest.supported_semantic_profiles)
                or _file_digest(Path(config.source_harness_path))!=manifest.source_harness_digest
                or _file_digest(Path(config.target_harness_path))!=manifest.target_harness_digest):
            raise ValueError('ISS_PROVIDER_MANIFEST_BINDING_INVALID')
        report=json.loads(Path(approval_path).read_text())
        matches=[f for f in report['findings'] if (f['fragment'].get('id') or f['fragment'].get('fragmentId'))==fid]
        if len(matches)!=1: raise ValueError('ISS_PROVIDER_APPROVAL_AMBIGUOUS')
        finding=matches[0]; approval=finding['approvalArtifact']
        validate_instruction_stream_approval(approval,finding['fragment'],finding.get('suggestedReplacement'),source_digest=finding.get('sourceDigest'))
        if approval['proofIdentity']!=artifact.proof_identity:
            raise ValueError('ISS_PROVIDER_APPROVAL_IDENTITY_MISMATCH')
        domain=approval['instructionStreamProof']['phase6Proof']['contract']['domain_authority']
        programs={}
        for side,command,digest in (('source',config.source_command,manifest.source_harness_digest),('target',config.target_command,manifest.target_harness_digest)):
            program=kwargs[side+'_program_artifact']; path=Path(program.artifact_path).resolve()
            if (_file_digest(path)!=program.artifact_digest or re.fullmatch(r'sha256:[0-9a-f]{64}',program.build_identity) is None):
                raise ValueError('ISS_PROGRAM_IDENTITY_MISMATCH')
            programs[side+'Program']={'path':str(path),'digest':program.artifact_digest,'buildIdentity':program.build_identity}
            if runner_identity(command,digest)!=domain[side+'Execution']['runnerIdentity']:
                raise ValueError('ISS_RUNNER_DOMAIN_MISMATCH')
            if not hasattr(os,'sched_getaffinity') or domain[side+'Execution']['pinnedCpu'] not in os.sched_getaffinity(0):
                raise ValueError('ISS_EXECUTION_AFFINITY_UNAVAILABLE')
        affinity_tool=shutil.which('taskset')
        if affinity_tool is None: raise ValueError('ISS_EXECUTION_AFFINITY_TOOL_UNAVAILABLE')
        harness=semantic_identity({'manifestIdentity':manifest.manifest_identity,'sourceHarnessDigest':manifest.source_harness_digest,'targetHarnessDigest':manifest.target_harness_digest})
        plan=execution_plan_for_provider(artifact,provider_id=kwargs['l2_provider_id'],harness_identity=harness)
        nonce={'runId':uuid4().hex,'programs':programs,'domainIdentity':domain['domainIdentity'],
            'affinityToolIdentity':_file_digest(Path(affinity_tool))}
        execution_payload={'schemaVersion':'riscv2x86.l2-authorized-execution.v1','executionPlanIdentity':plan.plan_identity,'executionNonce':nonce}
        request={'schemaVersion':SCHEMA,'fragmentId':fid,'executionPlanIdentity':plan.plan_identity,
            'executionIdentity':semantic_identity(execution_payload),'domainAuthority':domain,**programs}
    except (OSError,KeyError,ValueError,TypeError,AttributeError) as exc:
        return _reject(str(exc) if str(exc).startswith('ISS_') else 'ISS_PROVIDER_MANIFEST_INVALID',
            'runtime_authority_join',executionDisposition='precondition_rejected',exceptionType=type(exc).__name__,detail=str(exc))
    observations={}; executions={}
    try:
        for side,command in (('source',config.source_command),('target',config.target_command)):
            cpu=domain[side+'Execution']['pinnedCpu']
            executed_command=(affinity_tool,'--cpu-list',str(cpu),*command)
            result=subprocess.run(executed_command,input=json.dumps({**request,'side':side}),capture_output=True,text=True,
                timeout=config.timeout_seconds,check=False)
            executions[side]={'command':list(executed_command),'returnCode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
            if result.returncode: raise ValueError('ISS_RUNNER_EXECUTION_FAILED')
            observations[side]=json.loads(result.stdout)
        source,source_valid=validate_observation(observations['source'],request,'source',domain)
        target,target_valid=validate_observation(observations['target'],request,'target',domain)
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
        return _reject(str(exc) if str(exc).startswith('ISS_') else 'ISS_RUNNER_OUTPUT_INVALID',
            'runtime_observation',executionDisposition='executed_inconclusive',executions=executions,exceptionType=type(exc).__name__,detail=str(exc))
    matched=source_valid and target_valid and source==target
    status=ValidationStatus.VERIFIED if matched else ValidationStatus.FAILED if source_valid else ValidationStatus.INCONCLUSIVE
    disposition=(L2ProviderExecutionDisposition.EXECUTED_VERIFIED if matched else
        L2ProviderExecutionDisposition.EXECUTED_FAILED if source_valid else L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE)
    evidence=provider_evidence_fields(artifact,provider_id=kwargs['l2_provider_id'],harness_identity=harness,
        execution_nonce=nonce,dimensions=DIMENSIONS,dimension_evidence={d:L2DimensionEvidence(
            semantic_identity({'dimension':d.value,'side':'source','observation':observations['source']}),
            semantic_identity({'dimension':d.value,'side':'target','observation':observations['target']}),PROPERTIES[d]) for d in DIMENSIONS},
        execution_disposition=disposition)
    detail={'schemaVersion':'riscv2x86.instruction-visibility-result.v1','claimScope':'architectural',
        'status':status.value,'reasonCodes':[] if matched else ['ISS_TARGET_VISIBILITY_MISMATCH' if source_valid else 'ISS_SOURCE_EXECUTION_DOMAIN_VIOLATED'],
        'verifiedSemanticProperties':['completion','data_write_publication','instruction_fetch_visibility','required_scope'] if matched else [],
        'observationCoverage':'finite_return_u32_self_modifying_code_probes',
        'request':request,'domainAuthority':domain,'executions':executions,'observations':observations,**evidence}
    identity=semantic_identity(detail);detail['evidenceIdentity']=identity
    return ValidationLayerResult(ValidationLevel.L2,status,identity,json.dumps(detail,sort_keys=True,separators=(',',':')))


def build_validator(raw):
    config,approval=load_config(raw)
    return lambda **kwargs: run(config,approval,**kwargs)


def validate_persisted_result(detail):
    """Audit inline raw observations without needing mutable external files."""
    request=detail['request']; domain=detail['domainAuthority']
    if (request['domainAuthority']!=domain or request['executionIdentity']!=detail['executionIdentity']
            or request['executionPlanIdentity']!=detail['executionPlanIdentity']
            or detail['executionPayload']['executionNonce']['domainIdentity']!=domain['domainIdentity']):
        raise ValueError('ISS_PERSISTED_EXECUTION_BINDING_INVALID')
    for side in ('source','target'):
        if (detail['executionPayload']['executionNonce']['programs'][side+'Program']!=request[side+'Program']
                or detail['executions'][side]['returnCode']!=0
                or json.loads(detail['executions'][side]['stdout'])!=detail['observations'][side]):
            raise ValueError('ISS_PERSISTED_RAW_OBSERVATION_INVALID')
        for dimension in DIMENSIONS:
            expected=semantic_identity({'dimension':dimension.value,'side':side,
                'observation':detail['observations'][side]})
            if detail['dimensionObservations'][dimension.value][side+'EvidenceIdentity']!=expected:
                raise ValueError('ISS_PERSISTED_DIMENSION_BINDING_INVALID')
    source,valid=validate_observation(detail['observations']['source'],request,'source',domain)
    target,target_valid=validate_observation(detail['observations']['target'],request,'target',domain)
    matched=valid and target_valid and source==target
    expected='verified' if matched else 'failed' if valid else 'inconclusive'
    if detail['status']!=expected:
        raise ValueError('ISS_PERSISTED_VERDICT_INVALID')
