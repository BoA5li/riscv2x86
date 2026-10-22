"""Production L1/L2 runner for an explicitly selected controlled TIME domain.

Approvals, actual ELF artifacts, read-site events, return values and the common
trajectory are joined here. Native independent TSC runs are never compared by
tolerance. L2 evidence goes through the existing requirement-driven closer.
"""
import json
from pathlib import Path
import shutil
import subprocess
import struct
from uuid import uuid4
from .approved_replacement import approved_replacement
from .semantic_content import semantic_identity
from .time_trace_contract import validate_time_contract, digest_ok
from .time_trace_harness import observe, validate_observation, digest, ObserverExecutionError
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus
from .l2_dimensions import L2Dimension
from .l2_evidence_closure import (execution_plan_for_provider, provider_evidence_fields,
    L2DimensionEvidence, L2ProviderExecutionDisposition)

SCHEMA='riscv2x86.controlled-time-runner.v1'
RESULT='riscv2x86.controlled-time-result.v1'
DIMENSIONS=(L2Dimension.PRIVILEGED_STATE,L2Dimension.SHELL_SEMANTICS)
PROPERTIES={L2Dimension.PRIVILEGED_STATE:('csr_value','privilege_state','subject','value'),
    L2Dimension.SHELL_SEMANTICS:('clobbers','compiler_visibility','continuation','volatile_placement')}
LIMITATIONS=['native-qemu-tsc-equivalence','wall-time-preservation','microarchitecture-equivalence','arbitrary-function-observation',
    'full-architectural-time-clock-model','constant-frequency','inter-hart-clock-synchronization']
FIELDS={'schemaVersion','approvalPath','sourceCompiler','targetCompiler','sourceRunner',
    'sourceCompilerDigest','targetCompilerDigest','observerDigest','trajectory','timeoutSeconds'}


def observer_digest():
    return semantic_identity({name:digest(Path(__file__).with_name(name)) for name in
        ('time_trace_harness.py','time_trace_runner.py','compiler_time_scope.py','time_trace_contract.py',
         'approved_replacement.py','controlled_time_environment.py')})


def load_config(raw):
    if not isinstance(raw,dict) or set(raw)!=FIELDS or raw.get('schemaVersion')!=SCHEMA:
        raise ValueError('TIME_PROVIDER_SCHEMA_INVALID')
    if not isinstance(raw['approvalPath'],str) or not raw['approvalPath']:
        raise ValueError('TIME_APPROVAL_PATH_REQUIRED')
    values=raw['trajectory']
    if (not isinstance(values,list) or not 2<=len(values)<=1024 or len(set(values))<2
            or any(type(v) is not int or not 0<=v<1<<64 for v in values)):
        raise ValueError('TIME_TRAJECTORY_INVALID')
    if type(raw['timeoutSeconds']) is not int or not 1<=raw['timeoutSeconds']<=3600:
        raise ValueError('TIME_TIMEOUT_INVALID')
    if not isinstance(raw['sourceRunner'],list) or not raw['sourceRunner'] or any(not isinstance(x,str) or not x for x in raw['sourceRunner']):
        raise ValueError('TIME_SOURCE_RUNNER_REQUIRED')
    for side in ('source','target'):
        path=raw[side+'Compiler'];expected=raw[side+'CompilerDigest']
        if not isinstance(path,str) or not digest_ok(expected) or digest(shutil.which(path) or path)!=expected:
            raise ValueError('TIME_COMPILER_IDENTITY_MISMATCH')
    if raw['observerDigest']!=observer_digest():raise ValueError('TIME_OBSERVER_CHANGED')
    return raw


def validate_provider(provider):
    load_config(provider.config)
    if (tuple(provider.supported_dimensions)!=DIMENSIONS
            or tuple(provider.supported_patterns) != ('privileged_read',)):
        # Enums may be used by provider parsing.
        if ([getattr(x,'value',x) for x in provider.supported_dimensions]!=[d.value for d in DIMENSIONS]
                or [getattr(x,'value',x) for x in provider.supported_patterns]!=['privileged_read']):
            raise ValueError('TIME_PROVIDER_CAPABILITY_MISMATCH')


def load_finding(path, artifact):
    from .csr_runtime_approval import validate_csr_runtime_approval
    from .compiler_time_scope import validate_scope
    report=json.loads(Path(path).read_text())
    matches=[f for f in report['findings'] if (f['fragment'].get('id') or f['fragment'].get('fragmentId'))==artifact.fragment_id]
    if len(matches)!=1:raise ValueError('TIME_APPROVAL_FRAGMENT_AMBIGUOUS')
    f=matches[0];a=f['approvalArtifact']
    validate_csr_runtime_approval(a,f['fragment'],approved_replacement(f))
    if a['proofIdentity']!=artifact.proof_identity or a['proofPayload']['machineCodeHex']!=f.get('machineCodeHex'):
        raise ValueError('TIME_APPROVAL_BINDING_MISMATCH')
    scope=validate_scope(a.get('l2TimeReturnScope'),f['fragment'],f.get('sourceDigest'))
    trace=(a['proofPayload']['fieldProof']['constraints'][0].get('counter_contract_payload') or {}).get('trace_relation')
    validate_time_contract(trace,source_digest=f.get('sourceDigest'),fragment_id=artifact.fragment_id)
    if getattr(artifact,'effect_relation_set_identity',''):
        from .l2_authority import l2_authority_sidecar_from_dict
        facts=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'],expected_fragment_id=artifact.fragment_id)
        if facts.effect_relation_set_identity!=artifact.effect_relation_set_identity:
            raise ValueError('TIME_EFFECT_RELATION_MISMATCH')
    return f,scope,trace


def compare_observations(executions, programs, values):
    source,source_valid=validate_observation(executions['source'],side='source',program_digest=programs['source']['digest'],values=values)
    try:
        target,target_valid=validate_observation(executions['target'],side='target',program_digest=programs['target']['digest'],values=values)
    except ValueError as exc:
        # A trusted observer's well-formed evidence of extra/missing reads, or
        # termination after actual TIME events, is a target mismatch. Broken
        # observation formats and tool setup remain inconclusive.
        mismatch=str(exc) in {'TIME_READ_EVENT_COUNT_MISMATCH','TIME_READ_EVENT_ORDER_MISMATCH'}
        terminated=(str(exc)=='TIME_EXECUTION_FAILED' and executions['target']['returnCode']<0
                    and bool(executions['target']['events']))
        if not source_valid or not (mismatch or terminated):raise
        target,target_valid=[],False
    return source_valid,target_valid,source==target


def run(raw,**kwargs):
    level=kwargs.get('level',ValidationLevel.L2)
    if level not in (ValidationLevel.L1,ValidationLevel.L2):
        return ValidationLayerResult(level,ValidationStatus.INCONCLUSIVE,detail='TIME_LEVEL_UNSUPPORTED')
    executions={}
    try:
        config=load_config(raw);artifact=kwargs['translation_artifact']
        finding,scope,trace=load_finding(config['approvalPath'],artifact)
        from .controlled_time_environment import environment_binding, environment_id
        binding=environment_binding(config,trace)
        environment=kwargs.get('target_environment')
        actual_environment_id=environment.get('environmentId') if isinstance(environment,dict) else getattr(environment,'environment_id',None)
        if actual_environment_id!=environment_id(binding):
            raise ValueError('TIME_EXECUTION_ENVIRONMENT_IDENTITY_MISMATCH')
        target_isa=environment.get('targetIsa','') if isinstance(environment,dict) else getattr(environment,'target_isa','')
        source_isa=environment.get('sourceIsa','') if isinstance(environment,dict) else getattr(environment,'source_isa','')
        if target_isa!='x86_64' or not source_isa.startswith('rv64'):
            raise ValueError('TIME_EXECUTION_ENVIRONMENT_UNSUPPORTED')
        if level is ValidationLevel.L2 and tuple(kwargs.get('l2_provider_dimensions',DIMENSIONS))!=DIMENSIONS:
            raise ValueError('TIME_PROVIDER_DIMENSIONS_MISMATCH')
        programs={}
        for side in ('source','target'):
            p=kwargs[side+'_program_artifact']
            if digest(p.artifact_path)!=p.artifact_digest or not digest_ok(p.build_identity):
                raise ValueError('TIME_PROGRAM_IDENTITY_MISMATCH')
            programs[side]={'path':str(Path(p.artifact_path).resolve()),'digest':p.artifact_digest,'buildIdentity':p.build_identity}
        # The L1 and L2 executions are deliberately independent, each fresh.
        nonce={'runId':uuid4().hex,'programs':programs,'timeContractIdentity':trace['contractIdentity'],
            'trajectory':config['trajectory'],'observerIdentity':config['observerDigest']}
        for side in ('source','target'):
            load_config(config)
            executions[side]=observe(side=side,program=programs[side],symbol=scope['functionSymbol'],
                values=config['trajectory'],compiler=config[side+'Compiler'],
                runner=config['sourceRunner'] if side=='source' else [],contract=trace,
                timeout=config['timeoutSeconds'])
            load_config(config)
        if (executions['source'].get('runnerCommand') != config['sourceRunner']
                or executions['source'].get('runnerBinaryDigest') != trace['sourceBackend']['binaryDigest']):
            raise ValueError('TIME_ACTUAL_RUNNER_IDENTITY_MISMATCH')
        source_valid,target_valid,equal=compare_observations(executions,programs,config['trajectory'])
        matched=source_valid and target_valid and equal
        status=ValidationStatus.VERIFIED if matched else ValidationStatus.FAILED if source_valid else ValidationStatus.INCONCLUSIVE
        detail={'schemaVersion':RESULT,'level':level.value,'status':status.value,
            'claimScope':'architectural','environmentKind':'explicit-controlled-time',
            'claimBoundary':'same-logical-read-events-in-declared-external-trajectory',
            'executionEnvironment':binding,'environmentId':actual_environment_id,
            'notClaimedProperties':LIMITATIONS,
            'fragmentId':artifact.fragment_id,'proofIdentity':artifact.proof_identity,
            'timeContract':trace,'scope':scope,'nonce':nonce,'executions':executions,
            'reasonCodes':[] if matched else ['TIME_TARGET_TRACE_MISMATCH' if source_valid else 'TIME_SOURCE_DOMAIN_VIOLATED']}
        if level is ValidationLevel.L2:
            provider=kwargs['l2_provider_id'];harness=config['observerDigest']
            disposition=(L2ProviderExecutionDisposition.EXECUTED_VERIFIED if matched else
                L2ProviderExecutionDisposition.EXECUTED_FAILED if source_valid else L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE)
            detail.update(provider_evidence_fields(artifact,provider_id=provider,harness_identity=harness,
                execution_nonce=nonce,dimensions=DIMENSIONS,dimension_evidence={d:L2DimensionEvidence(
                    semantic_identity({'dimension':d.value,'side':'source','observation':executions['source']}),
                    semantic_identity({'dimension':d.value,'side':'target','observation':executions['target']}),PROPERTIES[d]) for d in DIMENSIONS},
                execution_disposition=disposition))
        identity=semantic_identity(detail);detail['evidenceIdentity']=identity
        return ValidationLayerResult(level,status,identity,json.dumps(detail,sort_keys=True))
    except (OSError,KeyError,ValueError,TypeError,AttributeError,struct.error,subprocess.TimeoutExpired) as exc:
        if isinstance(exc,ObserverExecutionError):executions[exc.record['side']]=exc.record
        return ValidationLayerResult(level,ValidationStatus.INCONCLUSIVE,detail=json.dumps({
            'reasonCode':str(exc),'failureStage':'controlled_time_execution',
            'evidenceProductionDisposition':'partial' if executions else 'not_produced',
            'executionDisposition':'executed_inconclusive' if executions else 'precondition_rejected','executions':executions}))


def validate_persisted_result(detail):
    validate_time_contract(detail['timeContract'],fragment_id=detail['fragmentId'])
    from .controlled_time_environment import environment_binding, environment_id
    binding=detail.get('executionEnvironment') or {}
    expected=environment_binding({'sourceRunner':binding.get('sourceRunner',[]),
        'observerDigest':detail['nonce']['observerIdentity']},detail['timeContract'])
    if binding!=expected or detail.get('environmentId')!=environment_id(expected):
        raise ValueError('TIME_PERSISTED_ENVIRONMENT_IDENTITY_MISMATCH')
    if (detail['executions']['source'].get('runnerCommand') != binding['sourceRunner']
            or detail['executions']['source'].get('runnerBinaryDigest') != binding['sourceBinaryDigest']):
        raise ValueError('TIME_PERSISTED_ACTUAL_RUNNER_MISMATCH')
    if (detail.get('claimScope')!='architectural' or detail.get('environmentKind')!='explicit-controlled-time'
            or detail.get('claimBoundary')!='same-logical-read-events-in-declared-external-trajectory'
            or detail.get('notClaimedProperties')!=LIMITATIONS
            or detail['nonce']['timeContractIdentity']!=detail['timeContract']['contractIdentity']):
        raise ValueError('TIME_PERSISTED_CLAIM_OR_ENVIRONMENT_MISMATCH')
    if detail.get('level')=='L2':
        if (detail['executionPayload']['executionNonce']!=detail['nonce']
                or detail['executionPayload']['executionPlanIdentity']!=detail['executionPlanIdentity']):
            raise ValueError('TIME_PERSISTED_EXECUTION_MISMATCH')

    values=detail['nonce']['trajectory']
    for side in ('source','target'):
        if detail.get('level')=='L2':
            for d in DIMENSIONS:
                identity=semantic_identity({'dimension':d.value,'side':side,'observation':detail['executions'][side]})
                if detail['dimensionObservations'][d.value][side+'EvidenceIdentity']!=identity:
                    raise ValueError('TIME_PERSISTED_OBSERVATION_MISMATCH')
    source_valid,target_valid,equal=compare_observations(detail['executions'],detail['nonce']['programs'],values)
    expected='verified' if source_valid and target_valid and equal else 'failed' if source_valid else 'inconclusive'
    if detail['status']!=expected:raise ValueError('TIME_PERSISTED_VERDICT_MISMATCH')
    if detail['evidenceIdentity']!=semantic_identity({k:v for k,v in detail.items() if k!='evidenceIdentity'}):
        raise ValueError('TIME_PERSISTED_IDENTITY_MISMATCH')


def build_validator(raw):
    load_config(raw)
    return lambda **kwargs:run(raw,**kwargs)
