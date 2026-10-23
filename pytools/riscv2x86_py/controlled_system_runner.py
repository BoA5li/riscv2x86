"""Actual L0/L1/L2 execution in the explicit bounded M-mode SYSTEM domain."""
import json
from pathlib import Path
import subprocess
import tempfile
import sys
from uuid import uuid4
import re
from .controlled_system_backend import validate_backend,build_program,implementation_identity,CPU_PROFILE
from .system_instruction_ingress import digest,decode_system_instruction
from .semantic_content import semantic_identity
from .translation_validation import ValidationLayerResult,ValidationLevel
from .validation_status import ValidationStatus
from .l2_dimensions import L2Dimension
from .l2_evidence_closure import L2DimensionEvidence,L2ProviderExecutionDisposition,provider_evidence_fields

SCHEMA='riscv2x86.controlled-system-runner.v1'
RESULT='riscv2x86.controlled-system-result.v1'
EXECUTION_PROFILE='rv64i-m-to-x86-logical-system-v1'
DIMENSIONS=(L2Dimension.PRIVILEGED_STATE,L2Dimension.SHELL_SEMANTICS,L2Dimension.TRAP_SEMANTICS)
LIMITATIONS=['native-linux-user-equivalence','future-interrupt-arrival','unbounded-liveness','arbitrary-programs',
    'multiple-system-instructions','cross-hart-interrupts','full-native-machine-state','L3-equivalence']
FIELDS={'schemaVersion','backendPath','approvalPath','environmentPath','sourcePath','sourceDigest',
        'frontend','frontendDigest','clang','clangDigest','targetPath','scope','operation','observerIdentity','timeoutSeconds'}


def observer_identity():
    return semantic_identity({'implementation':implementation_identity(),**{name:digest(Path(__file__).with_name(name).read_bytes())
        for name in ('controlled_system_runner.py','controlled_system_backend.py','controlled_system_scope.py',
                     'controlled_system_contract.py','system_instruction_ingress.py','system_build_profile.py')}})


def load_config(config):
    if not isinstance(config,dict) or set(config)!=FIELDS or config.get('schemaVersion')!=SCHEMA:
        raise ValueError('SYSTEM_PROVIDER_SCHEMA_INVALID')
    backend=validate_backend(config['backendPath'])
    if (config['operation'] not in ('ecall','wfi') or config['observerIdentity']!=observer_identity()
            or type(config['timeoutSeconds']) is not int or not 1<=config['timeoutSeconds']<=1200):
        raise ValueError('SYSTEM_PROVIDER_CONTRACT_INVALID')
    for key in ('frontend','clang'):
        if digest(Path(config[key]).read_bytes())!=config[key+'Digest']:
            raise ValueError('SYSTEM_PROVIDER_TOOL_CHANGED:'+key)
    if digest(Path(config['sourcePath']).read_bytes())!=config['sourceDigest']:
        raise ValueError('SYSTEM_PROVIDER_SOURCE_CHANGED')
    from .privileged_environment import load_privileged_environment_manifest,validate_privileged_environment_pipeline_authority
    env=load_privileged_environment_manifest(config['environmentPath'],source=config['sourcePath'])
    validate_privileged_environment_pipeline_authority(env)
    if (env.route_contract.get('backendIdentity')!=backend['backendIdentity']
            or env.route_contract.get('scopeIdentity')!=config['scope']['scopeIdentity']):
        raise ValueError('SYSTEM_PROVIDER_ENVIRONMENT_MISMATCH')
    return backend


def environment(config):
    backend=load_config(config)
    binding={'schemaVersion':'riscv2x86.controlled-system-environment.v1','profile':EXECUTION_PROFILE,
        'backendIdentity':backend['backendIdentity'],'qemuBinaryDigest':backend['qemuBinaryDigest'],'qemuBinary':backend['qemuBinary'],
        'observerIdentity':config['observerIdentity'],'domain':'single-hart-m-bare-trap-or-prepending-mtip'}
    binding['environmentProfileIdentity']=semantic_identity(binding)
    return binding


def environment_id(binding):return 'controlled-m-system:'+binding['environmentProfileIdentity']


def validate_provider(provider):
    load_config(provider.config)
    if ([getattr(d,'value',d) for d in provider.supported_dimensions]!=[d.value for d in DIMENSIONS]
            or [getattr(p,'value',p) for p in provider.supported_patterns]!=['privileged_write']
            or tuple(provider.execution_profiles)!=(EXECUTION_PROFILE,)):
        raise ValueError('SYSTEM_PROVIDER_DIMENSIONS_OR_PROFILE_MISMATCH')


def approved_finding(config,artifact,*,replay=True):
    from .approved_replacement import approved_replacement
    from .automatic_l2_authority import _proof_effect_authority
    payload=json.loads(Path(config['approvalPath']).read_text());matches=[f for f in payload['findings']
        if (f['fragment'].get('id') or f['fragment'].get('fragmentId'))==artifact.fragment_id]
    if len(matches)!=1:raise ValueError('SYSTEM_APPROVAL_FRAGMENT_AMBIGUOUS')
    finding=matches[0];approval=finding['approvalArtifact'];text=approved_replacement(finding)
    if (approval.get('proofIdentity')!=artifact.proof_identity or approval.get('systemOperation')!=config['operation']
            or approval.get('proofStatus')!='approved' or _proof_effect_authority(approval,artifact.fragment_id) is None
            or decode_system_instruction(bytes.fromhex(finding['machineCodeHex']))!=config['operation']
            or finding['sourceDigest']!=config['sourceDigest']):
        raise ValueError('SYSTEM_APPROVAL_IDENTITY_MISMATCH')
    from .controlled_system_scope import scope
    if scope(config['sourcePath'],finding,config['clang'])!=config['scope']:
        raise ValueError('SYSTEM_OBSERVER_SCOPE_MISMATCH')
    if replay:
        with tempfile.TemporaryDirectory(prefix='rv2x86-system-proof-replay-') as temp:
            report=Path(temp)/'translated_report.json'
            command=[sys.executable,'-m','riscv2x86_py.automatic_translation_command',
                '--frontend',config['frontend'],'--source',config['sourcePath'],'--source-root',str(Path(config['sourcePath']).parent),
                '--report',str(report),'--privileged-environment-sidecar',config['environmentPath']]
            result=subprocess.run(command,capture_output=True,text=True,timeout=config['timeoutSeconds'],check=False)
            if result.returncode not in (0,1) or not report.is_file():
                raise ValueError('SYSTEM_APPROVAL_REPLAY_FAILED:'+result.stderr[-1000:])
            replayed=json.loads(report.read_text())['findings']
            rows=[f for f in replayed if (f['fragment'].get('id') or f['fragment'].get('fragmentId'))==artifact.fragment_id]
            if len(rows)!=1:raise ValueError('SYSTEM_APPROVAL_REPLAY_FRAGMENT_MISMATCH')
            other=rows[0].get('approvalArtifact') or {}
            keys=('proofIdentity','sourceModelId','constraintsId','planId','rendererContractIdentity',
                  'privilegedCallableIdentifier','privilegedRendererManifestId','replacementDigest','runtimeContractId','runtimeContractVersion')
            if any(other.get(k)!=approval.get(k) for k in keys) or approved_replacement(rows[0])!=text:
                raise ValueError('SYSTEM_APPROVAL_REPLAY_CONTENT_MISMATCH')
    return finding


def expected(operation):
    return {'operation':1,'events':[1,2,3],'mstatus':128,'mcause':11,'mtval':0,'mepcNext':1,'mie':0,'mip':0,'completed':1} if operation=='ecall' else {
        'operation':2,'events':[4,5],'mstatus':0x1800,'mcause':0,'mtval':0,'mepcNext':0,'mie':128,'mip':128,'completed':1}


def observe(side,program,backend,timeout):
    command=([backend['qemuBinary'],'-machine','virt','-cpu',CPU_PROFILE,'-smp','1','-m','32M','-bios','none',
        '-nographic','-monitor','none','-kernel',program['path']] if side=='source' else [program['path']])
    record={'side':side,'programDigest':program['digest'],'command':command,'returnCode':None,'timedOut':False,
        'stdout':'','stderr':'',
        'runnerBinaryDigest':backend['qemuBinaryDigest'] if side=='source' else program['digest'],'state':None}
    try:
        result=subprocess.run(command,capture_output=True,text=True,timeout=timeout,check=False)
        record.update(returnCode=result.returncode,stdout=result.stdout,stderr=result.stderr)
    except subprocess.TimeoutExpired as exc:
        def text(value):return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
        record.update(timedOut=True,stdout=text(exc.stdout),stderr=text(exc.stderr))
        return record
    rows=[line[len('RV2X86_SYSTEM:'):] for line in result.stdout.splitlines() if line.startswith('RV2X86_SYSTEM:')]
    if result.returncode==0 and len(rows)==1:
        try:record['state']=json.loads(rows[0])
        except ValueError:pass
    return record


def validate_records(records,programs,operation):
    reference=expected(operation);valid={}
    for side in ('source','target'):
        record=records[side];state=record.get('state')
        shape=(isinstance(state,dict) and set(state)==set(reference)
            and all(type(state[k]) is int for k in reference if k!='events')
            and isinstance(state.get('events'),list) and all(type(x) is int for x in state['events']))
        rows=record.get('stdout','').splitlines()
        parsed=None
        if len(rows)==1 and rows[0].startswith('RV2X86_SYSTEM:'):
            try:parsed=json.loads(rows[0][len('RV2X86_SYSTEM:'):])
            except (ValueError,TypeError):pass
        valid[side]=(shape and state==reference and parsed==state
                     and record.get('side')==side and record.get('programDigest')==programs[side]['digest']
                     and record.get('returnCode')==0 and record.get('timedOut') is False and record.get('stderr')=='')
    return valid['source'],valid['target']


def execution_status(records,programs,operation):
    source,target=validate_records(records,programs,operation)
    if any(records[s].get('timedOut') is True for s in ('source','target')):return ValidationStatus.INCONCLUSIVE
    return ValidationStatus.VERIFIED if source and target else ValidationStatus.FAILED if source else ValidationStatus.INCONCLUSIVE


def run(config,**kwargs):
    level=kwargs['level'];records={}
    try:
        backend=load_config(config);artifact=kwargs['translation_artifact']
        finding=approved_finding(config,artifact)
        from .controlled_system_scope import target_scope
        target_scope(config['targetPath'],config['scope']['functionSymbol'],
            finding['approvalArtifact']['privilegedCallableIdentifier'],config['clang'],backend['implementationDirectory'])
        binding=environment(config);actual=kwargs.get('target_environment')
        actual_id=actual.get('environmentId') if isinstance(actual,dict) else getattr(actual,'environment_id',None)
        if actual_id!=environment_id(binding):raise ValueError('SYSTEM_EXECUTION_ENVIRONMENT_MISMATCH')
        programs={}
        for side in ('source','target'):
            program=kwargs[side+'_program_artifact'];path=Path(program.artifact_path)
            if (digest(path.read_bytes())!=program.artifact_digest
                    or re.fullmatch(r'sha256:[0-9a-f]{64}',program.build_identity or '') is None):
                raise ValueError('SYSTEM_PROGRAM_CHANGED_OR_BUILD_IDENTITY_MISSING')
            programs[side]={'path':str(path.resolve()),'digest':program.artifact_digest,'buildIdentity':program.build_identity}
        if level is ValidationLevel.L0:
            builds=[]
            with tempfile.TemporaryDirectory(prefix='rv2x86-system-l0-') as temp:
                for opt in ('-O0','-O2','-O3'):
                    for side in ('source','target'):
                        source=(config['sourcePath'] if side=='source' else config['targetPath'])
                        output=Path(temp)/side/opt[1:]/'program.elf'
                        record=build_program(backend_path=config['backendPath'],side=side,source=source,
                            symbol=config['scope']['functionSymbol'],operation=config['operation'],output=output,optimization=opt)
                        if opt=='-O0' and record['programDigest']!=programs[side]['digest']:
                            raise ValueError('SYSTEM_L0_INDEPENDENT_REBUILD_MISMATCH:'+side)
                        builds.append(record)
            detail={'schemaVersion':RESULT,'level':'L0','status':'verified','claimBoundary':'freestanding-rv64i-and-native-sysv-build-matrix',
                'builds':builds,'environmentId':actual_id,'environment':binding,
                'notClaimedProperties':LIMITATIONS+['freestanding-source-sanitizers']}
        else:
            for side in ('source','target'):
                records[side]=observe(side,programs[side],backend,config['timeoutSeconds'])
            source_valid,target_valid=validate_records(records,programs,config['operation'])
            status=execution_status(records,programs,config['operation'])
            nonce={'runId':uuid4().hex,'programs':programs,'backendIdentity':backend['backendIdentity'],
                'observerIdentity':config['observerIdentity'],'operation':config['operation']}
            detail={'schemaVersion':RESULT,'level':level.value,'status':status.value,'claimScope':'architectural',
                'claimBoundary':'bounded-m-mode-trap-or-prepending-event-logical-state','environmentId':actual_id,'environment':binding,
                'notClaimedProperties':LIMITATIONS,'fragmentId':artifact.fragment_id,'proofIdentity':artifact.proof_identity,
                'nonce':nonce,'executions':records,'reasonCodes':[] if status is ValidationStatus.VERIFIED else ['SYSTEM_EXECUTION_RELATION_MISMATCH']}
            if level is ValidationLevel.L2:
                dimensions=tuple(kwargs.get('l2_provider_dimensions',DIMENSIONS))
                if dimensions!=DIMENSIONS:raise ValueError('SYSTEM_L2_PROVIDER_DIMENSIONS_MISMATCH')
                properties={L2Dimension.PRIVILEGED_STATE:('kind','subject','value','privilege_state','csr_value'),
                    L2Dimension.SHELL_SEMANTICS:('volatile_placement','clobbers','compiler_visibility','continuation'),
                    L2Dimension.TRAP_SEMANTICS:('trap_availability','trap_target','error_representation')}
                detail.update(provider_evidence_fields(artifact,provider_id=kwargs['l2_provider_id'],harness_identity=config['observerIdentity'],
                    execution_nonce=nonce,dimensions=dimensions,dimension_evidence={d:L2DimensionEvidence(
                        semantic_identity({'dimension':d.value,'side':'source','observation':records['source']}),
                        semantic_identity({'dimension':d.value,'side':'target','observation':records['target']}),properties[d]) for d in dimensions},
                    execution_disposition=L2ProviderExecutionDisposition.EXECUTED_VERIFIED if status is ValidationStatus.VERIFIED else
                        L2ProviderExecutionDisposition.EXECUTED_FAILED if status is ValidationStatus.FAILED else L2ProviderExecutionDisposition.EXECUTED_INCONCLUSIVE))
        identity=semantic_identity(detail);detail['evidenceIdentity']=identity
        return ValidationLayerResult(level,ValidationStatus(detail['status']),identity,json.dumps(detail,sort_keys=True))
    except (OSError,ValueError,KeyError,TypeError,AttributeError,subprocess.SubprocessError) as exc:
        return ValidationLayerResult(level,ValidationStatus.INCONCLUSIVE,detail=json.dumps({
            'reasonCode':str(exc),'failureStage':'controlled_system_execution','executions':records,
            'executionDisposition':'executed_inconclusive' if records else 'precondition_rejected',
            'evidenceProductionDisposition':'partial' if records else 'not_produced'}))


def validate_persisted_result(detail):
    if detail['status'] not in ('verified','failed','inconclusive') or detail['notClaimedProperties']!=LIMITATIONS:
        raise ValueError('SYSTEM_PERSISTED_CLAIM_INVALID')
    source,target=validate_records(detail['executions'],detail['nonce']['programs'],detail['nonce']['operation'])
    expected_status=execution_status(detail['executions'],detail['nonce']['programs'],detail['nonce']['operation']).value
    if detail['status']!=expected_status:raise ValueError('SYSTEM_PERSISTED_VERDICT_MISMATCH')
    binding=detail['environment']
    if (binding['environmentProfileIdentity']!=semantic_identity({k:v for k,v in binding.items() if k!='environmentProfileIdentity'})
            or detail['environmentId']!=environment_id(binding) or binding['backendIdentity']!=detail['nonce']['backendIdentity']):
        raise ValueError('SYSTEM_PERSISTED_ENVIRONMENT_MISMATCH')
    for side in ('source','target'):
        program=detail['nonce']['programs'][side];record=detail['executions'][side]
        command=([binding['qemuBinary'],'-machine','virt','-cpu',CPU_PROFILE,'-smp','1','-m','32M','-bios','none',
            '-nographic','-monitor','none','-kernel',program['path']] if side=='source' else [program['path']])
        if (record['command']!=command or record['runnerBinaryDigest']!=(binding['qemuBinaryDigest'] if side=='source' else program['digest'])):
            raise ValueError('SYSTEM_PERSISTED_ACTUAL_RUNNER_MISMATCH')
    if (detail['claimScope']!='architectural' or detail['claimBoundary']!='bounded-m-mode-trap-or-prepending-event-logical-state'
            or detail['nonce']['observerIdentity']!=binding['observerIdentity']):
        raise ValueError('SYSTEM_PERSISTED_CLAIM_MISMATCH')
    if detail['evidenceIdentity']!=semantic_identity({k:v for k,v in detail.items() if k!='evidenceIdentity'}):
        raise ValueError('SYSTEM_PERSISTED_IDENTITY_MISMATCH')
    if detail['level']=='L2':
        if detail['executionPayload']['executionNonce']!=detail['nonce']:raise ValueError('SYSTEM_PERSISTED_EXECUTION_MISMATCH')
        for d in DIMENSIONS:
            for side in ('source','target'):
                ident=semantic_identity({'dimension':d.value,'side':side,'observation':detail['executions'][side]})
                if detail['dimensionObservations'][d.value][side+'EvidenceIdentity']!=ident:
                    raise ValueError('SYSTEM_PERSISTED_DIMENSION_MISMATCH')


def audit_case_environment(case,records=()):
    """The outer case may never label controlled execution as native Linux."""
    outer=(case.get('targetEnvironment') or {}).get('environmentId')
    for attempt in case.get('attempts',[]):
        for layer in (attempt.get('validation') or {}).get('layers',[]):
            try:detail=json.loads(layer.get('detail',''))
            except (ValueError,TypeError):continue
            if not isinstance(detail,dict) or detail.get('schemaVersion')!=RESULT:continue
            if detail.get('level')!='L0':validate_persisted_result(detail)
            elif detail['evidenceIdentity']!=semantic_identity({k:v for k,v in detail.items() if k!='evidenceIdentity'}):
                raise ValueError('SYSTEM_PERSISTED_L0_IDENTITY_MISMATCH')
            if outer!=detail['environmentId'] or layer['evidenceIdentity']!=detail['evidenceIdentity']:
                raise ValueError('SYSTEM_CASE_LAYER_ENVIRONMENT_MISMATCH')
    for entry in records:
        envelope=entry.get('envelope',entry)
        if envelope['providerDefinition']['validatorType']!='controlled-system-validation':continue
        detail=json.loads(envelope['normalizedResult']['detail'])
        if detail.get('schemaVersion')!=RESULT:
            if envelope['normalizedResult']['status']=='verified':raise ValueError('SYSTEM_CASE_EXECUTION_EVIDENCE_MISSING')
            continue
        validate_persisted_result(detail)
        binding=environment(envelope['providerDefinition']['config'])
        if outer!=environment_id(binding) or detail['environment']!=binding:
            raise ValueError('SYSTEM_CASE_PROVIDER_ENVIRONMENT_MISMATCH')


def build_validator(config):
    load_config(config)
    return lambda **kwargs:run(config,**kwargs)
