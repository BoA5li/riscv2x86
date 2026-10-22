"""Prepare explicit controlled TIME contracts, then bind existing approvals.

Contract preparation consumes compiler/decoder facts and an explicit environment
selection. Provider binding consumes a real approved production report. Neither
step fabricates an approval or changes a verdict. No case/function-name rules.
"""
import argparse
import json
from pathlib import Path
import shutil
from .semantic_content import semantic_identity, semantic_payload
from .time_trace_contract import (SCHEMA,TARGET,validate_backend,validate_time_contract,
    controlled_execution_facts)
from .time_trace_harness import digest
from .time_trace_runner import SCHEMA as RUNNER_SCHEMA, observer_digest, load_config, load_finding


def seal(payload,key):return {**payload,key:semantic_identity(payload)}


def finding(source,report,fragment_id):
    from .mechanism_route_checks import preparation_inputs
    return preparation_inputs(source, report, fragment_id, family='time')


def validate_static_join(f, architecture, *, source):
    """Replay ISA and compiler carrier joins; this does not permit execution."""
    from .csr_architecture_profile import profiles_from_payload,parse_profile
    from .csr_metadata_ingress import decode_csr_instruction,canonical_csr_operations_from_decoded
    from .csr_value_flow import _effect_id
    from .route_authority import validate_route_decision
    fragment_id=f['fragment'].get('id') or f['fragment'].get('fragmentId')
    profiles=profiles_from_payload(architecture,source_digest=digest(source),xlen_bits=64)
    profile=parse_profile(profiles.get(fragment_id))
    joins=[d for d in f.get('routeAuthorityDiagnostics',[]) if d.get('reasonCode')=='CSR_COMPILER_JOIN_COMPLETE' and d.get('accepted')]
    if len(joins)!=1:raise ValueError('TIME_STATIC_COMPILER_JOIN_REQUIRED')
    validate_route_decision(joins[0]);w=joins[0]['inputsPayload']
    code=bytes.fromhex(f['machineCodeHex']);decoded=decode_csr_instruction(code)
    if len(code)!=4 or decoded is None:raise ValueError('TIME_PREPARATION_DECODER_REQUIRED')
    operation=canonical_csr_operations_from_decoded(addr=w['instructionAddress'],decoded=decoded,
        xlen_bits=64,profile=profile)[0]
    eid=_effect_id(w['instructionAddress'],1,operation)
    from .csr_production_binding import bind_csr_compiler_operands
    from .runtime_facts import TranslationRuntimeFacts, canonicalize_riscv_register_name
    from .schema import AsmFragment, AsmOperand
    from types import SimpleNamespace
    raw=dict(f['fragment'])
    # Only the GNU operands need reconstruction; all authority payloads remain
    # the original structured compiler records.
    raw['outputs']=[AsmOperand(**x) for x in raw.get('outputs',[])]
    raw['inputs']=[AsmOperand(**x) for x in raw.get('inputs',[])]
    fragment=AsmFragment(**raw)
    registers=w['assemblerRegisterBindings']
    if (not isinstance(registers,dict) or len(registers)!=1 or any(
            type(index) is not int or index!=0 or not canonicalize_riscv_register_name(reg)
            or canonicalize_riscv_register_name(reg)!=canonicalize_riscv_register_name(decoded.rd_register_id)
            for reg,index in registers.items())):
        raise ValueError('TIME_PREPARATION_REGISTER_BINDING_MISMATCH')
    runtime=TranslationRuntimeFacts(rv_to_operand_index=registers,operand_width_bits={0:64})
    _,expected=bind_csr_compiler_operands(fragment,runtime,
        [SimpleNamespace(addr=w['instructionAddress'],decoded_csr_instruction=decoded,privileged_operations=(operation,))],
        source_digest=digest(source),architecture_profile=profile)
    if (w!=semantic_payload(expected) or w['sourceDigest']!=digest(source) or w['fragmentId']!=fragment_id
            or w['sourceEffectId']!=eid or w['effect']!=semantic_payload(operation)
            or w['decoder']!=semantic_payload(decoded) or operation.csr_id!='riscv.csr.time'
            or operation.csr_operation.value!='read'):
        raise ValueError('TIME_PREPARATION_DECODER_BINDING_MISMATCH')
    return operation,eid,profile


def prepare_contract(*,source,report,fragment_id,backend,architecture,review):
    from .phase6c_constraints import FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT
    f,scope=finding(source,report,fragment_id)
    validate_backend(backend)
    operation,eid,profile=validate_static_join(f,architecture,source=source)
    facts=controlled_execution_facts(fragment_id=fragment_id,backend=backend,
        privilege_spec=profile.privilege_spec_version.removeprefix('riscv-privileged-'),extensions=profile.extensions)
    trace=seal({'schemaVersion':SCHEMA,'sourceDigest':digest(source),'fragmentId':fragment_id,
        'sourceExecutionIdentity':semantic_identity(facts),
        'targetEnvironmentIdentity':semantic_identity(FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT),
        'sourceBackend':backend,'targetMechanism':TARGET,'unit':'opaque-64-bit-time-ticks',
        'readRelation':'same-index-same-external-value-modulo-2^64',
        'concurrency':'single-thread-no-asynchronous-readers',
        'transportIsolation':'reserved-trace-files-no-program-alias-no-resource-observation',
        'ordering':'logical-read-events-only-no-wall-time-or-memory-order-claim',
        'failurePolicy':'execution-failure-not-counter-value','review':review},'contractIdentity')
    validate_time_contract(trace)
    counter={'contractId':trace['contractIdentity'],'relationKind':'architectural-equivalence',
        'sourceEpoch':trace['contractIdentity'],'targetEpoch':trace['contractIdentity'],
        'frequencyHz':None,'scaleNumerator':1,'scaleDenominator':1,
        'monotonicity':'external-trajectory-modulo-2^64','wraparoundBits':64,
        'scope':'one-bound-logical-read-stream','migrationBehavior':'no-physical-time-dependence',
        'serialization':'logical-read-events-only','targetObservationMechanism':TARGET,
        'errorBoundTicks':0,'availabilityPolicy':'explicit-controlled-backend-required',
        'trapPolicy':'execution-failure-not-counter-value','complete':True,'traceRelation':trace}
    operation_id='controlled-time:'+trace['contractIdentity'];mapping={
        'sourceEffectId':eid,'sourceCsrId':operation.csr_id,'targetStateObjectId':trace['contractIdentity'],
        'targetOperationId':operation_id,'stateLifetimeId':'one-process-read-stream',
        'readResultMapping':'runtime-result','writeValueMapping':None,
        'fieldMappings':sorted(x.field_id for x in operation.affected_csr_fields),
        'oldNewStateRelationId':trace['readRelation'],'accessPolicyMappingId':facts.csr_access_policy.policy_id,
        'deniedAccessTrapMappingId':None,'sideEffectMappingIds':[],'orderingRelationId':trace['ordering']}
    recipe={'recipeId':'controlled-time-read.v1','callableIdentifier':'rv2x86_read_time_trace_checked_v1',
        'csrToken':'RV2X86_COUNTER_CONTROLLED_TIME','contextExpression':'((const struct rv2x86_counter_context *)0)',
        'inputExpression':None,'outputExpression':None,'requiredHeader':'riscv2x86_csr_runtime.h',
        'requiredLibrary':'libriscv2x86_runtime','runtimeVersion':'v1',
        'trapResultPolicy':'no-trap-observation','approved':True}
    return seal({'schemaVersion':'riscv2x86.csr-environment-contract.v3','semanticFamily':'counter_observation',
        'sourceDigest':digest(source),'fragmentId':fragment_id,'relationKind':'architectural-equivalence',
        'runtimeRegistry':{'registryVersion':'controlled-time.v1','runtimeVersion':'v1',
            'executionProfile':'riscv_user_process','shellTransportable':True,'externalStateComplete':True,
            'mapping':mapping,'counterContract':counter},
        'rendererRegistry':{'registryVersion':'controlled-time.v1','targetOperationId':operation_id,'recipe':recipe}},'contractIdentity')


def bind(*,source,source_root,report,fragment_id,output,source_compiler,target_compiler,source_runner,trajectory):
    from types import SimpleNamespace
    from .l2_validator_resolution import provider_from_dict,L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA
    from .l2_authority import l2_authority_sidecar_from_dict
    source=Path(source).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('TIME_PREPARATION_OUTPUT_EXISTS')
    f,scope=finding(source,report,fragment_id);a=f['approvalArtifact']
    load_finding(report,SimpleNamespace(fragment_id=fragment_id,proof_identity=a['proofIdentity']))
    sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'],expected_fragment_id=fragment_id)
    if not sidecar.complete:raise ValueError('TIME_AUTHORITY_INCOMPLETE')
    def executable(x):return str(Path(shutil.which(x) or x).resolve())
    source_compiler=executable(source_compiler);target_compiler=executable(target_compiler)
    source_runner=[executable(source_runner[0]),*source_runner[1:]]
    trace=a['proofPayload']['backendContract']['timeContract']
    if digest(source_runner[0])!=trace['sourceBackend']['binaryDigest']:raise ValueError('TIME_SOURCE_BINARY_MISMATCH')
    config={'schemaVersion':RUNNER_SCHEMA,'approvalPath':str(output/'approval.json'),
        'sourceCompiler':source_compiler,'targetCompiler':target_compiler,'sourceRunner':source_runner,
        'sourceCompilerDigest':digest(source_compiler),'targetCompilerDigest':digest(target_compiler),
        'observerDigest':observer_digest(),'trajectory':trajectory,'timeoutSeconds':120}
    load_config(config)
    provider={'providerId':'controlled-time:'+scope['scopeIdentity'],'supportedDimensions':['privileged_state','shell_semantics'],
        'supportedPatterns':['privileged_read'],'requiredCapabilities':['privileged_state_observation','shell_observation'],
        'executionProfiles':['rv64gc-user-to-x86_64-user'],'bindingKind':'explicit',
        'validatorType':'controlled-time-validation','configSchemaVersion':RUNNER_SCHEMA,'config':config,
        'fragmentIds':[fragment_id],'semanticProfileIds':[]}
    provider_from_dict(provider)
    relative=source.relative_to(Path(source_root).resolve()).as_posix()
    record=seal({'schemaVersion':L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA,'sourceRelativePath':relative,
        'sourceDigest':digest(source),'environmentCapabilities':['privileged_state_observation','shell_observation'],
        'providers':[provider]},'manifestIdentity')
    output.mkdir(parents=True);(output/'approval.json').write_bytes(Path(report).read_bytes())
    path=output/'providers'/(relative+'.l2-providers.json');path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(record,indent=2)+'\n')
    return {'disposition':'bound_to_existing_approval','semanticApproval':False,
        'sourceDigest':digest(source),'fragmentId':fragment_id,'proofIdentity':a['proofIdentity'],
        'providerManifest':str(path),'timeContractIdentity':trace['contractIdentity']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['contract','bind'])
    for name in ('source','report','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--fragment-id',required=True);p.add_argument('--source-root',type=Path)
    p.add_argument('--backend',type=Path);p.add_argument('--architecture',type=Path);p.add_argument('--review',type=Path)
    p.add_argument('--source-compiler');p.add_argument('--target-compiler');p.add_argument('--source-runner-json')
    p.add_argument('--trajectory-json',default='[0,1,9223372036854775807,9223372036854775808,18446744073709551615,0,7]')
    a=p.parse_args()
    try:
        if a.action=='contract':
            if a.output.exists():raise ValueError('TIME_PREPARATION_OUTPUT_EXISTS')
            if any(x is None for x in (a.backend,a.architecture,a.review)):raise ValueError('TIME_CONTRACT_ARGUMENTS_REQUIRED')
            value=prepare_contract(source=a.source,report=a.report,fragment_id=a.fragment_id,
                backend=json.loads(a.backend.read_text()),architecture=json.loads(a.architecture.read_text()),review=json.loads(a.review.read_text()))
            # Independently consume the file through the production loader.
            a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(value,indent=2)+'\n')
            from .csr_environment_contract import load_csr_environment_contract
            load_csr_environment_contract(a.output,source=a.source)
            value={'disposition':'prepared_pending_phase6d','contractPath':str(a.output),'semanticApproval':False}
        else:
            if any(x is None for x in (a.source_root,a.source_compiler,a.target_compiler,a.source_runner_json)):
                raise ValueError('TIME_BIND_ARGUMENTS_REQUIRED')
            value=bind(source=a.source,source_root=a.source_root,report=a.report,fragment_id=a.fragment_id,
                output=a.output,source_compiler=a.source_compiler,target_compiler=a.target_compiler,
                source_runner=json.loads(a.source_runner_json),trajectory=json.loads(a.trajectory_json))
        print(json.dumps(value,ensure_ascii=False));return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
        print(json.dumps({'failureStage':'time_preparation','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
