"""Preparation/approval protocol tests. Real frontend execution is tested separately."""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import sys
import pytest
from riscv2x86_py.semantic_content import semantic_identity
from riscv2x86_py.time_trace_harness import digest


def write_fixture(tmp_path):
    from tests.test_controlled_time import pipeline_fixture
    from tests.test_csr_sync_production_contracts import profile
    from riscv2x86_py.csr_architecture_profile import parse_profile
    from riscv2x86_py.csr_metadata_ingress import decode_csr_instruction, canonical_csr_operations_from_decoded
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.route_authority import RouteAuthorityDecision
    from types import SimpleNamespace as NS
    source=tmp_path/'arbitrary.c';source.write_text('/* synthetic compiler-protocol source fixture */')
    f,result,approval,registry,renderer=pipeline_fixture(source_digest=digest(source))
    p=profile(sourceDigest=digest(source),fragmentId=f.id)
    code=bytes.fromhex(approval['proofPayload']['machineCodeHex']);decoder=decode_csr_instruction(code)
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=decoder,xlen_bits=64,profile=parse_profile(p))[0]
    _,w=bind_csr_compiler_operands(f,TranslationRuntimeFacts(rv_to_operand_index={'a0':0},operand_width_bits={0:64}),
        [NS(addr=0x10000,decoded_csr_instruction=decoder,privileged_operations=(op,))],source_digest=digest(source),architecture_profile=parse_profile(p))
    decision=RouteAuthorityDecision('csr',f.id,'csr_compiler_join','CSR_COMPILER_JOIN_COMPLETE',
        'Static join only',semantic_identity(w),True,w).to_dict()
    finding={'fragment':asdict(f),'sourceDigest':digest(source),'machineCodeHex':code.hex(),
        'routeAuthorityDiagnostics':[decision], 'verificationStatus':'needs_route'}
    report=tmp_path/'translated_report.json';report.write_text(json.dumps({'findings':[finding]}))
    closed=f.compilerFragmentAuthority['candidate'];original=deepcopy(closed)
    original.pop('closureIdentity');original.pop('closureProvenance')
    original['schemaVersion']=original.pop('sourceCandidateSchemaVersion')
    function={'name':f.enclosingFunction,'functionId':f.compilerFragmentAuthority['functionIdentity'],
        'sourceDigest':digest(source),'l2OperandBoundary':{'fragmentCandidates':[original]},
        'compilerTimeReturnScope':f.compilerTimeReturnScope}
    snapshot={'schemaVersion':'riscv2x86.compiler-candidates.v1','sourceDigest':digest(source),
        'frontendReportIdentity':'sha256:'+'e'*64,'functions':[function]}
    snapshot['manifestIdentity']=semantic_identity(snapshot)
    report.with_name('compiler-candidates.json').write_text(json.dumps(snapshot))
    report.with_name('csr-architecture.materialized.json').write_text(json.dumps(p))
    return source,report,f,approval,registry,renderer,p


def test_static_checkpoint_closes_join_without_inventing_access_or_approval(tmp_path):
    from riscv2x86_py.mechanism_route_checks import checkpoints
    source,report,*_=write_fixture(tmp_path)
    value=checkpoints(source,report,family='time')
    assert value['architectureInterpretation']=='bound'
    assert value['staticCompilerJoin']=='closed'
    assert value['reportedApprovalStatus']=='not_produced'
    assert value['controlledExecutionContractIdentity'] is None
    assert value['semanticApproval'] is False


def test_contract_preparation_consumes_replayed_static_join(tmp_path):
    from tests.test_controlled_time import backend
    from riscv2x86_py.prepare_time_trace import prepare_contract
    from riscv2x86_py.csr_environment_contract import load_csr_environment_contract
    source,report,f,*rest=write_fixture(tmp_path);profile=rest[-1]
    value=prepare_contract(source=source,report=report,fragment_id=f.id,backend=backend(),architecture=profile,
        review={'owner':'protocol fixture','basis':'explicit-controlled-environment-selection','evidenceIdentity':'sha256:'+'a'*64})
    path=tmp_path/'contract.json';path.write_text(json.dumps(value))
    loaded=load_csr_environment_contract(path,source=source)
    assert loaded.fragment_id==f.id
    assert value['runtimeRegistry']['mapping']['sourceEffectId']=='csr-effect:0x10000:1:riscv.csr.time'
    # Prepared registry -> isolated source semantics -> proof -> consumed receipt.
    from tests.test_controlled_time import pipeline_fixture
    from riscv2x86_py.phase6c_constraints import FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT
    from riscv2x86_py.contract_consumption import consumption_receipt
    from riscv2x86_py.mechanism_route_checks import require_consumed_approval
    f,result,approval,_,_=pipeline_fixture(source_digest=digest(source),
        environment=FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT,
        registry_override=loaded.runtime_registry,renderer_override=loaded.renderer_registry)
    raw=json.loads(report.read_text());finding=raw['findings'][0]
    finding.update(approvalArtifact=approval,suggestedReplacement=result.suggested_replacement)
    report.write_text(json.dumps(raw))
    receipt=consumption_receipt(source,raw,csr=loaded,paths={'csr_environment':path})
    report.with_name('contract-consumption.json').write_text(json.dumps(receipt))
    consumed=require_consumed_approval(source,report,f.id,family='time',contract_path=path)
    assert consumed['disposition']=='consumed'
    receipt['records'][0]['disposition']='validated_not_consumed'
    receipt['receiptIdentity']=semantic_identity({k:v for k,v in receipt.items() if k!='receiptIdentity'})
    report.with_name('contract-consumption.json').write_text(json.dumps(receipt))
    with pytest.raises(ValueError,match='NOT_CONSUMED'):
        require_consumed_approval(source,report,f.id,family='time',contract_path=path)


@pytest.mark.parametrize('mutation',['source','snapshot_scope','candidate','join_role'])
def test_rehashed_preparation_mutations_are_rejected(tmp_path,mutation):
    from riscv2x86_py.mechanism_route_checks import checkpoints
    source,report,*_=write_fixture(tmp_path)
    if mutation=='source':source.write_text('changed')
    elif mutation in {'snapshot_scope','candidate'}:
        path=report.with_name('compiler-candidates.json');value=json.loads(path.read_text())
        if mutation=='snapshot_scope':value['functions'][0]['compilerTimeReturnScope']['functionSymbol']='foreign'
        else:value['functions'][0]['l2OperandBoundary']['fragmentCandidates'][0]['downstreamUseEnumerationComplete']=False
        value['manifestIdentity']=semantic_identity({k:v for k,v in value.items() if k!='manifestIdentity'})
        path.write_text(json.dumps(value))
    else:
        value=json.loads(report.read_text());d=value['findings'][0]['routeAuthorityDiagnostics'][0]
        d['inputsPayload']['operandRoles'][0]['operandIndex']=1
        d['inputsIdentity']=semantic_identity(d['inputsPayload'])
        d['decisionIdentity']=semantic_identity({k:v for k,v in d.items() if k!='decisionIdentity'})
        report.write_text(json.dumps(value))
    with pytest.raises(ValueError):checkpoints(source,report,family='time')


def test_observation_source_build_uses_bound_compiler_and_rejects_conflict(tmp_path):
    from riscv2x86_py.mechanism_route_checks import source_build_compiler
    a={'validatorType':'controlled-time-validation','config':{'sourceCompiler':sys.executable}}
    assert source_build_compiler([a])==str(Path(sys.executable).absolute())
    other=tmp_path/'other';other.write_text('different compiler')
    b={'validatorType':'l2-instruction-visibility-harness','config':{'sourceCommand':['observer','--compiler',str(other)]}}
    with pytest.raises(ValueError,match='CONFLICT'):source_build_compiler([a,b])


def test_sync_preparation_proof_and_consumption_replay(tmp_path):
    from tests.test_production_route_authority import _compiler_authority
    from tests.test_mechanism_preparation import evidence,domain
    from riscv2x86_py.schema import AsmFragment
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
    from riscv2x86_py.prepare_instruction_visibility_contract import prepare
    from riscv2x86_py.compiler_instruction_sync_scope import instruction_sync_scope
    from riscv2x86_py.instruction_stream_sync_contracts import instruction_stream_sync_registry_from_dict,prove_instruction_stream_sync,instruction_stream_environment_id
    from riscv2x86_py.phase6c_constraints import FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT as env
    from riscv2x86_py.l2_instruction_stream import close_instruction_stream_approval
    from riscv2x86_py.contract_consumption import consumption_receipt
    from riscv2x86_py.mechanism_route_checks import require_consumed_approval
    source=tmp_path/'arbitrary.c';source.write_text('void sync_probe(void){__asm__ volatile("fence.i" ::: "memory");}')
    fid='protocol:sync';a=_compiler_authority(fragment_id=fid,source_digest=digest(source))
    a['schemaVersion']='riscv2x86.compiler-fragment-authority.v1';a.pop('compilerTypeBindings')
    original=deepcopy(a['candidate']);original.pop('closureIdentity');original.pop('closureProvenance')
    original['schemaVersion']=original.pop('sourceCandidateSchemaVersion')
    for key in ('operandCarriers','operandBindings','valueNodes','downstreamUses'):original[key]=[]
    fragment=AsmFragment(id=fid,enclosingFunction='sync_probe',beginOffset=100,endOffset=140,isVolatile=True,clobbers=['memory'])
    a['candidate']=close_compiler_fragment_candidate(original,asdict(fragment),source_digest=digest(source),function_identity=a['functionIdentity'])
    a['authorityIdentity']=semantic_identity({k:v for k,v in a.items() if k!='authorityIdentity'})
    fragment.compilerFragmentAuthority=a
    ast={'name':'sync_probe','type':{'qualType':'void (void)'},'inner':[{'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt'}]}]}
    scope=instruction_sync_scope(ast,source_digest=digest(source),function_identity=a['functionIdentity'],source_range=lambda n:(100,140))
    finding={'fragment':asdict(fragment),'sourceDigest':digest(source),'machineCodeHex':'0f100000'}
    report=tmp_path/'translated_report.json';report.write_text(json.dumps({'findings':[finding]}))
    snapshot={'schemaVersion':'riscv2x86.compiler-candidates.v1','sourceDigest':digest(source),
        'frontendReportIdentity':'sha256:'+'e'*64,'functions':[{'name':'sync_probe','functionId':a['functionIdentity'],
        'sourceDigest':digest(source),'compilerInstructionSyncScope':scope,'l2OperandBoundary':{'fragmentCandidates':[original]}}]}
    snapshot['manifestIdentity']=semantic_identity(snapshot)
    report.with_name('compiler-candidates.json').write_text(json.dumps(snapshot))
    e=evidence();e['binaryDigest']=digest(sys.executable)
    e['evidenceIdentity']=semantic_identity({k:v for k,v in e.items() if k!='evidenceIdentity'})
    declaration={'schemaVersion':'riscv2x86.local-sync-selection.v1','sourceCpu':0,'targetCpu':0,
        'logicalHartIdentity':'protocol:local','modifiedCodeRange':{'objectIdentity':'probe-code-object',
        'offsetBytes':0,'lengthBytes':4096,'addressSpaceIdentity':'observer.private.anonymous'},'assumptions':domain()['reviewedAssumptions']}
    raw=prepare(source=source,report=report,fragment_id=fid,evidence=e,declaration=declaration,
        provider_output=tmp_path/'provider',source_compiler=sys.executable,target_compiler=sys.executable,source_runner=[sys.executable])
    registry=instruction_stream_sync_registry_from_dict(raw)
    contract=registry.resolve(fid,instruction_stream_environment_id(env));proof=prove_instruction_stream_sync(contract)
    assert proof.approved
    base={'proofStatus':'approved','sourceFragmentId':fid,'preservationMode':'architecture_equivalent',
        'planId':'phase6b:runtime_helper','constraintsId':'phase6c:'+contract.semantic_contract_id,
        'targetEnvironmentId':contract.target_environment_id,'targetCpuProfileId':contract.target_cpu_profile_id,
        'runtimeContractId':contract.runtime_adapter_identity,'runtimeContractVersion':contract.semantic_version,
        'requiredHeaders':[contract.required_header],'requiredLibraries':[contract.runtime_library],'requiredScope':'local_hart'}
    approved,text=close_instruction_stream_approval(base,proof,fragment,bytes.fromhex('0f100000'),'automatic-gcc-separate-tu-no-lto-v1')
    finding.update(approvalArtifact=approved,suggestedReplacement=text)
    report.write_text(json.dumps({'findings':[finding]}))
    path=tmp_path/'sync.json';path.write_text(json.dumps(raw))
    receipt=consumption_receipt(source,{'findings':[finding]},sync=registry,paths={'instruction_stream_sync':path})
    report.with_name('contract-consumption.json').write_text(json.dumps(receipt))
    assert require_consumed_approval(source,report,fid,family='sync',contract_path=path)['disposition']=='consumed'


def test_environment_selection_never_infers_a_domain_or_grants_approval(tmp_path):
    import os
    from riscv2x86_py.prepare_mechanism_selection import selection
    basis=tmp_path/'review.txt';basis.write_text('Protocol fixture: explicit assumptions, not mechanism proof.')
    with pytest.raises(ValueError):selection('local-sync',owner='reviewer',basis=basis,cpu=min(os.sched_getaffinity(0)))
    with pytest.raises(ValueError):selection('controlled-time',owner='reviewer',basis=basis)
    reviewed=selection('controlled-time',owner='reviewer',basis=basis,environment='shared-external-time-trajectory')
    assert reviewed['evidenceIdentity']==digest(basis) and set(reviewed)=={'owner','basis','evidenceIdentity'}
    with pytest.raises(ValueError):selection('local-sync',owner='reviewer',basis=basis,cpu=-1,domain='local-private-single-thread')


def test_shared_trajectory_runner_does_not_ignore_extra_target_reads():
    from riscv2x86_py.time_trace_runner import compare_observations
    values=[0,7];programs={s:{'digest':'sha256:'+s} for s in ('source','target')}
    def record(side):
        return {'side':side,'programDigest':programs[side]['digest'],'returnCode':0,'stderr':'',
            'stdout':'site 1000\n0 0000000000000000\n1 0000000000000007\n','functionSize':16,
            'events':''.join(f'{i} {v:016x} {0x1004 if side=="source" else 0:016x}\n' for i,v in enumerate(values))}
    executions={s:record(s) for s in ('source','target')}
    assert compare_observations(executions,programs,values)==(True,True,True)
    executions['target']['events']+='2 0000000000000007 0000000000000000\n'
    assert compare_observations(executions,programs,values)==(True,False,False)


def test_execution_checkpoint_does_not_treat_profile_as_access_permission():
    from types import SimpleNamespace
    from riscv2x86_py.mechanism_route_checks import execution_checkpoint
    from riscv2x86_py.privileged_execution_sidecar import default_user_process_execution_facts
    facts=default_user_process_execution_facts('fragment')
    state=SimpleNamespace(complete=False,access_permissions_complete=False,csr_effects=(),
        missing_fact_codes=('privileged-state.execution-facts-incomplete',))
    decision=execution_checkpoint('fragment',{'profileIdentity':'sha256:'+'a'*64},facts,state)
    assert not decision['accepted']
    assert decision['inputsPayload']['architectureProfileIdentity']
    assert not decision['inputsPayload']['executionFactsComplete']
    assert decision['inputsPayload']['semanticApproval'] is False


@pytest.mark.parametrize('register,number',[('a0',10),('x5',5),('t6',31)])
def test_static_join_replay_supports_independent_register_allocation(tmp_path,register,number):
    from types import SimpleNamespace
    from riscv2x86_py.csr_architecture_profile import parse_profile
    from riscv2x86_py.csr_metadata_ingress import decode_csr_instruction, canonical_csr_operations_from_decoded
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.prepare_time_trace import validate_static_join
    source,report,f,*rest=write_fixture(tmp_path);p=rest[-1]
    code=((0xc01<<20)|(2<<12)|(number<<7)|0x73).to_bytes(4,'little')
    d=decode_csr_instruction(code)
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=d,xlen_bits=64,profile=parse_profile(p))[0]
    _,w=bind_csr_compiler_operands(f,TranslationRuntimeFacts(rv_to_operand_index={register:0},operand_width_bits={0:64}),
        [SimpleNamespace(addr=0x10000,decoded_csr_instruction=d,privileged_operations=(op,))],
        source_digest=digest(source),architecture_profile=parse_profile(p))
    raw=json.loads(report.read_text());finding=raw['findings'][0];finding['machineCodeHex']=code.hex()
    decision=finding['routeAuthorityDiagnostics'][0]
    from riscv2x86_py.semantic_content import semantic_payload
    decision['inputsPayload']=semantic_payload(w);decision['inputsIdentity']=semantic_identity(w)
    decision['decisionIdentity']=semantic_identity({k:v for k,v in decision.items() if k!='decisionIdentity'})
    assert validate_static_join(finding,p,source=source)[0].csr_id=='riscv.csr.time'
