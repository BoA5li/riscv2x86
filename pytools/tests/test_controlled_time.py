"""Structured production/proof and actual native execution; no native-TIME claim."""
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace as NS
import json
import shutil
import subprocess
import pytest
from riscv2x86_py.semantic_content import semantic_identity,semantic_payload
from riscv2x86_py.time_trace_contract import SCHEMA,TARGET,MECHANISM,QEMU_BASE,PATCHED_CSR_DIGEST,controlled_execution_facts
from riscv2x86_py.time_trace_harness import digest

ROOT=Path(__file__).resolve().parents[2]


def seal(value,key='contractIdentity'):return {**value,key:semantic_identity(value)}


def backend():
    return seal({'schemaVersion':'riscv2x86.controlled-time-backend.v1','mechanism':MECHANISM,
        'baseCommit':QEMU_BASE,'sourceDigest':PATCHED_CSR_DIGEST,
        'traceHeaderDigest':digest(ROOT/'runtime/include/riscv2x86_time_trace.h'),
        'binaryDigest':'sha256:'+'2'*64,'buildIdentity':'sha256:'+'3'*64},'backendIdentity')


def trace_contract(fid='fragment:time',source_digest='sha256:'+'4'*64,target=None):
    facts=controlled_execution_facts(fragment_id=fid,backend=backend(),privilege_spec='1.12',extensions=('i','zicsr'))
    value={'schemaVersion':SCHEMA,'sourceDigest':source_digest,'fragmentId':fid,
        'sourceExecutionIdentity':semantic_identity(facts),'targetEnvironmentIdentity':semantic_identity(target),
        'sourceBackend':backend(),'targetMechanism':TARGET,'unit':'opaque-64-bit-time-ticks',
        'readRelation':'same-index-same-external-value-modulo-2^64',
        'concurrency':'single-thread-no-asynchronous-readers',
        'transportIsolation':'reserved-trace-files-no-program-alias-no-resource-observation',
        'ordering':'logical-read-events-only-no-wall-time-or-memory-order-claim',
        'failurePolicy':'execution-failure-not-counter-value',
        'review':{'owner':'protocol-test-fixture','basis':'explicit-controlled-environment-selection','evidenceIdentity':'sha256:'+'5'*64}}
    return seal(value),facts


def counter(trace):
    from riscv2x86_py.csr_runtime_registry import CounterObservationContract
    return CounterObservationContract(trace['contractIdentity'],'architectural-equivalence',
        trace['contractIdentity'],trace['contractIdentity'],None,1,1,
        'external-trajectory-modulo-2^64',64,'one-bound-logical-read-stream',
        'no-physical-time-dependence','logical-read-events-only',TARGET,0,
        'explicit-controlled-backend-required','execution-failure-not-counter-value',True,trace)


def pipeline_fixture():
    from tests.test_csr_sync_production_contracts import compiler_fragment,profile
    from tests.test_privileged_state_analysis import _cfg
    from riscv2x86_py.csr_architecture_profile import parse_profile
    from riscv2x86_py.csr_metadata_ingress import decode_csr_instruction,canonical_csr_operations_from_decoded
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.csr_value_flow import join_csr_operand_bindings
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.pcode_ir import CanonicalInsn,Block,Op
    from riscv2x86_py.privileged_state_analysis import analyze_privileged_state
    from riscv2x86_py.csr_state_dataflow import analyze_csr_state_dataflow
    from riscv2x86_py.source_csr_semantic_model import adapt_source_csr_semantic_model
    from riscv2x86_py.csr_effect_constraints import CsrTargetMapping
    from riscv2x86_py.csr_translation_pipeline import (CsrRuntimeRegistry,CsrRendererRegistry,
        CsrTranslationFallbackPolicy,run_csr_translation_pipeline)
    from riscv2x86_py.csr_structured_renderer import CsrRuntimeRecipe
    from riscv2x86_py.csr_runtime_approval import build_csr_runtime_approval
    f=compiler_fragment();f.outputs[0].exprText='out'
    f.enclosingFunction='probe'
    key=f.compilerFragmentAuthority['fragmentBindingKey']
    f.compilerTimeReturnScope=seal({'schemaVersion':'riscv2x86.compiler-time-return-scope.v1',
        'sourceDigest':f.compilerFragmentAuthority['sourceDigest'],
        'functionIdentity':f.compilerFragmentAuthority['functionIdentity'],'functionSymbol':'probe',
        'asmBegin':key['beginOffset'],'asmEnd':key['endOffset'],
        'scope':'u64-no-parameters-one-local-one-asm-direct-return'},'scopeIdentity')

    environment=NS(environment_id='controlled-test')
    trace,facts=trace_contract(f.id,f.compilerFragmentAuthority['sourceDigest'],environment)
    code=((0xc01<<20)|(2<<12)|(10<<7)|0x73).to_bytes(4,'little')
    decoder=parse_profile(profile());decoded=decode_csr_instruction(code)
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=decoded,xlen_bits=64,profile=decoder)[0]
    ins=CanonicalInsn(0x10000,4,privileged_operations=(op,));ins.decoded_csr_instruction=decoded
    block=Block(0x10000,ops=[Op(0x10000,'COPY',None,[])],instructions=[ins]);cfg=_cfg(block)
    authority,_=bind_csr_compiler_operands(f,TranslationRuntimeFacts(rv_to_operand_index={'a0':0},operand_width_bits={0:64}),
        [ins],source_digest=f.compilerFragmentAuthority['sourceDigest'],architecture_profile=decoder)
    binding=join_csr_operand_bindings(lifted_insns=[ins],authority=authority)[0]
    state=analyze_privileged_state(fragment_id=f.id,blocks=[block],cfg=cfg,execution_facts=facts)
    flow=analyze_csr_state_dataflow(blocks=[block],cfg=cfg,access_effects=state.csr_effects)
    model=adapt_source_csr_semantic_model(NS(csr_effects=state.csr_effects,csr_operand_bindings=(binding,),csr_state_dataflow=flow))
    assert model.complete and model.strict_eligible
    c=counter(trace)
    mapping=CsrTargetMapping(binding.source_effect_id,'riscv.csr.time','time-state','controlled-read','v1',
        'riscv_user_process','process',read_result_mapping='runtime-result',field_mappings=tuple(x.field_id for x in op.affected_csr_fields),
        old_new_state_relation_id=trace['readRelation'],access_policy_mapping_id=facts.csr_access_policy.policy_id,
        ordering_relation_id=trace['ordering'],counter_contract_identity=c.contract_id,counter_relation_kind=c.relation_kind,counter_contract=c)
    registry=CsrRuntimeRegistry('controlled-time.v1','v1','riscv_user_process',(mapping,),True,True,
        source_digest=trace['sourceDigest'],fragment_id=f.id,semantic_family='counter_observation')
    recipe=CsrRuntimeRecipe('controlled-read','rv2x86_read_time_trace_checked_v1','RV2X86_COUNTER_CONTROLLED_TIME',
        '((const struct rv2x86_counter_context *)0)',None,None,'riscv2x86_csr_runtime.h','libriscv2x86_runtime','v1','no-trap-observation',True)
    renderer=CsrRendererRegistry('controlled-time.v1',{'controlled-read':recipe},{'controlled-read':'v1'})
    result=run_csr_translation_pipeline(model,environment,state,registry,renderer,CsrTranslationFallbackPolicy(),
        operand_expressions={0:'out'},fragment_id=f.id,source_fragment=f,target_build_contract='automatic-gcc-separate-tu-no-lto-v1')
    assert result.status=='approved',result.reason_codes
    approval=build_csr_runtime_approval(f,result,machine_code=code,decoder_profile=asdict(decoder),
        target_environment_id=semantic_identity(environment))
    return f,result,approval,registry,renderer


def test_time_proof_replays_real_decoder_compiler_result_and_backend_contract():
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    f,result,a,_,_=pipeline_fixture()
    validate_csr_runtime_approval(a,f,result.suggested_replacement)
    assert a['proofStatus']=='approved' and not a['functionalFallbackEnabled']
    assert a['proofPayload']['backendContract']['timeContract']['sourceBackend']['mechanism']==MECHANISM
    assert a['microarchitectureSemanticsPreserved'] is False


@pytest.mark.parametrize('change',['unit','backend','epoch','scale','source','target','extra_read'])
def test_rehashed_time_mutations_do_not_acquire_approval(change):
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    f,result,a,_,_=pipeline_fixture();a=deepcopy(a);p=a['proofPayload']
    trace=p['backendContract']['timeContract']
    if change=='unit':trace['unit']='nanoseconds'
    if change=='backend':trace['sourceBackend']['binaryDigest']='invalid'
    if change=='source':p['backendContract']['sourceExecutionSnapshot']['fragment_id']='foreign'
    if change=='target':p['backendContract']['targetEnvironmentSnapshot']['environment_id']='foreign'
    if change=='extra_read':trace['readRelation']='ignore-extra-reads'
    if change in {'epoch','scale'}:
        p['fieldProof']['constraints'][0]['counter_contract_payload']['source_epoch' if change=='epoch' else 'scale_denominator']='foreign' if change=='epoch' else 2
    trace['contractIdentity']=semantic_identity({k:v for k,v in trace.items() if k!='contractIdentity'})
    a['proofIdentity']=semantic_identity(p)
    with pytest.raises(ValueError):validate_csr_runtime_approval(a,f,result.suggested_replacement)


def test_actual_native_time_runtime_returns_zero_high_bit_and_wrap_values(tmp_path):
    from riscv2x86_py.time_trace_harness import observe,validate_observation
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native C compiler unavailable')
    f,result,a,_,_=pipeline_fixture()
    main=tmp_path/'probe.c';library=tmp_path/'probe.so'
    main.write_text('#include "riscv2x86_csr_runtime.h"\nuint64_t renamed_probe(void){uint64_t out;'+result.suggested_replacement+'return out;}\n')
    built=subprocess.run([gcc,'-O2','-fPIC','-shared','-fno-lto','-Wall','-Wextra','-Werror','-I'+str(ROOT/'runtime/include'),
        str(main),str(ROOT/'runtime/riscv2x86_csr_runtime.c'),'-o',str(library)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    values=[0,1,(1<<63),(1<<64)-1,0,7]
    program={'path':str(library),'digest':digest(library)}
    record=observe(side='target',program=program,symbol='renamed_probe',values=values,compiler=gcc,runner=[],
        contract=a['proofPayload']['backendContract']['timeContract'],timeout=20)
    projection,valid=validate_observation(record,side='target',program_digest=program['digest'],values=values)
    assert valid and [x[2] for x in projection]==values
    bad=deepcopy(record);bad['events']+='6 0000000000000001 0000000000000000\n'
    with pytest.raises(ValueError,match='COUNT'):validate_observation(bad,side='target',program_digest=program['digest'],values=values)


def test_user_counter_facts_cannot_claim_machine_state_or_other_csr_permission():
    from dataclasses import replace
    trace,facts=trace_contract()
    assert facts.delegation_model is None and facts.virtual_memory_model is None and facts.complete
    with pytest.raises(ValueError):replace(facts,csr_access_policy=replace(facts.csr_access_policy,readable_csr_ids=('riscv.csr.mscratch',)))


def test_rehashed_foreign_source_implementation_is_not_a_supported_backend():
    from riscv2x86_py.time_trace_contract import validate_backend
    value=backend();value['sourceDigest']='sha256:'+'f'*64
    value['backendIdentity']=semantic_identity({k:v for k,v in value.items() if k!='backendIdentity'})
    with pytest.raises(ValueError,match='IMPLEMENTATION'):validate_backend(value)


def test_receipt_matches_consumed_registry_not_file_existence(tmp_path):
    from riscv2x86_py.contract_consumption import consumption_receipt
    f,result,a,registry,renderer=pipeline_fixture();source=tmp_path/'source.c';source.write_text('fixture')
    r=NS(fragment_id=f.id,runtime_registry=registry,renderer_registry=renderer)
    report={'findings':[{'fragment':asdict(f),'approvalArtifact':a,'suggestedReplacement':result.suggested_replacement}]}
    receipt=consumption_receipt(source,report,csr=r)
    assert receipt['records'][0]['disposition']=='consumed'
    r.runtime_registry=NS(other='not-the-consumed-registry')
    assert consumption_receipt(source,report,csr=r)['records'][0]['disposition']=='validated_not_consumed'


@pytest.mark.parametrize('level',['L1','L2'])
@pytest.mark.parametrize('wrong_target',[False,True])
def test_provider_lifecycle_and_persisted_event_audit_with_mocked_execution(tmp_path,monkeypatch,level,wrong_target):
    """Protocol test only: source/target execution is explicitly mocked."""
    from riscv2x86_py import time_trace_runner as runner
    from riscv2x86_py.automatic_l2_authority import _proof_effect_authority
    from riscv2x86_py.l2_authority import L2AuthoritySidecar,L2AuthorityProducer,L2RuntimeContractBinding
    from riscv2x86_py.translation_validation import ValidationLevel
    f,result,a,_,_=pipeline_fixture();a['l2TimeReturnScope']=f.compilerTimeReturnScope
    effects,relations,shell=_proof_effect_authority(a,f.id)
    runtime=L2RuntimeContractBinding(a['runtimeContractId'],'v1',semantic_identity(a['proofPayload']),True)
    sidecar=L2AuthoritySidecar(f.id,L2AuthorityProducer('translation-proof-sidecar','protocol-test','v1','sha256:'+'a'*64),
        shell,(),(),effects,relations,(runtime,),(),True)
    a['l2AuthoritySidecar']=sidecar.to_dict()
    finding={'fragment':asdict(f),'sourceDigest':f.compilerFragmentAuthority['sourceDigest'],
        'machineCodeHex':a['proofPayload']['machineCodeHex'],'approvalArtifact':a,'suggestedReplacement':result.suggested_replacement}
    report=tmp_path/'report.json';report.write_text(json.dumps({'findings':[finding]}))
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native compiler unavailable')
    config={'schemaVersion':runner.SCHEMA,'approvalPath':str(report),'sourceCompiler':gcc,'targetCompiler':gcc,
        'sourceCompilerDigest':digest(gcc),'targetCompilerDigest':digest(gcc),'observerDigest':runner.observer_digest(),
        'sourceRunner':['explicit-mocked-source'],'trajectory':[0,(1<<64)-1,7],'timeoutSeconds':10}
    programs={}
    for side in ('source','target'):
        path=tmp_path/(side+'.fixture');path.write_text('mocked execution input')
        programs[side+'_program_artifact']=NS(artifact_path=str(path),artifact_digest=digest(path),build_identity='sha256:'+'b'*64)
    artifact=NS(fragment_id=f.id,proof_identity=a['proofIdentity'],l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity,l2_authority_complete=True,
        target_route='controlled-time',renderer_semantic_contract_id='time-v1',runtime_contract_id=a['runtimeContractId'],runtime_contract_version='v1')
    def execute(**kwargs):
        side=kwargs['side'];values=kwargs['values'];program=kwargs['program']
        output='site 1000\n'+''.join(f'{i} {v if not wrong_target or side=="source" else 1:016x}\n' for i,v in enumerate(values))
        events=''.join(f'{i} {v:016x} {0x1004 if side=="source" else 0:016x}\n' for i,v in enumerate(values))
        return {'side':side,'programDigest':program['digest'],'returnCode':0,'stdout':output,'stderr':'','events':events,'functionSize':16}
    monkeypatch.setattr(runner,'observe',execute)
    value=runner.run(config,level=ValidationLevel(level),translation_artifact=artifact,
        target_environment={'targetIsa':'x86_64','sourceIsa':'rv64gc'},l2_provider_id='time-protocol',**programs)
    assert value.status.value==('failed' if wrong_target else 'verified'),value.detail
    detail=json.loads(value.detail);runner.validate_persisted_result(detail)
    detail['notClaimedProperties']=[];detail['evidenceIdentity']=semantic_identity({k:v for k,v in detail.items() if k!='evidenceIdentity'})
    with pytest.raises(ValueError,match='CLAIM'):runner.validate_persisted_result(detail)
