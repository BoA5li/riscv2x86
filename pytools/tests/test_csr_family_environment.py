from dataclasses import asdict,replace
from copy import deepcopy
from types import SimpleNamespace as NS
import json
import pytest
from riscv2x86_py.csr_environment_contract import load_csr_environment_contract
from riscv2x86_py.csr_state_contract import SCHEMA,ABI,CONTEXT_EXPRESSION
from riscv2x86_py.route_authority import content_identity
from riscv2x86_py.semantic_content import semantic_identity
from tests.test_csr_environment_contract import _contract


@pytest.mark.parametrize('mutation',['source','target','object','context','identity'])
def test_runtime_replay_rejects_backend_mutations(tmp_path,mutation):
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    f,result,approval=pipeline_fixture(tmp_path,1)
    payload=approval['proofPayload'];backend=payload['backendContract']
    if mutation=='source':backend['sourceExecutionSnapshot']['execution_profile']='other-profile'
    if mutation=='target':backend['targetEnvironmentSnapshot']['environment_id']='other-environment'
    if mutation=='object':backend['stateContract']['targetStateObjectId']='other-object'
    if mutation=='context':backend['stateContract']['contextExpression']='unbound()'
    if mutation=='identity':backend['stateContract']['initialStateIdentity']='invalid'
    state=backend['stateContract']
    state['contractIdentity']=content_identity({k:v for k,v in state.items() if k!='contractIdentity'})
    approval['proofIdentity']=semantic_identity(payload)
    with pytest.raises(ValueError):validate_csr_runtime_approval(approval,f,result.suggested_replacement)


def logical_contract(tmp_path,*,source_execution=None,target_environment=None):
    source,path,value=_contract(tmp_path)
    value.update(schemaVersion='riscv2x86.csr-environment-contract.v2',semanticFamily='logical_csr_state')
    runtime=value['runtimeRegistry'];runtime.pop('counterContract')
    runtime['mapping'].update(sourceCsrId='riscv.csr.mscratch',targetStateObjectId='bound-scratch',
        stateLifetimeId='execution',targetOperationId='scratch-read',fieldMappings=['riscv.csr.mscratch.value'])
    state={'schemaVersion':SCHEMA,'targetStateObjectId':'bound-scratch','stateLifetimeId':'execution',
        'initialStateIdentity':'sha256:'+'1'*64,'sourceExecutionIdentity':semantic_identity(source_execution),
        'targetEnvironmentIdentity':semantic_identity(target_environment),'ownership':'one-logical-hart-per-bound-thread',
        'concurrency':'single-owner-no-concurrent-access','contextAbi':ABI,'contextExpression':CONTEXT_EXPRESSION}
    state['contractIdentity']=content_identity(state);runtime['stateContract']=state
    renderer=value['rendererRegistry'];renderer['targetOperationId']='scratch-read'
    renderer['recipe'].update(callableIdentifier='rv2x86_csr_read_checked_v1',csrToken='832',
        contextExpression=CONTEXT_EXPRESSION,requiredLibrary='libriscv2x86_runtime')
    value['contractIdentity']=content_identity({k:v for k,v in value.items() if k!='contractIdentity'})
    path.write_text(json.dumps(value));return source,path,value


def test_logical_family_has_no_fabricated_counter_contract(tmp_path):
    source,path,_=logical_contract(tmp_path)
    loaded=load_csr_environment_contract(path,source=source)
    assert loaded.semantic_family=='logical_csr_state'
    assert loaded.runtime_registry.mappings[0].counter_contract is None
    assert loaded.runtime_registry.state_contract['contextExpression']==CONTEXT_EXPRESSION


@pytest.mark.parametrize('mutation,reason',[
    ('family','FAMILY_UNSUPPORTED'),('counter','RUNTIME_FIELDS_INVALID'),('object','BINDING_MISMATCH'),
    ('concurrency','DOMAIN_UNSUPPORTED'),('abi','DOMAIN_UNSUPPORTED'),('helper','FAMILY_MISMATCH'),
    ('csr','FAMILY_MISMATCH'),('recipe_context','FAMILY_MISMATCH')])
def test_family_contract_cannot_approve_other_domains(tmp_path,mutation,reason):
    source,path,value=logical_contract(tmp_path);runtime=value['runtimeRegistry'];state=runtime['stateContract']
    if mutation=='family':value['semanticFamily']='anything'
    if mutation=='counter':runtime['counterContract']={}
    if mutation=='object':state['targetStateObjectId']='other-object'
    if mutation=='concurrency':state['concurrency']='shared-unrestricted'
    if mutation=='abi':state['contextAbi']='unregistered'
    if mutation=='helper':value['rendererRegistry']['recipe']['callableIdentifier']='rv2x86_csr_read'
    if mutation=='csr':runtime['mapping']['sourceCsrId']='riscv.csr.time'
    if mutation=='recipe_context':value['rendererRegistry']['recipe']['contextExpression']='unknown_context'
    state['contractIdentity']=content_identity({k:v for k,v in state.items() if k!='contractIdentity'})
    value['contractIdentity']=content_identity({k:v for k,v in value.items() if k!='contractIdentity'})
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match=reason):load_csr_environment_contract(path,source=source)


def pipeline_fixture(tmp_path,funct3):
    """Decoder/compiler-envelope/6A/6D/6F integration, not frontend/QEMU."""
    from tests.test_csr_sync_production_contracts import compiler_fragment
    from tests.test_csr_runtime_value_shell import fragment_and_binding
    from tests.test_privileged_state_analysis import _facts
    from riscv2x86_py.csr_architecture_profile import parse_profile
    from tests.test_csr_sync_production_contracts import profile
    from riscv2x86_py.csr_metadata_ingress import decode_csr_instruction, canonical_csr_operations_from_decoded
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.csr_value_flow import join_csr_operand_bindings
    from riscv2x86_py.csr_state_dataflow import analyze_csr_state_dataflow
    from riscv2x86_py.source_csr_semantic_model import adapt_source_csr_semantic_model
    from riscv2x86_py.privileged_state_analysis import _typed_csr_effect
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.pcode_ir import Block,CanonicalInsn,Op
    from riscv2x86_py.csr_translation_pipeline import CsrTranslationFallbackPolicy,run_csr_translation_pipeline
    from riscv2x86_py.csr_runtime_shell import AUTOMATIC_RUNTIME_BUILD_CONTRACT
    from riscv2x86_py.csr_runtime_approval import build_csr_runtime_approval
    immediate=funct3>=5
    f=compiler_fragment() if immediate else fragment_and_binding('separate')[0]
    f.outputs[0].exprText='out'
    if f.inputs:f.inputs[0].exprText='value'
    word=(0x340<<20)|((3 if immediate else 11)<<15)|(funct3<<12)|(10<<7)|0x73
    code=word.to_bytes(4,'little');decoder_profile=parse_profile(profile())
    decoded=decode_csr_instruction(code)
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=decoded,xlen_bits=64,profile=decoder_profile)[0]
    ins=CanonicalInsn(0x10000,4,privileged_operations=(op,));ins.decoded_csr_instruction=decoded
    block=Block(0x10000,ops=[Op(0x10000,'COPY',None,[])],instructions=[ins]);cfg=NS(entry=0x10000)
    effect=_typed_csr_effect(block.addr,0,op,_facts(readable=('riscv.csr.mscratch',),writable=('riscv.csr.mscratch',)),isolated_counter_access=True)
    assert effect.complete and effect.may_trap is False
    regmap={'a0':0} if immediate else {'a0':0,'a1':1}
    authority,_=bind_csr_compiler_operands(f,TranslationRuntimeFacts(rv_to_operand_index=regmap,
        operand_width_bits={i:64 for i in regmap.values()}),[ins],source_digest=f.compilerFragmentAuthority['sourceDigest'],
        architecture_profile=decoder_profile)
    binding=join_csr_operand_bindings(lifted_insns=[ins],authority=authority)[0]
    flow=analyze_csr_state_dataflow(blocks=[block],cfg=cfg,access_effects=(effect,))
    model=adapt_source_csr_semantic_model(NS(csr_effects=(effect,),csr_operand_bindings=(binding,),csr_state_dataflow=flow))
    assert model.complete and model.strict_eligible
    source_facts=NS(execution_profile='unit-profile');target_environment=NS(environment_id='bound-environment')
    _,path,value=logical_contract(tmp_path,source_execution=source_facts,target_environment=target_environment)
    value['sourceDigest']=f.compilerFragmentAuthority['sourceDigest'];value['fragmentId']=f.id
    runtime=value['runtimeRegistry'];runtime['executionProfile']='unit-profile'
    runtime['mapping'].update(sourceEffectId=binding.source_effect_id,targetOperationId='scratch-operation',
        readResultMapping='result',writeValueMapping=None if immediate else 'argument')
    symbol={1:'write',2:'set_bits',3:'clear_bits',5:'write',6:'set_bits',7:'clear_bits'}[funct3]
    value['rendererRegistry']['targetOperationId']='scratch-operation'
    value['rendererRegistry']['recipe'].update(callableIdentifier='rv2x86_csr_'+symbol+'_checked_v1')
    value['contractIdentity']=content_identity({k:v for k,v in value.items() if k!='contractIdentity'})
    path.write_text(json.dumps(value));loaded=load_csr_environment_contract(path)
    result=run_csr_translation_pipeline(model,target_environment,source_facts,loaded.runtime_registry,loaded.renderer_registry,
        CsrTranslationFallbackPolicy(),operand_expressions={i:x.exprText for i,x in enumerate(f.outputs+f.inputs)},
        fragment_id=f.id,source_fragment=f,target_build_contract=AUTOMATIC_RUNTIME_BUILD_CONTRACT)
    assert result.status=='approved',result.reason_codes
    approval=build_csr_runtime_approval(f,result,machine_code=code,
        decoder_profile={'privilege_spec_version':'1.12','xlen_bits':64,'extensions':['zicsr']},target_environment_id='bound-environment')
    return f,result,approval


@pytest.mark.parametrize('funct3',[1,2,3,5,6,7])
def test_all_six_scratch_operations_use_family_loader_proof_and_actual_runtime(tmp_path,funct3):
    from pathlib import Path
    import shutil,subprocess
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    f,result,approval=pipeline_fixture(tmp_path,funct3)
    assert approval['proofPayload']['schemaVersion']=='riscv2x86.csr-runtime-proof.v2'
    validate_csr_runtime_approval(approval,f,result.suggested_replacement)
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native ABI execution requires gcc')
    old=0x8123456789abcdef;value=3 if funct3>=5 else 0xf0f00f0f98765432
    expected=value if funct3 in {1,5} else old|value if funct3 in {2,6} else old & (~value & ((1<<64)-1))
    root=Path(__file__).resolve().parents[2];main=tmp_path/'main.c';binary=tmp_path/'probe'
    main.write_text('#include "riscv2x86_csr_runtime.h"\nint main(void) {\n'
        'struct rv2x86_csr_context ctx={0}; ctx.version=1; ctx.profile=RV2X86_CSR_SCRATCH_PROFILE_V1;\n'
        f'ctx.values[832]=UINT64_C({old}); uint64_t out=0;\n'+
        (f'uint64_t value=UINT64_C({value});\n' if funct3<5 else '')+
        'rv2x86_csr_bind_context_v1(&ctx);\n'+result.suggested_replacement+
        '\nrv2x86_csr_unbind_context_v1(&ctx);\n'+
        f'return out != UINT64_C({old}) || ctx.values[832] != UINT64_C({expected}); }}\n')
    completed=subprocess.run([gcc,'-O2','-fno-lto','-Wall','-Wextra','-Werror','-I'+str(root/'runtime/include'),
        str(main),str(root/'runtime/riscv2x86_csr_runtime.c'),'-o',str(binary)],capture_output=True,text=True)
    assert completed.returncode==0,completed.stderr
    assert subprocess.run([str(binary)]).returncode==0


@pytest.mark.parametrize('funct3',[1,2,3,5,6,7])
def test_scratch_permission_requires_explicit_complete_isolated_source_facts(funct3):
    from tests.test_privileged_state_analysis import _facts
    from riscv2x86_py.csr_metadata_ingress import decode_csr_instruction,canonical_csr_operations_from_decoded,CsrDecoderProfile
    from riscv2x86_py.privileged_state_analysis import _typed_csr_effect
    word=(0x340<<20)|((3 if funct3>=5 else 11)<<15)|(funct3<<12)|(10<<7)|0x73
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=decode_csr_instruction(word.to_bytes(4,'little')),
        xlen_bits=64,profile=CsrDecoderProfile('1.12',64,('zicsr',)))[0]
    complete=_facts(readable=('riscv.csr.mscratch',),writable=('riscv.csr.mscratch',))
    assert _typed_csr_effect(0x10000,0,op,complete).may_trap is True
    denied=_typed_csr_effect(0x10000,0,op,_facts(readable=(),writable=()),isolated_counter_access=True)
    assert denied.access_allowed is False and denied.may_trap is True
    assert _typed_csr_effect(0x10000,0,op,replace(complete,complete=False),isolated_counter_access=True).may_trap is True
