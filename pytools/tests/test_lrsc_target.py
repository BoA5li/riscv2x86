from dataclasses import replace, asdict
from copy import deepcopy
import json
import subprocess
import shutil
from pathlib import Path
from types import SimpleNamespace
import pytest
from tests.test_lrsc_source import ingress, model_for
from riscv2x86_py.lrsc_source import LrScRuntimeEvidence
from riscv2x86_py.lrsc_target import CONTRACT, expected_contract, symbolic_proof
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import run_semantic_proof_gate, TargetSemanticCatalog, CompilerCapabilityModel


def case(bits=64,operation='fetch_add',word=False,slot_order=(0,1,2,3,4,5)):
    f,r,m=ingress(bits,slot_order=slot_order,operation=operation,word_alu=word)
    indexes={k:i for i,k in enumerate(slot_order)}
    # Source expressions remain compiler-owned bindings; names are only renderer inputs.
    expr={0:'old',1:'next',2:'status',3:'*p',4:'p',5:'value'}
    for i,o in enumerate(f.outputs+f.inputs):o.exprText=expr[slot_order[i]]
    compiler=deepcopy(f.compilerFragmentAuthority)
    from riscv2x86_py.route_authority import content_identity
    compiler['compilerTypeBindings']={str(i):{'operandIndex':i,
        'valueNodeIdentity':b['valueNodeIdentity'],'compilerType':(f.outputs+f.inputs)[i].compilerType}
        for i,b in enumerate(compiler['candidate']['operandBindings'])}
    compiler['authorityIdentity']=content_identity({k:v for k,v in compiler.items() if k!='authorityIdentity'})
    f.compilerFragmentAuthority=compiler
    evidence=LrScRuntimeEvidence.produce(f,m,base_address=0,xlen_bits=64,
        runtime_facts=replace(r,lrsc_sequence_evidence=None),source_digest=f.compilerFragmentAuthority['sourceDigest'])
    r=replace(r,lrsc_sequence_evidence=evidence)
    source=replace(model_for(f,r,m),privileged_state=None)
    env=TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features={'x86:atomic','x86:gpr_inline_asm'})
    plan=generate_candidate_plans(source)[0]
    derived=derive_target_constraints(source_model=source,candidate_plan=plan,target_environment=env)
    return f,r,m,source,env,plan,derived


def proof_for(source,env,plan,derived):
    return run_semantic_proof_gate(source_model=source,candidate_plan=plan,
        constraints=derived.constraints,target_environment=env,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}),frozenset({CONTRACT}),'lrsc-tests'),
        compiler_capabilities=CompilerCapabilityModel(True,False),fragment_id=source.lrsc_sequence.fragment_id)


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
def test_sequence_passes_registered_common_proof_and_effect_gate(bits,operation):
    f,r,m,source,env,plan,d=case(bits,operation)
    assert d.success,d
    proof=proof_for(source,env,plan,d)
    assert proof.approved,proof
    assert proof.l2_effect_proof_facts.complete
    assert proof.l2_effect_proof_facts.source_effects[0].effect_kind=='AtomicReadModifyWrite'
    assert 'all_register_outputs' in proof.l2_effect_proof_facts.relations[0].preserved_properties
    assert not source.atomic.complete
    assert symbolic_proof(d.constraints.lrsc_sequence_contract)['allBitPatterns']


def translated_case(bits=64,operation='fetch_add',word=False,slot_order=(0,1,2,3,4,5)):
    from riscv2x86_py.translate import (_translate_phase6_proof_pipeline,TranslationContext,
        _build_operand_binding_view,_build_shell_semantics)
    from riscv2x86_py.cfg import CFGResult
    from riscv2x86_py.pcode_ir import IRSummary
    from riscv2x86_py.phase6e_selection import Phase6ESelectionPolicy
    from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
    from riscv2x86_py.translate import PrivilegedFunctionalFallbackPolicy
    f,r,m,source,env,plan,d=case(bits,operation,word,slot_order)
    context=TranslationContext(fragment=f,blocks=[],cfg=CFGResult(ok=True),
        summary=IRSummary(is_single_block=False,has_branch=True,has_call_or_return=False,
            has_memory_barrier=False,has_atomic=True,reads_regs=set(),writes_regs=set(),reads_mem=True,writes_mem=True),
        machine_code=m,xlen=64,shell=_build_shell_semantics(f),
        bindings=_build_operand_binding_view(f,r.rv_to_operand_index),runtimeFacts=r,
        sourceModel=source,decision=source.preservation)
    result=_translate_phase6_proof_pipeline(context=context,target_environment=env,
        target_semantic_catalog=None,compiler_capabilities=None,helper_contract_registry=None,
        selection_policy=Phase6ESelectionPolicy(),renderer_context=None,
        renderer_contract_registry=GPR_INTEGER_RENDERER_CONTRACT_REGISTRY,
        privileged_runtime_registry=None,privileged_functional_registry=None,
        privileged_functional_policy=PrivilegedFunctionalFallbackPolicy())
    return f,r,m,source,result


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
def test_actual_selection_and_renderer_produce_registered_target(bits,operation):
    f,r,m,source,result=translated_case(bits,operation)
    assert result.kind=='x86_inline_asm',result
    assert result.metadata['approvalArtifact']['proofStatus']=='approved'
    assert result.metadata['approvalArtifact']['l2LrscProofFacts']['complete']
    assert 'lock cmpxchg' in result.replacement and '=&a' in result.replacement
    assert 'LRSC_TARGET_SEQUENCE_PROOF_UNAVAILABLE' not in result.reasonCodes


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
@pytest.mark.parametrize('optimization',['-O0','-O2'])
def test_native_target_preserves_all_outputs_and_object(bits,operation,optimization,tmp_path):
    from riscv2x86_py.lrsc_source import reference_attempt
    if shutil.which('gcc') is None:pytest.skip('native GCC unavailable')
    f,r,m,source,result=translated_case(bits,operation)
    assert result.kind=='x86_inline_asm',result
    values=(0,1,0x7fffffff,0x80000000,0xffffffff,0x7fffffffffffffff,1<<63,(1<<64)-1)
    rows=[]
    for old in values:
        for value in values:
            initial=old&((1<<bits)-1)
            expected=reference_attempt(source.lrsc_sequence,loaded_value=initial,input_value=value,sc_status=0)
            rows.append('{'+','.join(hex(x)+'ULL' for x in (initial,value,expected['old'],expected['next'],expected['storeValue']))+'}')
    text='#include <stdint.h>\n'
    text+='typedef struct {uint64_t old,next,status;} result;\n'
    text+=f'result probe(uint{bits}_t *p,uint64_t value){{uint64_t old,next,status;'+result.replacement+'return (result){old,next,status};}\n'
    text+='int main(void){const uint64_t rows[][5]={'+','.join(rows)+'};'
    text+=f'for(unsigned i=0;i<sizeof(rows)/sizeof(rows[0]);i++){{uint{bits}_t object[4] __attribute__((aligned(16)))={{rows[i][0],0x31,0x72,0x53}};'
    text+='result r=probe(object,rows[i][1]);if(r.old!=rows[i][2]||r.next!=rows[i][3]||r.status||object[0]!=rows[i][4]||object[1]!=0x31||object[2]!=0x72||object[3]!=0x53)return 1;}return 0;}'
    src=tmp_path/'target.c';binary=tmp_path/'target';src.write_text(text)
    compiled=subprocess.run(['gcc','-std=gnu11',optimization,'-Wall','-Wextra','-Werror',str(src),'-o',str(binary)],capture_output=True,text=True)
    assert compiled.returncode==0,compiled.stderr
    assert subprocess.run([str(binary)],timeout=10).returncode==0


def finding_case(bits=64,operation='fetch_add'):
    from riscv2x86_py.schema import Finding
    from riscv2x86_py.l2_lrsc_authority import materialize
    f,r,m,source,result=translated_case(bits,operation)
    assert result.kind=='x86_inline_asm',result
    finding=Finding(fragment=f,translationRuntimeFacts=r,machineCodeHex=m.hex(),
        approvalArtifact=result.metadata['approvalArtifact'],l2SemanticProfile=result.metadata['l2SemanticProfile']).to_dict()
    compiler=f.compilerFragmentAuthority;candidate=compiler['candidate'];roles=dict(source.lrsc_sequence.role_operand_indexes)
    names={roles[k]:k for k in roles}
    declarations={b['declarationIdentity']:{'name':names[i]}
        for i,b in enumerate(candidate['operandBindings']) if b['declarationIdentity']}
    parameters=[candidate['operandBindings'][roles[k]]['declarationIdentity'] for k in ('address','input')]
    function={'name':'probe','functionId':compiler['functionIdentity'],'sourceDigest':compiler['sourceDigest'],
        'l2OperandBoundary':{'parameterDeclarationIds':parameters,'declarations':declarations,
            'returnDeclarationId':candidate['operandBindings'][roles['old']]['declarationIdentity']}}
    return finding,[function],source,result


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
def test_lrsc_l2_authority_replays_independent_source_and_target_contracts(bits,operation):
    from riscv2x86_py.l2_lrsc_authority import materialize,validate,require_observable_scope
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.l2_materialization import assess_fragment_l2_materializability
    finding,functions,source,result=finding_case(bits,operation)
    atom,width,rebuilt=validate(finding)
    assert atom['width_bits']==bits and width['resultCarrierWidth']==64
    sidecar=materialize(finding,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    assert len(sidecar.operands)==6 and sidecar.complete
    assert l2_authority_sidecar_from_dict(sidecar.to_dict())==sidecar
    decision=assess_fragment_l2_materializability(finding,sidecar=sidecar)
    assert decision.executable,decision
    require_observable_scope(finding,functions[0],rebuilt)


@pytest.mark.parametrize('mutation',['status','old','lock','width','object','model','proof'])
def test_rehashed_sequence_fact_cannot_change_approved_contract(mutation):
    from riscv2x86_py.l2_lrsc_authority import materialize
    from riscv2x86_py.route_authority import content_identity
    finding,functions,source,result=finding_case()
    a=finding['approvalArtifact'];raw=a['l2LrscProofFacts']
    if mutation=='status':raw['targetContract']['role_indexes'][4][1]=99
    if mutation=='old':raw['targetContract']['operation']='fetch_xor'
    if mutation=='lock':raw['targetContract']['program'][6][0]='unlocked_cmpxchg'
    if mutation=='width':raw['sourceSequence']['memory_width_bits']=32
    if mutation=='object':raw['targetContract']['object_identity']='wrong-object'
    if mutation=='model':raw['sourceSequence']['modelIdentity']='stale'
    if mutation=='proof':raw['proofIdentity']='stale'
    raw['factsIdentity']=content_identity({k:v for k,v in raw.items() if k!='factsIdentity'})
    assert materialize(finding,functions,'sha256:'+'f'*64) is None


def test_live_next_or_status_requires_an_actual_observation_sink():
    from riscv2x86_py.l2_lrsc_authority import require_observable_scope
    finding,functions,source,result=finding_case()
    candidate=finding['fragment']['compilerFragmentAuthority']['candidate']
    node=candidate['operandBindings'][dict(source.lrsc_sequence.role_operand_indexes)['next']]['valueNodeIdentity']
    candidate['downstreamUses'].append({'valueNodeIdentity':node,'useKind':'function_return','complete':True})
    with pytest.raises(ValueError,match='ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED'):
        require_observable_scope(finding,functions[0],source)


def test_target_contract_and_missing_lock_are_rejected_before_rendering():
    from riscv2x86_py.lrsc_target import symbolic_proof
    f,r,m,source,env,plan,d=case()
    c=d.constraints.lrsc_sequence_contract
    changed=replace(c,program=tuple(('unlocked_cmpxchg',)+i[1:] if i[0]=='locked_cmpxchg' else i for i in c.program))
    with pytest.raises(ValueError):symbolic_proof(changed)
    bad=replace(d,constraints=replace(d.constraints,lrsc_sequence_contract=changed))
    assert not proof_for(source,env,plan,bad).approved


def test_word_alu_and_permuted_gnu_slots_still_render():
    for word in (False,True):
        f,r,m,source,result=translated_case(32,'fetch_add',word,(3,2,0,1,5,4))
        assert result.kind=='x86_inline_asm',result
        assert result.metadata['approvalArtifact']['l2LrscProofFacts']['sourceSequence']['arithmetic_width_bits']==(32 if word else 64)

@pytest.mark.parametrize('word',[False,True])
@pytest.mark.parametrize('optimization',['-O0','-O2'])
def test_native_permuted_slots_and_word_arithmetic(word,optimization,tmp_path):
    from riscv2x86_py.lrsc_source import reference_attempt
    _,_,_,source,result=translated_case(32,'fetch_add',word,(3,2,0,1,5,4))
    expected=reference_attempt(source.lrsc_sequence,loaded_value=0x80000000,input_value=0xffffffffffffffff,sc_status=0)
    text='#include <stdint.h>\nint main(void){uint32_t object=0x80000000;uint32_t *p=&object;uint64_t value=UINT64_MAX,old,next,status;'
    text+=result.replacement
    text+=f'return old!={expected["old"]}ULL||next!={expected["next"]}ULL||status||object!={expected["storeValue"]}U;}}'
    src=tmp_path/'permuted.c';binary=tmp_path/'permuted';src.write_text(text)
    built=subprocess.run(['gcc','-std=gnu11',optimization,'-Wall','-Wextra','-Werror',str(src),'-o',str(binary)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    assert subprocess.run([str(binary)],timeout=10).returncode==0


def test_missing_feature_and_microarchitectural_intent_do_not_approve():
    _,_,_,source,env,plan,d=case()
    missing=replace(env,available_features=frozenset())
    assert not derive_target_constraints(source_model=source,candidate_plan=plan,target_environment=missing).success
    sensitive=replace(source,microarch=replace(source.microarch,explicitly_microarch_sensitive=True))
    assert not derive_target_constraints(source_model=sensitive,candidate_plan=plan,target_environment=env).success


def test_incomplete_downstream_enumeration_cannot_claim_dead_outputs():
    from riscv2x86_py.l2_lrsc_authority import require_observable_scope
    finding,functions,source,_=finding_case()
    finding['fragment']['compilerFragmentAuthority']['candidate']['downstreamUseEnumerationComplete']=False
    with pytest.raises(ValueError,match='ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED'):
        require_observable_scope(finding,functions[0],source)


def test_direct_amo_l3_observer_does_not_accept_sequence_approval():
    from riscv2x86_py.l3_atomic_spec import spec
    finding,_,_,_=finding_case()
    with pytest.raises(ValueError,match='L3_LRSC_SOURCE_OBSERVATION_BACKEND_REQUIRED'):
        spec(finding,[])


def test_public_automatic_authority_entry_attaches_sequence_sidecar(tmp_path):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    finding,functions,_,_=finding_case()
    frontend=tmp_path/'frontend';frontend.write_bytes(b'frontend identity fixture')
    report={'findings':[finding]}
    assert materialize_automatic_l2_authority(report,functions,frontend)==1
    approval=finding['approvalArtifact']
    assert approval['proofStatus']=='approved'
    assert approval['l2AuthoritySidecar']['complete']
    assert approval['l2MaterializationDecision']['executable']


def test_corrupt_lrsc_authority_does_not_fall_back_to_amo_or_scalar(tmp_path):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    finding,functions,_,_=finding_case()
    finding['approvalArtifact']['l2LrscProofFacts']['proofIdentity']='sha256:'+'0'*64
    frontend=tmp_path/'frontend';frontend.write_bytes(b'frontend identity fixture')
    assert materialize_automatic_l2_authority({'findings':[finding]},functions,frontend)==0
    assert not finding['approvalArtifact'].get('l2AuthoritySidecar')
    assert not finding['approvalArtifact']['l2MaterializationDecision']['executable']
