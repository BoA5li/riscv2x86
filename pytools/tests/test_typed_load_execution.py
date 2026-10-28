"""IR/proof/native/typed-call checks; native runs are not dual-ISA acceptance."""
from dataclasses import replace
from types import SimpleNamespace as N
from copy import deepcopy
import ctypes
import json
import shutil
import subprocess
import pytest
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.schema import AsmFragment,AsmOperand
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.source_model import build_source_semantic_model
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import derive_target_constraints,TargetEnvironment
from riscv2x86_py.phase6d_common import run_semantic_proof_gate,CompilerCapabilityModel,TargetSemanticCatalog
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan,SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import Phase6FRenderRequest,RendererContext,render_approved_target_lowering
from riscv2x86_py.l2_memory_object import memory_proof_facts_from_source_model,memory_proof_facts_from_dict
from riscv2x86_py.memory_contracts import LOAD_ROLES
from riscv2x86_py.l3_memory_call import bind_load,load_value,load_initial_bytes
from riscv2x86_py.l3_trace_support import identity
from riscv2x86_py.compiler_memory_signature import export
from riscv2x86_py.l3_trace_deployment import harness
from riscv2x86_py.l3_qemu_memory_route import parse_objects


def model(width,carrier,projection,offset=0):
    def v(space,off,size,name=''):return N(space=space,offset=off,size=size,name=name)
    base=v('register',0x100,8,'a1');addr=v('unique',0x300,8)
    out=v('register',0x200,8,'a0');loaded=out if width==64 else v('unique',0x400,width//8)
    ops=[N(opcode='INT_ADD',output=addr,inputs=[base,v('const',offset,8)]),
         N(opcode='LOAD',output=loaded,inputs=[v('const',0,8),addr])]
    if width<64:
        ops.append(N(opcode='INT_SEXT' if projection=='sign_extend' else 'INT_ZEXT',output=out,inputs=[loaded]))
    ins=N(addr=0,size=4,asm_mnem='ld',asm_body='display only',terminator_kind=None,raw_ops=ops)
    blocks,summary=from_lifted([ins])
    fragment=AsmFragment(rawAsmText='opaque',isVolatile=True,clobbers=['memory'],
        outputs=[AsmOperand(constraint='=r',exprText='out',isOutput=True)],
        inputs=[AsmOperand(constraint='r',exprText='base',isOutput=False)])
    return build_source_semantic_model(fragment=fragment,blocks=blocks,cfg=CFGResult(ok=True),summary=summary,xlen=64,
        runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1},operand_width_bits={0:carrier,1:64}))


def approved(m):
    plan=next(p for p in generate_candidate_plans(m) if '.memory.load.' in p.metadata.get('renderer_semantic_contract_id',''))
    env=TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features={'x86:gpr_inline_asm'})
    derived=derive_target_constraints(source_model=m,candidate_plan=plan,target_environment=env)
    assert derived.success
    proof=run_semantic_proof_gate(source_model=m,preservation_decision=m.preservation,candidate_plan=plan,
        constraints=derived.constraints,target_environment=env,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}),frozenset({plan.metadata['renderer_semantic_contract_id']}),'typed-load-test'),
        compiler_capabilities=CompilerCapabilityModel(True,False),fragment_id='fragment:any')
    assert proof.approved
    a=ApprovedTargetLoweringPlan(plan,derived.constraints,proof,proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id,proof.evidence.target_environment_id,'test','1',SelectionTier.X86_INLINE_ASM)
    contract=GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(a)
    rendered=render_approved_target_lowering(Phase6FRenderRequest(a,env,RendererContext({plan.plan_id:contract},{0:'out',1:'base'})))
    return plan,rendered.emitted_text,proof


ROLES=sorted(set(LOAD_ROLES.values()))
@pytest.mark.parametrize('width,carrier,projection',ROLES)
@pytest.mark.parametrize('displaced',[False,True])
def test_ir_to_native_load_all_width_extension_contracts(tmp_path,width,carrier,projection,displaced):
    offset=3*(width//8) if displaced else 0
    m=model(width,carrier,projection,offset)
    plan,text,_=approved(m)
    assert LOAD_ROLES[plan.metadata['renderer_semantic_contract_id']]==(width,carrier,projection)
    facts=memory_proof_facts_from_source_model('fragment:any',m)
    assert facts.width_bytes==width//8 and facts.carrier_width_bits==carrier
    assert facts.value_projection==projection and memory_proof_facts_from_dict(facts.to_dict())==facts
    source=tmp_path/'load.c';binary=tmp_path/'load.so'
    source.write_text('#include <stdint.h>\nuint64_t f(void *base){uint'+str(carrier)+'_t out;'+text+'return (uint64_t)out;}\n')
    done=subprocess.run([shutil.which('cc'),'-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    f=ctypes.CDLL(str(binary)).f;f.argtypes=[ctypes.c_void_p];f.restype=ctypes.c_uint64
    for raw in (0,1,(1<<(width-1))-1,1<<(width-1),(1<<width)-1):
        data=bytearray([0xA5]*48);data[offset:offset+width//8]=raw.to_bytes(width//8,'little')
        obj=(ctypes.c_ubyte*48).from_buffer_copy(data)
        signed=raw-(1<<width) if projection=='sign_extend' and raw&(1<<(width-1)) else raw
        assert f(obj)==signed&((1<<carrier)-1)
        assert bytes(obj)==data


def fixture(width=8,projection='sign_extend',signed=False,result_signed=False,const=False):
    from tests.test_l3_memory_trace import finding
    f=finding();fid=f['fragment']['id'];m=model(width,64,projection,3*(width//8))
    facts=memory_proof_facts_from_source_model(fid,m)
    a=f['approvalArtifact'];a['l2MemoryProofFacts']=facts.to_dict()
    side=a['l2AuthoritySidecar'];side['memoryObjects'][0].update(readableRanges=[[facts.byte_offset,facts.byte_offset+facts.width_bytes]])
    side['operands'][0].update(declarationId='base',widthBits=64)
    side['operands'].append(dict(operandIndex=0,typeKind='integer',accessMode='output',widthBits=64,signedness='signed' if signed else 'unsigned',declarationId='out'))
    f['fragment']['compilerFragmentAuthority']={'fragmentBindingKey':{'beginOffset':12,'endOffset':24}}
    from riscv2x86_py.l3_memory_intent import memory_spec
    spec=memory_spec(f)
    typ={8:'unsigned char',16:'unsigned short',32:'unsigned int',64:'unsigned long long'}[width]
    fn={'functionId':'function','sourceDigest':'digest','arity':1,
        'l2OperandBoundary':{'parameterDeclarationIds':['base'],'returnDeclarationId':'out'}}
    result='long long' if result_signed else 'unsigned long long'
    pointer=('const ' if const else '')+typ+' *'
    fn['compilerMemoryCallSignature']=export(fn,[pointer],result,lambda t:t)
    scope={'scope':'single_asm_no_other_memory_or_control_effects','sourceDigest':'digest','functionIdentity':'function','asmBegin':12,'asmEnd':24}
    fn['compilerAtomicFunctionScope']=dict(scope,scopeIdentity=identity(scope))
    return f,fn,spec


@pytest.mark.parametrize('width',[8,16,32])
@pytest.mark.parametrize('projection',['sign_extend','zero_extend'])
@pytest.mark.parametrize('signed',[False,True])
@pytest.mark.parametrize('const',[False,True])
def test_typed_call_real_native_harness_and_full_object(tmp_path,width,projection,signed,const):
    f,fn,spec=fixture(width,projection,signed,signed,const)
    call=bind_load(fn,f,spec);scope={'name':'independent_load','callSignature':call}
    wrapper=harness(scope,spec,4)
    _,text,_=approved(model(width,64,projection,spec['offset']))
    result=call['compilerSignature']['result']['cType'];param=call['compilerSignature']['parameters'][0]['cType']
    source=tmp_path/'h.c';binary=tmp_path/'h'
    source.write_text(wrapper+'\n'+result+' independent_load('+param+' base){'+('long long' if signed else 'unsigned long long')+' out;'+text+'return out;}\n')
    done=subprocess.run([shutil.which('cc'),'-std=gnu11','-O2','-fstrict-aliasing','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    run=subprocess.run([str(binary),'a'*64],capture_output=True,text=True)
    assert run.returncode==0
    rows=parse_objects(run.stdout,'a'*64,spec,4,call)
    assert len(rows)==4
    wrong=[json.loads(line) for line in run.stdout.splitlines()];wrong[2]['value']='0000000000000000'
    with pytest.raises(ValueError,match='LOAD_VALUE_OR_OBJECT'):
        parse_objects('\n'.join(json.dumps(x) for x in wrong),'a'*64,spec,4,call)
    wrong=[json.loads(line) for line in run.stdout.splitlines()];raw=bytearray.fromhex(wrong[0]['objectHex']);raw[-1]^=1;wrong[0]['objectHex']=raw.hex()
    with pytest.raises(ValueError,match='LOAD_VALUE_OR_OBJECT'):
        parse_objects('\n'.join(json.dumps(x) for x in wrong),'a'*64,spec,4,call)


@pytest.mark.parametrize('mutation',['projection','output-type','return-binding','scope','pointer-type','json-bool'])
def test_typed_call_rejects_invalid_rehashed_authority(mutation):
    f,fn,spec=fixture()
    if mutation=='projection':
        a=f['approvalArtifact'];a['l2MemoryProofFacts']['valueProjection']='identity'
    if mutation=='output-type':f['approvalArtifact']['l2AuthoritySidecar']['operands'][1]['widthBits']=32
    if mutation=='return-binding':fn['l2OperandBoundary']['returnDeclarationId']='other'
    if mutation=='scope':fn['compilerAtomicFunctionScope']['asmBegin']=13
    if mutation=='pointer-type':fn['compilerMemoryCallSignature']['parameters'][0]['pointee']['widthBits']=16
    if mutation=='json-bool':fn['compilerMemoryCallSignature']['result']['signed']=0
    with pytest.raises(ValueError):bind_load(fn,f,spec)


def test_extended_facts_cannot_downgrade_to_equal_width_schema():
    facts=memory_proof_facts_from_source_model('fragment:any',model(8,64,'sign_extend'))
    with pytest.raises(ValueError,match='projection'):
        replace(facts,schema_version='riscv2x86.l2-memory-proof-facts.v3',facts_identity='')


@pytest.mark.parametrize('width',[8,16,32])
@pytest.mark.parametrize('projection',['sign_extend','zero_extend'])
def test_actual_profile_l2_authority_and_native_full_return_observation(tmp_path,width,projection):
    from tests.test_l2_memory_object_observation import _object_binding
    from riscv2x86_py.l2_semantic_profile import profile_from_source_model
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.automatic_l2_effect import _object_relative_memory_wrapper,_full_load_returns
    m=model(width,64,projection,3*(width//8));_,text,proof=approved(m)
    profile=profile_from_source_model('fragment:any',m);assert profile.complete
    facts=memory_proof_facts_from_source_model('fragment:any',m);e=proof.evidence
    a={'proofStatus':'approved','architectureSemanticsPreserved':True,'shellSemanticsPreserved':True,
        'sourceModelId':e.source_model_id,'constraintsId':e.constraints_id,'preservationDecisionId':e.preservation_decision_id,
        'planId':e.plan_id,'targetEnvironmentId':e.target_environment_id,'targetCatalogVersion':e.target_catalog_version,
        'l2MemoryProofFacts':facts.to_dict(),'proofIdentity':proof.l2_effect_proof_facts.proof_identity,
        'rendererContractIdentity':proof.l2_effect_proof_facts.renderer_contract_identity,'l2EffectProofFacts':proof.l2_effect_proof_facts.to_dict()}
    f={'fragment':{'id':'fragment:any','enclosingFunction':'read_value',
        'outputs':[{'constraint':'=r','symbolicName':'value'}],'inputs':[{'constraint':'r','symbolicName':'base'}]},
        'l2SemanticProfile':profile.to_dict(),'approvalArtifact':a}
    pointer='uint'+str(width)+'_t *'
    boundary={'complete':True,'sourceDigest':'sha256:'+'f'*64,'parameterDeclarationIds':['base'],
        'asmOperandDeclarationIds':['value','base'],'returnDeclarationId':'value',
        'asmOperandValueNodeIdentities':['sha256:'+'0'*64,'sha256:'+'1'*64],
        'declarationReferenceCounts':{'value':2,'base':1},
        'declarations':{'value':{'name':'value','type':'uint64_t'},'base':{'name':'base','type':pointer}},
        'memoryObjectBindings':{'base':_object_binding(origin='automatic-aligned-memory-object-harness-v1')}}
    fn={'name':'read_value','arity':1,'returnType':'uint64_t','sourceDigest':'sha256:'+'f'*64,
        'parameterTypes':[pointer],'pointerParameters':[0],'l2OperandBoundary':boundary}
    frontend=tmp_path/'frontend';frontend.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},[fn],frontend)==1
    sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    assert next(o for o in sidecar.operands if o.operand_index==0).width_bits==64
    wrapper=_object_relative_memory_wrapper(fn,a['l2AuthoritySidecar'],facts)
    src=tmp_path/'l2.c';exe=tmp_path/'l2'
    src.write_text(wrapper+'\nuint64_t read_value('+pointer+' base){uint64_t out;'+text+'return out;}\n')
    build=subprocess.run([shutil.which('cc'),'-O2','-Wall','-Wextra','-Werror','-fstrict-aliasing',str(src),'-o',str(exe)],capture_output=True,text=True)
    assert build.returncode==0,build.stderr
    actual=subprocess.run([str(exe)],capture_output=True,text=True)
    assert actual.returncode==0
    rows=_full_load_returns(actual.stdout);assert rows and len(rows)==4
    assert all('outside=0' in line for line in actual.stdout.splitlines() if line.startswith('l2mem;'))
    assert _full_load_returns(actual.stdout.replace('l2ret;sample=3','l2ret;sample=2')) is None
    changed=actual.stdout.replace('l2ret;sample=0;value=0000000000000000','l2ret;sample=0;value=8000000000000000')
    assert _full_load_returns(changed)!=rows


def test_load_contract_is_strictly_versioned_through_generic_dispatch():
    from tests.test_l3_memory_trace import contract
    from riscv2x86_py.l3_qemu_memory_route import parse_contract,TYPED_LOAD_CONTRACT_SCHEMA,CONTRACT_SCHEMA
    from riscv2x86_py.l3_experiment_runner import parse_experiment_contract
    f,fn,spec=fixture();call=bind_load(fn,f,spec)
    value=contract();value.update(schemaVersion=TYPED_LOAD_CONTRACT_SCHEMA,spec=spec,loadCall=call,
        deployment={'schemaVersion':'riscv2x86.compiler-region-execution-deployment.v3','spec':spec,'sampleCount':4,'functionScope':{'callSignature':call}})
    parse_contract(value);parse_experiment_contract(value)
    bad=deepcopy(value);bad['schemaVersion']=CONTRACT_SCHEMA;del bad['loadCall']
    with pytest.raises(ValueError,match='TYPED_LOAD_CONTRACT_VERSION_REQUIRED'):parse_contract(bad)
    bad=deepcopy(value);bad['loadCall']['outputSigned']=0
    bad['loadCall']['callIdentity']=identity({k:v for k,v in bad['loadCall'].items() if k!='callIdentity'})
    with pytest.raises(ValueError):parse_contract(bad)


def test_wrong_sign_extension_candidate_cannot_reuse_source_proof():
    m=model(8,64,'sign_extend');plan,_,_=approved(m)
    metadata=dict(plan.metadata);metadata['renderer_semantic_contract_id']=metadata['renderer_semantic_contract_id'].replace('.sx64.','.zx64.')
    plan=replace(plan,metadata=metadata)
    env=TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features={'x86:gpr_inline_asm'})
    assert not derive_target_constraints(source_model=m,candidate_plan=plan,target_environment=env).success


def test_signed_pointee_uses_real_typed_object(tmp_path):
    f,fn,spec=fixture()
    fn['compilerMemoryCallSignature']=export(fn,['signed char *'],'unsigned long long',lambda t:t)
    call=bind_load(fn,f,spec);scope={'name':'signed_input','callSignature':call}
    wrapper=harness(scope,spec,4);_,text,_=approved(model(8,64,'sign_extend',spec['offset']))
    src=tmp_path/'s.c';exe=tmp_path/'s'
    src.write_text(wrapper+'\nunsigned long long signed_input(signed char *base){unsigned long long out;'+text+'return out;}\n')
    done=subprocess.run([shutil.which('cc'),'-O2','-fstrict-aliasing','-Wall','-Wextra','-Werror',str(src),'-o',str(exe)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    result=subprocess.run([str(exe),'a'*64],capture_output=True,text=True)
    rows=parse_objects(result.stdout,'a'*64,spec,4,call)
    assert int(rows[2]['value'],16)==(1<<64)-128
    assert int(rows[3]['value'],16)==(1<<64)-1
