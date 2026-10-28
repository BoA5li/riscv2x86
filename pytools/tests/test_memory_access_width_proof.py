"""IR -> candidate -> proof -> native execution, with wider input carriers."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as N
import ctypes
import shutil
import subprocess
import pytest

from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.phase6c_constraints import TargetEnvironment, derive_target_constraints
from riscv2x86_py.phase6d_common import CompilerCapabilityModel, TargetSemanticCatalog, run_semantic_proof_gate, source_model_identity
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan, SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import Phase6FRenderRequest, RendererContext, render_approved_target_lowering
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.source_model import build_source_semantic_model
from riscv2x86_py.l2_memory_object import memory_proof_facts_from_source_model, memory_proof_facts_from_dict, assess_memory_authority_materializability
from tests.test_l2_memory_object_observation import _materialization_boundary


def model(width, carrier=64, offset=12, value_op='direct'):
    def var(space, offset, size, name=''):
        return N(space=space, offset=offset, size=size, name=name)
    base = var('register', 0x100, 8, 'a1')
    value = var('register', 0x200, width//8, 'a0')
    addr = var('unique', 0x300, 8)
    ops = [N(opcode='INT_ADD', output=addr, inputs=[base, var('const', offset, 8)])]
    if value_op != 'direct':
        full = var('register', 0x200, 8, 'a0')
        sliced = var('unique', 0x400, width//8)
        if value_op == 'low':
            ops.append(N(opcode='SUBPIECE', output=sliced, inputs=[full, var('const', 0, 8)]))
        elif value_op == 'high':
            ops.append(N(opcode='SUBPIECE', output=sliced, inputs=[full, var('const', 1, 8)]))
        else:
            ops.append(N(opcode='INT_ADD', output=sliced, inputs=[value, var('const', 1, width//8)]))
        value = sliced
    ops.append(N(opcode='STORE', output=None, inputs=[var('const', 0, 8), addr, value]))
    ins = N(addr=0, size=4, asm_mnem='sw', asm_body='irrelevant', terminator_kind=None, raw_ops=ops)
    blocks, summary = from_lifted([ins])
    fragment = AsmFragment(rawAsmText='opaque', isVolatile=True, clobbers=['memory'],
        inputs=[AsmOperand(constraint='r', exprText='value', isOutput=False),
                AsmOperand(constraint='r', exprText='base', isOutput=False)])
    return build_source_semantic_model(fragment=fragment, blocks=blocks, cfg=CFGResult(ok=True), summary=summary,
        xlen=64, runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1}, operand_width_bits={0:carrier,1:64}))


def approve(m):
    plans = generate_candidate_plans(m)
    plan = next(p for p in plans if '.memory.store.' in p.metadata.get('renderer_semantic_contract_id', ''))
    env = TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features={'x86:gpr_inline_asm'})
    derived = derive_target_constraints(source_model=m, candidate_plan=plan, target_environment=env)
    assert derived.success
    semantic_id = plan.metadata['renderer_semantic_contract_id']
    proof = run_semantic_proof_gate(source_model=m, preservation_decision=m.preservation,
        candidate_plan=plan, constraints=derived.constraints, target_environment=env,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({semantic_id}), 'width-proof-test'),
        compiler_capabilities=CompilerCapabilityModel(True, False), fragment_id='fragment:any')
    assert proof.approved
    approved = ApprovedTargetLoweringPlan(plan, derived.constraints, proof, proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id, proof.evidence.target_environment_id, 'test', '1', SelectionTier.X86_INLINE_ASM)
    contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    rendered = render_approved_target_lowering(Phase6FRenderRequest(approved, env,
        RendererContext({plan.plan_id:contract}, {0:'value',1:'base'})))
    return plan, rendered.emitted_text, derived, proof


@pytest.mark.parametrize('width,carrier', [(w,c) for c in (32,64) for w in (8,16,32,64) if w<=c])
@pytest.mark.parametrize('offset', [0,16])
def test_ir_width_proof_and_native_bytes(tmp_path, width, carrier, offset):
    m = model(width, carrier, offset)
    plan, text, _, _ = approve(m)
    assert f'.u{width}.v1' in plan.metadata['renderer_semantic_contract_id']
    facts = memory_proof_facts_from_source_model('fragment:any', m)
    assert facts.width_bytes == width//8 and facts.required_alignment == width//8
    assert facts.matches_value_width(carrier)
    assert memory_proof_facts_from_dict(facts.to_dict()) == facts
    cc = shutil.which('cc')
    assert cc, 'native compiler required for width proof regression'
    src = tmp_path/'store.c'; lib = tmp_path/'store.so'
    src.write_text(f'#include <stdint.h>\nvoid f(void *base,uint{carrier}_t value) {{ {text} }}\n')
    done = subprocess.run([cc,'-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',str(src),'-o',str(lib)],capture_output=True,text=True)
    assert done.returncode == 0, done.stderr
    f = ctypes.CDLL(str(lib)).f
    f.argtypes = [ctypes.c_void_p, ctypes.c_uint64 if carrier==64 else ctypes.c_uint32]
    for value in (0,1,(1<<carrier)-1,0x1020304050607080 & ((1<<carrier)-1)):
        storage = (ctypes.c_ubyte*48)(*([0xA5]*48))
        f(storage,value)
        expected = bytearray([0xA5]*48)
        expected[offset:offset+width//8] = (value & ((1<<width)-1)).to_bytes(width//8,'little')
        assert bytes(storage) == bytes(expected)


def test_original_sw_offset12_carrier64_reaches_l2():
    m = model(32)
    _, text, _, _ = approve(m)
    assert 'movl %k1, 12(%0)' in text
    facts = memory_proof_facts_from_source_model('fragment:any',m)
    assert facts.width_bytes == 4 and facts.byte_offset == 12 and facts.carrier_width_bits == 64
    boundary = _materialization_boundary()
    boundary['declarations']['base']['type'] = 'uint32_t *'
    decision = assess_memory_authority_materializability(
        {'proofStatus':'approved','architectureSemanticsPreserved':True,'shellSemanticsPreserved':True},
        facts,boundary,{'id':'fragment:any'})
    assert decision.materializable, decision.reason_codes
    boundary['declarations']['value']['type'] = 'uint32_t'
    assert not assess_memory_authority_materializability(
        {'proofStatus':'approved','architectureSemanticsPreserved':True,'shellSemanticsPreserved':True},
        facts,boundary,{'id':'fragment:any'}).materializable


@pytest.mark.parametrize('value_op', ['high','arithmetic'])
def test_unproved_value_definitions_have_no_memory_candidate(value_op):
    m = model(32,value_op=value_op)
    assert m.memory.access_width_bits is None
    assert not any('.memory.store.' in p.metadata.get('renderer_semantic_contract_id','') for p in generate_candidate_plans(m))
    assert memory_proof_facts_from_source_model('fragment:any',m) is None


def test_low_subpiece_is_bound_and_wrong_projection_rejected():
    m = model(32,value_op='low')
    approve(m)
    bad = replace(m,memory=replace(m.memory,value_projection='identity'))
    assert source_model_identity(m) != source_model_identity(bad)
    assert not any('.memory.store.' in p.metadata.get('renderer_semantic_contract_id','') for p in generate_candidate_plans(bad))
    facts = memory_proof_facts_from_source_model('fragment:any',m)
    with pytest.raises(ValueError,match='projection'):
        replace(facts,value_projection='identity',facts_identity='')
    stale = facts.to_dict(); stale['carrierWidthBits'] = 32
    with pytest.raises(ValueError):
        memory_proof_facts_from_dict(stale)


def test_unaligned_source_facts_are_unavailable_without_pipeline_exception():
    m = model(32,offset=3)
    assert memory_proof_facts_from_source_model('fragment:any',m) is None


def test_wider_carrier_materializes_complete_store_sidecar(tmp_path):
    from tests.test_l2_memory_object_observation import _object_binding
    from tests.l2_effect_proof_fixtures import attach_effect_proof
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.l2_semantic_profile import (
        L2FragmentSemanticProfile, L2PatternKind, L2OperandShape, L2ControlFlowShape,
        L2MemoryShape, L2OrderingShape, L2PrivilegedShape, L2InternalStateShape)
    fid = 'fragment:any'
    facts = memory_proof_facts_from_source_model(fid, model(32))
    profile = L2FragmentSemanticProfile(fid,L2PatternKind.MEMORY_STORE,
        L2OperandShape(0,2,0,True),L2ControlFlowShape(False,False,False,False,False,0,True),
        L2MemoryShape(False,True,False,True,True),L2OrderingShape(False,False,True,True),
        L2PrivilegedShape(False,False,False,True),L2InternalStateShape(False,False,True,True),
        'rv64gc-user-to-x86_64-user',('logical_operand_observation','object_relative_memory_observation','shell_observation'))
    approval = {'proofStatus':'approved','architectureSemanticsPreserved':True,'shellSemanticsPreserved':True,
        'sourceModelId':'model','constraintsId':'constraints','preservationDecisionId':'decision','planId':'plan',
        'targetEnvironmentId':'environment','targetCatalogVersion':'catalog','l2MemoryProofFacts':facts.to_dict()}
    _, _, _, proof = approve(model(32))
    e = proof.evidence
    approval.update(sourceModelId=e.source_model_id, constraintsId=e.constraints_id,
        preservationDecisionId=e.preservation_decision_id, planId=e.plan_id,
        targetEnvironmentId=e.target_environment_id, targetCatalogVersion=e.target_catalog_version,
        proofIdentity=proof.l2_effect_proof_facts.proof_identity,
        rendererContractIdentity=proof.l2_effect_proof_facts.renderer_contract_identity,
        l2EffectProofFacts=proof.l2_effect_proof_facts.to_dict())
    finding = {'fragment':{'id':fid,'enclosingFunction':'unrelated_name','outputs':[],
        'inputs':[{'constraint':'r','symbolicName':'value'},{'constraint':'r','symbolicName':'base'}]},
        'l2SemanticProfile':profile.to_dict(),'approvalArtifact':approval}
    boundary = {'complete':True,'sourceDigest':'sha256:'+'f'*64,
        'parameterDeclarationIds':['base','value'],'asmOperandDeclarationIds':['value','base'],
        'returnDeclarationId':'','asmOperandValueNodeIdentities':['sha256:'+'0'*64,'sha256:'+'1'*64],
        'declarationReferenceCounts':{'value':1,'base':1},
        'declarations':{'value':{'name':'value','type':'uint64_t'},'base':{'name':'base','type':'uint32_t *'}},
        'memoryObjectBindings':{'base':_object_binding(origin='automatic-aligned-memory-object-harness-v1')}}
    function = {'name':'unrelated_name','arity':2,'returnType':'void','sourceDigest':'sha256:'+'f'*64,
        'parameterTypes':['uint32_t *','uint64_t'],'pointerParameters':[0],'l2OperandBoundary':boundary}
    frontend = tmp_path/'frontend'; frontend.write_bytes(b'frontend')
    assert materialize_automatic_l2_authority({'findings':[finding]},[function],frontend) == 1, approval
    sidecar = l2_authority_sidecar_from_dict(approval['l2AuthoritySidecar'])
    assert sidecar.complete
    assert sidecar.memory_objects[0].writable_ranges == ((12,16),)
    assert next(op for op in sidecar.operands if op.operand_index==0).width_bits == 64


@pytest.mark.parametrize('width', [8,16,32,64])
def test_l2_harness_uses_typed_objects_and_wide_values(tmp_path,width):
    from riscv2x86_py.automatic_l2_effect import _object_relative_memory_wrapper
    offset = 16
    _, text, _, _ = approve(model(width,64,offset))
    function = {'name':'store_word','returnType':f'uint{width}_t',
        'parameterTypes':[f'uint{width}_t *','uint64_t'],'pointerParameters':[0]}
    authority = {'memoryObjects':[{'sizeBytes':32,'minimumAlignment':16}]}
    facts = memory_proof_facts_from_source_model('fragment:any', model(width,64,offset))
    wrapper = _object_relative_memory_wrapper(function,authority,facts)
    assert f'uint{width}_t typed_object[' in wrapper
    source = tmp_path/'harness.c'; binary=tmp_path/'harness'
    source.write_text('#include <stdint.h>\n'+f'uint{width}_t store_word(uint{width}_t *base,uint64_t value) {{ {text} return base[{offset//(width//8)}]; }}\n'+wrapper)
    done=subprocess.run([shutil.which('cc'),'-std=gnu11','-O2','-fstrict-aliasing','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    run=subprocess.run([str(binary)],capture_output=True,text=True)
    assert run.returncode==0 and len(run.stdout.splitlines())==8
    assert all(line.endswith('outside=0') for line in run.stdout.splitlines())


@pytest.mark.parametrize('mutation', [
    {'value_width_bits':64}, {'carrier_width_bits':32}, {'value_projection':'identity'},
])
def test_proof_rejects_tampered_target_width_contract(mutation):
    m=model(32)
    plan,_,derived,_=approve(m)
    contract=replace(derived.constraints.x86_memory_inline_asm_contract,**mutation)
    constraints=replace(derived.constraints,x86_memory_inline_asm_contract=contract)
    env=derived.constraints.environment
    proof=run_semantic_proof_gate(source_model=m,preservation_decision=m.preservation,
        candidate_plan=plan,constraints=constraints,target_environment=env,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}),
            frozenset({plan.metadata['renderer_semantic_contract_id']}),'test'),
        compiler_capabilities=CompilerCapabilityModel(True,False),fragment_id='fragment:any')
    assert not proof.approved


def test_low_register_view_needs_database_coordinates_and_rejects_prior_write():
    from riscv2x86_py.memory_access_semantics import decoded_access
    from riscv2x86_py.pcode_ir import Var,VarKind,Op
    from riscv2x86_py.register_views import RegisterReadView
    view=RegisterReadView('a0',0x200,8,0x200,4,'RISCV:LE:64:default')
    value=Var(VarKind.REG,'register',0x200,4,'a0',view)
    base=Var(VarKind.REG,'register',0x100,8,'a1')
    space=Var(VarKind.CONST,'const',0,8)
    store=Op(0,'STORE',None,[space,base,value])
    runtime=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1},operand_width_bits={0:64,1:64})
    def blocks(ops): return [N(instructions=[N(ops=ops)])]
    assert decoded_access(blocks([store]),runtime)==(32,0,'low_bits')
    wrong=replace(value,offset=0x201)
    assert decoded_access(blocks([Op(0,'STORE',None,[space,base,wrong])]),runtime) is None
    full=Var(VarKind.REG,'register',0x200,8,'a0')
    changed=Op(0,'INT_ADD',full,[full,Var(VarKind.CONST,'const',1,8)])
    assert decoded_access(blocks([changed,store]),runtime) is None


def test_load_output_overwrite_cannot_claim_identity_load_semantics():
    from riscv2x86_py.memory_access_semantics import decoded_access
    from riscv2x86_py.pcode_ir import Var,VarKind,Op
    out=Var(VarKind.REG,'register',0x200,8,'a0')
    base=Var(VarKind.REG,'register',0x100,8,'a1')
    space=Var(VarKind.CONST,'const',0,8)
    load=Op(0,'LOAD',out,[space,base])
    runtime=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1},operand_width_bits={0:64,1:64})
    blocks=lambda ops: [N(instructions=[N(ops=ops)])]
    assert decoded_access(blocks([load]),runtime)==(64,0,'identity')
    overwrite=Op(4,'COPY',out,[space])
    assert decoded_access(blocks([load,overwrite]),runtime) is None
