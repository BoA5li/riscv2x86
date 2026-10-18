from dataclasses import replace
from copy import deepcopy
from types import SimpleNamespace
import json
import pytest
from tests.test_production_route_authority import _compiler_authority,_atomic
from tests.test_canonical_atomic_operation import _atomic_model
from tests.test_compiler_expression_contracts import ctype
from riscv2x86_py.atomic_authority import atomic_runtime_object_from_compiler_authority
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.runtime_fact_model import RuntimeFactStatus
from riscv2x86_py.schema import AsmFragment,AsmOperand
from riscv2x86_py.shell_model import SourceShellModel
from riscv2x86_py.source_model import SourceOperandModel
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import TargetEnvironment,derive_target_constraints
from riscv2x86_py.phase6d_common import run_semantic_proof_gate,TargetSemanticCatalog,CompilerCapabilityModel
from riscv2x86_py.l2_atomic_authority import atomic_proof_facts,materialize_atomic_authority,validate_atomic_proof_facts
from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
from riscv2x86_py.atomic_builtin_shell import fnv,build_atomic_builtin_shell,validate_atomic_builtin_shell


def atomic_finding(expression=False,memory_width=64,memory_only=False,compiler_override=None):
    from tests.test_atomic_expression_consumer import authority_for_expression
    from tests.test_atomic_expression_consumer import memory_only_authority
    compiler=memory_only_authority(memory_width) if memory_only else authority_for_expression() if expression else _compiler_authority()
    if compiler_override is not None:compiler=compiler_override
    ranged=compiler.get('schemaVersion')=='riscv2x86.compiler-fragment-authority.v3'
    frontend_range={'beginOffset':100,'endOffset':141 if ranged else 140,
        'astBeginOffset':100 if ranged else -1,'astEndOffset':140 if ranged else -1}
    pointer_index=2 if expression else 1
    value_type=ctype()
    value_node=compiler['candidate']['operandBindings'][0]['valueNodeIdentity']
    compiler['compilerTypeBindings']['0']={'operandIndex':0,'valueNodeIdentity':value_node,'compilerType':value_type}
    compiler['authorityIdentity']=identity({k:v for k,v in compiler.items() if k!='authorityIdentity'})
    pointer_type=(compiler['candidate']['expressionClosureInputs']['fragment']['outputs'][1]['compilerAddressType']
        if memory_only else compiler['compilerTypeBindings'][str(pointer_index)]['compilerType'])
    if memory_width==32 and not memory_only:
        pointer_type.update(canonicalType='unsigned int *',pointeeType='unsigned int',pointeeWidthBits=32,pointeeAlignmentBytes=4)
        compiler['authorityIdentity']=identity({k:v for k,v in compiler.items() if k!='authorityIdentity'})
    if expression:
        compiler['compilerTypeBindings']['1']={'operandIndex':1,'valueNodeIdentity':compiler['candidate']['operandBindings'][1]['valueNodeIdentity'],'compilerType':value_type}
        compiler['authorityIdentity']=identity({k:v for k,v in compiler.items() if k!='authorityIdentity'})
    runtime=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':pointer_index},operand_width_bits={i:64 for i in range(pointer_index+1)})
    decoded=_atomic();decoded.width_bits=memory_width;decoded.register_width_bits=64;decoded.result_extension='sign_extend' if memory_width==32 else 'identity'
    obj=atomic_runtime_object_from_compiler_authority(compiler,fragment_id=compiler['fragmentId'],
        source_digest=compiler['sourceDigest'],begin_offset=100,end_offset=frontend_range['endOffset'],
        frontend_fragment={'id':compiler['fragmentId'],**frontend_range},runtime_facts=runtime,atomic_operation=decoded)[pointer_index]
    fragment=AsmFragment(id=compiler['fragmentId'],**frontend_range,rawAsmText='typed decoder fixture',isVolatile=True,clobbers=['memory','cc'],
        outputs=[AsmOperand(constraint='+r',exprText='value',isOutput=True,compilerType=value_type)]+([AsmOperand(constraint='+A' if memory_only else '+m',exprText='*ptr',isOutput=True,compilerType=compiler['compilerTypeBindings']['1']['compilerType'] if memory_only else value_type,compilerAddressType=pointer_type)] if expression or memory_only else []),
        inputs=[] if memory_only else [AsmOperand(constraint='r',exprText='ptr',compilerType=pointer_type)],compilerFragmentAuthority=compiler)
    model=_atomic_model();old_value,old_pointer=model.operands.operands
    address=replace(old_pointer.address,pointee_type_id=obj.pointee_type_id,memory_object_identity=obj.object_identity,
        atomic_authority_identity=obj.authority_identity,atomic_read_effect_identity=obj.read_effect_identity,
        atomic_write_effect_identity=obj.write_effect_identity,atomic_address_space_relation_identity=obj.address_space_relation_identity,address_projection=obj.address_projection)
    from riscv2x86_py.compiler_operand_type import compiler_operand_type_from_dict
    value_type_id=compiler_operand_type_from_dict(value_type).type_identity
    pointer_type_id=compiler_operand_type_from_dict(pointer_type).type_identity
    value=replace(old_value,expression=replace(old_value.expression,c_type_id=value_type_id),
        lvalue=replace(old_value.lvalue,c_type_id=value_type_id))
    pointer=replace(old_pointer,source_operand_index=pointer_index,address=address,expression=replace(old_pointer.expression,c_type_id=pointer_type_id))
    if memory_only:
        from riscv2x86_py.source_model import SourceOperandKind,SourceOperandAccess
        pointer=replace(pointer,kind=SourceOperandKind.MEMORY,access=SourceOperandAccess.READ_WRITE,
            writes=True,read_before_write=True,lvalue=value.lvalue)
    atom=replace(model.atomic,address_projection=obj.address_projection,width_bits=memory_width,wraparound_width_bits=memory_width,
        register_width_bits=64,result_extension=decoded.result_extension,address_operand_index=pointer_index,memory_object_identity=obj.object_identity,authority_identity=obj.authority_identity,
        read_effect_identity=obj.read_effect_identity,write_effect_identity=obj.write_effect_identity)
    model=replace(model,shell=SourceShellModel.from_fragment(fragment),atomic=atom,
        runtime_facts=RuntimeFactStatus.from_runtime_facts(runtime),operands=SourceOperandModel((value,pointer),True))
    plan=next(p for p in generate_candidate_plans(model) if p.plan_id=='c-builtin.atomic-fetch-add')
    environment=TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features={'compiler:atomic-builtin'},
        builtin_capabilities={'c_builtin:atomic','c_builtin:compiler_barrier'})
    derived=derive_target_constraints(source_model=model,candidate_plan=plan,target_environment=environment)
    assert derived.success,derived
    proof=run_semantic_proof_gate(source_model=model,preservation_decision=model.preservation,
        candidate_plan=plan,constraints=derived.constraints,target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}),frozenset({plan.metadata['renderer_semantic_contract_id']}),'atomic-test'),
        compiler_capabilities=CompilerCapabilityModel(True,True,frozenset({'c_builtin:atomic','c_builtin:compiler_barrier'})),
        fragment_id=fragment.id)
    assert proof.approved,proof
    facts=proof.l2_effect_proof_facts
    approval={'proofStatus':'approved','proofIdentity':facts.proof_identity,'planId':plan.plan_id,
        'constraintsId':facts.constraint_identity,'rendererContractIdentity':facts.renderer_contract_identity,
        'l2EffectProofFacts':facts.to_dict(),'rendererSemanticContractId':plan.metadata['renderer_semantic_contract_id']}
    approval['l2AtomicProofFacts']=atomic_proof_facts(fragment.id,model,approval)
    from dataclasses import asdict
    raw=asdict(fragment);raw['enclosingFunction']='probe'
    value_decl=compiler['candidate']['operandBindings'][0]['declarationIdentity']
    pointer_decl=(obj.address_projection['baseDeclarationIdentity'] if memory_only else compiler['candidate']['operandBindings'][pointer_index]['declarationIdentity'])
    function={'name':'probe','functionId':compiler['functionIdentity'],'sourceDigest':compiler['sourceDigest'],
        'arity':2,'parameterTypes':[pointer_type['canonicalType'],'unsigned long'],'returnType':'unsigned long','pointerParameters':[0],
        'l2OperandBoundary':{'declarations':{value_decl:{'name':'value','type':'unsigned long'},pointer_decl:{'name':'ptr','type':pointer_type['canonicalType']}},
            'parameterDeclarationIds':[pointer_decl,value_decl],'returnDeclarationId':value_decl}}
    return {'fragment':raw,'approvalArtifact':approval,'l2SemanticProfile':{'patternKind':'atomic'}},[function],model,derived.constraints


def test_real_phase6d_atomic_proof_consumed_by_dedicated_l2_authority():
    finding,functions,_,_=atomic_finding()
    sidecar=materialize_atomic_authority(finding,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    assert sidecar.source_effects[0].effect_kind=='AtomicReadModifyWrite'
    assert sidecar.memory_objects[0].size_bytes==32
    assert l2_authority_sidecar_from_dict(sidecar.to_dict())==sidecar


@pytest.mark.parametrize('field,value', [('rmw_operation','fetch_xor'),('value_operand_index',1),
    ('result_operand_index',1),('ordering_before','relaxed'),('memory_object_identity','wrong')])
def test_rehashed_atomic_fact_does_not_replace_compiler_decoder_authority(field,value):
    finding,functions,_,_=atomic_finding()
    raw=finding['approvalArtifact']['l2AtomicProofFacts']
    raw['atomicOperation'][field]=value;raw['factsIdentity']=identity({k:v for k,v in raw.items() if k!='factsIdentity'})
    assert materialize_atomic_authority(finding,functions,'sha256:'+'f'*64) is None


def test_registered_atomic_shell_is_not_generic_c_exception():
    finding,_,_,_=atomic_finding();approval=finding['approvalArtifact'];fragment=finding['fragment']
    text='{ __atomic_signal_fence(__ATOMIC_SEQ_CST); value=__atomic_fetch_add(ptr,value,__ATOMIC_ACQ_REL); __atomic_signal_fence(__ATOMIC_SEQ_CST); }'
    approval.update(replacementKind='c_builtin',atomicBuiltinCompilerBarrierShell=True,
        architectureSemanticsPreserved=True,shellSemanticsPreserved=True,
        sourceSliceDigest=fnv(fragment['rawAsmText']),replacementDigest=fnv(text))
    approval['atomicBuiltinShell']=build_atomic_builtin_shell(fragment,approval)
    assert validate_atomic_builtin_shell(fragment,approval,text)
    with pytest.raises(ValueError):validate_atomic_builtin_shell(fragment,approval,'value=0;')


def test_expression_memory_operand_uses_v5_without_fabricating_declaration():
    finding,functions,_,_=atomic_finding(expression=True)
    sidecar=materialize_atomic_authority(finding,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    assert sidecar.schema_version=='riscv2x86.l2-authority-sidecar.v5'
    assert sidecar.operands[1].declaration_id==''
    assert sidecar.operands[1].operand_role=='memory_lvalue'
    assert l2_authority_sidecar_from_dict(sidecar.to_dict())==sidecar
    wrong=sidecar.to_dict();wrong['schemaVersion']='riscv2x86.l2-authority-sidecar.v3'
    wrong.pop('authorityIdentity')
    with pytest.raises(ValueError):l2_authority_sidecar_from_dict(wrong)


def test_word_result_and_input_projections_are_proof_owned():
    finding,functions,model,constraints=atomic_finding(memory_width=32)
    contract=constraints.c_builtin_constraint
    assert contract.input_carrier_width_bits==64 and contract.input_truncation=='low_bits'
    assert contract.result_carrier_width_bits==64 and contract.result_projection=='sign_extend_32_to_64'
    sidecar=materialize_atomic_authority(finding,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    width=finding['approvalArtifact']['l2AtomicProofFacts']['widthRoles']
    assert (width['memoryAccessWidth'],width['inputEffectiveWidth'],width['registerResultWidth'])==(32,32,64)
    assert width['resultExtension']=='sign_extend'


def test_atomic_function_identity_cannot_be_joined_by_name_alone():
    finding,functions,_,_=atomic_finding()
    functions[0]['functionId']='sha256:'+'0'*64
    assert materialize_atomic_authority(finding,functions,'sha256:'+'f'*64) is None


def test_atomic_shell_distinguishes_source_slice_from_asm_template():
    finding,_,_,_=atomic_finding();approval=finding['approvalArtifact'];fragment=finding['fragment']
    text='{ __atomic_signal_fence(__ATOMIC_SEQ_CST); value=__atomic_fetch_add(ptr,value,__ATOMIC_ACQ_REL); __atomic_signal_fence(__ATOMIC_SEQ_CST); }'
    approval.update(replacementKind='c_builtin',atomicBuiltinCompilerBarrierShell=True,
        architectureSemanticsPreserved=True,shellSemanticsPreserved=True,
        sourceSliceDigest=fnv('__asm__ volatile("template" ::: "memory");'),replacementDigest=fnv(text))
    approval['atomicBuiltinShell']=build_atomic_builtin_shell(fragment,approval)
    assert approval['atomicBuiltinShell']['sourceSliceDigest']!=approval['atomicBuiltinShell']['asmTemplateDigest']
    assert validate_atomic_builtin_shell(fragment,approval,text)


def test_memory_only_address_projection_reaches_proof_and_l2_sidecar():
    finding,functions,model,constraints=atomic_finding(memory_only=True)
    assert constraints.c_builtin_constraint.object_address_of_lvalue
    assert model.atomic.address_projection['operandIndex']==1
    sidecar=materialize_atomic_authority(finding,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    assert sidecar.operands[1].declaration_id==''
    assert sidecar.operands[1].operand_role=='memory_lvalue'


def test_memory_operand_cannot_reuse_pointer_contract_without_projection():
    finding,functions,model,constraints=atomic_finding(memory_only=True)
    pointer=model.operands.operands[1]
    pointer=replace(pointer,address=replace(pointer.address,address_projection=None))
    model=replace(model,atomic=replace(model.atomic,address_projection=None),
        operands=replace(model.operands,operands=(model.operands.operands[0],pointer)))
    plan=next(p for p in generate_candidate_plans(model) if p.plan_id=='c-builtin.atomic-fetch-add')
    env=TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features={'compiler:atomic-builtin'},
        builtin_capabilities={'c_builtin:atomic','c_builtin:compiler_barrier'})
    result=derive_target_constraints(source_model=model,candidate_plan=plan,target_environment=env)
    assert not result.success
