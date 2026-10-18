from copy import deepcopy
import pytest
from riscv2x86_py.atomic_authority import atomic_runtime_object_from_compiler_authority
from riscv2x86_py.compiler_expression import expression_from_ast
from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.semantic_authority import SemanticAuthorityError
from tests.test_production_route_authority import _compiler_authority, _atomic
from tests.test_compiler_expression_contracts import node, ctype
from riscv2x86_py.automatic_batch_cli import _source_range


def authority_for_expression(*, wrong_base=False):
    authority = _compiler_authority()
    original = deepcopy(authority['candidate'])
    original.pop('closureIdentity')
    original.pop('closureProvenance')
    original['schemaVersion']=original.pop('sourceCandidateSchemaVersion')
    carriers=original['operandCarriers']
    carriers[1]['operandIndex']=2
    base=carriers[1]['declarationIdentity']
    value=carriers[0]['declarationIdentity']
    raw=[node(referencedDecl={'id':'value'}),
         node('UnaryOperator',opcode='*',inner=[node(typ='unsigned long *',referencedDecl={'id':'other' if wrong_base else 'pointer'})]),
         node(typ='unsigned long *',referencedDecl={'id':'pointer'})]
    expressions=[expression_from_ast(n,source_digest=authority['sourceDigest'],
        function_identity=authority['functionIdentity'],
        declaration_identity=lambda d: {'value':value,'pointer':base,'other':'sha256:'+'9'*64}[d],
        source_range=_source_range) for n in raw]
    facts={'schemaVersion':'riscv2x86.compiler-expression-slots.v1',
        'sourceDigest':authority['sourceDigest'],'functionIdentity':authority['functionIdentity'],
        'candidateIdentity':original['candidateIdentity'],
        'slots':[{'operandIndex':i,'complete':True,'expression':e,'reasonCode':'','detail':''} for i,e in enumerate(expressions)],'complete':True}
    facts['factsIdentity']=identity(facts)
    original.update(compilerExpressionFacts=facts,compilerStructureComplete=False,
        operandSlotFacts={'slots':[{'operandIndex':i,'complete':i!=1} for i in range(3)]},
        reasonCodes=['L2_FRAGMENT_DECLARATION_IDENTITY_MISSING','L2_FRAGMENT_VALUE_NODE_MISSING'])
    pointer_type=authority['compilerTypeBindings']['1']['compilerType']
    fragment={'id':authority['fragmentId'],'outputs':[
        {'constraint':'+r','compilerType':ctype()}, {'constraint':'+m','compilerType':ctype()}],
        'inputs':[{'constraint':'r','compilerType':pointer_type}]}
    authority['candidate']=close_compiler_fragment_candidate(original,fragment,
        source_digest=authority['sourceDigest'],function_identity=authority['functionIdentity'])
    authority['compilerTypeBindings']={'2':{**authority['compilerTypeBindings']['1'],'operandIndex':2}}
    authority['authorityIdentity']=identity({k:v for k,v in authority.items() if k!='authorityIdentity'})
    return authority


def consume(authority):
    facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':2},operand_width_bits={0:64,1:64,2:64})
    return atomic_runtime_object_from_compiler_authority(authority,
        fragment_id=authority['fragmentId'],source_digest=authority['sourceDigest'],
        begin_offset=100,end_offset=140,runtime_facts=facts,atomic_operation=_atomic())


def test_atomic_consumes_closed_memory_lvalue_without_fabricated_declaration():
    authority=authority_for_expression()
    assert authority['candidate']['operandBindings'][1]['declarationIdentity']==''
    assert consume(authority)[2].authority_complete


def test_another_object_dereference_is_not_the_atomic_address():
    with pytest.raises(SemanticAuthorityError) as failure:
        consume(authority_for_expression(wrong_base=True))
    assert failure.value.reason_code=='ATOMIC_EXPRESSION_OBJECT_ADDRESS_UNPROVEN'


def test_memory_lvalue_has_object_role_and_is_not_a_register_operand():
    from dataclasses import replace
    from riscv2x86_py.source_model import (_runtime_operand_bindings,
        _runtime_operand_semantics, SourceOperandKind, SourceOperandAccess)
    from riscv2x86_py.schema import AsmFragment, AsmOperand
    from riscv2x86_py.shell_model import SourceShellModel
    objects=consume(authority_for_expression())
    assert set(objects)=={1,2}
    assert objects[1].operand_role=='memory_lvalue'
    assert objects[2].operand_role=='address'
    facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':2},
        operand_width_bits={0:64,1:64,2:64},atomic_memory_objects=objects)
    bindings=_runtime_operand_bindings(facts)
    assert bindings[1] is objects[1]
    shell=SourceShellModel.from_fragment(AsmFragment(id='f',rawAsmText='',
        outputs=[AsmOperand(constraint='+r',isOutput=True),AsmOperand(constraint='+m',isOutput=True)],
        inputs=[AsmOperand(constraint='r')]))
    semantic=_runtime_operand_semantics(facts,shell=shell,
        authoritative_bindings=bindings,memory_address_operand_offsets={2:0})
    assert semantic[1].kind is SourceOperandKind.MEMORY
    assert semantic[1].access is SourceOperandAccess.READ_WRITE
    assert semantic[1].address.memory_object_identity==semantic[2].address.memory_object_identity
    assert semantic[2].kind is SourceOperandKind.ADDRESS


def test_memory_role_and_machine_join_survive_runtime_snapshot():
    from riscv2x86_py.runtime_facts import (translation_runtime_facts_to_dict,
        translation_runtime_facts_from_dict)
    objects=consume(authority_for_expression())
    facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':2},
        operand_width_bits={0:64,1:64,2:64},atomic_memory_objects=objects,
        asm_goto_machine_join={'unitSnapshot':'separate join validated by its consumer'})
    restored=translation_runtime_facts_from_dict(translation_runtime_facts_to_dict(facts))
    assert restored.atomic_memory_objects==objects
    assert restored.asm_goto_machine_join==facts.asm_goto_machine_join


def memory_only_authority(memory_width=64):
    authority=authority_for_expression()
    original=deepcopy(authority['candidate']['expressionClosureInputs']['candidate'])
    fragment=deepcopy(authority['candidate']['expressionClosureInputs']['fragment'])
    pointer=authority['compilerTypeBindings']['2']['compilerType']
    fragment['outputs'][1]['constraint']='+A'
    if memory_width==32:
        pointer=deepcopy(pointer)
        pointer.update(canonicalType='unsigned int *',pointeeType='unsigned int',
            pointeeWidthBits=32,pointeeAlignmentBytes=4)
        fragment['outputs'][1]['compilerType']=ctype(canonicalType='unsigned int',widthBits=32,alignmentBytes=4)
        base=next(iter(authority['memoryObjectBindings']))
        expression=expression_from_ast(node('UnaryOperator',typ='unsigned int',opcode='*',
            inner=[node(typ='unsigned int *',referencedDecl={'id':'pointer'})]),
            source_digest=authority['sourceDigest'],function_identity=authority['functionIdentity'],
            declaration_identity=lambda _:base,source_range=_source_range)
        original['compilerExpressionFacts']['slots'][1]['expression']=expression
    fragment['outputs'][1]['compilerAddressType']=pointer
    fragment['inputs']=[]
    original['operandCarriers']=[x for x in original['operandCarriers'] if x['operandIndex']!=2]
    original['operandBindings']=[x for x in original['operandBindings'] if x['operandIndex']!=2]
    original['operandSlotFacts']['slots']=original['operandSlotFacts']['slots'][:2]
    facts=original['compilerExpressionFacts'];facts['slots']=facts['slots'][:2]
    facts['factsIdentity']=identity({k:v for k,v in facts.items() if k!='factsIdentity'})
    authority['candidate']=close_compiler_fragment_candidate(original,fragment,
        source_digest=authority['sourceDigest'],function_identity=authority['functionIdentity'])
    authority['compilerTypeBindings']={'0':authority['compilerTypeBindings'].get('0',{}),
        '1':{'operandIndex':1,'valueNodeIdentity':authority['candidate']['operandBindings'][1]['valueNodeIdentity'],
             'compilerType':fragment['outputs'][1]['compilerType']}}
    authority['authorityIdentity']=identity({k:v for k,v in authority.items() if k!='authorityIdentity'})
    return authority


def test_memory_operand_projects_address_without_an_extra_pointer_gnu_slot():
    authority=memory_only_authority()
    runtime=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1},operand_width_bits={0:64,1:64})
    objects=atomic_runtime_object_from_compiler_authority(authority,
        fragment_id=authority['fragmentId'],source_digest=authority['sourceDigest'],
        begin_offset=100,end_offset=140,runtime_facts=runtime,atomic_operation=_atomic())
    assert set(objects)=={1}
    projection=objects[1].address_projection
    assert projection['baseDeclarationIdentity'] in authority['memoryObjectBindings']
    assert projection['offsetBytes']==0
    assert objects[1].operand_role=='memory_lvalue'
    assert authority['candidate']['operandBindings'][1]['declarationIdentity']==''
