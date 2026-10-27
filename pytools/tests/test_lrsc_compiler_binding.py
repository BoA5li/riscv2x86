from copy import deepcopy
import pytest
from riscv2x86_py.compiler_expression import expression_from_ast
from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.automatic_batch_cli import _source_range
from riscv2x86_py.lrsc_compiler_binding import bind, replay_binding
from riscv2x86_py.lrsc_sequence import candidate, SequenceError
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from tests.test_atomic_expression_consumer import authority_for_expression
from tests.test_compiler_expression_contracts import node, ctype
from tests.test_lrsc_sequence_contract import code


def fixture(bits=64, order=(0,1,2,3,4,5), registers=(5,6,9,10,11)):
    authority = authority_for_expression(memory_width=bits)
    original = deepcopy(authority['candidate']['expressionClosureInputs']['candidate'])
    pointer = authority['compilerTypeBindings']['2']['compilerType']
    base = next(iter(authority['memoryObjectBindings']))
    declarations = {'p':base, **{str(i):'sha256:'+str(i+1)*64 for i in (0,1,2,5)}}
    memory_type = 'unsigned int' if bits==32 else 'unsigned long'
    raws = [node(referencedDecl={'id':str(i)}) for i in range(3)] + [
        node('UnaryOperator', typ=memory_type, opcode='*', inner=[node(typ=memory_type+' *',referencedDecl={'id':'p'})]),
        node(typ=memory_type+' *',referencedDecl={'id':'p'}), node(referencedDecl={'id':'5'})]
    expressions = [expression_from_ast(raws[i], source_digest=authority['sourceDigest'],
        function_identity=authority['functionIdentity'], declaration_identity=lambda d:declarations[d],
        source_range=_source_range) for i in order]
    memory_index=order.index(3)
    # Permute within the output and input partitions; the machine mapping owns roles.
    fragment={'id':authority['fragmentId'], 'outputs':[], 'inputs':[]}
    carriers=[]; nodes=[]
    for index, old in enumerate(order):
        typ=pointer if old==4 else ctype(canonicalType=memory_type,widthBits=bits,alignmentBytes=bits//8) if old==3 else ctype()
        operand={'constraint':'+A' if old==3 else '=&r' if old<3 else 'r', 'compilerType':typ}
        if old==3:operand['compilerAddressType']=pointer
        fragment['outputs' if index<4 else 'inputs'].append(operand)
        if old==3:continue
        declaration=declarations['p' if old==4 else str(old)]
        value_node='sha256:'+str(index+1)*64
        carriers.append(dict(operandIndex=index,declarationIdentity=declaration,valueNodeIdentity=value_node,
            carrierKind='pointer' if old==4 else 'integer', widthBits=64,signedness='unsigned',
            addressSpaceIdentity='c.default' if old==4 else '',complete=True))
        nodes.append({'nodeIdentity':value_node})
    facts=original['compilerExpressionFacts']
    facts['slots']=[dict(operandIndex=i,complete=True,expression=e,reasonCode='',detail='') for i,e in enumerate(expressions)]
    facts['factsIdentity']=identity({k:v for k,v in facts.items() if k!='factsIdentity'})
    original.update(operandCarriers=carriers,valueNodes=nodes,downstreamUses=[],
        operandSlotFacts={'slots':[dict(operandIndex=i,complete=i!=memory_index) for i in range(6)]})
    authority['candidate']=close_compiler_fragment_candidate(original,fragment,
        source_digest=authority['sourceDigest'],function_identity=authority['functionIdentity'])
    address_index=order.index(4)
    authority['compilerTypeBindings']={str(address_index):dict(operandIndex=address_index,
        valueNodeIdentity=next(x['valueNodeIdentity'] for x in carriers if x['operandIndex']==address_index),compilerType=pointer)}
    authority['authorityIdentity']=identity({k:v for k,v in authority.items() if k!='authorityIdentity'})
    role_old=(0,1,2,4,5)
    runtime=TranslationRuntimeFacts(rv_to_operand_index={f'x{reg}':order.index(old) for reg,old in zip(registers,role_old)},
        operand_width_bits={i:bits if old==3 else 64 for i,old in enumerate(order)})
    context=dict(fragment_id=authority['fragmentId'],source_digest=authority['sourceDigest'],
        begin_offset=100,end_offset=140,runtime_facts=runtime,frontend_fragment=fragment)
    return candidate(code(bits,registers=registers)),authority,context


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('order',[(0,1,2,3,4,5),(3,2,0,1,5,4)])
@pytest.mark.parametrize('registers',[(5,6,9,10,11),(11,12,13,14,15)])
def test_complete_join_preserves_all_slots_and_outputs(bits,order,registers):
    sequence,authority,context=fixture(bits,order,registers)
    result=bind(sequence,authority,**context)
    assert replay_binding(result,sequence,authority,**context)==result
    assert result['roleOperandIndexes']==dict(zip(('old','next','status','address','input'),(order.index(i) for i in (0,1,2,4,5))))
    assert result['memoryOperandIndex']==order.index(3)
    assert len(result['operandBindings'])==6
    assert result['compilerBindingComplete'] and result['semanticApproval'] is False
    assert sequence['compilerBindingComplete'] is False
    assert authority['candidate']['operandSlotFacts']['slots'][order.index(3)]['complete'] is False


@pytest.mark.parametrize('mutation',['object','range','width','missing','alias','role','projection','approval','stale'])
def test_invalid_join_or_rehashed_result_cannot_approve(mutation):
    from dataclasses import replace
    sequence,authority,context=fixture()
    if mutation=='approval':
        result=bind(sequence,authority,**context);result['semanticApproval']=True
        result['bindingIdentity']=identity({k:v for k,v in result.items() if k!='bindingIdentity'})
        with pytest.raises(SequenceError):replay_binding(result,sequence,authority,**context)
        return
    if mutation=='range':context['begin_offset']=99
    if mutation=='object':
        obj=next(iter(authority['memoryObjectBindings'].values()));obj['objectSizeBytes']=1
        obj['bindingIdentity']=identity({k:v for k,v in obj.items() if k!='bindingIdentity'})
    if mutation=='projection':
        obj=next(iter(authority['memoryObjectBindings'].values()));obj['volatile']=True
        obj['bindingIdentity']=identity({k:v for k,v in obj.items() if k!='bindingIdentity'})
    if mutation in ('width','missing','alias','role'):
        facts=context['runtime_facts'];mapping=dict(facts.rv_to_operand_index);widths=dict(facts.operand_width_bits)
        if mutation=='width':widths[3]=32
        if mutation=='missing':mapping.pop('x5')
        if mutation=='alias':mapping['t0']=1
        if mutation=='role':mapping['x5'],mapping['x10']=mapping['x10'],mapping['x5']
        context['runtime_facts']=replace(facts,rv_to_operand_index=mapping,operand_width_bits=widths)
    if mutation!='stale':authority['authorityIdentity']=identity({k:v for k,v in authority.items() if k!='authorityIdentity'})
    else:authority['sourceDigest']='changed'
    with pytest.raises(ValueError):bind(sequence,authority,**context)


def test_production_diagnostic_binds_but_does_not_approve():
    from riscv2x86_py.lrsc_diagnostics import decision
    from riscv2x86_py.route_authority import validate_route_decision
    sequence,authority,context=fixture(32)
    fragment={**context['frontend_fragment'],'beginOffset':100,'endOffset':140,
              'compilerFragmentAuthority':authority}
    record=decision(fragment,bytes.fromhex(sequence['machineBytes']),
        runtime_facts=context['runtime_facts'],source_digest=context['source_digest'])
    validate_route_decision(record)
    assert record['reasonCode']=='LRSC_COMPILER_BINDING_COMPLETE_SEMANTIC_PROOF_REQUIRED'
    assert record['accepted'] is False
    assert record['inputsPayload']['compilerBinding']['compilerBindingComplete'] is True
    broken=decision(fragment,bytes.fromhex(sequence['machineBytes']),
        runtime_facts=context['runtime_facts'],source_digest='stale')
    assert broken['accepted'] is False
    assert broken['inputsPayload']['compilerBindingFailure']['reasonCode']=='ATOMIC_COMPILER_AUTHORITY_IDENTITY_MISMATCH'
