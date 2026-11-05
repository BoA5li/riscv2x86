"""Whole-asm GNU input relations, separate from semantic proof authority.

The legacy single-operand parser remains conservative. Consumers must not erase
a commutative modifier and then use the result without the whole relation.
"""
from .gnu_operand_contract import parse_riscv_operand
from .project_build_records import identity


def derive(outputs, inputs):
    if (not isinstance(outputs,list) or not isinstance(inputs,list)
            or any(not isinstance(c,str) or not c for c in outputs+inputs)):
        raise ValueError('GNU_RELATION_OPERANDS_INVALID')
    rows=[];pairs=[]
    for index,raw in enumerate(outputs+inputs):
        output=index<len(outputs);commutative=raw.startswith('%')
        if '%' in raw and (not commutative or raw.count('%')!=1):
            raise ValueError('GNU_COMMUTATIVE_MODIFIER_POSITION_INVALID')
        if commutative:
            if output:raise ValueError('GNU_COMMUTATIVE_READONLY_INPUT_REQUIRED')
            if index+1>=len(outputs)+len(inputs):raise ValueError('GNU_COMMUTATIVE_NEXT_INPUT_REQUIRED')
            if inputs[index-len(outputs)+1].startswith('%'):
                raise ValueError('GNU_COMMUTATIVE_OVERLAPPING_PAIRS')
            pairs.append([index,index+1])
        constraint=raw[1:] if commutative else raw
        parsed=parse_riscv_operand(constraint,output=output)
        if parsed.matching_output is not None and parsed.matching_output>=len(outputs):
            raise ValueError('GNU_MATCHING_OUTPUT_OUT_OF_RANGE')
        rows.append({'operandIndex':index,'originalConstraint':raw,'constraintBody':constraint,
            'role':parsed.role,'access':parsed.access,'matchingOutput':parsed.matching_output,
            'earlyClobber':parsed.early_clobber,'addressInRegister':parsed.address_in_register})
    if len(pairs)>1:raise ValueError('GNU_MULTIPLE_COMMUTATIVE_PAIRS_UNSUPPORTED')
    # Explicit alternatives and their interactions are not silently flattened;
    # the finite shared parser rejects them until a proved consumer is added.
    for left,right in pairs:
        if any(rows[i]['access']!='input' for i in (left,right)):
            raise ValueError('GNU_COMMUTATIVE_READONLY_INPUT_REQUIRED')
    order=list(range(len(rows)));permutations=[order]
    if pairs:
        swapped=list(order);left,right=pairs[0];swapped[left],swapped[right]=swapped[right],swapped[left]
        permutations.append(swapped)
    body={'schemaVersion':'riscv2x86.gnu-operand-relations.v1','outputs':list(outputs),'inputs':list(inputs),
        'operands':rows,'commutativePairs':pairs,'allowedOperandPermutations':permutations,
        'constraintRelationComplete':True,'semanticCommutativityProofRequired':bool(pairs),
        'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,relationIdentity=identity(body))


def validate(value):
    if (not isinstance(value,dict) or value.get('relationIdentity')!=identity({k:v for k,v in value.items() if k!='relationIdentity'})
            or identity(derive(value.get('outputs'),value.get('inputs')))!=identity(value)):
        raise ValueError('GNU_OPERAND_RELATION_REPLAY_MISMATCH')
    return value
