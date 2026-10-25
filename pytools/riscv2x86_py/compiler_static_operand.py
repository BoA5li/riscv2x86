"""Compiler-replayed literal inputs, never synthetic declarations/runtime reads."""
from copy import deepcopy
from collections.abc import Mapping
import re

from .compiler_value_flow import identity

SCHEMA = 'riscv2x86.compiler-static-operand.v1'
SHA = re.compile(r'sha256:[0-9a-f]{64}')


def validate_static_operand(raw, *, index, node, width, signedness, access, declaration):
    fields = {'schemaVersion','operandIndex','valueNodeIdentity','expressionIdentity',
              'evaluationBindingIdentity','value','widthBits','signedness','sourceConstraint','bindingIdentity'}
    if (not isinstance(raw, Mapping) or set(raw) != fields or raw['schemaVersion'] != SCHEMA
            or raw['bindingIdentity'] != identity({k:v for k,v in raw.items() if k!='bindingIdentity'})
            or access != 'input' or declaration or type(index) is not int
            or type(raw['operandIndex']) is not int or raw['operandIndex'] != index
            or raw['valueNodeIdentity'] != node or raw['widthBits'] != width
            or type(raw['widthBits']) is not int or not 1 <= width <= 64
            or raw['signedness'] != signedness or signedness not in {'signed','unsigned'}
            or raw['sourceConstraint'] not in {'i','n'} or type(raw['value']) is not int
            or any(not isinstance(raw[k],str) or SHA.fullmatch(raw[k]) is None
                   for k in ('valueNodeIdentity','expressionIdentity','evaluationBindingIdentity'))):
        raise ValueError('COMPILER_STATIC_OPERAND_INVALID')
    low = -(1 << (width-1)) if signedness == 'signed' else 0
    high = (1 << (width-(signedness == 'signed')))-1
    if not low <= raw['value'] <= high:
        raise ValueError('COMPILER_STATIC_OPERAND_RANGE_INVALID')
    return deepcopy(dict(raw))


def static_operands(fragment):
    """Replay the compiler envelope and exact GNU shell before reading literals."""
    from .compiler_fragment_closure import validate_closed_compiler_fragment_candidate
    from .compiler_provenance import bind_compiler_provenance
    from .compiler_expression_evaluation import literal_operand_value
    from types import SimpleNamespace
    authority = fragment.get('compilerFragmentAuthority') or {}
    candidate = authority.get('candidate') or {}
    if candidate.get('expressionEvaluation') is None:
        return {}
    validate_closed_compiler_fragment_candidate(candidate)
    embedded = candidate['expressionClosureInputs']['fragment']
    for name in ('outputs','inputs'):
        before,after = embedded[name],fragment[name]
        if len(before)!=len(after) or any(any(item.get(k)!=v for k,v in old.items()) for old,item in zip(before,after)):
            raise ValueError('COMPILER_STATIC_OPERAND_SHELL_MISMATCH')
    bindings = candidate['operandBindings']
    operands = [SimpleNamespace(operand_index=b['operandIndex'],declaration_id=b['declarationIdentity'],
        value_node_identity=b['valueNodeIdentity'],access_mode=b['access'],width_bits=b['widthBits'],
        signedness=b['signedness']) for b in bindings]
    bind_compiler_provenance(fragment,SimpleNamespace(fragment_id=fragment.get('id') or fragment.get('fragmentId'),
        operands=operands,authority_identity=authority['authorityIdentity']))
    evaluation=candidate['expressionEvaluation'];result={}
    for carrier in candidate['operandCarriers']:
        if 'constantValue' not in carrier:continue
        index=carrier['operandIndex'];b=bindings[index];evaluated=evaluation['bindings'][index]
        value=literal_operand_value(evaluated,evaluation['expressionJoin']['operands'][index])
        if carrier['constantValue']!=value:raise ValueError('COMPILER_STATIC_OPERAND_VALUE_MISMATCH')
        raw={'schemaVersion':SCHEMA,'operandIndex':index,'valueNodeIdentity':b['valueNodeIdentity'],
             'expressionIdentity':evaluated['expressionIdentity'],'evaluationBindingIdentity':evaluated['bindingIdentity'],
             'value':value,'widthBits':b['widthBits'],'signedness':b['signedness'],'sourceConstraint':evaluated['sourceConstraint']}
        raw['bindingIdentity']=identity(raw)
        result[index]=validate_static_operand(raw,index=index,node=b['valueNodeIdentity'],width=b['widthBits'],
            signedness=b['signedness'],access=b['access'],declaration=b['declarationIdentity'])
    return result
