"""Original Phase-6 proof projection for GNU operand permutations.

Only the registered unsigned high-product contract currently exports this
projection. This is not a lowering route, execution authority or program proof.
The original backend replay remains responsible for the source p-code proof;
the consumer checks its binding and reruns the registered finite lemma.
"""
from collections.abc import Mapping

from .compiler_operand_type import compiler_operand_type_from_dict
from .gnu_operand_relations import derive as relation_from_constraints
from .l2_effect_proof import effect_proof_facts_from_dict, identity, proof_identity

SCHEMA = 'riscv2x86.operand-permutation-proof.v1'
FIELD = 'operandPermutationProof'
_BINDINGS = ('sourceFragmentId', 'sourceModelId', 'planId', 'constraintsId',
             'targetEnvironmentId', 'targetCatalogVersion', 'proofIdentity',
             'rendererContractIdentity', 'rendererSemanticContractId')


def _relation(fragment):
    return relation_from_constraints([x['constraint'] for x in fragment['outputs']],
                                     [x['constraint'] for x in fragment['inputs']])


def _types(fragment):
    return [compiler_operand_type_from_dict(x['compilerType'])
            for x in fragment['outputs'] + fragment['inputs']]


def export(source, approved, fragment, approval):
    """Project actual approved model/constraints; never recover an opaque ID."""
    from . import wide_integer_target as wide
    from .phase6d_common import source_model_identity, constraint_identity
    if approved.plan.metadata.get('renderer_semantic_contract_id') != wide.CONTRACT:
        return None
    if not approved.proof.approved or not wide.applicable(source):
        raise ValueError('PERMUTATION_APPROVED_SOURCE_REQUIRED')
    expected = wide.derive(source, approved.plan, approved.constraints.environment)
    if (not expected.success or expected.constraints != approved.constraints
            or approved.source_model_id != source_model_identity(source)
            or approval.get('sourceModelId') != approved.source_model_id
            or approval.get('constraintsId') != constraint_identity(approved.constraints)
            or approval.get('proofIdentity') != proof_identity(approved.proof.evidence)):
        raise ValueError('PERMUTATION_APPROVED_BINDING_MISMATCH')
    # These are Clang API facts already bound by the original source model.
    raw = {'id': fragment.id,
           'outputs': [{'constraint': x.constraint, 'compilerType': x.compilerType} for x in fragment.outputs],
           'inputs': [{'constraint': x.constraint, 'compilerType': x.compilerType} for x in fragment.inputs]}
    relation = _relation(raw)
    if not relation['semanticCommutativityProofRequired']:
        return None
    contract = approved.constraints.x86_gnu_inline_asm_contract
    if (contract.operand_relation_identity != relation['relationIdentity']
            or source.operand_relation_identity != relation['relationIdentity']
            or list(map(list, contract.allowed_operand_permutations)) != relation['allowedOperandPermutations']
            or list(map(list, source.operand_permutations)) != relation['allowedOperandPermutations']):
        raise ValueError('PERMUTATION_SOURCE_RELATION_MISMATCH')
    types = _types(raw)
    by = {x.source_operand_index: x for x in source.operands.operands}
    for index, typ in enumerate(types):
        operand = by[index]
        carrier = operand.lvalue if index == source.value_operation.result_operand_index else operand.expression
        if carrier.c_type_id != typ.type_identity or operand.width_bits != typ.width_bits:
            raise ValueError('PERMUTATION_SOURCE_TYPE_MISMATCH')
    operation = source.value_operation
    body = {'schemaVersion': SCHEMA, 'bindings': {k: approval[k] for k in _BINDINGS},
        'relation': relation, 'operandTypeIdentities': [t.type_identity for t in types],
        'operation': {'kind': operation.kind.value, 'widthBits': source.xlen,
            'resultOperandIndex': operation.result_operand_index,
            'inputOperandIndexes': list(operation.input_operand_indexes)},
        'scope': 'registered-operation-permutation-not-execution-or-program-authority'}
    result = dict(body, factsIdentity=identity(body))
    consume(result, raw, approval)
    return result


def consume(value, fragment, approval):
    """Check all bindings, whole relation and current registered proof lemma."""
    from . import wide_integer_target as wide
    if (not isinstance(value, Mapping) or set(value) != {'schemaVersion', 'bindings',
            'relation', 'operandTypeIdentities', 'operation', 'scope', 'factsIdentity'}
            or value.get('schemaVersion') != SCHEMA
            or value.get('scope') != 'registered-operation-permutation-not-execution-or-program-authority'
            or value.get('factsIdentity') != identity({k:v for k,v in value.items() if k != 'factsIdentity'})):
        raise ValueError('PERMUTATION_PROOF_SCHEMA_OR_IDENTITY_INVALID')
    if not isinstance(approval, Mapping):
        raise ValueError('PERMUTATION_APPROVAL_REQUIRED')
    bindings = {k: approval.get(k) for k in _BINDINGS}
    expected_proof = identity({k: approval.get(k, '') for k in (
        'sourceModelId', 'preservationDecisionId', 'planId', 'constraintsId',
        'proofStatus', 'targetEnvironmentId', 'targetCatalogVersion')})
    if (value['bindings'] != bindings or not all(bindings.values())
            or approval.get('proofStatus') != 'approved'
            or approval.get('architectureSemanticsPreserved') is not True
            or approval.get('shellSemanticsPreserved') is not True
            or bindings['proofIdentity'] != expected_proof
            or bindings['rendererContractIdentity'] != identity({
                'semanticContractId': wide.CONTRACT, 'planId': bindings['planId'],
                'constraintsId': bindings['constraintsId']})
            or bindings['sourceFragmentId'] != (fragment.get('id') or fragment.get('fragmentId'))
            or bindings['rendererSemanticContractId'] != wide.CONTRACT):
        raise ValueError('PERMUTATION_PROOF_APPROVAL_BINDING_MISMATCH')
    effect = effect_proof_facts_from_dict(approval.get('l2EffectProofFacts', {}))
    relation = _relation(fragment)
    if (not effect.complete or not effect.shell_relation.complete
            or not all((effect.shell_relation.cc_clobber_preserved,
                        effect.shell_relation.volatile_placement_preserved,
                        effect.shell_relation.continuation_preserved,
                        effect.shell_relation.compiler_visibility_preserved))
            or effect.fragment_id != bindings['sourceFragmentId']
            or effect.proof_identity != bindings['proofIdentity']
            or effect.plan_identity != bindings['planId']
            or effect.constraint_identity != bindings['constraintsId']
            or effect.renderer_contract_identity != bindings['rendererContractIdentity']
            or list(effect.shell_relation.operand_modes) != ['0:output', '1:input', '2:input']
            or list(effect.shell_relation.constraints) != [f'{i}:general_register:r' for i in range(3)]
            or list(effect.shell_relation.early_clobbers) != [r['operandIndex'] for r in relation['operands'] if r['earlyClobber']]
            or effect.shell_relation.tied_operands
            or value['relation'] != relation):
        raise ValueError('PERMUTATION_EFFECT_OR_RELATION_MISMATCH')
    types = _types(fragment)
    operation = value['operation']
    if (not isinstance(operation, Mapping) or set(operation) != {
            'kind', 'widthBits', 'resultOperandIndex', 'inputOperandIndexes'}
            or operation['kind'] != 'unsigned_multiply_high'
            or type(operation['widthBits']) is not int or operation['widthBits'] not in (32, 64)
            or type(operation['resultOperandIndex']) is not int or operation['resultOperandIndex'] != 0
            or not isinstance(operation['inputOperandIndexes'], list)
            or any(type(i) is not int for i in operation['inputOperandIndexes'])
            or sorted(operation['inputOperandIndexes']) != [1, 2]
            or len(types) != 3 or len(fragment['outputs']) != 1 or len(fragment['inputs']) != 2
            or value['operandTypeIdentities'] != [t.type_identity for t in types]
            or any(not t.is_integer or t.is_pointer or t.width_bits != operation['widthBits']
                   or t.qualifiers or not t.side_effect_free for t in types)
            or not types[0].modifiable_lvalue
            or any(not t.expression_repeatable for t in types[1:])
            or relation['allowedOperandPermutations'] != [[0, 1, 2], [0, 2, 1]]
            or [r['access'] for r in relation['operands']] != ['output', 'input', 'input']
            or any(r['role'] != 'value' or r['matchingOutput'] is not None
                   or r['constraintBody'].lstrip('=&') != 'r' for r in relation['operands'])
            or not wide.bitvector_lemma(operation['widthBits'])):
        raise ValueError('PERMUTATION_REGISTERED_LEMMA_REQUIRED')
    return {'proofIdentity': bindings['proofIdentity'], 'relationIdentity': relation['relationIdentity'],
            'factsIdentity': value['factsIdentity'], 'scope': value['scope']}
