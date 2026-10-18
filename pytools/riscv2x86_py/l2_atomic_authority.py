"""Proof-owned atomic RMW authority; public builtin proof is not a load/store proof."""
from dataclasses import asdict
from enum import Enum
from collections.abc import Mapping
from .compiler_value_flow import identity
from .l2_effect_proof import effect_proof_facts_from_dict

SCHEMA='riscv2x86.l2-atomic-proof-facts.v1'


def _json(value):
    if isinstance(value,Enum):return value.value
    if isinstance(value,dict):return {k:_json(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [_json(v) for v in value]
    return value


def atomic_proof_facts(fragment_id,source_model,approval):
    atom=source_model.atomic
    if not atom.present or not atom.complete or approval.get('proofStatus')!='approved':return None
    xlen=source_model.xlen
    if xlen not in {32,64} or atom.width_bits not in {32,64} or atom.width_bits>xlen:return None
    by_index={x.source_operand_index:x for x in source_model.operands.operands}
    value=by_index.get(atom.value_operand_index);result=by_index.get(atom.result_operand_index)
    if value is None:return None
    width={'sourceXlen':xlen,'memoryAccessWidth':atom.width_bits,'inputEffectiveWidth':atom.width_bits,
        'inputCarrierWidth':value.width_bits,'registerResultWidth':0 if result is None else xlen,
        'resultCarrierWidth':0 if result is None else result.width_bits,
        'inputTruncation':'low_bits' if value.width_bits>atom.width_bits else 'none',
        'inputRegisterTruncation':'low_bits' if xlen>atom.width_bits else 'none',
        'resultExtension':'none' if result is None else 'sign_extend' if xlen>atom.width_bits else 'identity'}
    payload={'schemaVersion':SCHEMA,'fragmentId':fragment_id,'proofIdentity':approval['proofIdentity'],
        'planId':approval['planId'],'constraintsId':approval['constraintsId'],
        'rendererContractIdentity':approval['rendererContractIdentity'],
        'atomicOperation':_json(asdict(atom)),'widthRoles':width,
        'registerOperandMap':dict(source_model.runtime_facts.rv_to_operand_index),'complete':True}
    return {**payload,'factsIdentity':identity(payload)}


def validate_atomic_proof_facts(raw,approval,fragment_id):
    fields={'schemaVersion','fragmentId','proofIdentity','planId','constraintsId',
        'rendererContractIdentity','atomicOperation','widthRoles','registerOperandMap','complete','factsIdentity'}
    if (not isinstance(raw,Mapping) or set(raw)!=fields or raw['schemaVersion']!=SCHEMA
            or raw['complete'] is not True or raw['fragmentId']!=fragment_id
            or raw['factsIdentity']!=identity({k:v for k,v in raw.items() if k!='factsIdentity'})
            or approval.get('proofStatus')!='approved'
            or any(raw[k]!=approval.get(k) for k in ('proofIdentity','planId','constraintsId','rendererContractIdentity'))):
        raise ValueError('L2_ATOMIC_PROOF_IDENTITY_MISMATCH')
    atom=raw['atomicOperation'];width=raw['widthRoles']
    if (not isinstance(atom,Mapping) or atom.get('complete') is not True
            or atom.get('kind')!='read_modify_write' or atom.get('width_bits') not in {32,64}
            or atom.get('result_semantics') not in {'old_value','none'}
            or atom.get('rmw_operation') not in {'fetch_add','fetch_and','fetch_or','fetch_xor','exchange'}
            or not atom.get('authority_identity') or not atom.get('memory_object_identity')
            or atom.get('wraparound_width_bits')!=atom['width_bits']):
        raise ValueError('L2_ATOMIC_OPERATION_CONTRACT_INVALID')
    expected_width_fields={'sourceXlen','memoryAccessWidth','inputEffectiveWidth','inputCarrierWidth','registerResultWidth',
        'resultCarrierWidth','inputTruncation','inputRegisterTruncation','resultExtension'}
    if (not isinstance(width,Mapping) or set(width)!=expected_width_fields
            or type(width['sourceXlen']) is not int or width['sourceXlen'] not in {32,64}
            or width['sourceXlen']<atom['width_bits']
            or width['inputTruncation']!=('low_bits' if width['inputCarrierWidth']>atom['width_bits'] else 'none')
            or width['inputRegisterTruncation']!=('low_bits' if width['sourceXlen']>atom['width_bits'] else 'none')
            or width['memoryAccessWidth']!=atom['width_bits'] or width['inputEffectiveWidth']!=atom['width_bits']
            or width['inputCarrierWidth'] not in {atom['width_bits'],width['sourceXlen']}
            or (width['inputCarrierWidth']>atom['width_bits'] and atom.get('register_width_bits')!=width['sourceXlen'])
            or type(width['registerResultWidth']) is not int
            or width['registerResultWidth'] not in {0,32,64}):
        raise ValueError('L2_ATOMIC_WIDTH_CONTRACT_INVALID')
    discarded=atom['result_semantics']=='none'
    if (discarded!=(atom.get('result_operand_index') is None)
            or (discarded and (width['registerResultWidth'] or width['resultCarrierWidth'] or width['resultExtension']!='none'))
            or (not discarded and (width['registerResultWidth']!=width['sourceXlen']
                or width['resultCarrierWidth'] not in {atom['width_bits'],width['sourceXlen']}
                or (width['resultCarrierWidth']>atom['width_bits'] and atom.get('register_width_bits')!=width['sourceXlen'])
                or width['resultExtension']!=('sign_extend' if width['registerResultWidth']>atom['width_bits'] else 'identity')))):
        raise ValueError('L2_ATOMIC_RESULT_PROJECTION_INVALID')
    effects=effect_proof_facts_from_dict(approval['l2EffectProofFacts'])
    if (effects.proof_identity!=raw['proofIdentity'] or len(effects.source_effects)!=1
            or effects.source_effects[0].effect_kind!='AtomicReadModifyWrite'
            or effects.source_effects[0].logical_subject!=atom['memory_object_identity']
            or not all({'atomicity','memory_order','read_modify_write','result_extension'}.issubset(r.preserved_properties)
                       for r in effects.relations)):
        raise ValueError('L2_ATOMIC_APPROVED_EFFECT_MISMATCH')
    return atom,width


def materialize_atomic_authority(finding,functions,producer_digest):
    from .l2_authority import (L2AuthoritySidecar,L2AuthorityProducer,L2OperandAuthority,
        L2MemoryObjectAuthority,L2_EXPRESSION_AUTHORITY_SIDECAR_SCHEMA)
    from .automatic_l2_authority import _proof_effect_authority
    from .compiler_fragment_closure import validate_closed_compiler_fragment_candidate
    fragment,approval=finding.get('fragment'),finding.get('approvalArtifact')
    if not isinstance(fragment,Mapping) or not isinstance(approval,Mapping):return None
    if finding.get('l2SemanticProfile',{}).get('patternKind')!='atomic':return None
    try:
        fragment_id=fragment.get('id') or fragment['fragmentId']
        atom,width=validate_atomic_proof_facts(approval.get('l2AtomicProofFacts'),approval,fragment_id)
        matches=[f for f in functions if f.get('name')==fragment.get('enclosingFunction')]
        if len(matches)!=1:return None
        boundary=matches[0]['l2OperandBoundary']
        compiler=fragment['compilerFragmentAuthority'];candidate=compiler['candidate']
        if (matches[0].get('functionId')!=compiler.get('functionIdentity')
                or matches[0].get('sourceDigest')!=compiler.get('sourceDigest')):return None
        validate_closed_compiler_fragment_candidate(candidate)
        if (compiler.get('authorityIdentity')!=identity({k:v for k,v in compiler.items() if k!='authorityIdentity'})
                or compiler.get('fragmentId')!=fragment_id):return None
        from .atomic_authority import atomic_runtime_object_from_compiler_authority
        from .runtime_facts import TranslationRuntimeFacts
        from types import SimpleNamespace
        register_map=approval['l2AtomicProofFacts']['registerOperandMap']
        def register_for(index):
            values=[r for r,i in register_map.items() if i==index]
            if not values:raise ValueError('L2_ATOMIC_REGISTER_ROLE_UNBOUND')
            return sorted(values)[0]
        decoded=SimpleNamespace(operation_kind=atom['rmw_operation'],width_bits=atom['width_bits'],
            address_binding=register_for(atom['address_operand_index']),
            input_value_binding=register_for(atom['value_operand_index']),
            result_binding=None if atom['result_operand_index'] is None else register_for(atom['result_operand_index']),
            result_semantics=atom['result_semantics'],ordering_before=atom['ordering_before'],
            ordering_after=atom['ordering_after'],atomicity_scope=atom['atomicity_scope'],
            address_space_identity=atom['address_space_identity'],complete=True,
            register_width_bits=atom.get('register_width_bits',0),result_extension=atom.get('result_extension',''))
        key=compiler['fragmentBindingKey']
        rebound=atomic_runtime_object_from_compiler_authority(compiler,fragment_id=fragment_id,
            source_digest=compiler['sourceDigest'],begin_offset=key['beginOffset'],end_offset=key['endOffset'],
            runtime_facts=TranslationRuntimeFacts(rv_to_operand_index=register_map,
                operand_width_bits={b['operandIndex']:b['widthBits'] for b in candidate['operandBindings']}),
            atomic_operation=decoded)
        if rebound[atom['address_operand_index']].authority_identity!=atom['authority_identity']:return None
        raw_operands=fragment['outputs']+fragment['inputs']
        bindings=candidate['operandBindings'];carriers=candidate['operandCarriers']
        if len(bindings)!=len(raw_operands) or len(carriers)!=len(bindings):return None
        expression=candidate.get('expressionEvaluation')
        operands=[]
        for index,(binding,carrier,gnu) in enumerate(zip(bindings,carriers,raw_operands)):
            if binding['operandIndex']!=index or carrier['operandIndex']!=index:return None
            declaration=binding['declarationIdentity']
            access='read_write' if index<len(fragment['outputs']) and gnu['constraint'].startswith('+') else 'output' if index<len(fragment['outputs']) else 'input'
            if binding['access']!=access:return None
            typ=compiler['compilerTypeBindings'][str(index)]['compilerType']
            from .compiler_operand_type import compiler_operand_type_from_dict
            typed=compiler_operand_type_from_dict(typ)
            if not typed.side_effect_free or typed.qualifiers or typed.pointee_qualifiers:return None
            expression_kwargs={}
            if carrier.get('carrierKind')=='memory_lvalue':
                if expression is None:return None
                evaluated=expression['bindings'][index]
                if evaluated['role']!='memory_lvalue' or evaluated['access']!=access:return None
                expression_kwargs={'expression_identity':evaluated['expressionIdentity'],
                    'evaluation_binding_identity':evaluated['bindingIdentity'],'operand_role':'memory_lvalue'}
                logical_name='memory_lvalue:'+str(index);kind='aggregate';signed='not_applicable';parameter=None
                operand_id=f'{fragment_id}:{index}:{evaluated["expressionIdentity"]}'
            else:
                decl=boundary['declarations'][declaration]
                logical_name=decl['name'];kind='pointer' if typed.is_pointer else 'integer'
                signed='unsigned' if typed.is_pointer or not typed.is_signed else 'signed'
                params=boundary['parameterDeclarationIds'];parameter=params.index(declaration) if declaration in params else None
                operand_id=f'{fragment_id}:{index}:{declaration}'
            operands.append(L2OperandAuthority(operand_id,index,logical_name,access,kind,typed.width_bits,
                signed,'','&' in gnu['constraint'],'','memory_object' if kind in {'aggregate','pointer'} else 'function_return' if declaration==boundary.get('returnDeclarationId') else 'function_argument' if parameter is not None else 'non_escaping',
                binding['valueNodeIdentity'],declaration,parameter,gnu['constraint'],True,**expression_kwargs))
        address=operands[atom['address_operand_index']]
        obj=compiler['memoryObjectBindings'][address.declaration_id]
        if (obj['objectIdentity']!=atom['memory_object_identity'] or obj['objectSizeBytes']<atom['width_bits']//8
                or obj['provenAlignmentBytes']!=atom['alignment_bytes']):return None
        memory=L2MemoryObjectAuthority(obj['objectIdentity'],obj['bindingOrigin'],obj['objectSizeBytes'],
            obj['provenAlignmentBytes'],'function_invocation',obj['aliasDomainIdentity'],
            ((0,obj['objectSizeBytes']),),((0,obj['objectSizeBytes']),),True)
        effects,relations,shell=_proof_effect_authority(approval,fragment_id)
        return L2AuthoritySidecar(fragment_id,L2AuthorityProducer('translation-proof-sidecar',
            'automatic-atomic-authority','v1',producer_digest),shell,tuple(operands),(memory,),effects,relations,(),(),True,
            schema_version=L2_EXPRESSION_AUTHORITY_SIDECAR_SCHEMA if expression else 'riscv2x86.l2-authority-sidecar.v3')
    except (KeyError,TypeError,ValueError,IndexError):return None
