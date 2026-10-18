"""Proof-owned bounded asm-goto continuation facts, with no predicted traces."""
from dataclasses import asdict
from collections.abc import Mapping
from .compiler_value_flow import identity
from .source_model import AsmGotoControlFlowAuthority

SCHEMA='riscv2x86.l2-asm-goto-proof-facts.v1'


def asm_goto_proof_facts(fragment_id, source_model, approval):
    control=source_model.control_flow
    if not control.has_asm_goto:
        return None
    authority=control.asm_goto_authority
    if (approval.get('proofStatus')!='approved' or authority is None or not authority.complete
            or not authority.predicate_region_identity or not authority.machine_continuation_join_identity
            or authority.goto_outputs):
        return None
    payload={'schemaVersion':SCHEMA,'fragmentId':fragment_id,
        'proofIdentity':approval['proofIdentity'],'planId':approval['planId'],
        'constraintsId':approval['constraintsId'],
        'rendererContractIdentity':approval['rendererContractIdentity'],
        'sourceAuthority':asdict(authority),'complete':True}
    return {**payload,'factsIdentity':identity(payload)}


def validate_asm_goto_proof_facts(raw, fragment, approval):
    fields={'schemaVersion','fragmentId','proofIdentity','planId','constraintsId',
        'rendererContractIdentity','sourceAuthority','complete','factsIdentity'}
    if (not isinstance(raw,Mapping) or set(raw)!=fields or raw['schemaVersion']!=SCHEMA
            or raw['complete'] is not True
            or raw['factsIdentity']!=identity({k:v for k,v in raw.items() if k!='factsIdentity'})
            or raw['fragmentId']!=(fragment.get('id') or fragment.get('fragmentId'))
            or approval.get('proofStatus')!='approved'
            or any(raw[k]!=approval.get(k) for k in
                   ('proofIdentity','planId','constraintsId','rendererContractIdentity'))):
        raise ValueError('L2_ASM_GOTO_PROOF_IDENTITY_MISMATCH')
    value=raw['sourceAuthority']
    if not isinstance(value,Mapping):
        raise ValueError('L2_ASM_GOTO_SOURCE_AUTHORITY_INVALID')
    from .l2_effect_proof import effect_proof_facts_from_dict
    effects=effect_proof_facts_from_dict(approval.get('l2EffectProofFacts',{}))
    if (effects.proof_identity!=raw['proofIdentity'] or len(effects.source_effects)!=1
            or effects.source_effects[0].effect_kind!='ControlTransfer'
            or effects.source_effects[0].logical_subject!='asm-goto:'+identity(dict(value))):
        raise ValueError('L2_ASM_GOTO_EFFECT_AUTHORITY_MISMATCH')
    copied=dict(value)
    for key in ('goto_outputs','clobbers','reason_codes'):
        copied[key]=tuple(copied[key])
    authority=AsmGotoControlFlowAuthority(**copied)
    if (not authority.complete or not authority.predicate_region_identity
            or not authority.machine_continuation_join_identity or authority.goto_outputs
            or fragment.get('outputs')
            or len(fragment.get('gotoEdges',[]))!=1
            or authority.fragment_id!=raw['fragmentId']
            or authority.fallthrough_successor_block!=fragment.get('asmGotoFallthroughContinuationId')
            or set(fragment.get('asmGotoSuccessorContinuationIds',[]))!={
                authority.taken_successor_block,authority.fallthrough_successor_block}):
        raise ValueError('L2_ASM_GOTO_CONTINUATION_CONTRACT_MISMATCH')
    region=authority.predicate_region_payload
    machine=authority.machine_continuation_join_payload
    if (not isinstance(region,Mapping) or region.get('regionIdentity')!=authority.predicate_region_identity
            or region.get('regionIdentity')!=identity({k:v for k,v in region.items() if k!='regionIdentity'})
            or not isinstance(machine,Mapping) or machine.get('joinIdentity')!=authority.machine_continuation_join_identity):
        raise ValueError('L2_ASM_GOTO_CLOSURE_PAYLOAD_MISMATCH')
    from .asm_goto_machine_join import validate_machine_continuations
    edges=fragment['gotoEdges']
    validate_machine_continuations(machine,raw['fragmentId'],[
        (e['asmTarget'],e['cLabel'],e['exitCode'],e['targetContinuationId']) for e in edges])
    edge=fragment['gotoEdges'][0]
    if (edge.get('cLabel')!=authority.taken_label_identity
            or edge.get('targetContinuationId')!=authority.taken_successor_block
            or edge.get('exitCode')!=authority.external_label_index):
        raise ValueError('L2_ASM_GOTO_LABEL_BINDING_MISMATCH')
    return authority
