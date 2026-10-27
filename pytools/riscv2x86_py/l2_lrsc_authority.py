"""Proof-owned LR/SC sequence authority, separate from single-AMO facts."""
from dataclasses import asdict
import json
from .route_authority import content_identity
from .lrsc_target import CONTRACT, expected_contract, symbolic_proof

SCHEMA='riscv2x86.l2-lrsc-sequence-proof.v1'


def _plain(x):return json.loads(json.dumps(x))


def proof_facts(source, approval):
    if source.lrsc_sequence is None or approval.get('proofStatus')!='approved':return None
    if approval.get('rendererSemanticContractId')!=CONTRACT:return None
    contract=expected_contract(source)
    body={'schemaVersion':SCHEMA,'fragmentId':source.lrsc_sequence.fragment_id,
        **{k:approval[k] for k in ('proofIdentity','planId','constraintsId','rendererContractIdentity')},
        'sourceSequence':source.lrsc_sequence.to_dict(),'targetContract':asdict(contract),
        'refinement':symbolic_proof(contract),'complete':True}
    return _plain(dict(body,factsIdentity=content_identity(body)))


def rebound_source(finding):
    from .schema import _frag_from
    from .runtime_facts import translation_runtime_facts_from_dict
    from .source_model import build_source_semantic_model
    from .pcode_ir import IRSummary
    from .cfg import CFGResult
    fragment=_frag_from(finding['fragment'])
    runtime=translation_runtime_facts_from_dict(finding['translationRuntimeFacts'])
    if runtime is None or runtime.lrsc_sequence_evidence is None:raise ValueError('L2_LRSC_RUNTIME_EVIDENCE_REQUIRED')
    sequence=runtime.lrsc_sequence_evidence.to_dict()['sequence']
    code=bytes.fromhex(finding.get('machineCodeHex') or sequence['machineBytes'])
    summary=IRSummary(is_single_block=False,has_branch=True,has_call_or_return=False,
        has_memory_barrier=False,has_atomic=True,reads_regs=set(),writes_regs=set(),reads_mem=True,writes_mem=True)
    return build_source_semantic_model(fragment=fragment,blocks=(),cfg=CFGResult(ok=True),
        summary=summary,xlen=64,runtime_facts=runtime,machine_code=code)


def validate(finding):
    from .l2_effect_proof import effect_proof_facts_from_dict
    approval=finding['approvalArtifact'];raw=approval.get('l2LrscProofFacts')
    fields={'schemaVersion','fragmentId','proofIdentity','planId','constraintsId',
        'rendererContractIdentity','sourceSequence','targetContract','refinement','complete','factsIdentity'}
    if (not isinstance(raw,dict) or set(raw)!=fields or raw['schemaVersion']!=SCHEMA
            or raw['complete'] is not True or approval.get('proofStatus')!='approved'
            or approval.get('rendererSemanticContractId')!=CONTRACT
            or raw['fragmentId']!=(finding['fragment'].get('fragmentId') or finding['fragment'].get('id'))
            or any(raw[k]!=approval.get(k) for k in ('proofIdentity','planId','constraintsId','rendererContractIdentity'))
            or raw['factsIdentity']!=content_identity({k:v for k,v in raw.items() if k!='factsIdentity'})):
        raise ValueError('L2_LRSC_PROOF_BINDING_INVALID')
    source=rebound_source(finding)
    contract=expected_contract(source)
    if (raw['sourceSequence']!=_plain(source.lrsc_sequence.to_dict())
            or raw['targetContract']!=_plain(asdict(contract))
            or raw['refinement']!=symbolic_proof(contract)):
        raise ValueError('L2_LRSC_SEQUENCE_REPLAY_MISMATCH')
    effects=effect_proof_facts_from_dict(approval['l2EffectProofFacts'])
    if (effects.proof_identity!=raw['proofIdentity'] or not effects.complete
            or len(effects.source_effects)!=1
            or effects.source_effects[0].effect_kind!='AtomicReadModifyWrite'
            or effects.source_effects[0].logical_subject!=contract.object_identity
            or any(not {'all_register_outputs','completion_state','atomicity','memory_order'}.issubset(r.preserved_properties)
                   for r in effects.relations)):
        raise ValueError('L2_LRSC_EFFECT_PROOF_MISMATCH')
    roles=dict(contract.role_indexes)
    atom={'kind':'read_modify_write','rmw_operation':contract.operation,'width_bits':contract.width,
        'alignment_bytes':contract.alignment,'address_operand_index':roles['address'],
        'value_operand_index':roles['input'],'result_operand_index':roles['old'],
        'result_semantics':'old_value','memory_object_identity':contract.object_identity,
        'register_width_bits':64,'sourceSequenceProofIdentity':raw['factsIdentity']}
    widths={'sourceXlen':64,'memoryAccessWidth':contract.width,'inputEffectiveWidth':contract.width,
        'inputCarrierWidth':64,'registerResultWidth':64,'resultCarrierWidth':64,
        'inputTruncation':'low_bits' if contract.width==32 else 'none',
        'inputRegisterTruncation':'low_bits' if contract.width==32 else 'none',
        'resultExtension':'sign_extend' if contract.width==32 else 'identity'}
    return atom,widths,source


def materialize(finding,functions,producer_digest,*,failure_details=None):
    from .l2_authority import (L2AuthoritySidecar,L2AuthorityProducer,L2OperandAuthority,
        L2MemoryObjectAuthority,L2_EXPRESSION_AUTHORITY_SIDECAR_SCHEMA)
    from .automatic_l2_authority import _proof_effect_authority
    from .compiler_operand_type import compiler_operand_type_from_dict
    try:
        atom,width,source=validate(finding)
        fragment=finding['fragment'];compiler=fragment['compilerFragmentAuthority'];candidate=compiler['candidate']
        matches=[fn for fn in functions if fn.get('functionId')==compiler['functionIdentity']
                 and fn.get('sourceDigest')==compiler['sourceDigest']]
        if len(matches)!=1:raise ValueError('L2_LRSC_COMPILER_FUNCTION_JOIN_REQUIRED')
        boundary=matches[0]['l2OperandBoundary'];parameters=boundary['parameterDeclarationIds']
        operands=[];expression=candidate['expressionEvaluation'];raw=fragment['outputs']+fragment['inputs']
        for i,(b,carrier,gnu) in enumerate(zip(candidate['operandBindings'],candidate['operandCarriers'],raw)):
            typ=compiler_operand_type_from_dict(compiler['compilerTypeBindings'][str(i)]['compilerType'])
            if not typ.side_effect_free or typ.qualifiers or typ.pointee_qualifiers:
                raise ValueError('L2_LRSC_OPERAND_TYPE_DOMAIN_UNSUPPORTED')
            decl=b['declarationIdentity'];memory=i==source.lrsc_sequence.memory_operand_index
            access=b['access'];kwargs={}
            if memory:
                evaluated=expression['bindings'][i]
                kwargs={'expression_identity':evaluated['expressionIdentity'],
                    'evaluation_binding_identity':evaluated['bindingIdentity'],'operand_role':'memory_lvalue'}
                name='memory_lvalue:'+str(i);kind='aggregate';signed='not_applicable';parameter=None
            else:
                declaration=boundary['declarations'][decl]
                name=declaration['name'];kind='pointer' if typ.is_pointer else 'integer'
                signed='unsigned' if typ.is_pointer or not typ.is_signed else 'signed'
                parameter=parameters.index(decl) if decl in parameters else None
            operands.append(L2OperandAuthority(f'{fragment["id"]}:{i}:{b["valueNodeIdentity"]}',i,
                name,access,kind,typ.width_bits,signed,'','&' in gnu['constraint'],'',
                'memory_object' if kind in {'aggregate','pointer'} else 'function_return' if decl==boundary.get('returnDeclarationId')
                else 'function_argument' if parameter is not None else 'non_escaping',
                b['valueNodeIdentity'],decl,parameter,gnu['constraint'],True,**kwargs))
        binding=finding['translationRuntimeFacts']['lrscSequenceEvidence']['binding'];obj=binding['memoryObjectBinding']
        if obj['objectIdentity']!=atom['memory_object_identity']:
            raise ValueError('L2_LRSC_MEMORY_OBJECT_IDENTITY_MISMATCH')
        memory=L2MemoryObjectAuthority(obj['objectIdentity'],obj['bindingOrigin'],obj['objectSizeBytes'],
            obj['provenAlignmentBytes'],'function_invocation',obj['aliasDomainIdentity'],
            ((0,obj['objectSizeBytes']),),((0,obj['objectSizeBytes']),),True)
        joined=_proof_effect_authority(finding['approvalArtifact'],fragment['id'])
        if joined is None:raise ValueError('L2_LRSC_EFFECT_RELATION_JOIN_REQUIRED')
        effects,relations,shell=joined
        return L2AuthoritySidecar(fragment['id'],L2AuthorityProducer('translation-proof-sidecar',
            'automatic-lrsc-sequence-authority','v1',producer_digest),shell,tuple(operands),(memory,),
            effects,relations,(),(),True,schema_version=L2_EXPRESSION_AUTHORITY_SIDECAR_SCHEMA)
    except (ValueError,KeyError,TypeError,IndexError) as exc:
        if failure_details is not None:
            failure_details.append({'reasonCode':'L2_LRSC_AUTHORITY_MATERIALIZATION_REJECTED',
                'exceptionType':type(exc).__name__,'detail':str(exc)})
        return None


def require_observable_scope(finding,function,source):
    """The current invocation observer measures return/object, not hidden locals."""
    candidate=finding['fragment']['compilerFragmentAuthority']['candidate']
    roles=dict(source.lrsc_sequence.role_operand_indexes)
    for role in ('next','status'):
        node=candidate['operandBindings'][roles[role]]['valueNodeIdentity']
        uses=[u for u in candidate['downstreamUses'] if u['valueNodeIdentity']==node]
        if (candidate.get('downstreamUseEnumerationComplete') is not True
                or any(u.get('useKind') not in {'discarded','dead'} or not u.get('complete') for u in uses)):
            raise ValueError('L2_LRSC_ADDITIONAL_OUTPUT_OBSERVATION_REQUIRED:'+role)
