"""Reaching definitions for the compiler-confirmed direct joint grammar.

Raw AST use enumeration has no reliable GNU operand partition on all Clang
versions. Roles below are joined with the actual frontend output constraints;
no asm instruction or variable name is matched. All sites must be present.
Legacy/nonlinear programs retain their original use facts and gates.
"""
from .compiler_joint_context import valid
from .compiler_value_flow import identity,compiler_operand_carrier_from_dict
from .compiler_fragment_closure import close_compiler_fragment_candidate
from .l3_trace_support import require_json_match


def derive(function,resolved):
    if not valid(function):return None
    scope=function['compilerJointScope'];sites=scope['sites'];ordered=[]
    if len(resolved)!=len(sites):raise ValueError('JOINT_DEFINITION_ALL_SITES_REQUIRED')
    for fid,(candidate,reason,fragment) in resolved.items():
        if candidate is None or reason or candidate.get('complete') is not True:
            raise ValueError('JOINT_DEFINITION_CANDIDATE_REQUIRED')
        key=candidate['fragmentBindingKey']
        authority=fragment.get('compilerFragmentAuthority') or {}
        rebuilt=close_compiler_fragment_candidate(candidate,fragment,source_digest=function['sourceDigest'],function_identity=function['functionId'])
        require_json_match(rebuilt,authority.get('candidate'),'JOINT_DEFINITION_FRONTEND_JOIN_CHANGED')
        operands=fragment.get('outputs',[])+fragment.get('inputs',[])
        carriers=[compiler_operand_carrier_from_dict(v) for v in candidate['operandCarriers']]
        if len(carriers)!=len(operands):raise ValueError('JOINT_DEFINITION_ARITY_MISMATCH')
        rows=[]
        for index,(carrier,operand) in enumerate(zip(carriers,operands)):
            constraint=operand.get('constraint','')
            if (carrier.operand_index!=index or not constraint
                    or carrier.declaration_identity not in function['l2OperandBoundary']['declarations']):
                raise ValueError('JOINT_DEFINITION_OPERAND_REQUIRED')
            output=index<len(fragment['outputs'])
            rows.append({'operandIndex':index,'declarationIdentity':carrier.declaration_identity,
                'valueNodeIdentity':carrier.value_node_identity,
                'read':not output or constraint.startswith('+'),'write':output})
        writes=[r['declarationIdentity'] for r in rows if r['write']]
        if len(writes)!=len(set(writes)):raise ValueError('JOINT_DEFINITION_CONFLICTING_OUTPUTS')
        ordered.append({'fragmentId':fid,'candidateIdentity':candidate['candidateIdentity'],
            'begin':key['beginOffset'],'end':key['endOffset'],'operands':rows})
    ordered.sort(key=lambda r:r['begin'])
    if [(r['begin'],r['end']) for r in ordered]!=[(s['begin'],s['end']) for s in sites]:
        raise ValueError('JOINT_DEFINITION_SITE_BINDING_MISMATCH')
    current={d:None for d in function['l2OperandBoundary']['parameterDeclarationIds']}
    edges=[];versions=[]
    for row in ordered:
        # Read all old versions before defining any output of this asm.
        for operand in row['operands']:
            d=operand['declarationIdentity']
            if operand['read']:
                if d not in current:raise ValueError('JOINT_DEFINITION_UNINITIALIZED_READ')
                if current[d] is not None:
                    edges.append({'producer':current[d],'consumerFragmentId':row['fragmentId'],
                                  'consumerOperandIndex':operand['operandIndex']})
        for operand in row['operands']:
            if not operand['write']:continue
            version={'fragmentId':row['fragmentId'],'candidateIdentity':row['candidateIdentity'],
                'declarationIdentity':operand['declarationIdentity'],'valueNodeIdentity':operand['valueNodeIdentity']}
            versions.append(version);current[operand['declarationIdentity']]=version
    returned=function['l2OperandBoundary'].get('returnDeclarationId')
    if returned not in current:raise ValueError('JOINT_DEFINITION_RETURN_UNINITIALIZED')
    body={'schemaVersion':'riscv2x86.joint-reaching-definitions.v1',
        'sourceDigest':function['sourceDigest'],'functionIdentity':function['functionId'],
        'scopeIdentity':scope['scopeIdentity'],'regions':ordered,'definitions':versions,
        'uses':edges,'returnedVersion':current[returned],'semanticApproval':False}
    return dict(body,flowIdentity=identity(body))


def for_findings(function,findings):
    from .l2_fragment_execution import resolve_compiler_fragment_candidate
    resolved={}
    for f in findings:
        fragment=f['fragment'];fid=fragment.get('id') or fragment.get('fragmentId')
        candidate,reason=resolve_compiler_fragment_candidate(fragment,function['l2OperandBoundary']['fragmentCandidates'],function)
        if fid in resolved:raise ValueError('JOINT_DEFINITION_DUPLICATE_FRAGMENT')
        resolved[fid]=(candidate,reason,fragment)
    return derive(function,resolved)


def uses_for(flow,fid,candidate):
    """Refine only the complete direct grammar; preserve all other use facts.

    Surviving external facts must be the final direct return. Unknown uses are
    retained as incomplete obligations, never silently called discarded.
    """
    rows=next(r['operands'] for r in flow['regions'] if r['fragmentId']==fid)
    outputs={r['valueNodeIdentity'] for r in rows if r['write']};result=[]
    edges=[u for u in flow['uses'] if u['producer']['fragmentId']==fid]
    wanted={(u['producer']['valueNodeIdentity'],u['consumerFragmentId']) for u in edges}
    consumers={r['fragmentId']:r['candidateIdentity'] for r in flow['regions']}
    wanted={(node,consumers[consumer]) for node,consumer in wanted}
    returned=flow['returnedVersion'];returned_node=returned['valueNodeIdentity'] if returned and returned['fragmentId']==fid else None
    for use in candidate['downstreamUses']:
        if use['valueNodeIdentity'] not in outputs:
            result.append(use);continue
        kind=use['useKind']
        if kind=='subsequent_asm_input':
            # Exact consumer slots are derived below from joined compiler roles.
            # The raw enumeration still has to attest this producer/consumer.
            continue
        elif kind=='function_return':
            if use['valueNodeIdentity']==returned_node:result.append(use)
        elif kind not in {'dead','discarded'}:result.append(use)
    # An existing AST fact is still required for every surviving use.
    actual={(u['valueNodeIdentity'],u['consumerFragmentIdentity']) for u in candidate['downstreamUses'] if u['useKind']=='subsequent_asm_input'}
    if wanted-actual:raise ValueError('JOINT_DEFINITION_USE_ENUMERATION_MISSING')
    result.extend(derived_use(flow,edge)[0] for edge in edges)
    if returned_node and not any(u['valueNodeIdentity']==returned_node and u['useKind']=='function_return' for u in result):
        raise ValueError('JOINT_DEFINITION_RETURN_ENUMERATION_MISSING')
    used={u['valueNodeIdentity'] for u in result}
    for node in sorted(outputs-used):
        result.append({'valueNodeIdentity':node,'useNodeIdentity':identity({'flow':flow['flowIdentity'],'discarded':node}),
            'useKind':'discarded','consumerFragmentIdentity':'','observationSinkIdentity':'','relationKind':'discarded','complete':True})
    return result


def derived_use(flow,edge):
    consumer=next(r for r in flow['regions'] if r['fragmentId']==edge['consumerFragmentId'])
    operand=consumer['operands'][edge['consumerOperandIndex']]
    node=identity({'schemaVersion':'riscv2x86.joint-operand-version-use.v1','flowIdentity':flow['flowIdentity'],
        'producer':edge['producer'],'consumerFragmentId':edge['consumerFragmentId'],
        'consumerOperandIndex':edge['consumerOperandIndex'],'consumerValueNodeIdentity':operand['valueNodeIdentity']})
    use={'valueNodeIdentity':edge['producer']['valueNodeIdentity'],'useNodeIdentity':node,
        'useKind':'subsequent_asm_input','consumerFragmentIdentity':consumer['candidateIdentity'],
        'observationSinkIdentity':identity({'versionedUse':node}),'relationKind':'fragment_operand','complete':True}
    return use,operand['valueNodeIdentity']
