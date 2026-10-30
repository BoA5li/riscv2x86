"""All members, object effects and value dependencies in one direct invocation."""
from copy import deepcopy
from .l3_trace_support import identity,require_json_document,require_json_match
from .compiler_value_flow import identity as compiler_identity
from .l3_property_obligations import analyze
from .l3_scalar_trace import scalar_spec
from .l3_memory_intent import memory_spec
from .compiler_memory_signature import type_fact,SCHEMA as CALL_SCHEMA
from .l2_memory_object import memory_proof_facts_from_dict

CAPABILITY='qemu-joint-private-object-regions.v1'
LIMITS=sorted(['single-thread-private-valid-integer-object-with-unsigned64-carrier-domain',
    'direct-acyclic-proved-asm-regions-only','listed-input-vectors-only',
    'intermediate-values-observed-by-instrumented-l2-not-l3-register-callbacks',
    'physical-cache-timing-prediction-speculation-and-concurrency-not-claimed'])


def spec(findings,functions):
    if len(functions)!=1:raise ValueError('L3_JOINT_SINGLE_EXPORTED_ENTRY_REQUIRED')
    if not 2<=len(findings)<=16 or len({f['fragment']['id'] for f in findings})!=len(findings):raise ValueError('L3_JOINT_MEMBER_DOMAIN_REQUIRED')
    identities={f['fragment']['compilerFragmentAuthority']['functionIdentity'] for f in findings}
    if len(identities)!=1:raise ValueError('L3_JOINT_ONE_ENTRY_REQUIRED')
    from .l3_entry_binding import entry
    fn=entry(functions,identities.pop());scope=fn.get('compilerJointScope')
    from .compiler_joint_context import valid as valid_joint_scope
    if not valid_joint_scope(fn) or len(scope['sites'])!=len(findings):raise ValueError('L3_JOINT_COMPILER_SCOPE_REQUIRED')
    call=fn.get('compilerMemoryCallSignature');boundary=fn['l2OperandBoundary']
    if not call or call['schemaVersion']!=CALL_SCHEMA or call['factsIdentity']!=compiler_identity({k:v for k,v in call.items() if k!='factsIdentity'}):raise ValueError('L3_JOINT_CALL_REQUIRED')
    if (call['sourceDigest']!=fn['sourceDigest'] or call['functionIdentity']!=fn['functionId']
            or [p['declarationIdentity'] for p in call['parameters']]!=boundary['parameterDeclarationIds']
            or [{k:v for k,v in p.items() if k!='declarationIdentity'} for p in call['parameters']]!=scope['parameterTypes']
            or call['result']!=scope['resultType']):raise ValueError('L3_JOINT_CALL_BINDING_MISMATCH')
    for p in call['parameters']:
        require_json_match(type_fact(p['cType']),{k:v for k,v in p.items() if k!='declarationIdentity'},'L3_JOINT_PARAMETER_TYPE_MISMATCH')
    require_json_match(type_fact(call['result']['cType']),call['result'],'L3_JOINT_RESULT_TYPE_MISMATCH')
    pointers=scope.get('pointerParameters',[scope.get('pointerParameter')]);pointer=pointers[0]
    pointer_decls={call['parameters'][i]['declarationIdentity'] for i in pointers}
    ordered=sorted(findings,key=lambda f:f['fragment']['compilerFragmentAuthority']['fragmentBindingKey']['beginOffset'])
    from .l2_authority import l2_authority_sidecar_from_dict
    from .automatic_l2_authority import _scalar_authority,_memory_authority
    from .l2_fragment_execution import materialize_fragment_execution_authority
    program_ids={f['approvalArtifact']['l2FragmentOperandBoundary']['programId'] for f in ordered}
    if len(program_ids)!=1:raise ValueError('L3_JOINT_PROGRAM_CONFLICT')
    program_id=program_ids.pop()
    boundaries,graph,execution=materialize_fragment_execution_authority(ordered,fn,program_id)
    if not graph.complete or not execution.complete:raise ValueError('L3_JOINT_DEPENDENCY_CLOSURE_REQUIRED')
    defined=set(boundary['parameterDeclarationIds']);members=[];objects=[];kinds=set()
    for f,site in zip(ordered,scope['sites']):
        a=f['approvalArtifact'];fid=f['fragment']['id'];kind=f['l2SemanticProfile']['patternKind'];kinds.add(kind)
        ob=analyze(f,functions)
        fence=kind=='fence'
        if any(p['dimension'] not in ({'access_pattern','synchronization'} if fence else {'access_pattern'}) for p in ob['requiredProperties']):raise ValueError('L3_JOINT_REQUIRED_MECHANISM_UNAVAILABLE')
        from .versioned_program_contract import load as versioned_boundary
        versioned = versioned_boundary(f) if kind=='composite' else None
        scalar = kind=='scalar' or versioned is not None
        if not scalar and not fence and kind not in {'memory_load','memory_store'}:raise ValueError('L3_JOINT_SEMANTIC_FAMILY_UNSUPPORTED')
        key=f['fragment']['compilerFragmentAuthority']['fragmentBindingKey']
        if (key['beginOffset'],key['endOffset'])!=(site['begin'],site['end']):raise ValueError('L3_JOINT_SITE_BINDING_MISMATCH')
        if f.get('sourceDigest')!=fn['sourceDigest']:raise ValueError('L3_JOINT_SOURCE_CHANGED')
        side=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar']);producer=side.producer.producer_binary_digest
        from .automatic_l2_authority import _fence_authority
        rebuilt=(_fence_authority if fence else _scalar_authority if scalar else _memory_authority)(deepcopy(f),functions,producer)
        if rebuilt is None or rebuilt.to_dict()!=side.to_dict():raise ValueError('L3_JOINT_AUTHORITY_REPLAY_MISMATCH')
        require_json_match(boundaries[fid].to_dict(),a['l2FragmentOperandBoundary'],'L3_JOINT_BOUNDARY_CHANGED')
        require_json_match(graph.to_dict(),a['l2FragmentDependencyGraph'],'L3_JOINT_GRAPH_CHANGED')
        if side.runtime_contracts or side.ignored_state or (side.ordering and not fence) or side.control_flow:raise ValueError('L3_JOINT_UNCOVERED_STATE')
        if len(side.operands)!=len(f['fragment']['outputs'])+len(f['fragment']['inputs']):raise ValueError('L3_JOINT_OPERAND_ARITY_MISMATCH')
        operands=[]
        for index,(operand,gnu) in enumerate(zip(side.operands,f['fragment']['outputs']+f['fragment']['inputs'])):
            if operand.operand_index!=index:raise ValueError('L3_JOINT_OPERAND_INDEX_MISMATCH')
            if (gnu['constraint'] not in {'=r','=&r','r','+r','+&r'} or operand.fixed_register_contract
                    or operand.width_bits!=64 or operand.source_constraint!=gnu['constraint']):raise ValueError('L3_JOINT_OPERAND_DOMAIN_UNSUPPORTED')
            if operand.type_kind=='pointer':
                if operand.declaration_id not in pointer_decls or operand.access_mode!='address':raise ValueError('L3_JOINT_POINTER_REBINDING_UNSUPPORTED')
            elif operand.type_kind!='integer' or operand.signedness!='unsigned':raise ValueError('L3_JOINT_INTEGER64_REQUIRED')
            name=boundary['declarations'][operand.declaration_id]['name']
            operands.append({'index':operand.operand_index,'declarationIdentity':operand.declaration_id,'name':name,
                'kind':operand.type_kind,'access':operand.access_mode})
            if operand.access_mode in {'input','address','read_write'} and operand.declaration_id not in defined:raise ValueError('L3_JOINT_UNINITIALIZED_INPUT')
        # All inputs are checked before any output becomes defined.
        defined.update(o['declarationIdentity'] for o in operands if o['access'] in {'output','read_write'})
        if fence:
            from .l3_fence_spec import spec as fence_spec
            fence_basis=fence_spec(f,functions,joint=True)
            access={'access':'none','offset':0,'width':0,'fragmentId':fid,'fence':True}
        elif scalar:
            from .l2_joint_contract import operand_contract
            require_json_match(operand_contract(f,fn,side),a['l2JointOperandObservationContract'],'L3_JOINT_OPERAND_CONTRACT_CHANGED')
            access=scalar_spec(f,joint_versioned=True)
        else:
            access=memory_spec(f,joint_region=True);facts=memory_proof_facts_from_dict(a['l2MemoryProofFacts'])
            if not facts.matches_value_width(64):raise ValueError('L3_JOINT_MEMORY_CARRIER_PROOF_REQUIRED')
            address=next(o for o in side.operands if o.operand_index==facts.address_operand_index)
            if address.declaration_id not in pointer_decls:raise ValueError('L3_JOINT_OBJECT_POINTER_MISMATCH')
            objects.append(access)
        members.append({'fragmentId':fid,'kind':kind,'spec':access,'site':site,'operands':operands,
            'proofIdentity':a['proofIdentity'],'relationIdentity':side.effect_relation_set_identity,'authorityIdentity':side.authority_identity,
            'memoryFacts':a.get('l2MemoryProofFacts') if not scalar and not fence else None,
            **({'fenceBasis':fence_basis} if fence else {}),
            **({'versionedProgramBoundary':a['l2VersionedProgramBoundary']} if versioned is not None else {})})
    if not {'memory_load','memory_store'}<=kinds:raise ValueError('L3_JOINT_READ_WRITE_PROGRAM_REQUIRED')
    multi=len(pointers)>1
    if not multi and len({(o['objectId'],o['size'],o['alignment']) for o in objects})!=1:raise ValueError('L3_JOINT_SINGLE_PRIVATE_OBJECT_REQUIRED')
    returned=boundary.get('returnDeclarationId')
    if returned not in defined or returned in pointer_decls:raise ValueError('L3_JOINT_RETURN_BINDING_REQUIRED')
    from .joint_object_access_graph import build as object_graph
    from .object_layout_contract import build as layout_contract
    layout=layout_contract(fn) if multi else None
    if multi:
        by_id={v['objectId']:v for v in layout['views']}
        if any(o['objectId'] not in by_id or (o['size'],o['alignment'])!=(by_id[o['objectId']]['size'],by_id[o['objectId']]['alignment']) for o in objects):raise ValueError('L3_JOINT_OBJECT_LAYOUT_AUTHORITY_MISMATCH')
    access_graph=object_graph(members,layout)
    body={'schemaVersion':'riscv2x86.joint-program-spec.v1','programId':program_id,
        'functionName':fn['name'],'functionIdentity':fn['functionId'],'sourceDigest':fn['sourceDigest'],
        'scope':scope,'callSignature':call,'members':members,'objectAccessGraph':access_graph,'pointerParameter':pointer,'returnDeclarationIdentity':returned,
        'object':{k:objects[0][k] for k in ('objectId','size','alignment')},
        'dependencyGraphIdentity':graph.graph_identity,'executionAuthorityIdentity':identity(execution.to_dict())}
    if multi:
        body.update(schemaVersion='riscv2x86.joint-program-spec.v2',objectLayout=layout,pointerParameters=pointers)
        del body['pointerParameter'];del body['object']
    require_json_document(body,'L3_JOINT_JSON_INVALID')
    return dict(body,specIdentity=identity(body))


def sample_plan(program,count=8):
    if type(count) is not int or not 4<=count<=16:raise ValueError('L3_JOINT_SAMPLE_DOMAIN_INVALID')
    if 'objectLayout' in program:
        from .l3_multi_object_observation import sample_plan as multi_plan
        return multi_plan(program,count)
    values=[0,1,(1<<64)-1,1<<63,(1<<63)-1,0x5a17d3e4c29b806f,0xc4ceb9fe1a85ec53,0xffffffff]
    params=program['callSignature']['parameters'];pointer=program['pointerParameter']
    rows=[{'sample':s,'arguments':[None if i==pointer else f'{values[(s+i)%len(values)]:016x}' for i in range(len(params))],
        'initialObjectHex':bytes(((0x31+17*i+s*23)&255) for i in range(program['object']['size'])).hex()} for s in range(count)]
    body={'schemaVersion':'riscv2x86.joint-sample-plan.v1','specIdentity':program['specIdentity'],'inputs':rows}
    return dict(body,planIdentity=identity(body))
