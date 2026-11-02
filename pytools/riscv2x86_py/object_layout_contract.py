"""Compiler-bound views and explicit finite harness layouts, not alias proofs.

Different parameter identities never imply disjointness. Each invocation states
its actual allocation layout. Shared views are generated only for identical
unqualified integer pointee types; no incompatible effective-type alias is made.
"""
from itertools import combinations,product
from .l3_trace_support import identity,require_json_match
from .compiler_memory_signature import type_fact


def build(function):
    call=function['compilerMemoryCallSignature'];boundary=function['l2OperandBoundary']
    if (call['factsIdentity']!=identity({k:v for k,v in call.items() if k!='factsIdentity'})
            or call['sourceDigest']!=function['sourceDigest'] or call['functionIdentity']!=function['functionId']
            or [p['declarationIdentity'] for p in call['parameters']]!=boundary['parameterDeclarationIds']):raise ValueError('OBJECT_LAYOUT_CALL_BINDING_INVALID')
    views=[]
    for index,p in enumerate(call['parameters']):
        if p['kind']!='pointer':continue
        canonical=type_fact(p['cType'])
        require_json_match(canonical,{k:v for k,v in p.items() if k!='declarationIdentity'},'OBJECT_LAYOUT_POINTER_TYPE_CHANGED')
        if p.get('pointeeQualifiers') or p['pointee']['widthBits'] not in (8,16,32,64):raise ValueError('OBJECT_LAYOUT_TYPE_UNSUPPORTED')
        declaration=p['declarationIdentity'];binding=boundary['memoryObjectBindings'][declaration]
        if (binding['bindingIdentity']!=identity({k:v for k,v in binding.items() if k!='bindingIdentity'})
                or binding['sourceDigest']!=function['sourceDigest']
                or binding['baseDeclarationIdentity']!=declaration or binding['volatile'] is not False
                or binding['bindingOrigin']!='automatic-aligned-memory-object-harness-v1'
                or type(binding['objectSizeBytes']) is not int or not 0<binding['objectSizeBytes']<=65536
                or type(binding['provenAlignmentBytes']) is not int or binding['provenAlignmentBytes'] not in (1,2,4,8,16,32,64)
                or binding['objectSizeBytes']%(p['pointee']['widthBits']//8)):
            raise ValueError('OBJECT_LAYOUT_BINDING_INVALID')
        views.append({'parameterIndex':index,'declarationIdentity':declaration,'objectId':binding['objectIdentity'],
            'size':binding['objectSizeBytes'],'alignment':binding['provenAlignmentBytes'],
            'pointee':p['pointee'],'name':boundary['declarations'][declaration]['name'],
            'bindingIdentity':binding['bindingIdentity']})
    if not views or len({v['objectId'] for v in views})!=len(views):raise ValueError('OBJECT_LAYOUT_VIEWS_INVALID')
    layouts=[]
    def layout(pair=None,offset=0,coordinates=None):
        allocations={};bindings=[]
        for i,v in enumerate(views):
            owner=pair[0] if pair is not None and i==pair[1] else i
            delta=offset if pair is not None and i==pair[1] else 0
            if coordinates is not None:owner,delta=coordinates[i]
            aid='allocation:'+str(owner);size=delta+v['size']
            if aid not in allocations:allocations[aid]={'allocationId':aid,'size':size,'alignment':64,'pointee':v['pointee']}
            else:allocations[aid]['size']=max(allocations[aid]['size'],size)
            bindings.append({'objectId':v['objectId'],'allocationId':aid,'offset':delta})
        body={'allocations':list(allocations.values()),'views':bindings,'basis':'explicit-harness-construction; not source noalias inference'}
        return dict(body,layoutIdentity=identity(body))
    layouts.append(layout())
    for i,j in combinations(range(len(views)),2):
        if views[i]['pointee']!=views[j]['pointee']:continue
        layouts.append(layout((i,j)))
        # A real overlapping view, aligned for both compiler-bound objects.
        offset=max(views[i]['alignment'],views[j]['alignment'],views[i]['pointee']['widthBits']//8)
        if offset<views[i]['size']:layouts.append(layout((i,j),offset))
    # Enumerate every set partition of the finite pointer list, subject to
    # identical effective types. For each shared group construct coincident,
    # aligned staggered in both directions, and boundary-adjacent views.
    # This covers joint alias classes, not all possible byte offsets.
    def partitions(index,groups):
        if index==len(views):yield groups;return
        for position,group in enumerate(groups):
            if views[group[0]]['pointee']==views[index]['pointee']:
                yield from partitions(index+1,groups[:position]+[group+[index]]+groups[position+1:])
        yield from partitions(index+1,groups+[[index]])
    if len(views)>4:raise ValueError('OBJECT_LAYOUT_POINTER_BUDGET_EXCEEDED')
    for groups in partitions(0,[]):
        patterns=[]
        for group in groups:
            step=max(views[i]['alignment'] for i in group)
            step=max(step,views[group[0]]['pointee']['widthBits']//8)
            options=[[(i,0) for i in group]]
            if len(group)>1:
                options.extend([[(i,rank*step) for rank,i in enumerate(group)],
                    [(i,(len(group)-1-rank)*step) for rank,i in enumerate(group)]])
                cursor=0;adjacent=[]
                for i in group:
                    cursor=(cursor+step-1)//step*step
                    adjacent.append((i,cursor));cursor+=views[i]['size']
                options.append(adjacent)
            patterns.append(options)
        for selected in product(*patterns):
            coordinates={i:(group[0],delta) for group,positions in zip(groups,selected) for i,delta in positions}
            observable=True
            for group,positions in zip(groups,selected):
                end=0
                for i,start in sorted(positions,key=lambda item:item[1]):
                    if start>end:observable=False
                    end=max(end,start+views[i]['size'])
                if end>131072:observable=False
            if observable:layouts.append(layout(coordinates=coordinates))
    layouts=list({case['layoutIdentity']:case for case in layouts}.values())
    # Invalid/unobservable gaps must not be quietly generated as legal inputs.
    for case in layouts:materialize(case,views)
    body={'schemaVersion':'riscv2x86.object-layout-contract.v2','sourceDigest':function['sourceDigest'],
        'functionIdentity':function['functionId'],'views':views,'layouts':layouts,
        'domain':'ordinary-private-valid-object-invocations','semanticApproval':False,
        'aliasGuarantee':'per-invocation-layout-only',
        'layoutBasis':'all-type-compatible-set-partitions; completely observable bounded coincident, forward/reverse-aligned and adjacent representative offsets'}
    return dict(body,contractIdentity=identity(body))


def materialize(layout,views):
    """Validate a layout, then return view coordinates. No runtime addresses."""
    if layout['layoutIdentity']!=identity({k:v for k,v in layout.items() if k!='layoutIdentity'}):raise ValueError('OBJECT_LAYOUT_IDENTITY_INVALID')
    allocations={a['allocationId']:a for a in layout['allocations']}
    mapping={v['objectId']:v for v in layout['views']}
    if (len(allocations)!=len(layout['allocations']) or len(mapping)!=len(layout['views'])
            or len(mapping)!=len(views) or set(mapping)!={v['objectId'] for v in views}):raise ValueError('OBJECT_LAYOUT_MEMBERSHIP_INVALID')
    if not allocations or set(allocations)!={b['allocationId'] for b in mapping.values()}:raise ValueError('OBJECT_LAYOUT_ALLOCATION_MEMBERSHIP')
    for a in allocations.values():
        if (set(a)!={'allocationId','size','alignment','pointee'} or type(a['size']) is not int or not 0<a['size']<=131072
                or type(a['alignment']) is not int or a['alignment']!=64
                or type(a['pointee'].get('widthBits')) is not int or a['pointee']['widthBits'] not in (8,16,32,64)
                or a['size']%(a['pointee']['widthBits']//8)):raise ValueError('OBJECT_LAYOUT_ALLOCATION_INVALID')
    for v in views:
        b=mapping[v['objectId']];a=allocations[b['allocationId']];o=b['offset']
        if (type(o) is not int or o<0 or o%v['alignment'] or o+v['size']>a['size']
                or a['pointee']!=v['pointee'] or a['alignment']<v['alignment']):raise ValueError('OBJECT_LAYOUT_VIEW_INVALID')
    return allocations,mapping


def initial_objects(layout,views,seed):
    allocations,mapping=materialize(layout,views)
    raw={key:bytes((0x31+17*i+23*seed+13*j)&255 for i in range(a['size'])) for j,(key,a) in enumerate(allocations.items())}
    return {v['objectId']:raw[mapping[v['objectId']]['allocationId']][mapping[v['objectId']]['offset']:mapping[v['objectId']]['offset']+v['size']].hex() for v in views}


def allocation_bytes(layout,views,objects):
    allocations,mapping=materialize(layout,views);raw={k:[None]*a['size'] for k,a in allocations.items()}
    if set(objects)!={v['objectId'] for v in views}:raise ValueError('OBJECT_LAYOUT_OBSERVATION_MEMBERSHIP')
    for v in views:
        b=mapping[v['objectId']];data=bytes.fromhex(objects[v['objectId']])
        if len(data)!=v['size']:raise ValueError('OBJECT_LAYOUT_OBSERVATION_SIZE')
        for i,value in enumerate(data,b['offset']):
            old=raw[b['allocationId']][i]
            if old is not None and old!=value:raise ValueError('OBJECT_LAYOUT_ALIAS_STATE_CONFLICT')
            raw[b['allocationId']][i]=value
    if any(None in a for a in raw.values()):raise ValueError('OBJECT_LAYOUT_UNOBSERVED_ALLOCATION')
    return {k:bytearray(v) for k,v in raw.items()}


def project_bytes(layout,views,allocations):
    _,mapping=materialize(layout,views)
    return {v['objectId']:bytes(allocations[mapping[v['objectId']]['allocationId']][mapping[v['objectId']]['offset']:mapping[v['objectId']]['offset']+v['size']]).hex() for v in views}
