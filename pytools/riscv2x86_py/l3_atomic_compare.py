"""Actual RMW outcomes plus independently attributed mechanism/ordering contracts."""
from .l3_trace_support import identity,digest
from .l3_atomic_backend import callback_shape
from .l3_atomic_machine import satisfies
from .l3_atomic_semantics import result as rmw_result


def report(side,backend,deployment,observed,rows,evidence):
    item=deployment['sides'][side];machine=item['machineMechanism'];insn=machine['instruction'];region=item['region'];spec=deployment['spec'];atom=spec['operation']
    if len(observed['paths'])!=len(rows):raise ValueError('L3_ATOMIC_OBSERVATION_COUNT_MISMATCH')
    shape=None if 'retry' in machine else callback_shape(backend,side,insn);events=[];step_offset=0
    for i,(row,path) in enumerate(zip(rows,observed['paths'])):
        memory=[m for m in observed['memory'] if m['sample']==i];base=int(row['objectBase'],16)
        accesses=[{'offsetBytes':m['address']-base,'widthBytes':m['size'],'access':m['access']} for m in memory]
        bound=(base>0 and base%atom['alignment_bytes']==0 and [m['access'] for m in memory]==shape
               and all(m['address']==base and m['size']==atom['width_bits']//8 and m['pc']==region['start'] for m in memory))
        complete=path=={'pcs':[region['start']],'exit':region['end']}
        retry_detail=None
        if 'retry' in machine:
            from .l3_atomic_retry_observation import observe
            retry_detail=observe(machine,backend,observed,i,step_offset,row,atom,deployment['samplePlan']['objectCellCount']*(atom['width_bits']//8))
            bound=retry_detail['bound'];accesses=retry_detail['objectAccesses'];complete=True
        step_offset+=len(path['pcs'])
        mask=(1<<atom['width_bits'])-1;old=int(row['old'],16);value=int(row['input'],16)&mask
        wanted=rmw_result(atom['rmw_operation'],old,value,atom['width_bits'])
        projected=old
        if spec['widthRoles']['resultExtension']=='sign_extend' and old&(1<<(atom['width_bits']-1)):
            projected=old-(1<<atom['width_bits'])
        projected &= (1<<spec['widthRoles']['resultCarrierWidth'])-1 if atom['result_semantics']=='old_value' else 0
        outcome=(list(map(lambda x:int(x,16),row['after']))==[wanted,0x31,0x72,0x53]+[0]*(deployment['samplePlan']['objectCellCount']-4)
                 and int(row['result'],16)==projected)
        events.append({'sample':i,'objectId':atom['memory_object_identity'],
                       'objectOffsetBytes':accesses[0]['offsetBytes'] if accesses and len({a['offsetBytes'] for a in accesses})==1 else None,
                       'widthBits':8*accesses[0]['widthBytes'] if accesses and len({a['widthBytes'] for a in accesses})==1 else None,
                       'expectedObjectOffsetBytes':0,'expectedWidthBits':atom['width_bits'],
                       'rawCallbackAccesses':accesses,'callbackShapeMatched':bound,'completed':complete,
                       'actualOldValue':row['old'],'actualInputValue':row['input'],'actualAfterObject':row['after'],'actualReturnedValue':row['result'],
                       'outcomeMatchesApprovedOperation':outcome,'mechanismSatisfiesApprovedContract':satisfies(insn,atom,side),
                       'mechanismIdentity':machine['mechanismIdentity'],'outcomeObservationSource':'actual-invocation-harness',
                       'atomicityEvidenceKind':'approved-contract-and-executed-machine-attribution'})
        if retry_detail is not None:events[-1]['retryObservation']=retry_detail
    if 'retry' in machine:
        from .l3_atomic_backend import memory_by_step
        if any(step not in range(step_offset) for step in memory_by_step(observed)):raise ValueError('L3_ATOMIC_MEMORY_TIMELINE_UNBOUND')
    if any(m['sample'] not in range(len(rows)) for m in observed['memory']):raise ValueError('L3_ATOMIC_MEMORY_SAMPLE_UNBOUND')
    return {'schemaVersion':'riscv2x86.atomic-observation.v1','side':side,'backendIdentity':backend['backendIdentity'],
            'deploymentIdentity':deployment['deploymentIdentity'],'rawPaths':observed['paths'],'memory':observed['memory'],
            'memoryTimeline':observed.get('memoryTimeline',[]),
            'samples':rows,'atomicEvents':events,'mechanism':machine,'evidence':evidence,
            'environment':{'executor':backend[side+'Executor'],'executorDigest':digest(backend[side+'Executor']),
                           'runnerArguments':backend[side+'RunnerArguments'],'observationKind':'executed-cas-retry-region' if 'retry' in machine else 'executed-direct-atomic-region',
                           'physicalMicroarchitectureClaimed':False}}


def comparison(reports,spec):
    sync=spec['obligations']['synchronizationObligations'];props={p['propertyId'] for p in sync['requiredSubproperties']}
    required={'sync.compiler-contract','sync.atomic-mechanism','sync.atomic-outcome','sync.ordering-contract'}
    if props!=required or not sync['basisComplete']:raise ValueError('L3_ATOMIC_SYNC_COVERAGE_MISMATCH')
    sub={p:{'status':'verified','verificationMethod':'static-approved-contract' if p=='sync.compiler-contract'
             else 'attributed-machine-refines-approved-ordering' if p=='sync.ordering-contract'
             else 'actual-invocation-object-values' if p=='sync.atomic-outcome' else 'machine-attribution-and-complete-execution'} for p in sorted(props)}
    reasons=[];mem=[]
    count=len(reports['source']['atomicEvents'])
    if not count or len(reports['target']['atomicEvents'])!=count:raise ValueError('L3_ATOMIC_COMPARISON_SAMPLE_MISMATCH')
    for side in ('source','target'):
        for e in reports[side]['atomicEvents']:
            if not e['completed'] or not e['mechanismSatisfiesApprovedContract']:
                sub['sync.atomic-mechanism']['status']='failed';sub['sync.ordering-contract']['status']='failed';reasons.append('L3_ATOMIC_EXECUTED_CONTRACT_MISMATCH:'+side)
            if not e['outcomeMatchesApprovedOperation']:
                sub['sync.atomic-outcome']['status']='failed';reasons.append('L3_ATOMIC_VALUE_RELATION_MISMATCH:'+side)
            if not e['callbackShapeMatched']:
                mem.append('L3_ATOMIC_OBJECT_ACCESS_MISMATCH:'+side);sub['sync.atomic-outcome']['status']='failed';reasons.append('L3_ATOMIC_OBJECT_ACCESS_MISMATCH:'+side)
    keys=('actualOldValue','actualInputValue','actualAfterObject','actualReturnedValue','objectId','objectOffsetBytes','widthBits')
    if any(any(a[k]!=b[k] for k in keys) for a,b in zip(reports['source']['atomicEvents'],reports['target']['atomicEvents'])):
        reasons.append('L3_ATOMIC_CROSS_ISA_OUTCOME_MISMATCH');sub['sync.atomic-outcome']['status']='failed'
    return {'synchronization':{'status':'failed' if reasons else 'verified','reasonCodes':sorted(set(reasons)),
                               'subpropertyResults':sub,'concurrentAtomicityMeasured':False,'physicalMemoryOrderMeasured':False},
            'memory':{'status':'failed' if mem else 'verified','reasonCodes':sorted(set(mem))}}
