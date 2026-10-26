"""Compare executed mechanisms and explicit proof contracts, never synthetic memory anchors."""
from .fence_semantics import refinement
from .l3_trace_support import identity,digest


def report(side,backend,deployment,observed,rows,evidence):
    item=deployment['sides'][side];region=item['region'];mech=item['machineMechanism']
    if mech['kind']=='other':raise ValueError('L3_FENCE_MACHINE_ENCODING_UNSUPPORTED')
    expected=len(deployment['samplePlan']['inputs'])
    if len(rows)!=expected or len(observed['paths'])!=expected:raise ValueError('L3_FENCE_OBSERVATION_COUNT_MISMATCH')
    attributed=[]
    for sample,path in enumerate(observed['paths']):
        # Affirmative classification requires exactly one decoded fence instruction.
        complete=path['exit']==region['end'] and path['pcs']==[region['start']]
        attributed.append({'sample':sample,'completed':complete,'mechanismIdentity':mech['mechanismIdentity'],
                           'pc':region['start'],'kind':mech['kind']})
    return {'schemaVersion':'riscv2x86.fence-observation.v1','side':side,'backendIdentity':backend['backendIdentity'],
            'deploymentIdentity':deployment['deploymentIdentity'],'rawPaths':observed['paths'],'memory':observed['memory'],
            'samples':rows,'fenceEvents':attributed,'mechanism':mech,'evidence':evidence,
            'environment':{'executor':backend[side+'Executor'],'executorDigest':digest(backend[side+'Executor']),
                           'runnerArguments':backend[side+'RunnerArguments'],'observationKind':'executed-machine-region',
                           'physicalMicroarchitectureClaimed':False}}


def comparison(reports,spec):
    sync=spec['obligations']['synchronizationObligations'];basis=sync['basis'];reasons=[]
    sub={}
    for p in sync['requiredSubproperties']:
        sub[p['propertyId']]={'status':'verified','evidenceKinds':p['evidenceKinds'],
                             'verificationMethod':'static-approved-contract' if p['propertyId']!='sync.fence-mechanism' else 'machine-attribution-and-executed-region'}
    if set(sub)!={'sync.compiler-contract','sync.fence-mechanism','sync.ordering-contract'} or not sync['basisComplete']:
        raise ValueError('L3_FENCE_SYNC_COVERAGE_MISMATCH')
    a,b=(basis[k] for k in ('sourceOrderingContract','targetOrderingContract'))
    domain=lambda x:(x['compilerOrdering'],x['hardwareOrdering'],x['ordering'],x['scope'])
    if refinement(domain(a),domain(b))!=basis['relationKind']:
        reasons.append('L3_FENCE_ORDERING_REFINEMENT_UNPROVED');sub['sync.ordering-contract']['status']='failed'
    for side in ('source','target'):
        r=reports[side]
        if not r['fenceEvents'] or any(not e['completed'] or e['kind']!='ordinary-rw-fence' for e in r['fenceEvents']):
            reasons.append('L3_FENCE_EXECUTED_MECHANISM_MISMATCH:'+side);sub['sync.fence-mechanism']['status']='failed'
        contract=basis['sourceOrderingContract' if side=='source' else 'targetOrderingContract']
        if r['mechanism']['orderedPairs']!=contract['orderedPairs'] or r['mechanism']['memoryDomain']!=contract['memoryDomain']:
            reasons.append('L3_FENCE_MACHINE_CONTRACT_MISMATCH:'+side);sub['sync.fence-mechanism']['status']='failed'
    mem=any(r['memory'] for r in reports.values())
    return {'synchronization':{'status':'failed' if reasons else 'verified','reasonCodes':sorted(set(reasons)),
                               'subpropertyResults':sub,'physicalMemoryOrderMeasured':False},
            'memory':{'status':'failed' if mem else 'verified','reasonCodes':['L3_FENCE_UNEXPECTED_REGION_DATA_ACCESS'] if mem else []}}
