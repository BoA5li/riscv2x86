"""Conditional affine object-domain lemmas, never a substitute for code binding.

Views share allocation identity, so aliasing is not guessed from distinct view
names. The finite event model covers bounds, alignment, lifetime and initialized
reads under explicitly recorded mathematical assumptions. Relating its events
to C expressions, loops or machine instructions remains a separate obligation.
"""
import json
from pathlib import Path
from . import native_captured_deployment as d
from .native_verifier_manifest import current,compare
from .project_acquisition import Runner,publish_checked

SCHEMA='riscv2x86.conditional-object-domain.v1'
MODEL='riscv2x86.affine-object-event-model.v1'


def derive(model):
    import z3
    if not isinstance(model,dict) or set(model)!={'schemaVersion','variables','allocations','views','accesses'} or model['schemaVersion']!=MODEL:
        raise ValueError('OBJECT_MODEL_SCHEMA_INVALID')
    variables=model['variables'];allocations=model['allocations'];views=model['views'];accesses=model['accesses']
    if (not all(isinstance(v,dict) for v in (variables,allocations,views)) or not isinstance(accesses,list)
            or len(variables)>32 or len(allocations)>64 or len(views)>128 or len(accesses)>1024):
        raise ValueError('OBJECT_MODEL_BUDGET_OR_TYPES_INVALID')
    if not allocations or not accesses:raise ValueError('OBJECT_MODEL_NONEMPTY_OBLIGATIONS_REQUIRED')
    names={};assumptions=[]
    def integer(v):
        if type(v) is not int or abs(v)>2**128:raise ValueError('OBJECT_INTEGER_INVALID')
        return v
    for name,domain in variables.items():
        if not isinstance(name,str) or not name or not isinstance(domain,list) or len(domain)!=2:raise ValueError('OBJECT_VARIABLE_INVALID')
        low,high=map(integer,domain)
        if low>high:raise ValueError('OBJECT_VARIABLE_EMPTY_DOMAIN')
        names[name]=z3.Int('object-variable:'+name);assumptions.extend((names[name]>=low,names[name]<=high))
    def affine(value):
        if type(value) is int:return z3.IntVal(integer(value))
        if not isinstance(value,dict) or set(value)!={'constant','terms'} or not isinstance(value['terms'],dict):
            raise ValueError('OBJECT_AFFINE_EXPRESSION_REQUIRED')
        if set(value['terms'])-set(names):raise ValueError('OBJECT_UNBOUND_VARIABLE')
        return z3.IntVal(integer(value['constant']))+sum(integer(c)*names[n] for n,c in value['terms'].items())
    def power(v):
        integer(v)
        if v<1 or v>4096 or v&(v-1):raise ValueError('OBJECT_ALIGNMENT_INVALID')
        return v
    solver=z3.Solver();solver.set(timeout=2000);solver.add(*assumptions)
    def prove(condition):
        solver.push();solver.add(z3.Not(condition));result=solver.check()
        counter={n:str(solver.model().eval(v,model_completion=True)) for n,v in names.items()} if result==z3.sat else None
        solver.pop()
        return {'status':'verified-under-model' if result==z3.unsat else 'counterexample-under-model' if result==z3.sat else 'inconclusive',
                'counterexample':counter}
    initialized={};rows=[]
    for aid,a in allocations.items():
        if not isinstance(aid,str) or not aid or set(a)!={'size','alignment','startEpoch','endEpoch','initializedRanges'}:
            raise ValueError('OBJECT_ALLOCATION_INVALID')
        power(a['alignment']);start=integer(a['startEpoch']);end=integer(a['endEpoch'])
        if start<0 or end<=start or not isinstance(a['initializedRanges'],list):raise ValueError('OBJECT_LIFETIME_INVALID')
        size=affine(a['size']);initialized[aid]=[]
        for pair in a['initializedRanges']:
            if not isinstance(pair,list) or len(pair)!=2:raise ValueError('OBJECT_INITIALIZED_RANGE_INVALID')
            lo,hi=map(affine,pair);initialized[aid].append((lo,hi))
            rows.append({'kind':'initial-range','allocation':aid,**prove(z3.And(lo>=0,hi>=lo,hi<=size))})
        rows.append({'kind':'allocation-size','allocation':aid,**prove(size>0)})
    for vid,v in views.items():
        if not isinstance(vid,str) or not vid or set(v)!={'allocation','offset','size'} or v['allocation'] not in allocations:
            raise ValueError('OBJECT_VIEW_INVALID')
        offset,size=affine(v['offset']),affine(v['size']);a=allocations[v['allocation']]
        rows.append({'kind':'view','view':vid,**prove(z3.And(offset>=0,size>=0,offset+size<=affine(a['size'])))})
    previous=-1;effects=set()
    for index,event in enumerate(accesses):
        if (not isinstance(event,dict) or set(event)!={'sourceEffectId','view','offset','width','alignment','kind','epoch'}
                or event['view'] not in views or event['kind'] not in ('read','write')
                or not isinstance(event['sourceEffectId'],str) or not event['sourceEffectId']
                or event['sourceEffectId'] in effects):raise ValueError('OBJECT_ACCESS_INVALID')
        epoch=integer(event['epoch']);width=integer(event['width']);alignment=power(event['alignment'])
        if epoch<previous or width<=0:raise ValueError('OBJECT_EVENT_ORDER_OR_WIDTH_INVALID')
        previous=epoch;effects.add(event['sourceEffectId'])
        v=views[event['view']];aid=v['allocation'];a=allocations[aid]
        offset=affine(event['offset']);absolute=affine(v['offset'])+offset
        conditions=[offset>=0,offset+width<=affine(v['size']),absolute>=0,
            absolute+width<=affine(a['size']),absolute%alignment==0,
            z3.BoolVal(a['alignment']>=alignment),z3.BoolVal(a['startEpoch']<=epoch<a['endEpoch'])]
        if event['kind']=='read':
            conditions.append(z3.Or(*(z3.And(absolute>=lo,absolute+width<=hi) for lo,hi in initialized[aid])))
        proof=prove(z3.And(*conditions))
        rows.append({'kind':'access','accessIndex':index,'sourceEffectId':event['sourceEffectId'],**proof})
        # A failed/unknown write cannot establish initialization for a later read.
        if event['kind']=='write' and proof['status']=='verified-under-model':initialized[aid].append((absolute,absolute+width))
    return {'modelIdentity':d.identity(model),'obligations':rows,
        'conditionalObjectRelationsVerified':bool(rows) and all(r['status']=='verified-under-model' for r in rows),
        'codeAccessBindingVerified':False,'legalObjectDomainVerified':False,
        'scope':'finite-affine-event-model-under-recorded-assumptions-not-C-or-program-proof',
        'missingFacts':['COMPILER_OR_MACHINE_ACCESS_BINDING_REQUIRED','C_ARITHMETIC_AND_LOOP_REFINEMENT_REQUIRED']}


def acquire(input_path,output):
    model=d.read(input_path);facts=derive(model);runner=Runner(output,'conditional-object-evidence')
    try:
        saved=runner.output/'model.json';saved.write_text(json.dumps(model,indent=2)+'\n')
        value=d.seal({'schemaVersion':SCHEMA,'verifier':current(),'input':d.snapshot(input_path),
            'model':d.snapshot(saved),'facts':facts,'semanticApproval':False,'productionAcceptanceComplete':False},'objectEvidenceIdentity')
        publish_checked(runner.output/'result.json',value,check)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save();return value
    except Exception as exc:runner.failure('object-model',exc);raise


def check(path):
    from .native_external_providers import checked
    value=d.read(path);checked(value,'objectEvidenceIdentity');compare(value['verifier'],current())
    for key in ('input','model'):d.verify_snapshot(value[key])
    if (value['schemaVersion']!=SCHEMA or d.read(value['input']['path'])!=d.read(value['model']['path'])
            or value['facts']!=derive(d.read(value['model']['path']))
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('OBJECT_EVIDENCE_REDERIVATION_MISMATCH')
    return value
