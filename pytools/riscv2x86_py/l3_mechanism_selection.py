"""Explicit calibrated mechanisms selected by proof obligations, never case IDs."""
import argparse
import json
from pathlib import Path
import sys
from .l3_trace_support import identity,digest
from .l3_execution_plan import build
from .l3_intent_requirements import _hash

SCHEMA='riscv2x86.l3-mechanism-selections.v1'


def load(path,*,progress=None):
    path=Path(path).resolve();selection_digest=digest(path);raw=json.loads(path.read_text())
    if not isinstance(raw,dict) or set(raw)!={'schemaVersion','backends'} or raw['schemaVersion']!=SCHEMA or not isinstance(raw['backends'],dict) or not raw['backends'] or set(raw['backends'])-{'memory','control','scalar-program','fence','atomic','lrsc','joint'}:raise ValueError('L3_MECHANISM_SELECTION_INVALID')
    from .l3_memory_backend import validate_backend
    from .l3_control_backend import validate as control
    from .l3_program_backend import validate as program
    from .l3_fence_backend import validate as fence
    from .l3_atomic_backend import validate as atomic
    from .l3_lrsc_backend import validate as lrsc
    from .l3_joint_backend import validate as joint
    from .l3_backend_validation import BackendValidationSession
    result={};roots=[]
    validators={'memory':validate_backend,'control':control,'scalar-program':program,'fence':fence,'atomic':atomic,'lrsc':lrsc,'joint':joint}
    with BackendValidationSession(progress) as context:
        for name,p in sorted(raw['backends'].items()):
            if not isinstance(p,str) or not p:raise ValueError('L3_MECHANISM_BACKEND_PATH_INVALID')
            p=str((Path(p) if Path(p).is_absolute() else path.parent/p).resolve())
            if progress:progress({'stage':'mechanism-validation','mechanism':name,'state':'started'})
            before=digest(p)
            b=(context.check(control,p,nested=True) if name=='control' else
               context.check(validate_backend,p) if name=='memory' else
               validators[name](p,_context=context))
            if digest(p)!=before:raise ValueError('L3_MECHANISM_BACKEND_CHANGED_DURING_VALIDATION')
            result[name]={'path':p,'digest':before,'backendIdentity':b['backendIdentity']}
            if name not in {'control','memory'}:roots.append((validators[name],p,b))
            if progress:progress({'stage':'mechanism-validation','mechanism':name,'state':'complete'})
        for validator,p,expected in roots:
            if validator(p,_context=context)!=expected:
                raise ValueError("L3_MECHANISM_BACKEND_CHANGED_DURING_VALIDATION")
    if digest(path)!=selection_digest or any(digest(v["path"])!=v["digest"] for v in result.values()):
        raise ValueError("L3_MECHANISM_SELECTION_CHANGED_DURING_VALIDATION")
    return result


def plan(findings,functions,selections):
    p=build(findings,functions,set(selections));mechanisms={m['mechanism'] for m in p['members']}
    from .l3_intent_refusal import RouteUnavailable
    if len(findings)>1 and 'joint' in selections and any(fn.get('compilerJointScope') for fn in functions):
        try:
            from .l3_joint_spec import spec
            program=spec(findings,functions)
        except (ValueError,KeyError,TypeError,IndexError) as exc:
            raise RouteUnavailable('L3_JOINT_PREREQUISITE:'+str(exc),plan=p) from exc
        body={'schemaVersion':'riscv2x86.joint-mechanism-plan.v1','programId':p['programId'],
            'members':[dict(m,mechanism='joint',status='ready',reasonCodes=[]) for m in p['members']],
            'jointSpecIdentity':program['specIdentity'],'complete':True,
            'readinessScope':'static-proof-and-invocation-prerequisites; execution-not-run',
            'physicalMicroarchitectureClaimed':False}
        return dict(body,planIdentity=identity(body)),'joint'
    if len(mechanisms)!=1:raise RouteUnavailable('L3_MECHANISM_COMBINATION_NOT_YET_SUPPORTED',plan=p)
    if not p['complete']:
        missing=any(m['mechanism']!='unavailable' and m['mechanism'] not in selections for m in p['members'])
        raise RouteUnavailable('L3_MECHANISM_CAPABILITY_INCOMPLETE:'+json.dumps(p),
            disposition='prerequisites_missing' if missing else 'unsupported',plan=p)
    return p,mechanisms.pop()


def produce(request,selections):
    from .l3_program_intent import produce as program_produce
    from .l3_control_intent import produce as control_produce
    from .l3_trace_intent import produce as memory_produce
    from .l3_fence_intent import produce as fence_produce
    from .l3_atomic_intent import produce as atomic_produce
    from .l3_lrsc_intent import produce as lrsc_produce
    from .l3_joint_intent import produce as joint_produce
    if request.get('requestIdentity')!=_hash({k:v for k,v in request.items() if k!='requestIdentity'}):raise ValueError('L3_MECHANISM_REQUEST_CHANGED')
    try:
        candidates=request['candidates'];functions=candidates[0]['compilerFunctions']
        if any(c['compilerFunctions']!=functions for c in candidates):raise ValueError('L3_MECHANISM_SNAPSHOT_CONFLICT')
        _,kind=plan([c['finding'] for c in candidates],functions,selections)
    except (KeyError,TypeError,ValueError,IndexError) as exc:
        from .l3_intent_refusal import produce as refuse
        return refuse(request,exc)
    return {'memory':memory_produce,'control':control_produce,'scalar-program':program_produce,'fence':fence_produce,'atomic':atomic_produce,'lrsc':lrsc_produce,'joint':joint_produce}[kind](request)


def build_route(config):
    if not isinstance(config,dict) or set(config)!={'schemaVersion','selectionPath','selectionDigest','routeConfig'} or config['schemaVersion']!='riscv2x86.l3-mechanism-route.v1':raise ValueError('L3_MECHANISM_ROUTE_CONFIG_INVALID')
    def validate(**kwargs):
        from .translation_validation import ValidationLayerResult,ValidationLevel
        from .validation_status import ValidationStatus
        try:
            if digest(config['selectionPath'])!=config['selectionDigest']:raise ValueError('L3_MECHANISM_SELECTION_CHANGED')
            selections=load(config['selectionPath']);c=dict(config['routeConfig'])
            report=Path(c['reportPath']);findings=json.loads(report.read_text())['findings']
            functions=json.loads(report.with_name('compiler-candidates.json').read_text())['functions']
            _,kind=plan(findings,functions,selections);selected=selections[kind]
            c.update(backendPath=selected['path'],backendDigest=selected['digest'])
            if kind=='memory':
                from .l3_qemu_memory_route import build_route as factory
            elif kind=='joint':
                from .l3_joint_route import build_route as factory
                c.update(schemaVersion='riscv2x86.joint-program-route.v1',sampleCount=8,workDirectory=str(Path(c['workDirectory']).parent/'joint'),clang=config['routeConfig']['clang'])
            elif kind=='lrsc':
                from .l3_lrsc_route import build_route as factory
                c.update(schemaVersion='riscv2x86.lrsc-trace-route.v1',sampleCount=None,clang=config['routeConfig']['clang'])
            elif kind=='atomic':
                from .l3_atomic_route import build_route as factory
                c.update(schemaVersion='riscv2x86.atomic-trace-route.v1',sampleCount=None,clang=config['routeConfig']['clang'])
            elif kind=='fence':
                from .l3_fence_route import build_route as factory
                c.update(schemaVersion='riscv2x86.fence-trace-route.v1',sampleCount=None,clang=config['routeConfig']['clang'])
            elif kind=='control':
                from .l3_control_route import build_route as factory
                c.update(schemaVersion='riscv2x86.control-trace-route.v1',sampleCount=None,clang=config['routeConfig']['clang'])
            else:
                from .l3_program_route import build_route as factory
                c.update(schemaVersion='riscv2x86.scalar-program-route.v1',sampleCount=8,workDirectory=str(Path(c['workDirectory']).parent/'program'))
            if kind=='memory':c.pop('clang',None)
            return factory(c)(**kwargs)
        except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
            return ValidationLayerResult(ValidationLevel.L3,ValidationStatus.INCONCLUSIVE,detail=json.dumps({'reasonCodes':[str(exc)],'failureStage':'l3-mechanism-selection','evidenceProductionDisposition':'not_produced'}))
    return validate


def producer_dependencies():
    from .l3_implementation_dependencies import implementation_dependencies
    return set(implementation_dependencies())


def main():
    deps=producer_dependencies()
    p=argparse.ArgumentParser();p.add_argument('--implementation',required=True);p.add_argument('--dependency',action='append',default=[]);p.add_argument('--selection-file',required=True);a=p.parse_args()
    if Path(a.implementation).resolve()!=Path(__file__).resolve() or {str(Path(x).resolve()) for x in a.dependency}!={str((Path(__file__).parent/n).resolve()) for n in deps}:raise ValueError('L3_MECHANISM_DEPENDENCIES_UNPINNED')
    request=json.load(sys.stdin)
    progress=lambda event:print(json.dumps(event,sort_keys=True),file=sys.stderr,flush=True)
    from .l3_trace_support import emit_json
    emit_json(lambda: produce(request,load(a.selection_file,progress=progress)))
if __name__=='__main__':main()
