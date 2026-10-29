"""Read-only staged prerequisite assessment; never execution or approval.

Declared mechanism names are not backend calibration evidence. All runtime
stages remain not_run, even when the recorded static prerequisites validate.
"""
import argparse
import json
from pathlib import Path
from .l3_trace_support import identity,digest,require_json_document


def assess(findings,functions,capabilities):
    from .l3_property_obligations import analyze
    from .l3_execution_plan import build
    from .l3_entry_binding import entry
    stages=[]
    def check(stage,operation,fragment=None):
        item={'stage':stage,'fragmentId':fragment,'status':'satisfied','reasonCodes':[]}
        try:
            note=operation()
            if isinstance(note,str):item.update(status="not_assessed",reasonCodes=[note])
        except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
            item.update(status='unresolved',reasonCodes=[type(exc).__name__+': '+str(exc)])
        stages.append(item)
    for finding in findings:
        fid=finding['fragment']['id'];kind=finding.get('l2SemanticProfile',{}).get('patternKind')
        check('source-obligations-and-proof-authority',lambda:analyze(finding,functions),fid)
        def invocation():
            fn=entry(functions,finding['fragment']['compilerFragmentAuthority']['functionIdentity'])
            if len(findings)>1 and fn.get('compilerJointScope') and 'joint' in capabilities:
                from .l3_joint_spec import spec
                spec(findings,functions)
            elif kind in {'memory_load','memory_store'}:
                from .l3_memory_intent import memory_spec
                from .l3_memory_call import bind,bind_load
                spec=memory_spec(finding)
                if fn.get('compilerMemoryCallSignature') is None:
                    return 'L3_LEGACY_CALL_REQUIRES_OWN_ROUTE_REPLAY'
                (bind_load if kind=='memory_load' else bind)(fn,finding,spec)
            elif kind=='scalar':
                if len(findings)>1:
                    from .l3_control_spec import signature
                    signature(fn)
                else:
                    from .l3_scalar_call import call_signature
                    call_signature(fn,finding)
            elif kind in {'branch','jump','asm_goto'}:
                from .l3_control_spec import spec,signature
                spec(finding,functions);signature(fn)
            elif kind=='fence':
                from .l3_fence_spec import spec
                spec(finding,functions)
            elif kind=='atomic':
                if finding.get('approvalArtifact',{}).get('l2LrscProofFacts'):
                    from .l3_lrsc_spec import spec
                else:
                    from .l3_atomic_spec import spec
                spec(finding,functions)
            else:raise ValueError('L3_CAPABILITY_FAMILY_NOT_ASSESSED')
        check('typed-invocation-and-shell',invocation,fid)
    plan=None
    def selection():
        nonlocal plan
        if 'joint' in capabilities and any(fn.get('compilerJointScope') for fn in functions):
            from .l3_mechanism_selection import plan as select
            plan,_=select(findings,functions,{'joint':{}})
        else:plan=build(findings,functions,set(capabilities))
        if not plan['complete']:raise ValueError('L3_MEMBER_CAPABILITY_PREREQUISITES_MISSING')
    check('declared-mechanism-availability',selection)
    def composition():
        if not findings:raise ValueError('L3_EMPTY_PROGRAM')
        if len(findings)>1:
            if 'joint' in capabilities and any(fn.get('compilerJointScope') for fn in functions):
                from .l3_joint_spec import spec
                spec(findings,functions)
                return
            if any(f.get('l2SemanticProfile',{}).get('patternKind')!='scalar' for f in findings):
                raise ValueError('L3_JOINT_REGION_EXECUTION_CONTRACT_REQUIRED')
            from .l3_program_spec import spec
            spec(findings,functions)
    check('program-composition-and-dependency-closure',composition)
    body={'schemaVersion':'riscv2x86.l3-capability-assessment.v1',
        'recordedFindingsIdentity':identity(findings),'compilerFunctionsIdentity':identity(functions),
        'declaredCapabilities':sorted(set(capabilities)),'stages':stages,
        'staticPrerequisitesComplete':all(s['status']=='satisfied' for s in stages),
        'mechanismPlan':plan,'runtimeStages':{s:'not_run' for s in ('backend-validation','deployment','execution','comparison','independent-audit')},
        'semanticApproval':False,'productionAcceptanceComplete':False,
        'scope':'recorded-static-prerequisites-only; not source recompilation or backend calibration'}
    require_json_document(body,'L3_CAPABILITY_ASSESSMENT_JSON_INVALID')
    return dict(body,assessmentIdentity=identity(body))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report',required=True);p.add_argument('--output',required=True)
    p.add_argument('--capability',action='append',default=[],help='Declared only; not a calibrated backend selection')
    a=p.parse_args();report=Path(a.report).resolve();snapshot=report.with_name('compiler-candidates.json')
    value=assess(json.loads(report.read_text())['findings'],json.loads(snapshot.read_text())['functions'],a.capability)
    value={'assessment':value,'inputDigests':{str(path):digest(path) for path in (report,snapshot)}}
    with Path(a.output).open('x',encoding='utf-8') as stream:json.dump(value,stream,ensure_ascii=False,indent=2)
    print(json.dumps({'staticPrerequisitesComplete':value['assessment']['staticPrerequisitesComplete'],
                      'semanticApproval':False,'productionAcceptanceComplete':False}))
    return 0 if value['assessment']['staticPrerequisitesComplete'] else 2


if __name__=='__main__':raise SystemExit(main())
