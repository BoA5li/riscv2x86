"""Read-only coverage ledger. Never exclude untested/failed seeds from coverage.

Expectation rules and run evidence are separate. No case ID selects a route.
Results are joined by exact source path+digest, not by success or a case prefix.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
from .l3_trace_support import digest,identity,save
from .l3_supported_domain import catalog

STAGES=('translation','source-build','target-build','L0','L1','L2','L3','independent-audit')


def diagnose(report,case_root):
    """Preserve every attempt; absence and incomplete groups never become verified."""
    from .l3_production_acceptance import audit_evaluation
    rows=[]
    for attempt in report.get('attempts',[]):
        layers=(attempt.get('validation') or {}).get('layers',[])
        row={'fragmentId':attempt.get('fragmentId'),'translationOutcome':attempt.get('translationOutcome'),
            'stages':{level:'not_run' for level in ('L0','L1','L2','L3')},'blockers':[]}
        for layer in layers:
            row['stages'][layer['level']]=layer['status']
            if layer['status']!='verified':
                detail=layer.get('detail')
                try:detail=json.loads(detail) if isinstance(detail,str) else detail
                except ValueError:pass
                row['blockers'].append({'stage':layer['level'],'detail':detail})
                if layer['level']=='L2' and 'dimension-capability-undeclared' in str(detail):
                    row['blockers'][-1]['substage']='provider-resolution'
        rows.append(row)
    statuses={k:'not_run' for k in STAGES}
    for command in report.get('commands',[]):
        phase=command.get('phase')
        if phase in statuses:
            current=statuses[phase];new=command.get('status','inconclusive')
            statuses[phase]=new if current=='not_run' or current=='verified' else current
    for level in ('L0','L1','L2','L3'):
        actual=[row['stages'][level] for row in rows]
        statuses[level]=('verified' if actual and all(x=='verified' for x in actual)
            else 'failed' if 'failed' in actual else 'inconclusive' if any(x!='not_run' for x in actual) else 'not_run')
    audit={'status':'not_run','reasonCodes':[],'completed':False}
    if report.get('status')=='verified' or report.get('status')=='failed' and statuses['L3'] in {'verified','failed'}:
        try:
            joint=any('jointCapturePath' in str(l.get('detail','')) for a in report.get('attempts',[]) for l in (a.get('validation') or {}).get('layers',[]) if l.get('level')=='L3')
            if joint:
                from .l3_joint_route import audit_result
                value=audit_result(report)
            else:value=audit_evaluation(report)
            audit={'status':value['status'],'reasonCodes':[],'completed':True,'result':value}
        except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
            audit={'status':'inconclusive','reasonCodes':[str(exc)],'completed':False}
    statuses['independent-audit']=audit['status']
    # A recorded passing layer is distinct from independently accepted evidence.
    first=next(({'stage':s,'status':statuses[s]} for s in STAGES if statuses[s] not in ('verified','not_run')),None)
    runtime={key:('not_run' if statuses['L3']=='not_run' else 'not_assessed') for key in ('backend-validation','deployment','execution','comparison')}
    runtime['independent-audit']=audit['status']
    if audit['completed']:
        runtime.update({'backend-validation':'verified','deployment':'verified','execution':'verified','comparison':audit['status']})
    return {'runtimeEvidenceStages':runtime,'recordedEvaluationStatus':report.get('status'),'recordedReasonCodes':report.get('reasonCodes',[]),
        'recordedStages':statuses,'firstRecordedBlocker':first,'members':rows,'audit':audit,
        'productionAcceptanceComplete':report.get('status')=='verified' and audit['status']=='verified'}


def collect(source_directory,results_root,*,capabilities=(),clang=None):
    source_directory=Path(source_directory).resolve();results_root=Path(results_root).resolve()
    if not source_directory.is_dir() or not results_root.is_dir():raise ValueError('L3_COVERAGE_DIRECTORY_REQUIRED')
    records=[];index={};errors=[]
    for source in sorted(source_directory.rglob('*.c')):
        if source.is_symlink():raise ValueError('L3_COVERAGE_SOURCE_SYMLINK_UNSUPPORTED')
        row={'sourcePath':str(source),'sourceDigest':digest(source),'expectedDomainMembership':'not_assessed',
            'compilerInspection':'not_run','staticAssessments':[],'runs':[]}
        if clang:
            try:
                from .automatic_batch_cli import inspect_entry_points
                _,functions=inspect_entry_points(source,clang=clang)
                row.update(compilerInspection='complete',compilerFunctionsIdentity=identity(functions),
                    compilerScopes=[{k:f[k] for k in ('functionId','compilerJointScope','compilerMemoryCallSignature') if k in f} for f in functions])
            except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
                row.update(compilerInspection='inconclusive',compilerInspectionError=str(exc))
        records.append(row);index[str(source)]=row
    for path in sorted(results_root.rglob('evaluation-result.json')):
        try:
            report=json.loads(path.read_text())
            if report.get('evaluationIdentity')!=identity({k:v for k,v in report.items() if k not in {'evaluationIdentity','replayArtifact'}}):
                raise ValueError('L3_COVERAGE_EVALUATION_IDENTITY_MISMATCH')
            commands=[c['command'] for c in report.get('commands',[]) if c.get('phase')=='translation']
            if len(commands)!=1 or commands[0].count('--source')!=1:raise ValueError('L3_COVERAGE_SOURCE_JOIN_UNAVAILABLE')
            command=commands[0];source=Path(command[command.index('--source')+1]).resolve()
            if str(source) not in index:continue
            row=index[str(source)]
            if digest(source)!=row['sourceDigest']:raise ValueError('L3_COVERAGE_SOURCE_CHANGED')
            run={'reportPath':str(path),'reportDigest':digest(path),**diagnose(report,path.parent)}
            translations=list((path.parent/'work').rglob('translated_report.json'))
            if len(translations)==1:
                p=translations[0];snapshot=p.with_name('compiler-candidates.json')
                if snapshot.is_file():
                    from .l3_capability_assessment import assess
                    findings=json.loads(p.read_text())['findings'];functions=json.loads(snapshot.read_text())['functions']
                    if any(f.get('sourceDigest')!=row['sourceDigest'] for f in findings):raise ValueError('L3_COVERAGE_FINDING_SOURCE_CHANGED')
                    configs=[]
                    for config_path in sorted((path.parent/'work/replay').glob('*-registry.json')):
                        configuration=json.loads(config_path.read_text()).get('validators',{}).get('L2',{}).get('config')
                        if configuration and configuration.get('schemaVersion')=='riscv2x86.l2-requirement-driven-registry.v3':
                            configs.append({'path':str(config_path),'digest':digest(config_path),'assessment':assess(findings,functions,set(capabilities),configuration)})
                    static=assess(findings,functions,set(capabilities));run['staticAssessment']=static
                    run['recordedConfigurationAssessments']=configs
                    row['staticAssessments'].append(static['assessmentIdentity'])
                    # Membership is determined by the declared validator, never by the run verdict.
                    if 'joint' in capabilities:
                        try:
                            from .l3_joint_spec import spec
                            spec(findings,functions);row['expectedDomainMembership']='joint-domain-proved'
                        except (ValueError,KeyError,TypeError,IndexError) as exc:
                            row['domainAssessmentReason']=str(exc)
            row['runs'].append(run)
        except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
            errors.append({'reportPath':str(path),'error':str(exc)})
    for row in records:
        row['coverageStatus']=('not_run' if not row['runs'] else 'accepted' if all(r['productionAcceptanceComplete'] for r in row['runs']) else 'blocked')
        row['expectedDomainViolation']=row['expectedDomainMembership']=='joint-domain-proved' and row['coverageStatus']!='accepted'
    frozen={'schemaVersion':'riscv2x86.l3-source-inventory.v1',
        'sources':[{'sourceRelativePath':str(Path(r['sourcePath']).relative_to(source_directory)),'sourceDigest':r['sourceDigest']} for r in records],
        'catalogIdentity':catalog()['catalogIdentity']}
    preparations=[]
    for p in sorted(results_root.rglob('build-status.json')):
        try:preparations.append({'path':str(p),'digest':digest(p),'recordedStatus':json.loads(p.read_text()),'programAcceptanceInferred':False})
        except (OSError,ValueError) as exc:errors.append({'path':str(p),'error':str(exc)})
    body={'schemaVersion':'riscv2x86.l3-coverage-inventory.v1','catalog':catalog(),
        'sourceInventory':dict(frozen,inventoryIdentity=identity(frozen)),
        'sourceCount':len(records),'records':records,'errors':errors,'recordedBackendPreparations':preparations,
        'statusCounts':dict(Counter(r['coverageStatus'] for r in records)),
        'semanticApproval':False,'productionAcceptanceComplete':False,
        'scope':'read-only ledger; per-run acceptance requires independent audit; missing results remain in denominator'}
    return dict(body,ledgerIdentity=identity(body))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sources',required=True);p.add_argument('--results',required=True)
    p.add_argument('--output',required=True);p.add_argument('--clang');p.add_argument('--capability',action='append',default=[])
    a=p.parse_args();v=collect(a.sources,a.results,capabilities=a.capability,clang=a.clang);save(Path(a.output),v)
    print(json.dumps({k:v[k] for k in ('sourceCount','statusCounts','errors','ledgerIdentity','productionAcceptanceComplete')},ensure_ascii=False))
    return 2 if v['errors'] else 0

if __name__=='__main__':raise SystemExit(main())
