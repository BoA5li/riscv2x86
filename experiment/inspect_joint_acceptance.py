#!/usr/bin/env python3
"""Reread retained joint production evidence; no execution/approval inferred."""
import argparse
import json
from pathlib import Path


def inspect(root):
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    state=json.loads((root/'run-status.json').read_text())
    flags=('executionComplete','independentResultAuditComplete','productionAcceptanceComplete')
    result={k:state.get(k) for k in ('currentStage',*flags,'primaryFailure','blockers')}
    print(json.dumps(result,ensure_ascii=False),flush=True)
    reports=sorted(root.glob('batch/cases/*/evaluation-result.json'))
    if len(reports)!=1:raise ValueError('exactly one evaluation report required')
    report=json.loads(reports[0].read_text())
    print(json.dumps({'evaluationStatus':report.get('status'),'reasonCodes':report.get('reasonCodes')},ensure_ascii=False),flush=True)
    for attempt in report.get('attempts',[]):
        print(json.dumps({'fragmentId':attempt.get('fragmentId'),'translationOutcome':attempt.get('translationOutcome'),
            'layers':(attempt.get('validation') or {}).get('layers',[])},ensure_ascii=False),flush=True)
    if (state.get('currentStage')!='complete' or state.get('blockers')
            or any(state.get(k) is not True for k in flags) or report.get('status')!='verified'):
        raise ValueError('joint production workflow not fully accepted')
    audit=audit_evaluation(report)
    print(json.dumps({'independentAudit':audit},ensure_ascii=False,indent=2),flush=True)
    if audit.get('status')!='verified' or audit.get('programExecutionUnitCount')!=1:
        raise ValueError('independent whole-program audit not verified')
    groups=set()
    for attempt in report['attempts']:
        layers=attempt['validation']['layers']
        if [(v['level'],v['status']) for v in layers]!=[(v,'verified') for v in ('L0','L1','L2','L3')]:
            raise ValueError('every member must complete L0-L3')
        groups.add(json.loads(layers[3]['detail'])['jointCapturePath'])
    if len(groups)!=1:raise ValueError('all members must share one capture')
    group=json.loads(Path(next(iter(groups))).read_text())
    for side in ('source','target'):
        observation=group['reports'][side]
        print(json.dumps({'side':side,'samples':len(observation['samples']),'events':len(observation['events']),
            'fenceEvents':sum(e['access']=='fence' for e in observation['events'])}),flush=True)
    return 0


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);args=parser.parse_args()
    try:return inspect(Path(args.root).resolve())
    except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
        print(json.dumps({'status':'not_accepted','error':type(exc).__name__+': '+str(exc)},ensure_ascii=False),flush=True)
        return 1


if __name__=='__main__':raise SystemExit(main())
