#!/usr/bin/env python3
"""Check explicit case acceptance goals without modifying semantic verdicts."""
import argparse
import json
from pathlib import Path
import re


def check(results,case_ids):
    results=Path(results);records=[]
    if not case_ids or len(set(case_ids))!=len(case_ids):raise ValueError('GOALS_EMPTY_OR_DUPLICATE')
    for case_id in case_ids:
        if not isinstance(case_id,str) or re.fullmatch(r'[A-Za-z0-9_.-]+',case_id) is None or case_id in {'.','..'}:
            raise ValueError('GOAL_CASE_ID_INVALID')
        path=results/'cases'/case_id/'evaluation-result.json'
        try:
            value=json.loads(path.read_text());status=value['status']
            records.append({'caseId':case_id,'status':status,'goalSatisfied':status=='verified',
                'evaluationIdentity':value.get('evaluationIdentity'),'reasonCodes':value.get('reasonCodes',[])})
        except (OSError,ValueError,KeyError,TypeError) as exc:
            records.append({'caseId':case_id,'goalSatisfied':False,'artifactPath':str(path),
                'exceptionType':type(exc).__name__,'detail':str(exc)})
    return {'schemaVersion':'riscv2x86.route-goal-check.v1','goalSatisfied':all(r['goalSatisfied'] for r in records),
        'scope':'case verdict acceptance; does not replace provider audit or semantic proof','cases':records}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results',type=Path,required=True);parser.add_argument('--case',action='append',required=True)
    args=parser.parse_args()
    try:
        value=check(args.results,args.case);print(json.dumps(value,ensure_ascii=False,indent=2))
        return 0 if value['goalSatisfied'] else 1
    except (ValueError,TypeError) as exc:
        print(json.dumps({'failureStage':'goal_configuration','detail':str(exc)}));return 2


if __name__=='__main__':raise SystemExit(main())
