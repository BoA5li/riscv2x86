#!/usr/bin/env python3
"""Summarize diagnostic spans without double-counting nested work as wall time."""
import argparse
from collections import defaultdict
import json
from pathlib import Path


def summarize(path):
    spans={}
    for number,line in enumerate(Path(path).read_text().splitlines(),1):
        row=json.loads(line)
        if (row.get('schemaVersion')!='riscv2x86.validation-timing.v1'
                or type(row.get('pid')) is not int or type(row.get('span')) is not str
                or type(row.get('stage')) is not str or type(row.get('returned')) is not bool
                or type(row.get('startNs')) is not int or type(row.get('endNs')) is not int
                or row['endNs']<row['startNs'] or row['span'] in spans
                or row.get('parent') is not None and type(row['parent']) is not str):
            raise ValueError('INVALID_TIMING_RECORD:'+str(number))
        spans[row['span']]=row
    children=defaultdict(list);child_ids=defaultdict(list);missing=[]
    for row in spans.values():
        parent=row['parent']
        if parent is None:continue
        if parent not in spans:
            missing.append(row['span']);continue
        owner=spans[parent]
        if owner['pid']!=row['pid'] or not owner['startNs']<=row['startNs']<=row['endNs']<=owner['endNs']:
            raise ValueError('INVALID_TIMING_NESTING')
        if parent==row['span']:raise ValueError('INVALID_TIMING_CYCLE')
        children[parent].append((row['startNs'],row['endNs']))
        child_ids[parent].append(row['span'])
    totals=defaultdict(lambda: {'calls':0,'raised':0,'inclusiveSeconds':0.,'exclusiveSeconds':0.})
    for span,row in spans.items():
        intervals=sorted(children[span]);covered=0;end=row['startNs']
        for left,right in intervals:
            covered+=max(0,right-max(left,end));end=max(end,right)
        elapsed=row['endNs']-row['startNs'];t=totals[row['stage']]
        t['calls']+=1;t['raised']+=int(not row['returned'])
        t['inclusiveSeconds']+=elapsed/1e9;t['exclusiveSeconds']+=(elapsed-covered)/1e9
    operations=[]
    for span,row in spans.items():
        if row['stage']!='joint.new-capture-operation':continue
        pending=[span];descendants=[];seen=set()
        while pending:
            parent=pending.pop()
            if parent in seen:raise ValueError('INVALID_TIMING_CYCLE')
            seen.add(parent)
            direct=child_ids[parent]
            descendants.extend(spans[s] for s in direct);pending.extend(direct)
        operations.append({'span':span,'returned':row['returned'],
            'backendValidationCalls':sum(r['stage']=='joint.backend-validation' for r in descendants),
            'calibrationChecks':sum(r['stage']=='joint.calibration-check-and-rebuild' for r in descendants)})
    atomic_operations=[]
    for row in sorted(spans.values(),key=lambda r:r['startNs']):
        if not row['stage'].startswith('atomic.operation-complete.'):
            continue
        pending=[row['span']];descendants=[];seen=set()
        while pending:
            parent=pending.pop()
            if parent in seen:raise ValueError('INVALID_TIMING_CYCLE')
            seen.add(parent)
            direct=child_ids[parent]
            descendants.extend(spans[s] for s in direct);pending.extend(direct)
        atomic_operations.append({'span':row['span'],'pid':row['pid'],
            'name':row['stage'][len('atomic.operation-complete.'):],
            'parent':row['parent'],'returned':row['returned'],
            'inclusiveSeconds':(row['endNs']-row['startNs'])/1e9,
            'closingReplayCalls':sum(r['stage']=='atomic.operation-closing-replay' for r in descendants),
            'baseBackendFullValidationCalls':sum(r['stage']=='atomic.base-backend-full-validation' for r in descendants),
            'intentReplayCalls':sum(r['stage']=='atomic.intent-program-replay' for r in descendants),
            'scope':'same-process descendants; nested operations overlap; not experiment wall time'})
    return {'schemaVersion':'riscv2x86.validation-timing-summary.v1','spanCount':len(spans),
            'processCount':len({r['pid'] for r in spans.values()}),'incompleteParentSpans':missing,
            'newCaptureOperations':operations,'atomicOperations':atomic_operations,
            'stages':dict(sorted(totals.items(),key=lambda p:-p[1]['exclusiveSeconds'])),
            'note':'Instrumented work only. Inclusive spans overlap; sums across processes are not experiment wall time. returned is not semantic acceptance.',
            'semanticApproval':False}


def main():
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);a=p.parse_args()
    print(json.dumps(summarize(a.input),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
