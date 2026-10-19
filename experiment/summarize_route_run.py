#!/usr/bin/env python3
"""Read-only per-case route/validation diagnostics and baseline comparison.

A non-verified case is data, not a shell failure. Missing or malformed artifacts
are retained as structured errors; this reader never changes an evaluation.
"""
import argparse
from collections import Counter
import json
from pathlib import Path


def read_json(path, errors):
    try:
        value=json.loads(path.read_text())
        if not isinstance(value,dict): raise ValueError('expected a JSON object')
        return value
    except (OSError,ValueError) as exc:
        errors.append({'artifactPath':str(path),'exceptionType':type(exc).__name__,'detail':str(exc)})
        return {}


def objects(value):
    if isinstance(value,dict):
        yield value
        for child in value.values(): yield from objects(child)
    elif isinstance(value,list):
        for child in value: yield from objects(child)
    elif isinstance(value,str) and value.lstrip().startswith(('{','[')):
        try: child=json.loads(value)
        except ValueError:return
        yield from objects(child)


def summarize(results):
    results=Path(results).resolve();errors=[]
    root=results/'generated-suite-strict' if (results/'generated-suite-strict').is_dir() else results
    batch=read_json(root/'batch-evaluation.json',errors)
    inventory=root.with_name(root.name+'-inventory')
    records=[]
    for path in sorted((root/'cases').glob('*/evaluation-result.json')):
        case=read_json(path,errors);case_id=path.parent.name;dimensions={};routes={}
        for item in objects(case):
            if item.get('schemaVersion')=='riscv2x86.route-authority-decision.v1':
                routes[item.get('decisionIdentity') or json.dumps(item,sort_keys=True)]={
                    k:item.get(k) for k in ('route','accepted','failureStage','reasonCode','detail','inputsPayload')}
            if item.get('schemaVersion')=='riscv2x86.l2-fragment-result.v4':
                for name,dimension in item.get('dimensionResults',{}).items():
                    dimensions[(item.get('fragmentId'),name)]={'fragmentId':item.get('fragmentId'),
                        'dimension':name, **{k:dimension.get(k) for k in ('status','reasonCodes',
                            'authorityIdentity','effectRelationIdentity','executionIdentity',
                            'sourceObservationIdentity','targetObservationIdentity')},
                        'precondition':item.get('precondition')}
        record={'caseId':case_id,'artifactPath':str(path),'status':case.get('status'),
            'reasonCodes':case.get('reasonCodes',[]),'routeDecisions':list(routes.values()),
            'l2Dimensions':list(dimensions.values()),'commands':case.get('commands',[])}
        contracts=inventory/'cases'/case_id/'contract-resolution.json'
        record['contractResolution']=read_json(contracts,errors) if contracts.is_file() else None
        record['preflightFailure']=(case.get('translationEvaluationLink') or {}).get('preflightFailure')
        records.append(record)
    expected=batch.get('caseCount')
    if type(expected) is int and expected!=len(records):
        errors.append({'artifactPath':str(root/'cases'),'exceptionType':'CaseCountMismatch',
                       'detail':f'expected {expected}, read {len(records)}'})
    return {'schemaVersion':'riscv2x86.route-run-summary.v1','resultsPath':str(results),
        'batchIdentity':batch.get('batchIdentity'),'statusCounts':batch.get('statusCounts'),
        'programValidationCounts':batch.get('programValidationCounts'),
        'l2CoverageDiagnostics':batch.get('l2CoverageDiagnostics'),
        'observedStatusCounts':dict(Counter(x['status'] for x in records)),
        'cases':records,'artifactErrors':errors}


def compare(current,baseline):
    before={x['caseId']:x for x in baseline['cases']};after={x['caseId']:x for x in current['cases']}
    changes=[];regressions=[];dimension_regressions=[]
    for case_id in sorted(set(before)|set(after)):
        old=before.get(case_id,{});new=after.get(case_id,{})
        if old.get('status')!=new.get('status'):
            changes.append({'caseId':case_id,'before':old.get('status'),'after':new.get('status')})
        if old.get('status')=='verified' and new.get('status')!='verified':regressions.append(case_id)
        # Fragment IDs contain absolute source paths. Compare within a case by
        # suffix source location only when unique; preserve ambiguous results.
        def index(record):
            grouped={}
            for d in record.get('l2Dimensions',[]):
                location=':'.join(str(d.get('fragmentId')).rsplit(':',2)[-2:])
                key=(location,d.get('dimension'))
                grouped.setdefault(key,[]).append(d.get('status'))
            return grouped
        olddims,newdims=index(old),index(new)
        for key,statuses in olddims.items():
            if statuses==['verified'] and newdims.get(key)!=['verified']:
                dimension_regressions.append({'caseId':case_id,'sourceLocation':key[0],
                    'dimension':key[1],'after':newdims.get(key)})
    return {'caseStatusChanges':changes,'previouslyVerifiedCaseRegressions':regressions,
        'previouslyVerifiedDimensionRegressions':dimension_regressions,
        'baselineArtifactErrors':baseline['artifactErrors'],
        'comparisonScope':'status preservation only; identities and semantic claims require independent validation'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results',type=Path,required=True)
    parser.add_argument('--compare',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=summarize(args.results)
    if args.compare:result['comparison']=compare(result,summarize(args.compare))
    text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if args.output:
        if args.output.exists():
            print('Output already exists; preserved existing file.')
            return 2
        # Exclusive creation prevents accidentally overwriting a raw artifact.
        with args.output.open('x') as handle:handle.write(text)
    else:print(text,end='')
    return 2 if result['artifactErrors'] else 0


if __name__=='__main__':raise SystemExit(main())
