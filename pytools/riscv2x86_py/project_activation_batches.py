"""Freeze all captured C contexts and inspect deterministic source batches.

The aggregate is a checked inventory of recorded inspection/replay runs. It is
not a new compiler replay, native activation proof or translation acceptance.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys

from .project_build_records import identity
from .project_compile_context import derive, digest
from .project_inspection_pilot import execute, verify_members
from .project_tool_resolution import resolve_executable


def read(path):
    return json.loads(Path(path).read_text())


def write_new(path,value):
    with Path(path).open('x') as stream:json.dump(value,stream,ensure_ascii=False,indent=2)


def make_plan(records_path,batch_sources=16,*,clang):
    if type(batch_sources) is not int or batch_sources<1:raise ValueError('ACTIVATION_BATCH_SIZE_INVALID')
    path=Path(records_path).resolve(strict=True);before=digest(path);records=read(path)
    compiler=resolve_executable(clang);compiler_digest=digest(compiler)
    if (records.get('schemaVersion')!='riscv2x86.project-build-records.v1'
            or records.get('inventoryIdentity')!=identity({k:v for k,v in records.items() if k!='inventoryIdentity'})
            or records.get('semanticApproval') is not False or records.get('buildSuccessVerified') is not False):
        raise ValueError('ACTIVATION_BUILD_RECORDS_INVALID')
    grouped={};errors=[];seen=set();statuses=Counter()
    for action in records['actions']:
        if action['kind']!='compile':continue
        try:
            context=derive(action);cid=context['contextIdentity'];source=context['sourcePath']
            if not source:raise ValueError('ACTIVATION_SOURCE_PATH_REQUIRED')
            if cid in seen:raise ValueError('ACTIVATION_DUPLICATE_CONTEXT')
            seen.add(cid)
            grouped.setdefault(source,[]).append(cid)
            statuses['context_ready' if context['inspectionReady'] else 'blocked']+=1
        except (OSError,ValueError,KeyError,TypeError) as exc:
            errors.append({'actionIdentity':action.get('actionIdentity'),'detail':str(exc)})
    batches=[];sources=sorted(grouped)
    for start in range(0,len(sources),batch_sources):
        selected=sources[start:start+batch_sources]
        batches.append({'purpose':'compiler-acquisition-pilot-only','sourcePaths':selected,
            'contextIdentities':[cid for source in selected for cid in grouped[source]],'semanticApproval':False})
    if not batches:errors.append({'actionIdentity':None,'detail':'ACTIVATION_NO_CAPTURED_COMPILE_CONTEXTS'})
    if digest(path)!=before or digest(compiler)!=compiler_digest:raise ValueError('ACTIVATION_BUILD_RECORDS_OR_TOOL_CHANGED')
    body={'schemaVersion':'riscv2x86.project-activation-batches.v1','recordsPath':str(path),
        'recordsDigest':before,'buildInventoryIdentity':records['inventoryIdentity'],
        'inspectionCompiler':str(compiler),'inspectionCompilerDigest':compiler_digest,'inspectionTarget':'riscv64',
        'batchSourceLimit':batch_sources,'selectionPolicy':'all-captured-compile-contexts-sorted-source-path',
        'sourceCount':len(sources),'contextCount':len(seen),'statusCounts':dict(statuses),
        'capturedCompileActionCount':sum(a['kind']=='compile' for a in records['actions']),
        'planningErrors':errors,'unresolvedBuildRecords':records.get('unresolved',[]),
        'batches':batches,'asmInstanceInventoryComplete':False,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,planIdentity=identity(body))


def validate_plan(path):
    value=read(path)
    if value.get('planIdentity')!=identity({k:v for k,v in value.items() if k!='planIdentity'}):
        raise ValueError('ACTIVATION_PLAN_IDENTITY_INVALID')
    if identity(make_plan(value['recordsPath'],value['batchSourceLimit'],clang=value['inspectionCompiler']))!=identity(value):
        raise ValueError('ACTIVATION_PLAN_REPLAY_MISMATCH')
    return value


def run_batch(plan_path,index,tooling,clang,output):
    plan=validate_plan(plan_path)
    if str(resolve_executable(clang))!=plan['inspectionCompiler']:raise ValueError('ACTIVATION_COMPILER_PLAN_MISMATCH')
    if plan['planningErrors'] or not plan['batches']:raise ValueError('ACTIVATION_PLAN_BLOCKED')
    if type(index) is not int or not 0<=index<len(plan['batches']):raise ValueError('ACTIVATION_BATCH_INDEX_INVALID')
    output=Path(output)
    if output.exists():raise FileExistsError(str(output))
    batch=dict(plan['batches'][index],parentPlanIdentity=plan['planIdentity'],batchIndex=index)
    batch_path=output.with_name(output.name+'.plan.json')
    write_new(batch_path,batch)
    return execute(tooling,plan['recordsPath'],batch_path,clang,output,asm_inventory=True)


def summarize(plan_path,result_root):
    plan=validate_plan(plan_path);root=Path(result_root);rows=[];occurrences=[]
    for index,batch in enumerate(plan['batches']):
        directory=root/f'batch-{index:04d}';status_path=directory/'run-status.json'
        row={'batchIndex':index,'sourceCount':len(batch['sourcePaths']),
            'contextCount':len(batch['contextIdentities']),'status':'not_run','blocker':None}
        if status_path.exists():
            try:
                state=read(status_path)
                if state.get('stateIdentity')!=identity({k:v for k,v in state.items() if k!='stateIdentity'}):
                    raise ValueError('ACTIVATION_RUN_STATE_INVALID')
                if state.get('status')!='complete':
                    row.update(status='blocked',blocker=state.get('primaryFailure') or {'stage':state.get('currentStage')})
                else:
                    for name,key in [('contexts.json','inspectionReportDigest'),('summary.json','inspectionSummaryDigest'),
                                     ('replay.log','replayLogDigest')]:
                        if digest(directory/name)!=state.get(key):raise ValueError('ACTIVATION_RUN_ARTIFACT_CHANGED:'+name)
                    expected_plan=dict(batch,parentPlanIdentity=plan['planIdentity'],batchIndex=index)
                    batch_path=directory.with_name(directory.name+'.plan.json')
                    if identity(read(batch_path))!=identity(expected_plan):raise ValueError('ACTIVATION_BATCH_BINDING_MISMATCH')
                    for path,expected in state['inputs'].items():
                        if digest(path)!=expected:raise ValueError('ACTIVATION_RUN_INPUT_CHANGED')
                    if (state.get('inputs',{}).get(str(batch_path.resolve()))!=digest(batch_path)
                            or state['inputs'].get(plan['recordsPath'])!=plan['recordsDigest']):
                        raise ValueError('ACTIVATION_RUN_INPUT_BINDING_MISMATCH')
                    if (state.get('compilerInspectionComplete') is not True
                            or state.get('independentContextReplayComplete') is not True
                            or state.get('acquisitionComplete') is not True
                            or state.get('semanticApproval') is not False
                            or state.get('productionAcceptanceComplete') is not False):
                        raise ValueError('ACTIVATION_RUN_INCOMPLETE')
                    report=read(directory/'contexts.json')
                    if report.get('selection',{}).get('asmInventory') is not True:raise ValueError('ACTIVATION_ASM_SCAN_REQUIRED')
                    summary=verify_members(report,batch)
                    if identity(summary)!=identity(read(directory/'summary.json')):raise ValueError('ACTIVATION_SUMMARY_CHANGED')
                    replay=read(directory/'replay.log')
                    if (replay.get('contextReplayComplete') is not True
                            or type(replay.get('buildVariantCount')) is not int
                            or replay['buildVariantCount']!=row['contextCount']
                            or replay.get('semanticApproval') is not False
                            or replay.get('productionAcceptanceComplete') is not False):
                        raise ValueError('ACTIVATION_REPLAY_RECORD_INCOMPLETE')
                    batch_occurrences=[]
                    for record in report['records']:
                        inventory=record['inspection']['snapshot']['asmActivationInventory']
                        if (inventory['compilerDigest']!=plan['inspectionCompilerDigest']
                                or inventory['target']!=plan['inspectionTarget']):
                            raise ValueError('ACTIVATION_RECORDED_COMPILER_MISMATCH')
                        for instance in inventory['instances']:
                            batch_occurrences.append({'contextIdentity':inventory['contextIdentity'],
                                'translationUnit':inventory['sourcePath'],
                                'sourceDigest':inventory['sourceDigest'],'compilerDigest':inventory['compilerDigest'],
                                'target':inventory['target'],
                                'dependencyIdentity':inventory['dependencyIdentity'],
                                'inventoryIdentity':inventory['inventoryIdentity'],
                                'batchIndex':index,'instance':instance,
                                'translationEvaluationStatus':'not_assessed'})
                    row.update(status='recorded_inspection_replayed',summary=summary)
                    occurrences.extend(batch_occurrences)
            except (OSError,ValueError,KeyError,TypeError) as exc:
                row.update(status='invalid',blocker={'type':type(exc).__name__,'detail':str(exc)})
        rows.append(row)
    counts=dict(Counter(r['status'] for r in rows))
    complete=(bool(rows) and all(r['status']=='recorded_inspection_replayed' for r in rows)
              and not plan['planningErrors'] and not plan['unresolvedBuildRecords'])
    body={'schemaVersion':'riscv2x86.project-activation-ledger.v1','planIdentity':plan['planIdentity'],
        'inspectionCompiler':plan['inspectionCompiler'],'inspectionCompilerDigest':plan['inspectionCompilerDigest'],
        'sourceCount':plan['sourceCount'],'contextCount':plan['contextCount'],
        'planningErrors':plan['planningErrors'],'unresolvedBuildRecords':plan['unresolvedBuildRecords'],
        'batchStatusCounts':counts,'batches':rows,'occurrences':occurrences,
        'inspectionAstAsmOccurrenceCount':len(occurrences),
        'recordedInspectionAstCoverageComplete':complete,'freshIndependentReplayPerformed':False,
        'nativeCompilerActivationConfirmed':False,'sourceInstanceBindingComplete':False,
        'asmInstanceInventoryComplete':False,'endToEndEligibilityAssessed':False,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,ledgerIdentity=identity(body))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    plan=sub.add_parser('plan');plan.add_argument('--records',required=True)
    plan.add_argument('--clang',required=True)
    plan.add_argument('--batch-sources',type=int,default=16);plan.add_argument('--output',required=True)
    run=sub.add_parser('run');run.add_argument('--plan',required=True);run.add_argument('--batch-index',type=int,required=True)
    for name in ('tooling','clang','output'):run.add_argument('--'+name,required=True)
    summary=sub.add_parser('summarize');summary.add_argument('--plan',required=True)
    summary.add_argument('--result-root',required=True);summary.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    try:
        if args.operation=='run':return run_batch(args.plan,args.batch_index,args.tooling,args.clang,args.output)
        result=(make_plan(args.records,args.batch_sources,clang=args.clang) if args.operation=='plan'
                else summarize(args.plan,args.result_root))
        write_new(args.output,result)
        print(json.dumps({k:v for k,v in result.items() if k in {'planIdentity','sourceCount','contextCount',
            'planningErrors','batchStatusCounts','inspectionAstAsmOccurrenceCount',
            'recordedInspectionAstCoverageComplete','semanticApproval','productionAcceptanceComplete'}}))
        return 2 if (result.get('planningErrors') or result.get('unresolvedBuildRecords')
                     or result.get('batchStatusCounts',{}).get('invalid')) else 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False}),file=sys.stderr)
        return 2
