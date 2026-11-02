#!/usr/bin/env python3
"""Same-code full-work/reuse comparison; every run retains production and fresh audit.

This driver measures the existing approved domain. It does not calibrate a backend,
reduce the sample plan, or replace any acceptance predicate with timing success.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import time
from riscv2x86_py.l3_trace_support import digest,require_json_match


def measurement(command,directory,env,timeout):
    started=time.perf_counter()
    with (directory/'stdout.log').open('w') as out,(directory/'stderr.log').open('w') as err:
        process=subprocess.Popen(command,stdout=out,stderr=err,env=env,start_new_session=True)
        try:code=process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # The driver launches producers/emulators: stop its whole process
            # group, not just the parent, before recording an incomplete run.
            try:os.killpg(process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait()
            code=None
    return {'command':command,'returnCode':code,'wallSeconds':time.perf_counter()-started,'timedOut':code is None}


def workload(group):
    """Diagnostic A/B equality after BOTH runs pass full independent audits.

    Absolute addresses, invocation tokens, PCs and generated file identities are
    run-specific. Exact original records remain archived and audited separately.
    """
    plan=group['deployment']['samplePlan'];program=group['deployment']['spec']
    samples={};events={}
    for side,report in group['reports'].items():
        samples[side]=[]
        for row in report['samples']:
            normalized={k:v for k,v in row.items() if k not in {'token','objectBase','planIdentity'}}
            if 'objects' in normalized:
                normalized['objects']=[{k:v for k,v in obj.items() if k!='base'} for obj in normalized['objects']]
            samples[side].append(normalized)
        events[side]=[{k:v for k,v in event.items() if k not in {'pc','address'}} for event in report['events']]
    return {'sampleInputs':plan['inputs'],'memberCount':len(program['members']),
            'samples':samples,'eventShapes':events}


def audited_workload(run):
    state=json.loads((run/'run-status.json').read_text())
    if (state.get('currentStage')!='complete' or state.get('blockers') or any(state.get(k) is not True for k in
        ('executionComplete','independentResultAuditComplete','productionAcceptanceComplete'))):
        raise ValueError('BENCHMARK_PRODUCTION_NOT_ACCEPTED')
    reports=list(run.glob('batch/cases/*/evaluation-result.json'))
    if len(reports)!=1:raise ValueError('BENCHMARK_SINGLE_EVALUATION_REQUIRED')
    report=json.loads(reports[0].read_text());groups=set()
    if report.get('status')!='verified' or not report.get('attempts'):raise ValueError('BENCHMARK_EVALUATION_NOT_VERIFIED')
    for attempt in report['attempts']:
        layers=attempt['validation']['layers']
        if [r['level'] for r in layers]!=['L0','L1','L2','L3'] or any(r['status']!='verified' for r in layers):
            raise ValueError('BENCHMARK_LAYERS_NOT_VERIFIED')
        groups.add(json.loads(layers[-1]['detail'])['jointCapturePath'])
    if len(groups)!=1:raise ValueError('BENCHMARK_CAPTURE_NOT_UNIQUE')
    return reports[0],workload(json.loads(Path(next(iter(groups))).read_text()))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('input','frontend','backend','output'):p.add_argument('--'+flag)
    p.add_argument('--repeats',type=int,default=1)
    p.add_argument('--wall-timeout-seconds',type=int,default=7200)
    p.add_argument('--timeout-seconds',type=int,default=240)
    p.add_argument('--l3-producer-timeout-seconds',type=int,default=600)
    p.add_argument('--audit-report',help=argparse.SUPPRESS);a=p.parse_args()
    if a.audit_report:
        from riscv2x86_py.l3_production_acceptance import audit_evaluation
        audit=audit_evaluation(json.loads(Path(a.audit_report).read_text()))
        print(json.dumps(audit,ensure_ascii=False,indent=2))
        return 0 if audit.get('status')=='verified' and audit.get('programExecutionUnitCount')==1 else 1
    if not all((a.input,a.frontend,a.backend,a.output)) or a.repeats<1 or min(a.wall_timeout_seconds,a.timeout_seconds,a.l3_producer_timeout_seconds)<=0:
        p.error('input/frontend/backend/output and positive bounds required')
    out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=False)
    paths={key:str(Path(getattr(a,key)).resolve()) for key in ('input','frontend','backend')}
    original={path:digest(path) for path in paths.values()};repo=Path(__file__).resolve().parents[1]
    head=subprocess.run(['git','rev-parse','HEAD'],cwd=repo,capture_output=True,text=True,check=False).stdout.strip()
    summary={'schemaVersion':'riscv2x86.joint-performance-comparison.v1','head':head,'inputDigests':original,
        'runs':[],'complete':False,'semanticApproval':False,'note':'Wall times include production/audits. Timing never grants acceptance.'}
    reference=None
    try:
        for repeat in range(a.repeats):
            # Alternate order to reduce fixed cold-cache/order bias.
            for mode in (('0','1') if repeat%2==0 else ('1','0')):
                root=out/('repeat-'+str(repeat)+'-reuse-'+mode);root.mkdir()
                env=dict(os.environ,RV2X86_JOINT_OPERATION_REUSE=mode,RV2X86_VALIDATION_TIMING=str(root/'production-timing.jsonl'))
                if any(digest(path)!=sha for path,sha in original.items()):raise ValueError('BENCHMARK_INPUT_CHANGED')
                command=[sys.executable,str(repo/'experiment/run_l3_joint_trace.py'),'--input',paths['input'],
                    '--frontend',paths['frontend'],'--backend',paths['backend'],'--output',str(root/'production'),
                    '--timeout-seconds',str(a.timeout_seconds),'--l3-producer-timeout-seconds',str(a.l3_producer_timeout_seconds)]
                row={'repeat':repeat,'reuse':mode,'directory':str(root)};summary['runs'].append(row)
                row['production']=measurement(command,root,env,a.wall_timeout_seconds)
                if row['production']['returnCode']!=0:raise ValueError('BENCHMARK_PRODUCTION_FAILED:'+str(root))
                report,actual=audited_workload(root/'production')
                if reference is None:reference=actual
                else:require_json_match(reference,actual,'BENCHMARK_WORKLOAD_OR_OUTPUT_CHANGED')
                audit_root=root/'standalone-audit';audit_root.mkdir()
                env['RV2X86_VALIDATION_TIMING']=str(root/'audit-timing.jsonl')
                row['standaloneAudit']=measurement([sys.executable,str(Path(__file__).resolve()),'--audit-report',str(report)],audit_root,env,a.wall_timeout_seconds)
                if row['standaloneAudit']['returnCode']!=0:raise ValueError('BENCHMARK_STANDALONE_AUDIT_FAILED:'+str(root))
                if any(digest(path)!=sha for path,sha in original.items()):raise ValueError('BENCHMARK_INPUT_CHANGED')
                row.update(accepted=True,sampleCount=len(actual['samples']['source']),memberCount=actual['memberCount'],
                    sourceEventCount=len(actual['eventShapes']['source']),targetEventCount=len(actual['eventShapes']['target']))
                print(json.dumps(row,ensure_ascii=False),flush=True)
        summary['complete']=True;summary['medians']={}
        for key in ('production','standaloneAudit'):
            times={mode:statistics.median(r[key]['wallSeconds'] for r in summary['runs'] if r['reuse']==mode) for mode in ('0','1')}
            summary['medians'][key]={'fullWorkSeconds':times['0'],'reuseSeconds':times['1'],'speedup':times['0']/times['1']}
    except (OSError,ValueError,KeyError,TypeError) as exc:
        summary['error']=type(exc).__name__+': '+str(exc);print(summary['error'],file=sys.stderr)
    finally:(out/'comparison.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
    return 0 if summary['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
