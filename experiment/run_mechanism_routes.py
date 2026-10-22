#!/usr/bin/env python3
"""Prepare and execute reviewed local-sync / controlled-TIME production routes.

All subprocess status/logs are retained. Expected bootstrap needs_route is not
success: a source-bound compiler report must exist. Final runs require verified
L0/L1/L2 and the central provider audit. No shell exit/assertion is used.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.prepare_route_environment import prepare as prepare_environment
from riscv2x86_py.prepare_time_trace import prepare_contract,bind as bind_time
from riscv2x86_py.prepare_instruction_visibility_contract import prepare as prepare_sync
from riscv2x86_py.prepare_instruction_visibility import bind as bind_sync
from riscv2x86_py.csr_environment_contract import load_csr_environment_contract
from riscv2x86_py.mechanism_evidence import collect
from riscv2x86_py.mechanism_route_checks import checkpoints, require_consumed_approval, require_suite_preserved


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--frontend',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--architecture-template',type=Path,required=True)
    p.add_argument('--sync-source',type=Path);p.add_argument('--sync-declaration',type=Path)
    p.add_argument('--qemu-source',type=Path);p.add_argument('--qemu-build',type=Path)
    p.add_argument('--native-runner-json')
    p.add_argument('--time-source',type=Path);p.add_argument('--time-review',type=Path)
    p.add_argument('--time-backend',type=Path);p.add_argument('--time-runner-json')
    p.add_argument('--time-mode',choices=('controlled','native'),
        help='native has no registered strict backend; controlled requires explicit backend/review')
    p.add_argument('--stop-after',choices=('architecture','contracts','approval','complete'),default='complete',
        help='bounded checkpoints never count as completed production routes')
    p.add_argument('--source-compiler',default='riscv64-linux-gnu-gcc');p.add_argument('--target-compiler',default='gcc')
    p.add_argument('--suite',type=Path,help='optional full configured suite after selected routes pass')
    a=p.parse_args();repo=Path(__file__).resolve().parents[1];out=a.output.resolve()
    status={'schemaVersion':'riscv2x86.mechanism-production-run.v1','steps':[],
        'selectedRoutes':[],'completedRoutes':[],'blockers':[],'originalNativeTimeEquivalent':False,
        'stopAfter':a.stop_after,'preparedRoutes':[],'checkpoints':[],'currentStage':'input_validation',
        'productionAcceptanceComplete':False}
    def save(): (out/'run-status.json').write_text(json.dumps(status,indent=2)+'\n')
    owned=False
    try:
        if out.exists() and any(out.iterdir()):raise ValueError('OUTPUT_NOT_EMPTY')
        out.mkdir(parents=True,exist_ok=True);owned=True
        if not a.sync_source and not a.time_source:raise ValueError('NO_ROUTE_SELECTED')
        if a.suite and a.stop_after!='complete':raise ValueError('SUITE_REQUIRES_COMPLETE_PRODUCTION_RUN')
        if a.time_source and a.time_mode=='native' and a.stop_after!='architecture':
            raise ValueError('TIME_NATIVE_STRICT_BACKEND_UNAVAILABLE')
        if a.stop_after!='architecture':
            if a.sync_source and any(x is None for x in (a.sync_declaration,a.qemu_source,a.qemu_build,a.native_runner_json)):
                raise ValueError('SYNC_EXPLICIT_INPUTS_REQUIRED')
            if a.time_source and any(x is None for x in (a.time_review,a.time_backend,a.time_runner_json)):
                raise ValueError('TIME_EXPLICIT_INPUTS_REQUIRED')
        if a.suite:
            for selected in (a.sync_source,a.time_source):
                if selected is not None and selected.resolve().parent!=a.suite.resolve():
                    raise ValueError('SUITE_SELECTED_SOURCE_MUST_BE_DIRECT_CHILD')
        template=json.loads(a.architecture_template.read_text())
        from riscv2x86_py.csr_architecture_profile import validate_template
        validate_template(template)
        env=dict(os.environ);env['PYTHONPATH']=str(repo/'pytools')+os.pathsep+env.get('PYTHONPATH','')
        def run(name,command,allowed=(0,)):
            status['currentStage']=name
            step={'stage':name,'command':command};status['steps'].append(step);save()
            with (out/(name+'.log')).open('w') as log:
                try:step['returnCode']=subprocess.run(command,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=3600,check=False).returncode
                except (OSError,subprocess.TimeoutExpired) as exc:step.update(returnCode=None,detail=str(exc))
            save();print(name+': '+str(step['returnCode']),flush=True)
            if step['returnCode'] not in allowed:raise ValueError('STEP_FAILED:'+name)
        runtime_config=out/'contracts';profiles=runtime_config/'architecture';csr=runtime_config/'csr';sync=runtime_config/'sync';providers=runtime_config/'providers'
        for directory in (profiles,csr,sync,providers):directory.mkdir(parents=True)
        def batch(name,source,**directories):
            cmd=[sys.executable,'-m','riscv2x86_py.automatic_batch_cli','--input',str(source),
                '--frontend',str(a.frontend.resolve()),'--output-directory',str(out/name),'--jobs','1','--timeout-seconds','120']
            for key,value in directories.items():cmd+=['--'+key.replace('_','-'),str(value)]
            run(name,cmd,allowed=(0,1))
            return out/name
        def report_in(result):
            paths=list(result.glob('cases/*/work/translation-work/translated_report.json'))
            if len(paths)!=1:raise ValueError('BOOTSTRAP_TRANSLATION_REPORT_MISSING:'+str(result))
            return paths[0]
        def check_final(name,result):
            batch_result=json.loads((result/'batch-evaluation.json').read_text())
            if batch_result.get('statusCounts')!={'verified':1}:
                raise ValueError('ROUTE_NOT_VERIFIED:'+name)
            run(name+'-provider-audit',[sys.executable,'-m','riscv2x86_py.l2_provider_artifacts',
                '--batch',str(result/'batch-evaluation.json')])
            from riscv2x86_py.l2_evidence_reader import load_case_evaluation_result,read_l2_fragment_results
            cases=batch_result.get('cases',[])
            if len(cases)!=1:raise ValueError('ROUTE_EVALUATION_MISSING')
            if any(cases[0].get('programValidationLevels',{}).get(level)!='verified' for level in ('L0','L1','L2')):
                raise ValueError('ROUTE_PROGRAM_LEVELS_NOT_VERIFIED:'+name)
            typed=read_l2_fragment_results(load_case_evaluation_result(result,cases[0]))
            if not typed or any(not r.architectural_verified for _,r in typed):raise ValueError('ROUTE_TYPED_L2_NOT_VERIFIED')
        for name,source in (('sync',a.sync_source),('time',a.time_source)):
            if source is None:continue
            source=source.resolve();status['selectedRoutes'].append(name)
            prepared=out/(name+'-bootstrap-environment')
            prepare_environment(source=source,output=prepared,environment_id='explicit-mechanism-bootstrap',
                directories={},architecture=template)
            result=batch(name+'-bootstrap',source,experiment_environment=prepared/'environment.json')
            report=report_in(result);data=json.loads(report.read_text());findings=data['findings']
            if len(findings)!=1:raise ValueError('BOUNDED_ROUTE_REQUIRES_ONE_FRAGMENT')
            fid=findings[0]['fragment'].get('id') or findings[0]['fragment']['fragmentId']
            architecture=report.with_name('csr-architecture.materialized.json')
            (profiles/(source.name+'.csr-architecture.json')).write_bytes(architecture.read_bytes())
            status['currentStage']=name+'-static-checkpoint'
            checkpoint=checkpoints(source,report,family=name)
            (out/(name+'-static-checkpoint.json')).write_text(json.dumps(checkpoint,indent=2)+'\n')
            status['checkpoints'].append({'route':name,'stage':'architecture','path':name+'-static-checkpoint.json'})
            if a.stop_after=='architecture':
                status['preparedRoutes'].append(name);save();continue
            provider_output=out/(name+'-provider')
            status['currentStage']=name+'-contract-preparation';save()
            if name=='sync':
                if any(x is None for x in (a.sync_declaration,a.qemu_source,a.qemu_build,a.native_runner_json)):
                    raise ValueError('SYNC_EXPLICIT_INPUTS_REQUIRED')
                runner=json.loads(a.native_runner_json)
                evidence=collect(a.qemu_source,shutil.which(runner[0]) or runner[0],a.qemu_build)
                (out/'qemu-mechanism.json').write_text(json.dumps(evidence,indent=2)+'\n')
                raw=prepare_sync(source=source,report=report,fragment_id=fid,evidence=evidence,
                    declaration=json.loads(a.sync_declaration.read_text()),provider_output=provider_output,
                    source_compiler=a.source_compiler,target_compiler=a.target_compiler,source_runner=runner)
                (sync/(source.name+'.instruction-stream-sync.json')).write_text(json.dumps(raw,indent=2)+'\n')
                contract_path=sync/(source.name+'.instruction-stream-sync.json')
            else:
                if any(x is None for x in (a.time_review,a.time_backend,a.time_runner_json)):
                    raise ValueError('TIME_EXPLICIT_INPUTS_REQUIRED')
                runner=json.loads(a.time_runner_json)
                raw=prepare_contract(source=source,report=report,fragment_id=fid,
                    backend=json.loads(a.time_backend.read_text()),architecture=json.loads(architecture.read_text()),
                    review=json.loads(a.time_review.read_text()))
                path=csr/(source.name+'.csr-environment.json');path.write_text(json.dumps(raw,indent=2)+'\n')
                load_csr_environment_contract(path,source=source)
                contract_path=path
            status['checkpoints'].append({'route':name,'stage':'contracts','path':str(contract_path)})
            if a.stop_after=='contracts':
                status['preparedRoutes'].append(name);save();continue
            options={'csr_architecture_directory':profiles,'csr_environment_contract_directory':csr,'instruction_stream_sync_directory':sync}
            result=batch(name+'-approval',source,**options);approved=report_in(result)
            status['currentStage']=name+'-approval-consumption';save()
            consumed=require_consumed_approval(source,approved,fid,family=name,contract_path=contract_path)
            (out/(name+'-approval-consumption.json')).write_text(json.dumps(consumed,indent=2)+'\n')
            status['checkpoints'].append({'route':name,'stage':'approval','path':name+'-approval-consumption.json'})
            if a.stop_after=='approval':
                status['preparedRoutes'].append(name);save();continue
            status['currentStage']=name+'-provider-binding';save()
            if name=='sync':
                receipt=bind_sync(source=source,source_root=source.parent,report=approved,fragment_id=fid,
                    output=provider_output,execution_profile='rv64gc-user-to-x86_64-user',
                    source_compiler=a.source_compiler,target_compiler=a.target_compiler,source_runner=runner)
            else:
                receipt=bind_time(source=source,source_root=source.parent,report=approved,fragment_id=fid,
                    output=provider_output,source_compiler=a.source_compiler,target_compiler=a.target_compiler,
                    source_runner=runner,trajectory=[0,1,(1<<63)-1,1<<63,(1<<64)-1,0,7])
            (out/(name+'-binding.json')).write_text(json.dumps(receipt,indent=2)+'\n')
            provider=provider_output/'providers'/(source.name+'.l2-providers.json')
            (providers/provider.name).write_bytes(provider.read_bytes())
            result=batch(name+'-configured',source,l2_provider_directory=providers,**options)
            check_final(name,result)
            status['completedRoutes'].append(name);save()
        if a.suite:
            baseline=batch('full-strict-suite',a.suite.resolve())
            configured=batch('full-configured-suite',a.suite.resolve(),csr_architecture_directory=profiles,
                csr_environment_contract_directory=csr,instruction_stream_sync_directory=sync,l2_provider_directory=providers)
            run('full-configured-provider-audit',[sys.executable,'-m','riscv2x86_py.l2_provider_artifacts',
                '--batch',str(configured/'batch-evaluation.json')])
            status['currentStage']='suite-preservation';save()
            preservation=require_suite_preserved(baseline,configured,
                [s for s in (a.sync_source,a.time_source) if s is not None])
            (out/'suite-preservation.json').write_text(json.dumps(preservation,indent=2)+'\n')
        status['productionAcceptanceComplete']=(a.stop_after=='complete'
            and status['completedRoutes']==status['selectedRoutes'] and bool(status['selectedRoutes']))
        status['currentStage']='complete' if status['productionAcceptanceComplete'] else 'checkpoint_complete'
        save();return 0
    except (OSError,ValueError,TypeError,KeyError,IndexError,ImportError,AttributeError) as exc:
        if owned and out.is_dir():
            status['blockers'].append(str(exc));save()
        print(json.dumps({'failureStage':'mechanism_production_run','detail':str(exc),'output':str(out)}));return 2


if __name__=='__main__':raise SystemExit(main())
