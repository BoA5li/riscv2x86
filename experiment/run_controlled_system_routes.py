#!/usr/bin/env python3
"""Real controlled M-mode ECALL / pre-pending-MTIP WFI production acceptance.

Fresh outputs, explicit backend, normal compiler/Phase-6/renderer pipeline,
actual kernel/native builds, L0/L1/L2 and the central provider audit are required.
No case number, function name or input path grants translation permission.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from riscv2x86_py.controlled_system_backend import validate_backend,executable
from riscv2x86_py.controlled_system_contract import prepare
from riscv2x86_py.controlled_system_runner import SCHEMA,DIMENSIONS,EXECUTION_PROFILE,observer_identity,load_config
from riscv2x86_py.system_instruction_ingress import digest
from riscv2x86_py.semantic_content import semantic_identity
from riscv2x86_py.mechanism_route_checks import compiler_bound_finding,require_suite_preserved
from run_mechanism_routes import report_in,require_disjoint_output


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',action='append',required=True,type=Path)
    p.add_argument('--frontend',required=True,type=Path);p.add_argument('--clang',required=True,type=Path)
    p.add_argument('--backend',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--suite',type=Path);p.add_argument('--existing-provider-directory',type=Path)
    for name in ('csr-architecture-directory','csr-environment-contract-directory','instruction-stream-sync-directory'):
        p.add_argument('--'+name,type=Path)
    a=p.parse_args();out=a.output.resolve();owned=False
    status={'schemaVersion':'riscv2x86.controlled-system-production-run.v1','currentStage':'input_validation',
        'steps':[],'blockers':[],'completedRoutes':[],'productionAcceptanceComplete':False,
        'sourceEnvironment':'explicit-controlled-m-mode','originalLinuxUserEquivalent':False,
        'claimBoundary':'single-system-instruction-trap-return-or-already-pending-mtip',
        'L3Equivalent':False,'productionAcceptance':[]}
    def save():(out/'run-status.json').write_text(json.dumps(status,indent=2)+'\n')
    try:
        if out.exists():raise ValueError('SYSTEM_RUN_OUTPUT_EXISTS')
        require_disjoint_output(out,a.source,a.suite)
        backend=validate_backend(a.backend);frontend=executable(a.frontend);clang=executable(a.clang)
        sources=[s.resolve() for s in a.source]
        if a.existing_provider_directory is not None and (a.suite is None or not a.existing_provider_directory.is_dir()):
            raise ValueError('SYSTEM_RUN_EXISTING_PROVIDERS_REQUIRE_SUITE_AND_DIRECTORY')
        if len(sources)!=len(set(sources)) or len({s.name for s in sources})!=len(sources):
            raise ValueError('SYSTEM_RUN_SOURCE_IDENTITIES_AMBIGUOUS')
        if a.suite and any(s.parent!=a.suite.resolve() for s in sources):
            raise ValueError('SYSTEM_RUN_SUITE_DIRECT_CHILD_REQUIRED')
        out.mkdir(parents=True);owned=True;save()
        configs=out/'contracts';providers=out/'providers';configs.mkdir();providers.mkdir()
        def run(name,command,allowed=(0,)):
            status['currentStage']=name;step={'stage':name,'command':command,'returnCode':None};status['steps'].append(step);save()
            with (out/(name+'.log')).open('w') as log:
                step['returnCode']=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=False,timeout=3600).returncode
            save();print(name+': '+str(step['returnCode']),flush=True)
            if step['returnCode'] not in allowed:raise ValueError('SYSTEM_RUN_STEP_FAILED:'+name)
        def batch(name,source,configured=False,additional=False):
            command=[sys.executable,'-m','riscv2x86_py.automatic_batch_cli','--input',str(source),
                '--frontend',frontend,'--output-directory',str(out/name),'--jobs','1','--timeout-seconds','600']
            if configured:command+=['--privileged-config-directory',str(configs),'--l2-provider-directory',str(providers)]
            if additional:
                for flag in ('csr_architecture_directory','csr_environment_contract_directory','instruction_stream_sync_directory'):
                    value=getattr(a,flag)
                    if value is not None:command+=['--'+flag.replace('_','-'),str(value.resolve())]
            run(name,command,(0,1));return out/name
        for index,source in enumerate(sources):
            tag='system-'+str(index)
            bootstrap=batch(tag+'-bootstrap',source)
            report=report_in(bootstrap);data=json.loads(report.read_text())
            if len(data['findings'])!=1:raise ValueError('SYSTEM_RUN_ONE_FRAGMENT_REQUIRED')
            fid=data['findings'][0]['fragment'].get('id') or data['findings'][0]['fragment']['fragmentId']
            status['currentStage']=tag+'-prepare';save()
            contract=prepare(source=source,report=report,fragment_id=fid,backend_path=a.backend,clang=clang,output=configs/source.name)
            env_path=Path(contract['environmentPath'])
            (configs/(source.name+'.privileged-environment.json')).symlink_to(env_path)
            approved=batch(tag+'-approval',source,True)
            approved_report=report_in(approved);finding,_=compiler_bound_finding(source,approved_report,fid)
            approval=finding.get('approvalArtifact') or {}
            if (approval.get('proofStatus')!='approved' or approval.get('systemOperation')!=contract['operation']
                    or not (approval.get('l2AuthoritySidecar') or {}).get('complete')):
                raise ValueError('SYSTEM_RUN_APPROVAL_OR_AUTHORITY_INCOMPLETE:'+json.dumps(finding.get('translationReasonCodes',[])))
            config={'schemaVersion':SCHEMA,'backendPath':str(a.backend.resolve()),'approvalPath':str(approved_report),
                'environmentPath':str(env_path),'sourcePath':str(source),'sourceDigest':digest(source.read_bytes()),
                'frontend':frontend,'frontendDigest':digest(Path(frontend).read_bytes()),'clang':clang,'clangDigest':digest(Path(clang).read_bytes()),
                'targetPath':'${TARGET_PATH}','scope':contract['scope'],'operation':contract['operation'],
                'observerIdentity':observer_identity(),'timeoutSeconds':600}
            load_config(config)
            provider={'providerId':'controlled-system:'+semantic_identity(config),'supportedDimensions':[d.value for d in DIMENSIONS],
                'supportedPatterns':['privileged_write'],'requiredCapabilities':['privileged_state_observation','shell_observation'],
                'executionProfiles':[EXECUTION_PROFILE],'bindingKind':'explicit','validatorType':'controlled-system-validation',
                'configSchemaVersion':SCHEMA,'config':config,'fragmentIds':[fid],'semanticProfileIds':[]}
            manifest={'schemaVersion':'riscv2x86.explicit-l2-providers.v2','sourceRelativePath':source.name,
                'sourceDigest':digest(source.read_bytes()),'environmentCapabilities':['privileged_state_observation','shell_observation'],'providers':[provider]}
            manifest['manifestIdentity']=semantic_identity(manifest)
            (providers/(source.name+'.l2-providers.json')).write_text(json.dumps(manifest,indent=2)+'\n')
            configured=batch(tag+'-configured',source,True)
            result=json.loads((configured/'batch-evaluation.json').read_text())
            if result.get('statusCounts')!={'verified':1}:raise ValueError('SYSTEM_RUN_PRODUCTION_NOT_VERIFIED')
            run(tag+'-provider-audit',[sys.executable,'-m','riscv2x86_py.l2_provider_artifacts','--batch',str(configured/'batch-evaluation.json')])
            case=result['cases'][0]
            if any(case.get('programValidationLevels',{}).get(level)!='verified' for level in ('L0','L1','L2')):
                raise ValueError('SYSTEM_RUN_PROGRAM_LEVELS_INCOMPLETE')
            acceptance={'operation':contract['operation'],'sourceDigest':config['sourceDigest'],'fragmentId':fid,
                'proofIdentity':approval['proofIdentity'],'backendIdentity':backend['backendIdentity'],
                'resultPath':str(configured/'batch-evaluation.json'),'programValidationLevels':case['programValidationLevels'],
                'centralAudit':'complete','environment':'controlled-m-mode','nativeLinuxUserEquivalent':False}
            status['productionAcceptance'].append(acceptance);status['completedRoutes'].append(contract['operation']);save()
        if a.suite:
            retained_sources=[]
            if a.existing_provider_directory:
                old_manifests=list(a.existing_provider_directory.rglob('*.l2-providers.json'))
                if not old_manifests:raise ValueError('SYSTEM_RUN_EXISTING_PROVIDERS_EMPTY')
                for file in old_manifests:
                    relative=file.relative_to(a.existing_provider_directory);dest=providers/relative
                    if dest.exists():raise ValueError('SYSTEM_RUN_PROVIDER_CONFLICT:'+str(relative))
                    old=json.loads(file.read_text());retained=(a.suite/old['sourceRelativePath']).resolve()
                    if not retained.is_relative_to(a.suite.resolve()) or digest(retained.read_bytes())!=old['sourceDigest']:
                        raise ValueError('SYSTEM_RUN_RETAINED_PROVIDER_SOURCE_MISMATCH')
                    retained_sources.append(retained)
                    dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file.resolve(),dest)
            baseline=batch('suite-baseline',a.suite)
            configured=batch('suite-configured',a.suite,True,True)
            run('suite-provider-audit',[sys.executable,'-m','riscv2x86_py.l2_provider_artifacts','--batch',str(configured/'batch-evaluation.json')])
            preservation=require_suite_preserved(baseline,configured,sources+retained_sources)
            preservation['retainedProviderSources']=[str(s) for s in retained_sources]
            (out/'suite-preservation.json').write_text(json.dumps(preservation,indent=2)+'\n')
        status['currentStage']='complete';status['productionAcceptanceComplete']=True;save();return 0
    except (OSError,ValueError,KeyError,TypeError,AttributeError,subprocess.SubprocessError) as exc:
        if owned:
            status['blockers'].append(str(exc))
            if getattr(exc,'diagnostic',None) is not None:status['failureDiagnostics']=exc.diagnostic
            save()
        print(json.dumps({'failureStage':'controlled_system_production','detail':str(exc),'output':str(out)}));return 2


if __name__=='__main__':raise SystemExit(main())
