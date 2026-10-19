#!/usr/bin/env python3
"""Collect exact blocked-route sources, reports and tool identities read-only.

This is diagnostic evidence, never a platform guarantee or semantic approval.
Existing outputs are never overwritten. No environment variables are exported.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import zipfile


def digest(data):return 'sha256:'+sha256(data).hexdigest()


def collect(results,output):
    results=Path(results).resolve();output=Path(output)
    if output.exists():raise ValueError('OUTPUT_EXISTS')
    root=results/'generated-suite-strict';inventory=results/'generated-suite-strict-inventory'
    batch=json.loads((root/'batch-evaluation.json').read_text())
    files={};cases=[]
    for path in sorted((root/'cases').glob('*/evaluation-result.json')):
        case=json.loads(path.read_text());case_id=path.parent.name
        if case.get('status')=='verified':continue
        prefix='cases/'+case_id+'/'
        files[prefix+'evaluation-result.json']=path.read_bytes()
        resolution=inventory/'cases'/case_id/'contract-resolution.json'
        if resolution.is_file():files[prefix+'contract-resolution.json']=resolution.read_bytes()
        source_paths=set()
        for command in case.get('commands',[]):
            argv=command.get('command',[])
            if command.get('phase')=='translation' and '--source' in argv:
                source_paths.add(Path(argv[argv.index('--source')+1]))
        if len(source_paths)!=1:raise ValueError('SOURCE_COMMAND_AMBIGUOUS:'+case_id)
        source=source_paths.pop();data=source.read_bytes()
        if resolution.is_file() and json.loads(resolution.read_text()).get('sourceDigest')!=digest(data):
            raise ValueError('SOURCE_CHANGED_SINCE_RUN:'+case_id)
        files[prefix+'source.c']=data
        work=path.parent/'work'/'translation-work'
        for name in ('raw_report.json','translated_report.json','frontend.stderr','compiler-fragment-joins.json',
                     'csr-architecture.materialized.json'):
            artifact=work/name
            if artifact.is_file():files[prefix+name]=artifact.read_bytes()
        cases.append({'caseId':case_id,'status':case.get('status'),'sourcePath':str(source),
            'sourceDigest':digest(data)})
    tools={}
    for tool in ('clang','gcc','riscv64-linux-gnu-gcc','qemu-riscv64','llvm-mc'):
        executable=shutil.which(tool)
        if executable is None:tools[tool]={'disposition':'unavailable'};continue
        data=Path(executable).read_bytes()
        try:
            result=subprocess.run([executable,'--version'],capture_output=True,text=True,timeout=10,check=False)
            version={'returnCode':result.returncode,'stdout':result.stdout[:8000],'stderr':result.stderr[:8000]}
        except (OSError,subprocess.TimeoutExpired) as exc:version={'exceptionType':type(exc).__name__,'detail':str(exc)}
        tools[tool]={'path':str(Path(executable).resolve()),'digest':digest(data),'version':version}
    manifest={'schemaVersion':'riscv2x86.route-evidence-bundle.v1','batchIdentity':batch.get('batchIdentity'),
        'cases':cases,'tools':tools,'semanticApproval':False,
        'files':{name:digest(data) for name,data in files.items()}}
    files['manifest.json']=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode()
    # Exclusive create; an error leaves a clearly unsuccessful archive rather
    # than changing any experiment input or evaluation result.
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in files.items():archive.writestr(name,data)
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        value=collect(args.results,args.output)
        print(json.dumps({'artifactPath':str(args.output),'caseCount':len(value['cases']),'semanticApproval':False}));return 0
    except (OSError,ValueError,KeyError,IndexError,TypeError) as exc:
        print(json.dumps({'failureStage':'evidence_collection','exceptionType':type(exc).__name__,'detail':str(exc)}));return 2


if __name__=='__main__':raise SystemExit(main())
