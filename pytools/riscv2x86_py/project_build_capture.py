"""Observe configured build tools without interpreting build-system shell text.

Started and finished records are separate, exclusive files. A missing finish is
unresolved, never a successful action. Receipts attest observation consistency,
not process-tree completeness, immutable dependencies, semantics or acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import struct
import sys
import time
import uuid

from .project_build_records import identity, record, document
from .project_compile_context import digest, ENV_KEYS, derive
from .project_compile_arguments import action_option
from .project_tool_resolution import resolve_executable

SCHEMA = 'riscv2x86.project-build-capture.v1'


def seal(body):
    return dict(body, recordIdentity=identity(body))


def check(value):
    if (not isinstance(value, dict) or value.get('recordIdentity') !=
            identity({k:v for k,v in value.items() if k!='recordIdentity'})):
        raise ValueError('PROJECT_CAPTURE_RECORD_IDENTITY_INVALID')
    return value


def write(path, body):
    """Atomic publication, no shared append log or replacement of old evidence."""
    path=Path(path);temporary=path.with_name('.'+path.name+'.'+uuid.uuid4().hex)
    payload=seal(body)
    try:
        with temporary.open('x',encoding='utf-8') as stream:
            json.dump(payload,stream,ensure_ascii=False,sort_keys=True);stream.write('\n')
            stream.flush();os.fsync(stream.fileno())
        os.link(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)
    return payload


def read(path):
    return check(json.loads(Path(path).read_text()))


def environment():
    return {k:os.environ.get(k,'') for k in ENV_KEYS}


def snapshot(paths):
    rows=[]
    for name in paths:
        lexical=Path(os.path.abspath(name));resolved=lexical.resolve(strict=True)
        if not resolved.is_file():raise ValueError('PROJECT_CAPTURE_INPUT_FILE_REQUIRED')
        rows.append({'path':str(lexical),'resolvedPath':str(resolved),'digest':digest(resolved)})
    if len({r['path'] for r in rows})!=len(rows):raise ValueError('PROJECT_CAPTURE_DUPLICATE_INPUT')
    return sorted(rows,key=lambda r:r['path'])


def create(directory,tools,*,inputs=()):
    directory=Path(directory).resolve()
    if not tools or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',k) for k in tools):
        raise ValueError('PROJECT_CAPTURE_TOOL_NAMES_INVALID')
    resolved={}
    for name,tool in tools.items():
        p=resolve_executable(tool)
        if not p.is_file() or not os.access(p,os.X_OK):raise ValueError('PROJECT_CAPTURE_EXECUTABLE_REQUIRED')
        resolved[name]={'path':str(p),'digest':digest(p)}
    driver=Path(__file__).resolve().parents[2]/'experiment/capture_project_build.py'
    if not driver.is_file():raise ValueError('PROJECT_CAPTURE_DRIVER_MISSING')
    input_rows=snapshot(inputs)
    directory.mkdir(parents=True,exist_ok=False)
    (directory/'invocations').mkdir();(directory/'runs').mkdir();(directory/'bin').mkdir()
    manifest={'schemaVersion':SCHEMA,'directory':str(directory),'tools':resolved,
        'driverPath':str(driver),'driverDigest':digest(driver),'modulePath':str(Path(__file__).resolve()),
        'moduleDigest':digest(__file__),'python':str(Path(sys.executable).resolve()),
        'pythonDigest':digest(sys.executable),'inputs':input_rows,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    config=directory/'capture.json'
    # Wrapper bytes are bound by the manifest as well as being auditable text.
    wrappers={}
    for name in tools:
        text='#!/bin/sh\nexec '+shlex.quote(manifest['python'])+' '+shlex.quote(str(driver))+\
            ' driver --capture '+shlex.quote(str(config))+' --tool '+shlex.quote(name)+' -- "$@"\n'
        path=directory/'bin'/name;path.write_text(text);path.chmod(0o755)
        wrappers[name]={'path':str(path),'digest':digest(path)}
    manifest['wrappers']=wrappers
    return write(config,manifest)


def load(path,*,inputs=True):
    config=Path(path).resolve(strict=True);value=read(config)
    fields={'schemaVersion','directory','tools','driverPath','driverDigest','modulePath','moduleDigest',
        'python','pythonDigest','inputs','wrappers','semanticApproval','productionAcceptanceComplete','recordIdentity'}
    if (set(value)!=fields or value['schemaVersion']!=SCHEMA
            or Path(value['directory'])!=config.parent or config.name!='capture.json'
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('PROJECT_CAPTURE_CONFIG_INVALID')
    for p,h in [('driverPath','driverDigest'),('modulePath','moduleDigest'),('python','pythonDigest')]:
        if digest(value[p])!=value[h]:raise ValueError('PROJECT_CAPTURE_IMPLEMENTATION_CHANGED:'+p)
    for item in [*value['tools'].values(),*value['wrappers'].values()]:
        if digest(item['path'])!=item['digest']:raise ValueError('PROJECT_CAPTURE_TOOL_CHANGED')
    if inputs and snapshot([r['path'] for r in value['inputs']])!=value['inputs']:
        raise ValueError('PROJECT_CAPTURE_CONFIGURATION_CHANGED')
    return value


def _output(argv,cwd):
    # Only an explicit, unambiguous -o is observed here. Do not guess default
    # outputs, archive members or linker-script semantics from basenames.
    values=[];args=argv[1:];i=0
    while i<len(args):
        try:option=action_option(args,i)
        except ValueError:return None
        if args[i] in {'-I','-D','-U','-include','-imacros','-isystem','-iquote','-isysroot'}:
            i+=2;continue
        if option is not None:
            if option[0]=='output':values.append(option[1])
            i+=option[2]
        else:i+=1
    if len(values)!=1 or values[0]=='-':return None
    p=Path(values[0]);p=p if p.is_absolute() else Path(cwd)/p
    try:
        result=snapshot([p])[0]
        with p.open('rb') as stream:header=stream.read(64)
        elf=None
        if len(header)>=52 and header[:4]==b'\x7fELF' and header[4] in (1,2) and header[5] in (1,2):
            order='<' if header[5]==1 else '>'
            elf={'classBits':32 if header[4]==1 else 64,'byteOrder':'little' if header[5]==1 else 'big',
                'type':struct.unpack(order+'H',header[16:18])[0],
                'machine':struct.unpack(order+'H',header[18:20])[0]}
        result['elfHeader']=elf
        return result
    except (OSError,ValueError):return None


def invoke(config,tool,args):
    value=load(config);selected=value['tools'].get(tool)
    if selected is None:raise ValueError('PROJECT_CAPTURE_TOOL_UNREGISTERED')
    argv=[selected['path'],*args];cwd=os.getcwd();token=uuid.uuid4().hex
    run_id=os.environ.get('RV2X86_PROJECT_CAPTURE_RUN','')
    if run_id:
        if re.fullmatch('[0-9a-f]{32}',run_id) is None:
            raise ValueError('PROJECT_CAPTURE_RUN_ID_INVALID')
        start=read(Path(value['directory'])/'runs'/(run_id+'.start.json'))
        if (start.get('captureIdentity')!=value['recordIdentity'] or start.get('runId')!=run_id
                or start.get('schemaVersion')!=SCHEMA+'.run-start'):
            raise ValueError('PROJECT_CAPTURE_RUN_MISMATCH')
        if snapshot([r['path'] for r in start['inputs']])!=start['inputs']:
            raise ValueError('PROJECT_CAPTURE_RUN_CONFIGURATION_CHANGED')
    action=record(argv,cwd,{'kind':'capture-start'})
    context=None;context_error=None
    if action['kind']=='compile':
        try:context=derive(action)
        except (OSError,ValueError) as exc:context_error=str(exc)
    started={'schemaVersion':SCHEMA+'.invocation-start','captureIdentity':value['recordIdentity'],
        'invocationId':token,'runId':run_id,'tool':tool,'arguments':argv,'directory':cwd,
        'environment':environment(),'contextAtStart':context,'contextError':context_error,
        'startedMonotonicNs':time.monotonic_ns()}
    path=Path(value['directory'])/'invocations'/token
    first=write(str(path)+'.start.json',started)
    error=None
    try:
        result=subprocess.run(argv,check=False)
        code=result.returncode
    except OSError as exc:
        code=127;error=type(exc).__name__+': '+str(exc)
    finished={'schemaVersion':SCHEMA+'.invocation-finish','captureIdentity':value['recordIdentity'],
        'invocationId':token,'startIdentity':first['recordIdentity'],'returnCode':code,
        'launchError':error,'output':_output(argv,cwd),'finishedMonotonicNs':time.monotonic_ns(),
        'toolDigestAfter':digest(selected['path'])}
    write(str(path)+'.finish.json',finished)
    if code<0:
        if -code not in {signal.SIGKILL,signal.SIGSTOP}:signal.signal(-code,signal.SIG_DFL)
        os.kill(os.getpid(),-code)
    return code


def run(config,stage,command,*,cwd,source_proof=None,inputs=()):
    value=load(config)
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}',stage) or not command:
        raise ValueError('PROJECT_CAPTURE_STAGE_OR_COMMAND_INVALID')
    release_identity=None
    if source_proof is not None:
        from .project_source_release import replay
        proof_path=Path(source_proof)
        if not proof_path.is_file():
            raise ValueError('PROJECT_CAPTURE_SOURCE_PROOF_REQUIRED:'+str(proof_path))
        source_proof=str(proof_path.resolve(strict=True));release_identity=replay(source_proof)
    cwd=str(Path(cwd).resolve(strict=True));token=uuid.uuid4().hex
    executable=resolve_executable(command[0],cwd)
    argv=[str(executable),*command[1:]]
    run_inputs=snapshot(inputs)
    first=write(Path(value['directory'])/'runs'/(token+'.start.json'),{
        'schemaVersion':SCHEMA+'.run-start','captureIdentity':value['recordIdentity'],
        'runId':token,'stage':stage,'command':argv,'directory':cwd,
        'executableDigest':digest(executable),'environment':environment(),
        'sourceProof':source_proof,'sourceReleaseIdentity':release_identity,'inputs':run_inputs})
    env=dict(os.environ,RV2X86_PROJECT_CAPTURE_RUN=token)
    try:
        code=subprocess.run(argv,cwd=cwd,env=env,check=False).returncode
    except OSError:
        code=127
    release_after=None;release_error=None
    if source_proof is not None:
        try:release_after=replay(source_proof)
        except (OSError,ValueError) as exc:release_error=str(exc)
    input_error=None
    try:
        inputs_after=snapshot([r['path'] for r in value['inputs']])
        run_inputs_after=snapshot([r['path'] for r in run_inputs])
    except (OSError,ValueError) as exc:inputs_after=None;run_inputs_after=None;input_error=str(exc)
    write(Path(value['directory'])/'runs'/(token+'.finish.json'),{
        'schemaVersion':SCHEMA+'.run-finish','captureIdentity':value['recordIdentity'],
        'runId':token,'startIdentity':first['recordIdentity'],'returnCode':code,
        'executableDigestAfter':digest(executable),'inputsAfter':inputs_after,'inputObservationError':input_error,
        'sourceReleaseIdentityAfter':release_after,'sourceReleaseError':release_error,'runInputsAfter':run_inputs_after})
    if (input_error is not None or inputs_after!=value['inputs'] or run_inputs_after!=run_inputs or release_error is not None
            or release_identity!=release_after):
        raise ValueError('PROJECT_CAPTURE_CLOSING_INPUTS_CHANGED:'+token)
    return token,code


def inventory(config,*,stage=None):
    value=load(config);root=Path(value['directory']);rows=[];unresolved=[];unselected=[];runs={};summaries=[]
    snapshots=[]
    for directory,idkey,prefix in [(root/'runs','runId','run'),(root/'invocations','invocationId','invocation')]:
        starts={p.name.removesuffix('.start.json'):p for p in directory.glob('*.start.json')}
        finishes={p.name.removesuffix('.finish.json'):p for p in directory.glob('*.finish.json')}
        for token in sorted(set(starts)|set(finishes)):
            try:
                if not re.fullmatch('[0-9a-f]{32}',token):raise ValueError('PROJECT_CAPTURE_FILENAME_INVALID')
                if token not in starts or token not in finishes:raise ValueError('PROJECT_CAPTURE_UNFINISHED_'+prefix.upper())
                a=read(starts[token]);b=read(finishes[token])
                if (a.get('schemaVersion')!=SCHEMA+'.'+prefix+'-start' or b.get('schemaVersion')!=SCHEMA+'.'+prefix+'-finish'
                        or a.get(idkey)!=token or b.get(idkey)!=token
                        or a.get('captureIdentity')!=value['recordIdentity'] or b.get('captureIdentity')!=value['recordIdentity']
                        or b.get('startIdentity')!=a['recordIdentity'] or type(b.get('returnCode')) is not int):
                    raise ValueError('PROJECT_CAPTURE_PAIR_INVALID')
                snapshots.extend([{'path':str(starts[token]),'digest':digest(starts[token])},
                                  {'path':str(finishes[token]),'digest':digest(finishes[token])}])
                if prefix=='run':
                    if (b.get('inputObservationError') is not None or a['executableDigest']!=b['executableDigestAfter'] or digest(a['command'][0])!=a['executableDigest']
                            or b['inputsAfter']!=value['inputs'] or b['runInputsAfter']!=a['inputs']
                            or snapshot([r['path'] for r in a['inputs']])!=a['inputs']):
                        raise ValueError('PROJECT_CAPTURE_RUN_INPUT_CHANGED')
                    if a['sourceProof'] is not None:
                        from .project_source_release import replay
                        if (b['sourceReleaseError'] is not None or a['sourceReleaseIdentity']!=b['sourceReleaseIdentityAfter']
                                or replay(a['sourceProof'])!=a['sourceReleaseIdentity']):
                            raise ValueError('PROJECT_CAPTURE_SOURCE_RELEASE_CHANGED')
                    runs[token]=a
                    summaries.append({'runId':token,'stage':a['stage'],'command':a['command'],
                        'directory':a['directory'],'returnCode':b['returnCode']})
                else:
                    selected=value['tools'].get(a['tool'])
                    if not selected or a['arguments'][0]!=selected['path'] or b['toolDigestAfter']!=selected['digest']:
                        raise ValueError('PROJECT_CAPTURE_TOOL_MISMATCH')
                    observed={k:a['contextAtStart'][k] for k in ('sourcePath','sourceDigest','nativeCompilerDigest',
                        'searchEnvironment')} if a['contextAtStart'] is not None else None
                    action=record(a['arguments'],a['directory'],{'kind':'compiler-exec-capture','configPath':str(Path(config).resolve()),
                        'captureIdentity':value['recordIdentity'],'invocationId':token,'stageSelection':stage})
                    action.pop('actionIdentity')
                    action.update(exitStatusObserved=True,observedReturnCode=b['returnCode'],
                        observedCompileInputs=observed,observedOutput=b['output'],captureRunId=a['runId'])
                    action['actionIdentity']=identity(action)
                    rid=a['runId']
                    if rid and rid not in runs:raise ValueError('PROJECT_CAPTURE_PARENT_RUN_UNRESOLVED')
                    if stage is not None and not rid:
                        raise ValueError('PROJECT_CAPTURE_STAGE_UNATTRIBUTED')
                    if stage is None or rid and runs[rid]['stage']==stage:rows.append(action)
                    else:unselected.append(action)
            except (OSError,ValueError,KeyError,TypeError) as exc:
                unresolved.append({'path':str(starts.get(token,finishes.get(token))),'reasonCode':str(exc)})
    selected_failures=[summary for summary in summaries
        if (stage is None or summary['stage']==stage) and summary['returnCode']!=0]
    if not rows:
        if not summaries:
            reason='PROJECT_CAPTURE_NO_COMPLETED_RUN'
        elif stage is not None and not any(r['stage']==stage for r in summaries):
            reason='PROJECT_CAPTURE_STAGE_NOT_RUN'
        else:
            reason='PROJECT_CAPTURE_NO_SELECTED_TOOL_INVOCATIONS'
        unresolved.append({'reasonCode':'PROJECT_CAPTURE_EMPTY_SELECTION','detailReasonCode':reason})
    body=document(rows,unresolved,[],identity(snapshots));body.pop('inventoryIdentity')
    body.update(captureConfig=str(Path(config).resolve()),captureIdentity=value['recordIdentity'],
        captureFiles=sorted(snapshots,key=lambda x:x['path']),stageSelection=stage,
        runRecords=summaries,unselectedActions=unselected,selectedRunFailures=selected_failures,
        observedFailureCount=sum(a['observedReturnCode']!=0 for a in rows),
        processTreeCompletenessVerified=False)
    return dict(body,inventoryIdentity=identity(body))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    c=sub.add_parser('create');c.add_argument('--output',required=True);c.add_argument('--tool',action='append',required=True)
    c.add_argument('--input',action='append',default=[])
    for name in ('run','driver'):
        p=sub.add_parser(name);p.add_argument('--capture',required=True)
        if name=='run':
            p.add_argument('--stage',required=True);p.add_argument('--cwd',required=True);p.add_argument('--source-proof')
            p.add_argument('--input',action='append',default=[])
        else:p.add_argument('--tool',required=True)
        p.add_argument('command',nargs=argparse.REMAINDER)
    i=sub.add_parser('import');i.add_argument('--capture',required=True);i.add_argument('--stage');i.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    try:
        if args.operation=='create':
            tools={}
            for spec in args.tool:
                key,sep,path=spec.partition('=')
                if not sep or key in tools:raise ValueError('PROJECT_CAPTURE_TOOL_SPEC_INVALID')
                tools[key]=path
            result=create(args.output,tools,inputs=args.input)
            print(json.dumps({'capture':str(Path(args.output).resolve()/'capture.json'),'wrappers':result['wrappers']}));return 0
        if args.operation=='import':
            result=inventory(args.capture,stage=args.stage)
            with Path(args.output).open('x') as out:json.dump(result,out,indent=2)
            print(json.dumps({k:result[k] for k in ('actionCounts','observedFailureCount','importComplete')}))
            return 0 if result['importComplete'] else 2
        command=args.command[1:] if args.command[:1]==['--'] else args.command
        if args.operation=='driver':return invoke(args.capture,args.tool,command)
        token,code=run(args.capture,args.stage,command,cwd=args.cwd,source_proof=args.source_proof,inputs=args.input)
        print(json.dumps({'runId':token,'returnCode':code,'semanticApproval':False,'productionAcceptanceComplete':False}),file=sys.stderr)
        return code if code>=0 else 128-code
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc)}),file=sys.stderr);return 2
