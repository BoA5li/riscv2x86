"""Reproducible, opt-in QEMU 7.2/API-v1 backend and actual capture calibration."""
import argparse
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4

from .l3_trace_support import Elf, digest, identity, run, save

SCHEMA = 'riscv2x86.qemu-fragment-trace-backend.v2'
LEGACY_SCHEMA = 'riscv2x86.qemu-fragment-trace-backend.v1'
REVIEWED_COMMIT = 'b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56'


def executable(name):
    path = Path(shutil.which(str(name)) or name).resolve()
    if not path.is_file(): raise ValueError('L3_TRACE_TOOL_MISSING:' + str(name))
    return str(path)


def compiler_files(cc):
    files = {cc: digest(cc)}
    for name in ('as', 'ld', 'cc1'):
        result = subprocess.run([cc, '-print-prog-name=' + name], capture_output=True, text=True, check=False)
        if result.returncode: raise ValueError('L3_TRACE_TOOLCHAIN_QUERY_FAILED:' + name)
        path = executable(result.stdout.strip()); files[path] = digest(path)
    return files


def parse_capture(text, *, token, target, region, calls):
    lines = text.splitlines()
    header = ['H', '1', token, target, format(region['start'], 'x'), format(region['end'], 'x')]
    if not lines or lines[0].split() != header: raise ValueError('L3_TRACE_CAPTURE_HEADER_INVALID')
    events = []; entered = 0; exited = 0; active = None; finished = False
    try:
        for line in lines[1:]:
            item = line.split()
            if finished or not item: raise ValueError('record after footer or empty record')
            if item[0] == 'B' and len(item) == 3:
                if active is not None or int(item[1]) != entered or int(item[2],16) != region['start']:
                    raise ValueError('entry order')
                active = entered; entered += 1
            elif item[0] == 'E' and len(item) == 3:
                if active != exited or int(item[1]) != exited or int(item[2],16) != region['end']:
                    raise ValueError('exit order')
                active = None; exited += 1
            elif item[0] == 'M' and len(item) == 7:
                seq, sample = int(item[1]), int(item[2]); pc, address = int(item[3],16), int(item[4],16)
                width = int(item[5])
                if (active is None or sample != active or seq != len(events) or
                        not region['start'] <= pc < region['end'] or address < 0 or
                        width not in (1,2,4,8,16,32,64) or item[6] not in ('R','W')):
                    raise ValueError('memory record')
                events.append({'sample':sample,'pc':pc,'address':address,'size':width,
                               'access':'read' if item[6]=='R' else 'write'})
            elif item[0] == 'F' and len(item) == 5:
                if active is not None or list(map(int,item[1:])) != [entered,exited,len(events),0]:
                    raise ValueError('footer incomplete')
                finished = True
            else: raise ValueError('unknown record')
        if not finished or entered != calls or exited != calls: raise ValueError('capture incomplete')
    except (ValueError, IndexError) as exc:
        raise ValueError('L3_TRACE_CAPTURE_INCOMPLETE:' + str(exc)) from exc
    return events


def capture(backend, side, binary, region, directory, calls, timeout=120, *, calibration=False):
    validate_backend(backend, allow_uncalibrated=calibration)
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    token = uuid4().hex + uuid4().hex
    trace = directory / 'guest-trace.log'
    # Commas are delimiters in the QEMU plugin CLI, so refuse ambiguous paths.
    for path in (backend['plugin'], trace):
        if ',' in str(path): raise ValueError('L3_TRACE_PLUGIN_PATH_HAS_COMMA')
    option = ','.join([backend['plugin'], 'start='+hex(region['start']), 'end='+hex(region['end']),
                       'limit=4096', 'output='+str(trace.resolve()), 'token='+token])
    args = backend[side+'RunnerArguments']
    binary_digest = digest(binary)
    result = run([backend[side+'Executor'], *args, '-plugin', option, str(binary), token], directory, 'execute', timeout)
    validate_backend(backend, allow_uncalibrated=calibration)
    if digest(binary) != binary_digest: raise ValueError('L3_TRACE_EXECUTABLE_CHANGED')
    events = parse_capture(trace.read_text(), token=token,
        target='riscv64' if side=='source' else 'x86_64', region=region, calls=calls)
    return events, result.stdout, {'token':token,'rawTracePath':str(trace),'rawTraceDigest':digest(trace),
                                 'commandRecordDigest':digest(directory/'execute.command.json')}


def validate_backend(value, *, allow_uncalibrated=False):
    if isinstance(value, (str,Path)): value = json.loads(Path(value).read_text())
    fields = {'schemaVersion','sourceCommit','sourceExecutor','targetExecutor','plugin',
              'sourceCompiler','targetCompiler','sourceRunnerArguments','targetRunnerArguments',
              'files','calibration','scope','backendIdentity','sourcePreparation'}
    if isinstance(value,dict) and value.get('schemaVersion')==LEGACY_SCHEMA:
        raise ValueError('L3_TRACE_BACKEND_LEGACY_PREPARATION_MISSING')
    if not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA:
        raise ValueError('L3_TRACE_BACKEND_SCHEMA_INVALID')
    if value['backendIdentity'] != identity({k:v for k,v in value.items() if k!='backendIdentity'}):
        raise ValueError('L3_TRACE_BACKEND_IDENTITY_INVALID')
    if value['sourceCommit']!=REVIEWED_COMMIT: raise ValueError('L3_TRACE_QEMU_COMMIT_UNREVIEWED')
    if value['scope']!='single-thread-successful-compiler-asm-region-memory-stream':
        raise ValueError('L3_TRACE_BACKEND_SCOPE_INVALID')
    if not isinstance(value['files'],dict) or not value['files']: raise ValueError('L3_TRACE_BACKEND_FILES_MISSING')
    required = [value[k] for k in ('sourceExecutor','targetExecutor','plugin','sourceCompiler','targetCompiler')]
    if not set(required) <= set(value['files']): raise ValueError('L3_TRACE_BACKEND_BINDING_MISSING')
    for path, expected in value['files'].items():
        if digest(path)!=expected: raise ValueError('L3_TRACE_BACKEND_FILE_CHANGED:'+path)
    for side in ('source','target'):
        args=value[side+'RunnerArguments']
        if not isinstance(args,list) or (args and (len(args)!=2 or args[0]!='-L' or not Path(args[1]).is_dir())):
            raise ValueError('L3_TRACE_RUNNER_ARGUMENTS_INVALID')
    for side in ('source','target'):
        for path, expected in compiler_files(value[side+'Compiler']).items():
            if value['files'].get(path)!=expected: raise ValueError('L3_TRACE_TOOLCHAIN_SELECTION_CHANGED')
    _validate_source_preparation(value)
    calibration=value['calibration']
    if not isinstance(calibration,list) or len(calibration) not in ((0,4) if allow_uncalibrated else (4,)): raise ValueError('L3_TRACE_CALIBRATION_INVALID')
    if calibration:
        if {(x['side'],x['access']) for x in calibration}!={(s,a) for s in ('source','target') for a in ('read','write')}:
            raise ValueError('L3_TRACE_CALIBRATION_COVERAGE_INVALID')
        for record in calibration:
            if record['status']!='verified' or digest(record['recordPath'])!=record['recordDigest']:
                raise ValueError('L3_TRACE_CALIBRATION_STALE')
            witness=json.loads(Path(record['recordPath']).read_text())
            binary=Path(record['recordPath']).parent/'probe'
            elf=Elf(binary)
            region={'start':elf.symbol('__rv2x86_fragment_begin')[0],
                    'end':elf.symbol('__rv2x86_fragment_end')[0]}
            trace=Path(witness['rawTracePath'])
            command_path=trace.with_name('execute.command.json')
            if (digest(binary)!=witness['binaryDigest'] or digest(trace)!=witness['rawTraceDigest'] or
                    digest(command_path)!=witness['commandRecordDigest']):
                raise ValueError('L3_TRACE_CALIBRATION_ARTIFACT_CHANGED')
            events=parse_capture(trace.read_text(),token=witness['token'],
                target='riscv64' if record['side']=='source' else 'x86_64',region=region,calls=1)
            if (len(events)!=1 or events[0]!=witness['event'] or
                    events[0]['address']!=elf.symbol('data')[0] or events[0]['size']!=8 or
                    events[0]['access']!=record['access']):
                raise ValueError('L3_TRACE_CALIBRATION_REPLAY_MISMATCH')
            command=json.loads(command_path.read_text())
            option=','.join([value['plugin'],'start='+hex(region['start']),'end='+hex(region['end']),
                'limit=4096','output='+str(trace.resolve()),'token='+witness['token']])
            if (command['command']!=[value[record['side']+'Executor'],*value[record['side']+'RunnerArguments'],
                    '-plugin',option,str(binary),witness['token']] or command['returnCode']!=0 or
                    command['timedOut'] is not False or command['stderr'] or command['stdout']):
                raise ValueError('L3_TRACE_CALIBRATION_EXECUTION_INVALID')

    return value


def _validate_source_preparation(backend):
    from .l3_qemu_dependencies import verify_prepared_dependencies, validate_build_configuration
    binding=backend['sourcePreparation']
    if not isinstance(binding,dict) or set(binding)!={'recordPath','recordDigest','preparationIdentity','configuration'}:
        raise ValueError('L3_TRACE_BACKEND_SOURCE_PREPARATION_BINDING_INVALID')
    if backend['files'].get(binding['recordPath'])!=binding['recordDigest'] or digest(binding['recordPath'])!=binding['recordDigest']:
        raise ValueError('L3_TRACE_BACKEND_SOURCE_PREPARATION_CHANGED')
    record=json.loads(Path(binding['recordPath']).read_text())
    verify_prepared_dependencies(record,expected_commit=backend['sourceCommit'])
    if record['qemuCommit']!=backend['sourceCommit'] or record['preparationIdentity']!=binding['preparationIdentity']:
        raise ValueError('L3_TRACE_BACKEND_SOURCE_PREPARATION_IDENTITY_MISMATCH')
    configuration=binding['configuration']
    build=Path(configuration['configPath']).parent
    if validate_build_configuration(build,record['requirements'],prepared_source=record['preparedSourcePath'])!=configuration:
        raise ValueError('L3_TRACE_BACKEND_BUILD_CONFIGURATION_CHANGED')
    expected=Path(record['preparedSourcePath']).parent/'build'
    if build.resolve()!=expected.resolve():
        raise ValueError('L3_TRACE_BACKEND_BUILD_SOURCE_LOCATION_MISMATCH')
    for side,name in (('source','qemu-riscv64'),('target','qemu-x86_64')):
        if Path(backend[side+'Executor']).resolve()!=(build/name).resolve():
            raise ValueError('L3_TRACE_BACKEND_EXECUTOR_BUILD_LOCATION_MISMATCH')
    expected_command=[str(Path(record['preparedSourcePath'])/'configure'),
        '--target-list=riscv64-linux-user,x86_64-linux-user','--disable-system','--enable-plugins',
        '--with-git-submodules=validate','--meson=git','--enable-tcg','--cc='+backend['targetCompiler']]
    for name in ('config-host.mak','config.status','meson-info/intro-buildoptions.json','configure.command.json','compile.command.json'):
        path=str(build/name)
        if backend['files'].get(path)!=digest(path):
            raise ValueError('L3_TRACE_BACKEND_CONFIGURATION_BINDING_MISSING:'+name)
    configured=json.loads((build/'configure.command.json').read_text())
    compiled=json.loads((build/'compile.command.json').read_text())
    if (configured['command']!=expected_command or configured['returnCode']!=0 or
            configured['timedOut'] is not False or configured.get('gitNetworkPolicy')!='file' or
            compiled['returnCode']!=0 or compiled['timedOut'] is not False or
            compiled.get('gitNetworkPolicy')!='file' or len(compiled['command'])!=2 or
            compiled['command'][0]!='make' or not re.fullmatch(r'-j[1-9][0-9]*',compiled['command'][1])):
        raise ValueError('L3_TRACE_BACKEND_CONFIGURATION_COMMAND_MISMATCH')
    return record


def prepare(source, output, jobs, source_compiler, target_compiler, source_sysroot):
    source=Path(source).resolve(); output=Path(output).resolve()
    if output.exists(): raise ValueError('L3_TRACE_BACKEND_OUTPUT_EXISTS')
    output.mkdir(parents=True)
    status={'schemaVersion':'riscv2x86.trace-backend-build-status.v1','currentStage':'source','complete':False,'semanticApproval':False}
    def stage(name):
        status['currentStage']=name
        (output/'build-status.json').write_text(json.dumps(status,indent=2))
    stage('source')
    try:
        if not Path(source_sysroot).is_dir(): raise ValueError('L3_TRACE_SOURCE_SYSROOT_MISSING')
        if (source/'VERSION').read_text().strip()!='7.2.0': raise ValueError('L3_TRACE_QEMU_VERSION_UNREVIEWED')
        dirty=run(['git','-C',source,'status','--porcelain','--untracked-files=no','--ignore-submodules=all'], output,'source-status')
        if dirty.stdout.strip(): raise ValueError('L3_TRACE_QEMU_SOURCE_DIRTY')
        commit=run(['git','-C',source,'rev-parse','HEAD'],output,'source-commit').stdout.strip()
        if commit!=REVIEWED_COMMIT: raise ValueError('L3_TRACE_QEMU_COMMIT_UNREVIEWED')
        cc=executable(source_compiler); native=executable(target_compiler)
        tools={**compiler_files(cc),**compiler_files(native)}
        from .l3_qemu_dependencies import prepare_source, verify_prepared_dependencies, validate_build_configuration, _offline_env
        tree=output/'source'; prep_dir=output/'dependency-preparation'
        preparation=prepare_source(source,tree,prep_dir,commit=commit,stage=stage)
        prep_path=prep_dir/'source-preparation.json'
        stage('configure'); build=output/'build'; build.mkdir()
        run([tree/'configure','--target-list=riscv64-linux-user,x86_64-linux-user','--disable-system','--enable-plugins',
             '--with-git-submodules=validate','--meson=git','--enable-tcg','--cc='+native],build,'configure',1200,env=_offline_env())
        stage('configuration_validation')
        configuration=validate_build_configuration(build,preparation['requirements'],prepared_source=tree)
        verify_prepared_dependencies(preparation,expected_commit=commit)
        stage('compile'); run(['make','-j'+str(jobs)],build,'compile',7200,env=_offline_env())
        verify_prepared_dependencies(preparation,expected_commit=commit)
        source_preparation={'recordPath':str(prep_path),'recordDigest':digest(prep_path),
                            'preparationIdentity':preparation['preparationIdentity'],'configuration':configuration}
        plugin_source=Path(__file__).resolve().parents[2]/'runtime/l3_qemu_trace.c'
        stage('plugin'); plugin=output/'l3-trace.so'
        run([native,'-std=gnu11','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror','-I'+str(tree/'include'),plugin_source,'-o',plugin],output,'plugin')
        files={**tools,str(prep_path):digest(prep_path),str(Path(__file__).resolve()):digest(__file__),
               str(Path(__file__).with_name('l3_qemu_dependencies.py').resolve()):digest(Path(__file__).with_name('l3_qemu_dependencies.py')),
               preparation['gitTool']['path']:preparation['gitTool']['digest'],str(plugin):digest(plugin),str(plugin_source):digest(plugin_source),
               str(tree/'include/qemu/qemu-plugin.h'):digest(tree/'include/qemu/qemu-plugin.h')}
        for config in (build/'config-host.mak',build/'config.status',build/'meson-info/intro-buildoptions.json',
                       build/'configure.command.json',build/'compile.command.json'):
            files[str(config)]=digest(config)
        executors={side:str((build/('qemu-riscv64' if side=='source' else 'qemu-x86_64')).resolve()) for side in ('source','target')}
        for side,path in executors.items():
            files[path]=digest(path)
            version=run([path,'--version'],output,side+'-version')
            if 'version 7.2.0' not in version.stdout: raise ValueError('L3_TRACE_EXECUTOR_VERSION_INVALID')
        value={'schemaVersion':SCHEMA,'sourceCommit':commit,'sourceExecutor':executors['source'],
            'targetExecutor':executors['target'],'plugin':str(plugin),'sourceCompiler':cc,'targetCompiler':native,
            'sourceRunnerArguments':['-L',str(Path(source_sysroot).resolve())], 'targetRunnerArguments':[],
            'sourcePreparation':source_preparation,'files':files,'calibration':[],'scope':'single-thread-successful-compiler-asm-region-memory-stream'}
        value['backendIdentity']=identity(value)
        stage('calibration'); calibrations=[]
        for side in ('source','target'):
            for access in ('read','write'):
                directory=output/'calibration'/side/access; directory.mkdir(parents=True)
                if side=='source':
                    memory='ld a1,0(a0)' if access=='read' else 'sd a1,0(a0)'
                    assembly='.text\n.globl _start\n_start:\n la a0,data\n li a1,7\n.globl __rv2x86_fragment_begin\n__rv2x86_fragment_begin:\n '+memory+'\n.globl __rv2x86_fragment_end\n__rv2x86_fragment_end:\n li a0,0\n li a7,93\n ecall\n.data\n.balign 8\ndata: .quad 1\n'
                    flags=['-march=rv64gc','-mabi=lp64d','-Wl,--no-relax']; compiler=cc
                else:
                    memory='movq (%rax),%rdi' if access=='read' else 'movq %rdi,(%rax)'
                    assembly='.text\n.globl _start\n_start:\n leaq data(%rip),%rax\n movq $7,%rdi\n.globl __rv2x86_fragment_begin\n__rv2x86_fragment_begin:\n '+memory+'\n.globl __rv2x86_fragment_end\n__rv2x86_fragment_end:\n movq $60,%rax\n xorq %rdi,%rdi\n syscall\n.data\n.balign 8\ndata: .quad 1\n.section .note.GNU-stack,"",@progbits\n'
                    flags=[]; compiler=native
                asm=directory/'probe.S'; asm.write_text(assembly); binary=directory/'probe'
                run([compiler,*flags,'-nostdlib','-static','-no-pie',asm,'-o',binary],directory,'compile')
                elf=Elf(binary); first=elf.symbol('__rv2x86_fragment_begin')[0]; end=elf.symbol('__rv2x86_fragment_end')[0]
                events,stdout,raw=capture(value,side,binary,{'start':first,'end':end},directory/'capture',1,calibration=True)
                expected={'size':8,'access':access,'address':elf.symbol('data')[0]}
                if len(events)!=1 or any(events[0][k]!=v for k,v in expected.items()): raise ValueError('L3_TRACE_CALIBRATION_MISMATCH')
                witness={'status':'verified','side':side,'access':access,'binaryDigest':digest(binary),'event':events[0],**raw}
                record=save(directory/'calibration.json',witness)
                files[str(record)]=digest(record); files[str(binary)]=digest(binary)
                files[raw['rawTracePath']]=raw['rawTraceDigest']
                calibrations.append({'side':side,'access':access,'status':'verified','recordPath':str(record),'recordDigest':digest(record)})
                # Calibration is accumulated only after all four real probes pass.
                value['backendIdentity']=identity({k:v for k,v in value.items() if k!='backendIdentity'})
        value['calibration']=calibrations
        value['backendIdentity']=identity({k:v for k,v in value.items() if k!='backendIdentity'})
        stage('final_validation')
        validate_backend(value); save(output/'backend.json',value)
        status.update(complete=True,currentStage='complete',backendIdentity=value['backendIdentity']); stage('complete')
        return value
    except Exception as exc:
        status['blocker']=str(exc)
        if hasattr(exc,'failure'): status['failureDetail']=exc.failure
        stage(status['currentStage']); raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu-source',required=True); parser.add_argument('--output',required=True)
    parser.add_argument('--source-compiler',default='riscv64-linux-gnu-gcc'); parser.add_argument('--target-compiler',default='gcc')
    parser.add_argument('--source-sysroot',required=True); parser.add_argument('--jobs',type=int,default=2)
    args=parser.parse_args()
    try:
        if args.jobs<1: raise ValueError('L3_TRACE_BUILD_JOBS_INVALID')
        value=prepare(args.qemu_source,args.output,args.jobs,args.source_compiler,args.target_compiler,args.source_sysroot)
        print(json.dumps({'backendIdentity':value['backendIdentity'],'backendPath':str(Path(args.output).resolve()/'backend.json'),'semanticApproval':False}))
        return 0
    except Exception as exc:
        print(json.dumps({'failureStage':'l3-trace-backend','detail':str(exc)})); return 2


if __name__=='__main__':
    raise SystemExit(main())
