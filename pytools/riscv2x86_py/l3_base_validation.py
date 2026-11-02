"""Full v2 base validator with the same gates and optimized provenance walk.

The legacy pinned implementation remains present and is itself authenticated
by the existing backend file map. Joint wrappers pin this companion as well.
No backend record or semantic claim is upgraded or rewritten.
"""
import json
import re
from pathlib import Path
from .l3_qemu_backend import (SCHEMA,LEGACY_SCHEMA,REVIEWED_COMMIT,compiler_files,parse_capture)
from .l3_trace_support import digest,identity,Elf
from .validation_timing import timed
from .joint_performance import enabled


@timed('joint.base-backend-request')
def validate(value):
    if not enabled():
        return _legacy_full(value)
    from .joint_validation_operation import leaf_checked
    if isinstance(value,(str,Path)):
        request={'path':str(Path(value).resolve()),'digest':digest(value)}
    else:request={'document':value}
    return leaf_checked(_full,request)


@timed('joint.base-backend-full-validation')
def _full(request):
    if 'path' in request:
        if digest(request['path'])!=request['digest']:raise ValueError('L3_JOINT_BASE_BINDING_CHANGED')
        value=request['path']
    else:value=request['document']
    return validate_optimized(value)


@timed('joint.base-backend-full-validation')
def _legacy_full(value):
    from .l3_qemu_backend import validate_backend
    return validate_backend(value)


def validate_optimized(value, *, allow_uncalibrated=False):
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
    from .l3_dependency_validation import verify_prepared_dependencies, validate_build_configuration
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
