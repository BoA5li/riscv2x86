"""Bounded prerequisite orchestration; command success is never acceptance.

Plans are explicit experiment inputs. Each stage has an exclusive output
directory, a dependency list and mandatory output files. A first failure stops
the remaining stages. Existing semantic validators remain the only authority.
"""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time

from .native_audit_evidence import strict_json
from .project_acquisition import publish
from .project_build_records import identity
from .project_compile_context import digest
from .project_tool_resolution import resolve_executable

SCHEMA = 'riscv2x86.native-experiment-plan.v1'
RESULT = 'riscv2x86.native-experiment-run.v1'


def read(path):
    return strict_json(Path(path).read_bytes())


def _relative(value):
    return (isinstance(value, str) and value and not Path(value).is_absolute()
            and '..' not in Path(value).parts and value not in ('.', ''))


def validate(plan):
    if (not isinstance(plan, dict) or set(plan) != {'schemaVersion', 'stages', 'planIdentity'}
            or plan['schemaVersion'] != SCHEMA
            or plan['planIdentity'] != identity({k: v for k, v in plan.items() if k != 'planIdentity'})
            or not isinstance(plan['stages'], list) or not plan['stages']):
        raise ValueError('NATIVE_EXPERIMENT_PLAN_INVALID')
    seen = set()
    for row in plan['stages']:
        if not isinstance(row, dict) or set(row) != {
                'id', 'dependsOn', 'command', 'directory', 'environment', 'inputs',
                'outputs', 'timeoutSeconds', 'maxLogBytes'}:
            raise ValueError('NATIVE_EXPERIMENT_STAGE_FIELDS_INVALID')
        name = row['id']
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                or name in seen):
            raise ValueError('NATIVE_EXPERIMENT_STAGE_ID_INVALID')
        deps = row['dependsOn']
        if (not isinstance(deps, list) or any(not isinstance(v, str) for v in deps)
                or len(set(deps)) != len(deps) or not set(deps) <= seen):
            raise ValueError('NATIVE_EXPERIMENT_DEPENDENCY_INVALID')
        if (not isinstance(row['command'], list) or not row['command']
                or any(not isinstance(v, str) or '\x00' in v for v in row['command'])
                or not row['command'][0] or not isinstance(row['directory'], str)
                or not row['directory']):
            raise ValueError('NATIVE_EXPERIMENT_COMMAND_INVALID')
        env = row['environment']
        if (not isinstance(env, dict) or 'PATH' not in env
                or any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k)
                       or not isinstance(v, str) or '\x00' in v for k, v in env.items())):
            raise ValueError('NATIVE_EXPERIMENT_ENVIRONMENT_INVALID')
        for field in ('inputs', 'outputs'):
            if (not isinstance(row[field], list) or any(not isinstance(v, str) for v in row[field])
                    or len(set(row[field])) != len(row[field])):
                raise ValueError('NATIVE_EXPERIMENT_FILES_INVALID')
        if not row['outputs'] or not all(_relative(v) for v in row['outputs']):
            raise ValueError('NATIVE_EXPERIMENT_OUTPUT_PATH_INVALID')
        if (type(row['timeoutSeconds']) is not int or not 1 <= row['timeoutSeconds'] <= 86400
                or type(row['maxLogBytes']) is not int or not 1024 <= row['maxLogBytes'] <= 2**30):
            raise ValueError('NATIVE_EXPERIMENT_BUDGET_INVALID')
        seen.add(name)
    return plan


def command(argv, cwd, env, output, timeout, limit):
    """Drain both pipes with a common budget; terminate the entire process group."""
    started = time.monotonic()
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    reason = None
    total = 0
    streams = {}
    sel = selectors.DefaultSelector()
    try:
        for name in ('stdout', 'stderr'):
            pipe = getattr(process, name)
            os.set_blocking(pipe.fileno(), False)
            streams[name] = (Path(output)/(name+'.log')).open('xb')
            sel.register(pipe, selectors.EVENT_READ, name)
        while sel.get_map() or process.poll() is None:
            if reason is None and time.monotonic()-started > timeout:
                reason = 'TIMEOUT'
            if reason is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for key, _ in sel.select(0.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                kept = data[:max(0, limit-total)]
                streams[key.data].write(kept)
                total += len(data)
                if total > limit and reason is None:
                    reason = 'LOG_BUDGET_EXCEEDED'
        code = process.wait()
        # A child may have closed its pipes and outlived the driver process.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return code, reason
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        sel.close()
        for pipe in (process.stdout, process.stderr):
            pipe.close()
        for stream in streams.values():
            stream.close()


def execute(plan, output):
    validate(plan)
    root = Path(output).absolute()
    root.mkdir()  # Never merge sessions or replace old evidence.
    root = root.resolve()
    (root/'plan.json').write_text(json.dumps(plan, indent=2)+'\n')
    state = {'schemaVersion': RESULT, 'planIdentity': plan['planIdentity'],
             'planDigest': digest(root/'plan.json'),
             'output': str(root), 'status': 'running', 'primaryFailure': None,
             'implementationDigest': digest(__file__),
             'stages': [{'id': r['id'], 'status': 'not_run', 'reason': 'PREDECESSOR_NOT_COMPLETE'}
                        for r in plan['stages']], 'acquisitionComplete': False,
             'semanticApproval': False, 'productionAcceptanceComplete': False}
    publish(root/'run-status.json', state)
    def expand(text, stage):
        return text.replace('${RUN}', str(root)).replace('${STAGE}', str(stage))
    for spec, row in zip(plan['stages'], state['stages']):
        if state['primaryFailure'] is not None:
            row['reason'] = 'PREDECESSOR_FAILED'
            continue
        folder = root/spec['id']
        try:
            folder.mkdir()
            argv = [expand(v, folder) for v in spec['command']]
            cwd = Path(expand(spec['directory'], folder)).resolve(strict=True)
            env = {k: expand(v, folder) for k, v in spec['environment'].items()}
            # Resolve before execution under the exact declared PATH.
            import shutil
            executable = shutil.which(argv[0], path=env['PATH']) if '/' not in argv[0] else argv[0]
            if executable is None:
                raise ValueError('NATIVE_EXPERIMENT_EXECUTABLE_MISSING')
            argv[0] = str(resolve_executable(executable, cwd))
            inputs = [Path(expand(v, folder)).resolve(strict=True) for v in spec['inputs']]
            bound = {str(p): digest(p) for p in [Path(argv[0]), *inputs]}
            row.update(status='running', reason=None, command=argv, directory=str(cwd),
                       environment=env, inputDigests=bound)
            publish(root/'run-status.json', state)
            code, reason = command(argv, cwd, env, folder, spec['timeoutSeconds'], spec['maxLogBytes'])
            row.update(returnCode=code, logDigests={n: digest(folder/(n+'.log'))
                                                   for n in ('stdout', 'stderr')})
            if reason:
                raise ValueError('NATIVE_EXPERIMENT_'+reason)
            if code:
                raise ValueError('NATIVE_EXPERIMENT_COMMAND_FAILED:'+str(code))
            outputs = {}
            for name in spec['outputs']:
                path = (folder/name).resolve(strict=True)
                if not path.is_relative_to(folder) or not path.is_file():
                    raise ValueError('NATIVE_EXPERIMENT_OUTPUT_ESCAPES_STAGE')
                outputs[name] = digest(path)
            for path, sha in bound.items():
                if digest(path) != sha:
                    raise ValueError('NATIVE_EXPERIMENT_INPUT_CHANGED:'+path)
            if digest(root/'plan.json') != state['planDigest']:
                raise ValueError('NATIVE_EXPERIMENT_PLAN_CHANGED')
            row.update(status='succeeded', outputDigests=outputs)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            row.update(status='failed', reason=str(exc), errorType=type(exc).__name__)
            state.update(status='failed', primaryFailure={'stage': spec['id'],
                         'reason': str(exc), 'errorType': type(exc).__name__})
        publish(root/'run-status.json', state)
    state['acquisitionComplete'] = all(r['status'] == 'succeeded' for r in state['stages'])
    state['status'] = 'complete' if state['acquisitionComplete'] else 'failed'
    publish(root/'run-status.json', state)
    return read(root/'run-status.json')


def check_run(output):
    """Recompute acquisition integrity, not independent execution or semantics."""
    root = Path(output).resolve(strict=True)
    plan = validate(read(root/'plan.json'))
    value = read(root/'run-status.json')
    if (value.get('schemaVersion') != RESULT or value.get('stateIdentity') != identity({
            k: v for k, v in value.items() if k != 'stateIdentity'})
            or value.get('output') != str(root) or value.get('planIdentity') != plan['planIdentity']
            or value.get('planDigest') != digest(root/'plan.json')
            or value.get('implementationDigest') != digest(__file__)
            or value.get('semanticApproval') is not False
            or value.get('productionAcceptanceComplete') is not False
            or [r['id'] for r in value['stages']] != [r['id'] for r in plan['stages']]):
        raise ValueError('NATIVE_EXPERIMENT_RUN_INVALID')
    failures = []
    for spec, row in zip(plan['stages'], value['stages']):
        if row['status'] == 'failed':
            failures.append(row)
        elif row['status'] == 'succeeded':
            folder = root/spec['id']
            def expand(text):
                return text.replace('${RUN}', str(root)).replace('${STAGE}', str(folder))
            env = {k: expand(v) for k, v in spec['environment'].items()}
            cwd = Path(expand(spec['directory'])).resolve(strict=True)
            argv = [expand(v) for v in spec['command']]
            import shutil
            executable = shutil.which(argv[0], path=env['PATH']) if '/' not in argv[0] else argv[0]
            if executable is None:
                raise ValueError('NATIVE_EXPERIMENT_EXECUTABLE_MISSING')
            argv[0] = str(resolve_executable(executable, cwd))
            expected_inputs = {str(Path(p).resolve(strict=True)) for p in
                               [argv[0], *[expand(v) for v in spec['inputs']]]}
            if (failures or type(row['returnCode']) is not int or row['returnCode'] != 0
                    or row['command'] != argv or row['environment'] != env or row['directory'] != str(cwd)
                    or set(row['inputDigests']) != expected_inputs
                    or set(row['logDigests']) != {'stdout', 'stderr'}
                    or set(row['outputDigests']) != set(spec['outputs'])):
                raise ValueError('NATIVE_EXPERIMENT_STAGE_INVALID')
            for path, sha in row['inputDigests'].items():
                if digest(path) != sha:
                    raise ValueError('NATIVE_EXPERIMENT_BOUND_INPUT_CHANGED')
            for name, sha in row['outputDigests'].items():
                path = (root/spec['id']/name).resolve(strict=True)
                if not path.is_relative_to(root/spec['id']) or digest(path) != sha:
                    raise ValueError('NATIVE_EXPERIMENT_BOUND_OUTPUT_CHANGED')
            for name, sha in row['logDigests'].items():
                if digest(root/spec['id']/(name+'.log')) != sha:
                    raise ValueError('NATIVE_EXPERIMENT_LOG_CHANGED')
        elif row['status'] != 'not_run' or not failures:
            raise ValueError('NATIVE_EXPERIMENT_STAGE_STATE_INVALID')
    complete = all(r['status'] == 'succeeded' for r in value['stages'])
    if (value['acquisitionComplete'] is not complete or len(failures) > 1
            or value['status'] != ('complete' if complete else 'failed')
            or (value['primaryFailure'] is None) is not complete):
        raise ValueError('NATIVE_EXPERIMENT_COMPLETION_INVALID')
    if failures and value['primaryFailure'] != {'stage': failures[0]['id'],
            'reason': failures[0]['reason'], 'errorType': failures[0]['errorType']}:
        raise ValueError('NATIVE_EXPERIMENT_PRIMARY_FAILURE_CHANGED')
    return {'acquisitionIntegrityChecked': True, 'acquisitionComplete': complete,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
