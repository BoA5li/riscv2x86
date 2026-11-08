"""Replayable GCC configuration and actual-TU macro/dependency observations.

Neither macro values, compiler specs nor help output prove generated protection
mechanisms or call ABI. These observations locate the missing evidence.
"""
import os
from pathlib import Path

from .native_dependency_inventory import checked_records
from .native_external_providers import read, checked
from .native_experiment_driver import command
from .project_compile_context import derive, validate, digest, ENV_KEYS
from .project_build_records import identity
from .compiler_call_dependencies import parse_dependencies, _snapshot

SCHEMA = 'riscv2x86.native-compiler-configuration.v1'


def observe(action, output, timeout=60, max_log_bytes=16*1024*1024):
    context = derive(action)
    if not context['inspectionReady']:
        raise ValueError('COMPILER_CONFIGURATION_CONTEXT_BLOCKED:'+','.join(context['blockers']))
    validate(context)
    root = Path(output)
    root.mkdir()
    cc = context['nativeCompiler']
    cwd = context['workingDirectory']
    flags = context['inspectionArguments']
    source = context['sourcePath']
    commands = []
    def run(stage, args):
        folder = root/stage
        folder.mkdir()
        argv = [cc, *args]
        code, reason = command(argv, cwd, dict(os.environ), folder, timeout, max_log_bytes)
        row = {'stage': stage, 'arguments': argv, 'returnCode': code, 'failureReason': reason,
               'stdoutDigest': digest(folder/'stdout.log'), 'stderrDigest': digest(folder/'stderr.log')}
        commands.append(row)
        if code or reason:
            raise ValueError('COMPILER_CONFIGURATION_PROBE_FAILED:'+stage)
        return (folder/'stdout.log').read_text()
    before = _snapshot(parse_dependencies(run('dependencies-before', [*flags, '-M', '-MT', 'rv2x86_call_inventory', source])), Path(cwd))
    # The driver really executes GCC; unknown/unsupported drivers fail their
    # actual probes, instead of receiving a GCC mechanism contract by basename.
    run('version', ['--version'])
    triple = run('triple', ['-dumpmachine']).strip()
    run('specs', ['-dumpspecs'])
    run('sysroot', ['-print-sysroot'])
    run('macros', [*flags, '-E', '-dM', source])
    run('target-options', [*flags, '-Q', '--help=target'])
    run('optimizer-options', [*flags, '-Q', '--help=optimizers'])
    after = _snapshot(parse_dependencies(run('dependencies-after', [*flags, '-M', '-MT', 'rv2x86_call_inventory', source])), Path(cwd))
    if before != after:
        raise ValueError('COMPILER_CONFIGURATION_DEPENDENCIES_CHANGED')
    validate(context)
    body = {'schemaVersion': SCHEMA, 'actionIdentity': action['actionIdentity'],
            'contextIdentity': context['contextIdentity'], 'context': context,
            'compilerTriple': triple, 'dependencySnapshots': before, 'commands': commands,
            'macroTextDigest': commands[5]['stdoutDigest'],
            'searchEnvironment': {k: os.environ.get(k, '') for k in ENV_KEYS},
            'generatedMechanismVerified': False, 'compilerAbiVerified': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, configurationIdentity=identity(body))


def acquire(records_path, action_ids, output, timeout=60):
    path = Path(records_path).resolve(strict=True)
    before = digest(path)
    records = checked_records(path)
    if (not isinstance(action_ids, list) or not action_ids or len(set(action_ids)) != len(action_ids)
            or any(not isinstance(v, str) for v in action_ids)):
        raise ValueError('COMPILER_CONFIGURATION_ACTION_SELECTION_INVALID')
    actions = {a['actionIdentity']: a for a in records['actions']}
    rows = [observe(actions[name], Path(output)/str(i), timeout) for i, name in enumerate(action_ids)]
    checked_records(path)
    if digest(path) != before:
        raise ValueError('COMPILER_CONFIGURATION_RECORDS_CHANGED')
    body = {'schemaVersion': 'riscv2x86.native-compiler-configuration-bundle.v1',
            'recordsPath': str(path), 'recordsDigest': before, 'actionIdentities': action_ids,
            'configurations': rows, 'generatedMechanismVerified': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, configurationBundleIdentity=identity(body))


def replay(value, original, output, timeout=60):
    checked(value, 'configurationBundleIdentity')
    if value.get('schemaVersion') != 'riscv2x86.native-compiler-configuration-bundle.v1':
        raise ValueError('COMPILER_CONFIGURATION_SCHEMA_INVALID')
    if digest(value['recordsPath']) != value['recordsDigest']:
        raise ValueError('COMPILER_CONFIGURATION_RECORDS_CHANGED')
    fresh = acquire(value['recordsPath'], value['actionIdentities'], output, timeout)
    if fresh != value:
        raise ValueError('COMPILER_CONFIGURATION_REPLAY_MISMATCH')
    for i, row in enumerate(value['configurations']):
        for cmd in row['commands']:
            for stream in ('stdout', 'stderr'):
                if digest(Path(original)/str(i)/cmd['stage']/(stream+'.log')) != cmd[stream+'Digest']:
                    raise ValueError('COMPILER_CONFIGURATION_ARTIFACT_CHANGED')
    return {'compilerConfigurationReplayComplete': True,
            'configurationBundleIdentity': value['configurationBundleIdentity'],
            'generatedMechanismVerified': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False}
