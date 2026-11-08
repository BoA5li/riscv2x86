"""Bounded native execution plus GNU loader diagnostic observations.

Natural runs and diagnostic runs are separate. Loader --list is selection for
that invocation, not execution or symbol-binding proof. LD_DEBUG binding rows
are observations of exercised bindings, never completeness or ABI approval.
"""
import json
import os
from pathlib import Path
import re

from .native_captured_deployment import check_result, read, seal, snapshot, verify_snapshot
from .native_elf_runtime import parse
from .native_experiment_driver import command
from .native_external_providers import checked
from .project_compile_context import digest

SCHEMA = 'riscv2x86.deployment-observation.v1'


def loader_paths(text):
    rows = []; ignored = []; unresolved = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r'linux-vdso\.so\.\d+ \(0x[0-9a-fA-F]+\)', line):
            ignored.append(line); continue
        match = re.fullmatch(r'(?:(\S+) => )?(/.+?) \(0x[0-9a-fA-F]+\)', line)
        if match:
            rows.append({'requested': match[1], **snapshot(match[2])})
        else:
            unresolved.append(line)
    return rows, ignored, unresolved


def observe(deployment_path, output, *, arguments=(), timeout=300, diagnostic=False):
    value = check_result(deployment_path)
    root = Path(output).absolute(); root.mkdir(); root = root.resolve()
    deployment_path = Path(deployment_path).resolve(strict=True)
    plan = read(value['planPath'])
    if not isinstance(arguments, (list, tuple)) or any(not isinstance(x, str) or '\0' in x for x in arguments):
        raise ValueError('DEPLOYMENT_EXECUTION_ARGUMENTS_INVALID')
    program = next(x for x in value['artifacts'] if x['stage'] == 'derived-entry')
    library = next(x for x in value['artifacts'] if x['stage'] == 'derived-library')
    interpreter = program['elf']['interpreter']
    if not interpreter or os.geteuid() != os.getuid() or os.getegid() != os.getgid():
        raise ValueError('DEPLOYMENT_ORDINARY_DYNAMIC_EXECUTION_REQUIRED')
    mode = Path(program['path']).stat().st_mode
    if mode & 0o6000:
        raise ValueError('DEPLOYMENT_PRIVILEGED_EXECUTABLE_UNSUPPORTED')
    loader = snapshot(interpreter)
    loader_elf = parse(Path(loader['path']).read_bytes())
    if loader_elf['machine'] != 62:
        raise ValueError('DEPLOYMENT_NATIVE_LOADER_REQUIRED')
    env = dict(plan['environment'])
    if any(env.get(k) for k in ('LD_PRELOAD', 'LD_AUDIT', 'LD_DEBUG', 'LD_DEBUG_OUTPUT', 'LD_BIND_NOW')):
        raise ValueError('DEPLOYMENT_UNSUPPORTED_LOADER_ENVIRONMENT')
    commands = []
    def run(name, argv, environment):
        folder = root/name; folder.mkdir()
        code, reason = command(argv, str(root), environment, folder, timeout, 64*1024*1024)
        row = {'stage': name, 'arguments': argv, 'environment': environment, 'returnCode': code,
               'failureReason': reason, 'stdoutDigest': digest(folder/'stdout.log'),
               'stderrDigest': digest(folder/'stderr.log')}
        commands.append(row)
        return row
    version = run('loader-version', [loader['path'], '--version'], env)
    version_text = (root/'loader-version/stdout.log').read_text()
    # Older glibc loaders do not implement --version. Keep that failed query
    # as a capability observation instead of rejecting their working --list.
    private_versions = [s for s in loader_elf['dynamicSymbols'] if s['defined']
                        and s['version'] and s['version']['name'] == 'GLIBC_PRIVATE']
    if not private_versions:
        raise ValueError('DEPLOYMENT_GNU_LOADER_DIAGNOSTICS_REQUIRED')
    listing = run('loader-list', [loader['path'], '--list', program['path']], env)
    paths, virtual, unknown = loader_paths((root/'loader-list/stdout.log').read_text())
    selected = [r for r in paths if r['requested'] == library['elf']['soname']]
    selection = (listing['returnCode'] == 0 and listing['failureReason'] is None and not unknown
                 and len(selected) == 1 and selected[0]['resolvedPath'] == library['resolvedPath']
                 and selected[0]['digest'] == library['digest'])
    # Do not execute if the dry diagnostic selects an unexpected library.
    if not selection:
        raise ValueError('DEPLOYMENT_EXPECTED_LIBRARY_NOT_SELECTED')
    natural = run('natural', [program['path'], *arguments], env)
    bindings = []; unresolved_bindings = []; diagnostic_row = None
    if diagnostic and natural['failureReason'] is None:
        diagnostic_env = dict(env, LD_DEBUG='files,bindings,versions')
        diagnostic_row = run('diagnostic', [program['path'], *arguments], diagnostic_env)
        for line in (root/'diagnostic/stderr.log').read_text(errors='strict').splitlines():
            if 'binding file ' not in line:
                continue
            match = re.fullmatch(r"\s*\d+:\s+binding file (.+?) \[\d+\] to (.+?) \[\d+\]: normal symbol `([^']+)'(?: \[([^\]]+)\])?\s*", line)
            if match:
                requester, provider, symbol, version_name = match.groups()
                if not Path(requester).is_absolute() or not Path(provider).is_absolute():
                    unresolved_bindings.append(line); continue
                bindings.append({'requester': snapshot(requester), 'provider': snapshot(provider),
                                 'symbol': symbol, 'version': version_name})
            else:
                unresolved_bindings.append(line)
    check_result(deployment_path); verify_snapshot(loader)
    for row in paths:
        verify_snapshot({k: row[k] for k in ('path', 'resolvedPath', 'digest')})
    for row in bindings:
        verify_snapshot(row['requester']); verify_snapshot(row['provider'])
    body = {'schemaVersion': SCHEMA, 'deploymentPath': str(deployment_path),
            'deploymentDigest': digest(deployment_path), 'deploymentIdentity': value['deploymentIdentity'],
            'loader': loader, 'commands': commands, 'listedLibraries': paths,
            'virtualObjects': virtual, 'unparsedLoaderListLines': unknown,
            'loaderListSelectionVerified': selection, 'testExecutionPerformed': natural['failureReason'] is None,
            'observedReturnCode': natural['returnCode'], 'naturalRunCompletedWithinBudget': natural['failureReason'] is None,
            'diagnosticBindings': bindings, 'unparsedBindingLines': unresolved_bindings,
            'diagnosticRunPerformed': diagnostic_row is not None,
            'diagnosticOutputComparisonIsSemanticProof': False,
            'runtimeLibrarySelectionVerified': False, 'runtimeBindingClosureComplete': False,
            'translatedInstanceExecutionVerified': False, 'externalContractClosureComplete': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False,
            'remainingWork': ['NATURAL_RUN_LOADED_OBJECT_IDENTITY', 'ALL_APPLICABLE_BINDINGS',
                              'CANDIDATE_INSTANCE_EXECUTION', 'TYPED_BEHAVIOR_CONTRACTS', 'PROGRAM_AUDIT']}
    body['artifactDigests'] = {str(p.relative_to(root)): digest(p) for p in root.rglob('*') if p.is_file()}
    result = seal(body, 'observationIdentity')
    (root/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def check_observation(path):
    path = Path(path).resolve(strict=True); v = read(path); checked(v, 'observationIdentity')
    if v['schemaVersion'] != SCHEMA or digest(v['deploymentPath']) != v['deploymentDigest']:
        raise ValueError('DEPLOYMENT_OBSERVATION_PARENT_CHANGED')
    parent = check_result(v['deploymentPath'])
    if parent['deploymentIdentity'] != v['deploymentIdentity']:
        raise ValueError('DEPLOYMENT_OBSERVATION_IDENTITY_MISMATCH')
    verify_snapshot(v['loader'])
    for name, sha in v['artifactDigests'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or digest(path.parent/name) != sha:
            raise ValueError('DEPLOYMENT_OBSERVATION_ARTIFACT_CHANGED')
    fresh = {str(p.relative_to(path.parent)): digest(p) for p in path.parent.rglob('*')
             if p.is_file() and p != path}
    if fresh != v['artifactDigests']:
        raise ValueError('DEPLOYMENT_OBSERVATION_INVENTORY_CHANGED')
    paths, virtual, unknown = loader_paths((path.parent/'loader-list/stdout.log').read_text())
    if (paths != v['listedLibraries'] or virtual != v['virtualObjects']
            or unknown != v['unparsedLoaderListLines']):
        raise ValueError('DEPLOYMENT_OBSERVATION_LIST_REDERIVATION_MISMATCH')
    lib = next(x for x in parent['artifacts'] if x['stage'] == 'derived-library')
    selected = [r for r in paths if r['requested'] == lib['elf']['soname']]
    if (v['loaderListSelectionVerified'] is not True or unknown or len(selected) != 1
            or selected[0]['resolvedPath'] != lib['resolvedPath'] or selected[0]['digest'] != lib['digest']):
        raise ValueError('DEPLOYMENT_OBSERVATION_SELECTION_MISMATCH')
    for c in v['commands']:
        for stream in ('stdout', 'stderr'):
            if digest(path.parent/c['stage']/(stream+'.log')) != c[stream+'Digest']:
                raise ValueError('DEPLOYMENT_OBSERVATION_COMMAND_LOG_CHANGED')
    for row in v['diagnosticBindings']:
        verify_snapshot(row['requester']); verify_snapshot(row['provider'])
    if any(v.get(k) is not False for k in ('semanticApproval', 'productionAcceptanceComplete',
            'runtimeLibrarySelectionVerified', 'runtimeBindingClosureComplete',
            'translatedInstanceExecutionVerified', 'externalContractClosureComplete')):
        raise ValueError('DEPLOYMENT_OBSERVATION_UNSUPPORTED_APPROVAL')
    return v
