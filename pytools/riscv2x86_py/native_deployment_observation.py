"""Re-derived observations. Events are not calls; integrity is not collector authenticity.

V1 lacks execution receipts: reacquire rather than upgrading its approval scope.
"""
import json
import os
from pathlib import Path
import re
from .native_captured_deployment import check_result, read, seal, snapshot, verify_snapshot
from .native_dynamic_obligations import inspect as inspect_dynamic
from .native_experiment_driver import command
from .native_external_providers import checked
from .project_compile_context import digest

LEGACY = 'riscv2x86.deployment-observation.v2'
SCHEMA = 'riscv2x86.deployment-observation.v3'
MANIFEST = 'riscv2x86.observation-execution.v1'
RECEIPT = 'riscv2x86.observation-command.v1'


def _json(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2); f.write('\n')


def loader_paths(text):
    rows = []; labels = []; unknown = []
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        match = re.fullmatch(r'(?:(\S+) => )?(/.+?) \(0x[0-9a-fA-F]+\)', line)
        if match: rows.append({'requested': match[1], **snapshot(match[2])})
        elif re.fullmatch(r'[^\s/]+ \(0x[0-9a-fA-F]+\)', line): labels.append(line)
        else: unknown.append(line)
    return rows, labels, unknown


def binding_events(text):
    rows = []; syntax = []; unresolved = []
    def obj(label):
        if not Path(label).is_absolute():
            return {'kind': 'loader-label', 'label': label, 'runtimeIdentityVerified': False}
        try: return {'kind': 'file', **snapshot(label), 'runtimeIdentityVerified': False}
        except OSError: return {'kind': 'unresolved-file', 'label': label, 'runtimeIdentityVerified': False}
    pattern = (r"\s*(\d+):\s+binding file (.+?) \[(\d+)\] to (.+?) \[(\d+)\]: "
               r"(\S+) symbol `([^']+)'(?: \[([^\]]+)\])?\s*")
    for ordinal, line in enumerate(text.splitlines()):
        if 'binding file ' not in line: continue
        m = re.fullmatch(pattern, line)
        if not m:
            syntax.append({'line': ordinal, 'text': line}); continue
        pid, req, reqns, prov, provns, mode, sym, ver = m.groups()
        row = {'line': ordinal, 'processId': int(pid), 'requesterNamespace': int(reqns),
               'providerNamespace': int(provns), 'bindingMode': mode,
               'requester': obj(req), 'provider': obj(prov), 'symbol': sym, 'version': ver}
        rows.append(row)
        if mode != 'normal' or any(row[k]['kind'] != 'file' for k in ('requester', 'provider')):
            unresolved.append({'eventIndex': len(rows)-1, 'reason': 'OBJECT_IDENTITY_OR_BINDING_MODE_UNVERIFIED'})
    return rows, syntax, unresolved


def _context(value):
    plan = read(value['planPath'])
    program = next(x for x in value['artifacts'] if x['stage'] == 'derived-entry')
    library = next(x for x in value['artifacts'] if x['stage'] == 'derived-library')
    interpreter = program['elf']['interpreter']
    if not interpreter or os.geteuid() != os.getuid() or os.getegid() != os.getgid():
        raise ValueError('DEPLOYMENT_ORDINARY_DYNAMIC_EXECUTION_REQUIRED')
    if Path(program['path']).stat().st_mode & 0o6000:
        raise ValueError('DEPLOYMENT_PRIVILEGED_EXECUTABLE_UNSUPPORTED')
    env = dict(plan['environment'])
    if any(env.get(k) for k in ('LD_PRELOAD', 'LD_AUDIT', 'LD_DEBUG', 'LD_DEBUG_OUTPUT', 'LD_BIND_NOW')):
        raise ValueError('DEPLOYMENT_UNSUPPORTED_LOADER_ENVIRONMENT')
    return program, library, snapshot(interpreter), env


def _specs(value, args, diagnostic):
    program, library, loader, env = _context(value)
    specs = [('loader-version', [loader['path'], '--version'], env),
             ('loader-list', [loader['path'], '--list', program['path']], env),
             ('natural', [program['path'], *args], env)]
    if diagnostic:
        specs.append(('diagnostic', [program['path'], *args], dict(env, LD_DEBUG='files,bindings,versions')))
    return [{'stage': n, 'arguments': a, 'environment': e} for n,a,e in specs]


def _selection(paths, unknown, library):
    selected = [r for r in paths if r['requested'] == library['elf']['soname']]
    return (not unknown and len(selected) == 1 and selected[0]['resolvedPath'] == library['resolvedPath']
            and selected[0]['digest'] == library['digest'])


def derive(root, manifest, value, *, schema=SCHEMA):
    """Shared deterministic projection: no result-level conclusion is trusted."""
    root = Path(root).resolve(strict=True); checked(manifest, 'executionIdentity')
    if (set(manifest) != {'schemaVersion', 'deploymentPath', 'deploymentDigest', 'deploymentIdentity',
                          'loader', 'programArguments', 'diagnostic', 'timeoutSeconds',
                          'outputDirectory', 'commands', 'executionIdentity'}
            or manifest['schemaVersion'] != MANIFEST or type(manifest['diagnostic']) is not bool
            or type(manifest['timeoutSeconds']) is not int or not 1 <= manifest['timeoutSeconds'] <= 86400
            or not isinstance(manifest['programArguments'], list)
            or any(not isinstance(x, str) or '\0' in x for x in manifest['programArguments'])
            or manifest['outputDirectory'] != str(root)
            or manifest['deploymentIdentity'] != value['deploymentIdentity']
            or digest(manifest['deploymentPath']) != manifest['deploymentDigest']):
        raise ValueError('OBSERVATION_EXECUTION_MANIFEST_INVALID')
    program, library, loader, env = _context(value)
    verify_snapshot(manifest['loader'])
    if manifest['loader'] != loader: raise ValueError('OBSERVATION_LOADER_CHANGED')
    expected = _specs(value, manifest['programArguments'], manifest['diagnostic'])
    if manifest['commands'] != expected: raise ValueError('OBSERVATION_COMMAND_PLAN_MISMATCH')
    commands = []
    for spec in expected:
        folder = root/spec['stage']; row = read(folder/'execution.json'); checked(row, 'commandIdentity')
        if (set(row) != {'schemaVersion', 'executionIdentity', 'stage', 'arguments', 'environment',
                         'workingDirectory', 'timeoutSeconds', 'maxLogBytes', 'returnCode',
                         'failureReason', 'stdoutDigest', 'stderrDigest', 'commandIdentity'}
                or row['schemaVersion'] != RECEIPT or row['executionIdentity'] != manifest['executionIdentity']
                or row['workingDirectory'] != str(root) or type(row['returnCode']) is not int
                or row['failureReason'] not in (None, 'TIMEOUT', 'LOG_BUDGET_EXCEEDED')
                or any(row.get(k) != v for k,v in spec.items())
                or row['timeoutSeconds'] != manifest['timeoutSeconds'] or row['maxLogBytes'] != 64*1024*1024):
            raise ValueError('OBSERVATION_EXECUTION_RECEIPT_INVALID')
        for stream in ('stdout', 'stderr'):
            if digest(folder/(stream+'.log')) != row[stream+'Digest']:
                raise ValueError('OBSERVATION_COMMAND_LOG_CHANGED')
        commands.append(row)
    by_stage = {r['stage']: r for r in commands}; listing = by_stage['loader-list']
    paths, labels, unknown = loader_paths((root/'loader-list/stdout.log').read_text())
    selection = (listing['returnCode'] == 0 and listing['failureReason'] is None
                 and _selection(paths, unknown, library))
    if not selection: raise ValueError('DEPLOYMENT_EXPECTED_LIBRARY_NOT_SELECTED')
    bindings = []; syntax = []; unresolved = []
    if manifest['diagnostic']:
        bindings, syntax, unresolved = binding_events((root/'diagnostic/stderr.log').read_text())
    files = [program['path'], library['path'], loader['path'], *[r['resolvedPath'] for r in paths]]
    for row in bindings:
        for k in ('requester', 'provider'):
            if row[k]['kind'] == 'file': files.append(row[k]['resolvedPath'])
    dynamic = inspect_dynamic([str(Path(p).resolve(strict=True)) for p in files], legacy_v2=schema == LEGACY)
    natural = by_stage['natural']; version = by_stage['loader-version']
    version_ok = version['returnCode'] == 0 and version['failureReason'] is None
    result = {'schemaVersion': schema, 'deploymentPath': manifest['deploymentPath'],
            'deploymentDigest': manifest['deploymentDigest'], 'deploymentIdentity': value['deploymentIdentity'],
            'executionManifestDigest': digest(root/'execution-plan.json'), 'executionIdentity': manifest['executionIdentity'],
            'loader': loader, 'commands': commands, 'loaderCapabilities': {
                'versionQuerySucceeded': version_ok, 'versionQueryRequiredForSelection': False,
                'versionQueryFailureClass': None if version_ok else 'query-unavailable-or-failed-see-original-output',
                'listQuerySucceeded': selection, 'exactReleaseProven': False},
            'listedLibraries': paths, 'virtualObjects': labels, 'virtualObjectIdentityVerified': False,
            'unparsedLoaderListLines': unknown, 'loaderListSelectionVerified': selection,
            'testExecutionPerformed': True, 'observedReturnCode': natural['returnCode'],
            'naturalRunCompletedWithinBudget': natural['failureReason'] is None,
            'diagnosticBindings': bindings, 'unparsedBindingLines': syntax, 'unverifiedObjectBindings': unresolved,
            'diagnosticRunPerformed': manifest['diagnostic'],
            'diagnosticRunCompletedWithinBudget': by_stage['diagnostic']['failureReason'] is None if manifest['diagnostic'] else None,
            'diagnosticObservedReturnCode': by_stage['diagnostic']['returnCode'] if manifest['diagnostic'] else None,
            'diagnosticOutputComparisonIsSemanticProof': False, 'dynamicObligations': dynamic,
            'runtimeLibrarySelectionVerified': False, 'runtimeBindingClosureComplete': False,
            'translatedInstanceExecutionVerified': False, 'externalContractClosureComplete': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False,
            'remainingWork': ['NATURAL_RUN_LOADED_OBJECT_IDENTITY', 'ALL_APPLICABLE_BINDINGS',
                              'VIRTUAL_OBJECT_RUNTIME_IDENTITY', 'CANDIDATE_INSTANCE_EXECUTION',
                              'TYPED_BEHAVIOR_CONTRACTS', 'PROGRAM_AUDIT']}
    if schema != LEGACY:
        endpoints = [row[k] for row in bindings for k in ('requester', 'provider')]
        result['bindingEvidenceCoverage'] = {
            'eventCount': len(bindings), 'endpointOccurrenceCount': len(endpoints),
            'unverifiedFileEndpointOccurrences': sum(e['kind'] == 'file' and not e['runtimeIdentityVerified'] for e in endpoints),
            'unverifiedLabelEndpointOccurrences': sum(e['kind'] == 'loader-label' and not e['runtimeIdentityVerified'] for e in endpoints),
            'unresolvedFileEndpointOccurrences': sum(e['kind'] == 'unresolved-file' for e in endpoints),
            'unverifiedEndpointOccurrences': sum(e['runtimeIdentityVerified'] is not True for e in endpoints),
            'unparsedLineCount': len(syntax),
            'unverifiedObjectBindingsIsExhaustive': False,
            'diagnosticEventsProveNaturalRunBindings': False}
    return result


def observe(deployment_path, output, *, arguments=(), timeout=300, diagnostic=False):
    from .native_deployment_prerequisites import output_path
    value = check_result(deployment_path)
    if (not isinstance(arguments, (list, tuple)) or any(not isinstance(x,str) or '\0' in x for x in arguments)
            or type(diagnostic) is not bool or type(timeout) is not int or not 1 <= timeout <= 86400):
        raise ValueError('DEPLOYMENT_OBSERVATION_OPTIONS_INVALID')
    root = output_path(output); root.mkdir()
    program, library, loader, env = _context(value)
    specs = _specs(value, list(arguments), diagnostic)
    manifest = seal({'schemaVersion': MANIFEST, 'deploymentPath': str(Path(deployment_path).resolve(strict=True)),
        'deploymentDigest': digest(deployment_path), 'deploymentIdentity': value['deploymentIdentity'],
        'loader': loader, 'programArguments': list(arguments), 'diagnostic': diagnostic,
        'timeoutSeconds': timeout, 'outputDirectory': str(root), 'commands': specs}, 'executionIdentity')
    _json(root/'execution-plan.json', manifest)
    for spec in specs:
        folder = root/spec['stage']; folder.mkdir()
        code, reason = command(spec['arguments'], str(root), spec['environment'], folder, timeout, 64*1024*1024)
        receipt = seal({'schemaVersion': RECEIPT, 'executionIdentity': manifest['executionIdentity'], **spec,
            'workingDirectory': str(root), 'timeoutSeconds': timeout, 'maxLogBytes': 64*1024*1024,
            'returnCode': code, 'failureReason': reason,
            'stdoutDigest': digest(folder/'stdout.log'), 'stderrDigest': digest(folder/'stderr.log')}, 'commandIdentity')
        _json(folder/'execution.json', receipt)
        if spec['stage'] == 'loader-list':
            paths, _, unknown = loader_paths((folder/'stdout.log').read_text())
            if code or reason or not _selection(paths, unknown, library):
                raise ValueError('DEPLOYMENT_EXPECTED_LIBRARY_NOT_SELECTED')
        if reason: raise ValueError('OBSERVATION_COMMAND_BUDGET_FAILED:'+spec['stage']+':'+reason)
    check_result(deployment_path)
    body = derive(root, manifest, value)
    body['artifactDigests'] = {str(p.relative_to(root)): digest(p) for p in root.rglob('*') if p.is_file()}
    result = seal(body, 'observationIdentity'); _json(root/'result.json', result)
    return result


def check_observation(path):
    path = Path(path).resolve(strict=True); value = read(path); checked(value, 'observationIdentity')
    if value.get('schemaVersion') not in (LEGACY, SCHEMA):
        raise ValueError('OBSERVATION_LEGACY_RECEIPTS_MISSING_REACQUIRE_V2')
    parent = check_result(value['deploymentPath']); manifest = read(path.parent/'execution-plan.json')
    if manifest['deploymentPath'] != value['deploymentPath']: raise ValueError('OBSERVATION_PARENT_PATH_MISMATCH')
    fresh = derive(path.parent, manifest, parent, schema=value['schemaVersion'])
    fresh['artifactDigests'] = {str(p.relative_to(path.parent)): digest(p) for p in path.parent.rglob('*') if p.is_file() and p != path}
    if seal(fresh, 'observationIdentity') != value: raise ValueError('OBSERVATION_FULL_REDERIVATION_MISMATCH')
    return value


def replay_observation(path, output, timeout=None):
    from .native_deployment_prerequisites import output_path
    old = check_observation(path); plan = read(Path(path).resolve().parent/'execution-plan.json')
    root = output_path(output); root.mkdir()
    fresh = observe(old['deploymentPath'], root/'run', arguments=plan['programArguments'],
                    timeout=plan['timeoutSeconds'] if timeout is None else timeout, diagnostic=plan['diagnostic'])
    def projection(v):
        c = next(r for r in v['commands'] if r['stage'] == 'natural')
        return {k:c[k] for k in ('returnCode', 'failureReason', 'stdoutDigest', 'stderrDigest')}
    check_observation(path)
    result = seal({'schemaVersion': 'riscv2x86.observation-replay.v1',
        'originalObservationIdentity': old['observationIdentity'], 'freshObservationIdentity': fresh['observationIdentity'],
        'freshObservationPath': str(root/'run/result.json'),
        'naturalObservationReproduced': projection(old) == projection(fresh),
        'scope': 'independent-natural-return-code-budget-and-output-digests-not-binding-completeness',
        'runtimeBindingClosureComplete': False, 'semanticApproval': False, 'productionAcceptanceComplete': False}, 'observationReplayIdentity')
    _json(root/'replay.json', result)
    return result
