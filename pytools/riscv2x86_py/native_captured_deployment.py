"""Exact captured ELF-input substitution and isolated GNU driver relinks.

This establishes deployment facts, never libc semantics or translation approval.
The supported language is deliberately smaller than arbitrary GCC/linker argv;
unknown options, scripts, response files and archive-member substitution reject.
Original argv order, duplicate operands and driver defaults are retained.
"""
import json
import os
from pathlib import Path
import re

from .native_audit_evidence import strict_json
from .native_dependency_inventory import checked_records
from .native_elf_runtime import parse
from .native_experiment_driver import command
from .native_external_providers import checked
from .project_build_records import identity
from .project_compile_context import digest, ENV_KEYS

PLAN = 'riscv2x86.captured-deployment-plan.v1'
RESULT = 'riscv2x86.captured-deployment-result.v1'


def read(path):
    return strict_json(Path(path).read_bytes())


def seal(body, key):
    return dict(body, **{key: identity(body)})


def snapshot(path, cwd=None):
    p = Path(path)
    if not p.is_absolute():
        p = Path(cwd or os.getcwd())/p
    p = Path(os.path.abspath(p))
    return {'path': str(p), 'resolvedPath': str(p.resolve(strict=True)), 'digest': digest(p)}


def verify_snapshot(row):
    if snapshot(row['path']) != row:
        raise ValueError('DEPLOYMENT_INPUT_CHANGED:'+row['path'])


def definitions(elf):
    return sorted((s['name'], s['binding'], s['type'], s['visibility'])
                  for s in elf['staticSymbols'] if s['name'] and s['defined'] and s['binding'] != 0)


def captured_link(action):
    """Parse the supported driver language; do not remove unknown switches."""
    checked(action, 'actionIdentity')
    if (action['kind'] != 'link' or action.get('exitStatusObserved') is not True
            or type(action.get('observedReturnCode')) is not int or action['observedReturnCode'] != 0):
        raise ValueError('DEPLOYMENT_SUCCESSFUL_LINK_REQUIRED')
    args = action['arguments']
    cwd = str(Path(action['directory']).resolve(strict=True))
    inputs = []; paths = []; output_index = None; pending = None
    for i, arg in enumerate(args[1:], 1):
        if pending:
            if pending == 'output':
                if output_index is not None:
                    raise ValueError('DEPLOYMENT_MULTIPLE_OUTPUTS')
                output_index = i
            else:
                if not arg.startswith('-Wl,') or ',' in arg[4:] or not arg[4:]:
                    raise ValueError('DEPLOYMENT_LINKER_VALUE_UNSUPPORTED')
                value = arg[4:]
                if pending == 'rpath':
                    if any(not Path(v).is_absolute() for v in value.split(':')):
                        raise ValueError('DEPLOYMENT_RELATIVE_RPATH_UNSUPPORTED')
                    paths.append({'argumentIndex': i, 'directories': value.split(':')})
                elif '/' in value or value in ('.', '..'):
                    raise ValueError('DEPLOYMENT_SONAME_INVALID')
            pending = None
            continue
        if arg == '-o':
            pending = 'output'
        elif arg in ('-Wl,-rpath', '-Wl,--rpath'):
            pending = 'rpath'
        elif arg in ('-Wl,-soname', '-Wl,--soname'):
            pending = 'soname'
        elif (arg in ('-shared', '-fPIC', '-fpic', '-fPIE', '-fpie', '-pie', '-no-pie', '-static',
                      '-pthread', '-funsigned-char', '-fsigned-char', '-fstack-protector',
                      '-fstack-protector-strong', '-fstack-protector-all', '-fno-stack-protector')
              or re.fullmatch(r'-O(?:[0-3sg]|fast)', arg)
              or re.fullmatch(r'-D[A-Za-z_][A-Za-z0-9_]*(?:=[A-Za-z0-9_]+)?', arg)
              or re.fullmatch(r'-(?:march|mabi)=[A-Za-z0-9_+.\-]+', arg)):
            pass
        elif arg.startswith('-') or arg.startswith('@'):
            raise ValueError('DEPLOYMENT_OPTION_UNSUPPORTED:'+arg)
        else:
            row = snapshot(arg, cwd)
            raw = Path(row['path']).read_bytes()
            if raw.startswith(b'!<arch>\n'):
                from .native_dependency_evidence import archive_members
                members = archive_members(raw)
                if not members:
                    raise ValueError('DEPLOYMENT_EMPTY_ARCHIVE_UNSUPPORTED')
                for member in members:
                    if parse(member['bytes'])['elfType'] != 1:
                        raise ValueError('DEPLOYMENT_ARCHIVE_ELF_OBJECT_REQUIRED')
            elif parse(raw)['elfType'] not in (1, 3):
                raise ValueError('DEPLOYMENT_ELF_INPUT_REQUIRED')
            inputs.append(dict(argumentIndex=i, **row))
    if pending or output_index is None or not inputs:
        raise ValueError('DEPLOYMENT_INCOMPLETE_LINK')
    observed = action['observedOutput']
    output = snapshot(args[output_index], cwd)
    if output != {k: observed[k] for k in ('path', 'resolvedPath', 'digest')}:
        raise ValueError('DEPLOYMENT_CAPTURED_OUTPUT_CHANGED')
    return {'action': action, 'compiler': snapshot(args[0], cwd), 'directory': cwd,
            'inputs': inputs, 'searchPathArguments': paths, 'outputIndex': output_index,
            'originalOutput': output}


def candidate_inputs(path):
    p = Path(path).resolve(strict=True); c = read(p)
    checked(c, 'candidateIdentity')
    if (c['schemaVersion'] != 'riscv2x86.native-integer-candidate.v1'
            or c.get('semanticApproval') is not False or c.get('productionAcceptanceComplete') is not False):
        raise ValueError('DEPLOYMENT_CANDIDATE_SCOPE_INVALID')
    root = Path(c['candidatePath']).parent
    files = [snapshot(p)]
    for name, expected in c['artifactDigests'].items():
        if Path(name).name != name or name in ('.', '..'):
            raise ValueError('DEPLOYMENT_CANDIDATE_ARTIFACT_NAME_INVALID')
        row = snapshot(root/name)
        if row['digest'] != expected:
            raise ValueError('DEPLOYMENT_CANDIDATE_ARTIFACT_CHANGED')
        files.append(row)
    target = snapshot(root/'target.o')
    if target['digest'] != c['targetObjectDigest']:
        raise ValueError('DEPLOYMENT_CANDIDATE_OBJECT_CHANGED')
    elf = parse(Path(target['path']).read_bytes())
    if elf['machine'] != 62 or elf['elfType'] != 1 or not definitions(elf):
        raise ValueError('DEPLOYMENT_X86_OBJECT_REQUIRED')
    return c, target, files


def prepare(candidate_path, library_records, test_records, requirements_path,
            *, library_action=None, entry_action=None, environment=None):
    """Only unique structural selection; names and byte equality do not select variants."""
    c, target, files = candidate_inputs(candidate_path)
    library_records = Path(library_records).resolve(strict=True)
    test_records = Path(test_records).resolve(strict=True)
    library = checked_records(library_records); tests = checked_records(test_records)
    signature = definitions(parse(Path(target['path']).read_bytes()))
    choices = []
    for a in library['actions']:
        if a['kind'] != 'link' or library_action and a['actionIdentity'] != library_action:
            continue
        observed = a.get('observedOutput')
        if not observed:
            continue
        elf = parse(Path(observed['path']).read_bytes())
        if elf['machine'] != 62 or elf['elfType'] != 3 or elf['interpreter'] is not None:
            continue
        link = captured_link(a)
        matches = []
        for row in link['inputs']:
            raw = Path(row['path']).read_bytes()
            if raw.startswith(b'\x7fELF'):
                obj = parse(raw)
                if obj['elfType'] == 1 and definitions(obj) == signature:
                    matches.append(row)
        if len(matches) == 1:
            choices.append((link, matches[0], elf))
    if len(choices) != 1:
        raise ValueError('DEPLOYMENT_UNIQUE_LIBRARY_OBJECT_REQUIRED')
    link, original, elf = choices[0]
    producers = [a for a in library['actions'] if a['kind'] in ('compile', 'assemble')
                 and all((a.get('observedOutput') or {}).get(k) == original[k]
                         for k in ('path', 'resolvedPath', 'digest'))
                 and a.get('observedReturnCode') == 0 and a.get('exitStatusObserved') is True]
    if len(producers) != 1:
        raise ValueError('DEPLOYMENT_UNIQUE_OBJECT_PRODUCER_REQUIRED')
    producer = producers[0]
    interval = producer.get('observedInvocationInterval', {})
    linked = link['action'].get('observedInvocationInterval', {})
    if not (type(interval.get('finish')) is int and type(linked.get('start')) is int
            and interval['finish'] < linked['start']):
        raise ValueError('DEPLOYMENT_OBJECT_PRODUCER_ORDER_UNPROVEN')
    entries = []
    for a in tests['actions']:
        if a['kind'] != 'link' or entry_action and a['actionIdentity'] != entry_action:
            continue
        row = captured_link(a)
        entry_elf = parse(Path(row['originalOutput']['path']).read_bytes())
        positions = [x['argumentIndex'] for x in row['inputs']
                     if x['resolvedPath'] == link['originalOutput']['resolvedPath']
                     and x['digest'] == link['originalOutput']['digest']]
        if positions and entry_elf['machine'] == 62 and entry_elf['interpreter']:
            entries.append((row, positions))
    if len(entries) != 1:
        raise ValueError('DEPLOYMENT_UNIQUE_ENTRY_REQUIRED')
    entry, positions = entries[0]
    requirements_path = Path(requirements_path).resolve(strict=True)
    requirements = read(requirements_path); checked(requirements, 'requirementsIdentity')
    if requirements['schemaVersion'] != 'riscv2x86.native-external-requirements.v1':
        raise ValueError('DEPLOYMENT_REQUIREMENTS_SCHEMA_INVALID')
    requirements_bound = False
    if 'providerPath' in requirements:
        provider_path = requirements['providerPath']
        if digest(provider_path) != requirements['providerDigest']:
            raise ValueError('DEPLOYMENT_REQUIREMENTS_PROVIDER_CHANGED')
        provider = read(provider_path); checked(provider, 'inventoryIdentity')
        for p, expected in provider['inputDigests'].items():
            if digest(p) != expected:
                raise ValueError('DEPLOYMENT_REQUIREMENTS_INPUT_CHANGED')
        dependency = read(provider['dependencyPath']); checked(dependency, 'inventoryIdentity')
        if (dependency['inventoryIdentity'] != provider['dependencyInventoryIdentity']
                or dependency['candidateIdentity'] != c['candidateIdentity']
                or Path(dependency['candidatePath']).resolve(strict=True) != Path(candidate_path).resolve(strict=True)):
            raise ValueError('DEPLOYMENT_REQUIREMENTS_CANDIDATE_MISMATCH')
        requirements_bound = True
    env = environment if environment is not None else {
        k: v for k, v in os.environ.items() if k in ENV_KEYS or k.startswith('LD_')}
    env = dict(env, PATH=env.get('PATH', '/usr/bin:/bin'), LC_ALL='C')
    if any(not isinstance(k, str) or not isinstance(v, str) or '\0' in k+v for k, v in env.items()):
        raise ValueError('DEPLOYMENT_ENVIRONMENT_INVALID')
    body = {'schemaVersion': PLAN, 'candidatePath': str(Path(candidate_path).resolve()),
            'candidateIdentity': c['candidateIdentity'], 'candidateObject': target,
            'candidateInputs': files, 'libraryRecords': snapshot(library_records),
            'testRecords': snapshot(test_records), 'requirements': snapshot(requirements_path),
            'library': link, 'originalObject': original, 'originalObjectProducer': producer,
            'entry': entry, 'entryLibraryPositions': positions, 'soname': elf['soname'],
            'environment': env, 'environmentOrigin': 'explicit-current-observation-not-original-capture',
            'requirementsCandidateBindingVerified': requirements_bound,
            'selectionBasis': 'unique-full-definition-signature-and-captured-producer',
            'translationInstanceMappingVerified': False}
    return seal(body, 'deploymentPlanIdentity')


def validate(plan):
    checked(plan, 'deploymentPlanIdentity')
    if plan['schemaVersion'] != PLAN:
        raise ValueError('DEPLOYMENT_PLAN_SCHEMA_INVALID')
    for row in [*plan['candidateInputs'], plan['libraryRecords'], plan['testRecords'], plan['requirements']]:
        verify_snapshot(row)
    fresh = prepare(plan['candidatePath'], plan['libraryRecords']['path'], plan['testRecords']['path'],
                    plan['requirements']['path'], library_action=plan['library']['action']['actionIdentity'],
                    entry_action=plan['entry']['action']['actionIdentity'], environment=plan['environment'])
    if fresh != plan:
        raise ValueError('DEPLOYMENT_PLAN_REDERIVATION_MISMATCH')


def _argv(link, output, replacements, search_directory=None):
    argv = list(link['action']['arguments'])
    argv[0] = link['compiler']['resolvedPath']
    argv[link['outputIndex']] = str(output)
    valid = {r['argumentIndex'] for r in link['inputs']}
    if not set(replacements) <= valid:
        raise ValueError('DEPLOYMENT_REPLACEMENT_NOT_AN_INPUT')
    for i, path in replacements.items():
        argv[i] = str(path)
    if search_directory is not None:
        # Preserve each original path's relative order after the isolated route.
        # This is an explicit deployment change, never source-link equivalence.
        for row in link['searchPathArguments']:
            argv[row['argumentIndex']] = '-Wl,'+str(search_directory)+':'+':'.join(row['directories'])
    return argv


def attribution(candidate, library, mapfile):
    from .native_link_attribution import sections, contributions
    raw = Path(candidate).read_bytes(); elf = parse(raw); table = sections(raw)
    final = parse(Path(library).read_bytes())
    mapped = contributions(Path(mapfile).read_text())
    rows = []
    for s in elf['staticSymbols']:
        if not s['name'] or not s['defined'] or s['binding'] == 0:
            continue
        index = s['sectionIndex']; reason = None
        supported = (s['binding'] == 1 and s['type'] in (1, 2) and s['size'] > 0
                     and 0 < index < len(table) and table[index]['flags'] & 2
                     and not table[index]['flags'] & 0x400)
        owners = []; symbols = []
        if not supported:
            reason = 'DEFINITION_KIND_UNSUPPORTED'
        else:
            sec = table[index]
            owners = [r for r in mapped if r['owner'] == str(candidate)
                      and r['section'] == sec['name'] and r['size'] == sec['size']]
            symbols = [x for x in final['staticSymbols'] if x['name'] == s['name'] and x['defined']
                       and x['binding'] == 1 and x['type'] == s['type']]
            if (len(owners) != 1 or len(symbols) != 1 or s['value']+s['size'] > sec['size']
                    or symbols[0]['value'] != owners[0]['address']+s['value']
                    or symbols[0]['size'] != s['size']):
                reason = 'DEFINITION_CONTRIBUTION_AMBIGUOUS'
        rows.append({'symbol': s, 'inputContributions': owners, 'finalSymbols': symbols,
                     'verified': reason is None, 'reason': reason})
    return {'definitions': rows, 'candidateDefinitionAttributionVerified': bool(rows) and all(r['verified'] for r in rows),
            'scope': 'gnu-bfd-explicit-object-input-contributions-not-runtime-binding'}


def implicit_inputs(mapfile, cwd):
    """Inventory observed LOAD directives, without claiming linker-script closure."""
    result = []
    for line in Path(mapfile).read_text().splitlines():
        if line.startswith('LOAD '):
            result.append(snapshot(line[5:], cwd))
    if not result:
        raise ValueError('DEPLOYMENT_LINK_MAP_LOAD_INPUTS_REQUIRED')
    return result


def execute(plan, output, timeout=300):
    validate(plan)
    root = Path(output).absolute(); root.mkdir(); root = root.resolve()
    (root/'plan.json').write_text(json.dumps(plan, indent=2)+'\n')
    stage_names = ['baseline-library', 'derived-library', 'baseline-entry', 'derived-entry']
    state = {'schemaVersion': RESULT, 'deploymentPlanIdentity': plan['deploymentPlanIdentity'],
             'status': 'running', 'primaryFailure': None,
             'stages': [{'id': name, 'status': 'not_run'} for name in stage_names],
             'semanticApproval': False, 'productionAcceptanceComplete': False}
    def save():
        (root/'run-status.json').write_text(json.dumps(seal(state, 'stateIdentity'), indent=2)+'\n')
    save(); artifacts = []; commands = []; loads = []
    try:
        candidate = root/'candidate.o'
        candidate.write_bytes(Path(plan['candidateObject']['path']).read_bytes())
        verify_snapshot(plan['candidateObject'])
        if digest(candidate) != plan['candidateObject']['digest']:
            raise ValueError('DEPLOYMENT_CANDIDATE_COPY_MISMATCH')
        libdir = root/'lib'; libdir.mkdir()
        derived_lib = libdir/Path(plan['library']['originalOutput']['path']).name
        derived_entry = root/'program'
        steps = [('baseline-library', plan['library'], root/'baseline-library', {}, None),
                 ('derived-library', plan['library'], derived_lib,
                  {plan['originalObject']['argumentIndex']: candidate}, None),
                 ('baseline-entry', plan['entry'], root/'baseline-entry', {}, None),
                 ('derived-entry', plan['entry'], derived_entry,
                  {i: derived_lib for i in plan['entryLibraryPositions']}, libdir)]
        for index, (name, link, dest, replacements, route) in enumerate(steps):
            folder = root/name if name.startswith('derived-') else root/(name+'-logs')
            folder.mkdir()
            row = state['stages'][index]; row['status'] = 'running'; save()
            for snap in [link['compiler'], link['originalOutput'], *link['inputs']]:
                verify_snapshot({k: snap[k] for k in ('path', 'resolvedPath', 'digest')})
            argv = _argv(link, dest, replacements, '$ORIGIN/lib' if route else None)
            mapfile = folder/'link.map'
            # Instrumentation is additional; all captured argument tokens retain order.
            argv += ['-Wl,-t', '-Xlinker', '-Map', '-Xlinker', str(mapfile)]
            code, reason = command(argv, link['directory'], plan['environment'], folder, timeout, 64*1024*1024)
            commands.append({'stage': name, 'arguments': argv, 'workingDirectory': link['directory'],
                             'returnCode': code, 'failureReason': reason})
            (root/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
            if code != 0 or reason:
                raise ValueError('DEPLOYMENT_LINK_FAILED:'+name+':'+str(reason or code))
            elf = parse(dest.read_bytes())
            if elf['machine'] != 62 or elf['elfType'] not in (2, 3):
                raise ValueError('DEPLOYMENT_OUTPUT_ELF_INVALID')
            artifacts.append({'stage': name, **snapshot(dest), 'elf': elf})
            loads.append({'stage': name, 'inputs': implicit_inputs(mapfile, link['directory'])})
            if name == 'derived-library':
                soname = elf['soname']
                if soname != plan['soname'] or not soname or Path(soname).name != soname:
                    raise ValueError('DEPLOYMENT_SONAME_NOT_PRESERVED')
                alias = libdir/soname
                if alias != dest:
                    alias.symlink_to(dest.name)
            row.update(status='complete', artifactDigest=digest(dest)); save()
        validate(plan)
        baseline = {a['stage']: a for a in artifacts}
        baseline_match = all(baseline['baseline-'+name]['digest'] == plan[name]['originalOutput']['digest']
                             for name in ('library', 'entry'))
        owner = attribution(candidate, derived_lib, root/'derived-library/link.map')
        for group in loads:
            for item in group['inputs']:
                verify_snapshot(item)
        body = {'schemaVersion': RESULT, 'deploymentPlanIdentity': plan['deploymentPlanIdentity'],
                'planPath': str(root/'plan.json'), 'planDigest': digest(root/'plan.json'),
                'artifacts': artifacts, 'commands': commands, 'linkLoadInputs': loads,
                'capturedInputReplacementVerified': True, 'entryLibraryOperandsReplaced': True,
                'capturedBaselineBytesReproduced': baseline_match,
                'derivedLibraryBuildComplete': True, 'derivedEntryBuildComplete': True,
                'candidateObjectDigest': digest(candidate), **owner,
                'runtimeLibrarySelectionVerified': False, 'translatedInstanceExecutionVerified': False,
                'translationInstanceMappingVerified': False, 'externalContractClosureComplete': False,
                'targetDependencyLinkClosureComplete': False, 'semanticApproval': False,
                'productionAcceptanceComplete': False,
                'blockers': ['CANDIDATE_DEPLOYMENT_CONTEXT_AND_PROOF_REQUIRED',
                             'LINK_CONTRIBUTION_AND_IMPLICIT_INPUT_CLOSURE_REQUIRED',
                             'RUNTIME_BINDING_REQUIRED', 'EXTERNAL_BEHAVIOR_CONTRACTS_REQUIRED']}
        if not baseline_match:
            body['blockers'].append('CAPTURED_BASELINE_BYTES_NOT_REPRODUCED')
        if not owner['candidateDefinitionAttributionVerified']:
            body['blockers'].append('CANDIDATE_DEFINITION_ATTRIBUTION_UNRESOLVED')
        body['evidenceDigests'] = {str(p.relative_to(root)): digest(p) for p in root.rglob('*')
                                   if p.is_file() and p.name not in ('run-status.json', 'result.json')}
        result = seal(body, 'deploymentIdentity')
        (root/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        state['status'] = 'complete'; save()
        return result
    except (OSError, ValueError, KeyError, TypeError) as exc:
        for row in state['stages']:
            if row['status'] == 'running':
                row['status'] = 'failed'
        state.update(status='failed', primaryFailure={'type': type(exc).__name__, 'detail': str(exc)})
        save()
        raise


def check_result(path):
    path = Path(path).resolve(strict=True); value = read(path)
    checked(value, 'deploymentIdentity')
    if value['schemaVersion'] != RESULT or value['planPath'] != str(path.parent/'plan.json'):
        raise ValueError('DEPLOYMENT_RESULT_SCHEMA_INVALID')
    if digest(value['planPath']) != value['planDigest']:
        raise ValueError('DEPLOYMENT_PLAN_CHANGED')
    validate(read(value['planPath']))
    fresh_inventory = {str(p.relative_to(path.parent)): digest(p) for p in path.parent.rglob('*')
                       if p.is_file() and p.name not in ('run-status.json', 'result.json')}
    if fresh_inventory != value['evidenceDigests']:
        raise ValueError('DEPLOYMENT_EVIDENCE_INVENTORY_CHANGED')
    for name, expected in value['evidenceDigests'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or digest(path.parent/name) != expected:
            raise ValueError('DEPLOYMENT_EVIDENCE_CHANGED')
    for row in value['artifacts']:
        verify_snapshot({k: row[k] for k in ('path', 'resolvedPath', 'digest')})
        if parse(Path(row['path']).read_bytes()) != row['elf']:
            raise ValueError('DEPLOYMENT_ELF_CHANGED')
    plan = read(value['planPath']); root = path.parent
    expected_paths = {'baseline-library': root/'baseline-library',
                      'derived-library': root/'lib'/Path(plan['library']['originalOutput']['path']).name,
                      'baseline-entry': root/'baseline-entry', 'derived-entry': root/'program'}
    if (len(value['artifacts']) != 4 or len(value['commands']) != 4
            or [a['stage'] for a in value['artifacts']] != list(expected_paths)):
        raise ValueError('DEPLOYMENT_STAGE_SET_INVALID')
    for a, c in zip(value['artifacts'], value['commands']):
        stage = a['stage']; link = plan['library' if stage.endswith('library') else 'entry']
        replacements = ({plan['originalObject']['argumentIndex']: root/'candidate.o'} if stage == 'derived-library'
                        else {i: expected_paths['derived-library'] for i in plan['entryLibraryPositions']}
                        if stage == 'derived-entry' else {})
        argv = _argv(link, expected_paths[stage], replacements, '$ORIGIN/lib' if stage == 'derived-entry' else None)
        folder = root/(stage+'-logs') if stage.startswith('baseline-') else root/stage
        argv += ['-Wl,-t', '-Xlinker', '-Map', '-Xlinker', str(folder/'link.map')]
        if (a['path'] != str(expected_paths[stage]) or c != {'stage': stage, 'arguments': argv,
                'workingDirectory': link['directory'], 'returnCode': 0, 'failureReason': None}):
            raise ValueError('DEPLOYMENT_COMMAND_REDERIVATION_MISMATCH')
    if digest(root/'candidate.o') != plan['candidateObject']['digest']:
        raise ValueError('DEPLOYMENT_CANDIDATE_COPY_CHANGED')
    if value['candidateObjectDigest'] != plan['candidateObject']['digest']:
        raise ValueError('DEPLOYMENT_CANDIDATE_DIGEST_MISMATCH')
    owner = attribution(root/'candidate.o', expected_paths['derived-library'], root/'derived-library/link.map')
    if any(value[k] != v for k, v in owner.items()):
        raise ValueError('DEPLOYMENT_ATTRIBUTION_REDERIVATION_MISMATCH')
    baseline = {a['stage']: a for a in value['artifacts']}
    same = all(baseline['baseline-'+name]['digest'] == plan[name]['originalOutput']['digest'] for name in ('library', 'entry'))
    if value['capturedBaselineBytesReproduced'] is not same:
        raise ValueError('DEPLOYMENT_BASELINE_REDERIVATION_MISMATCH')
    if any(value.get(k) is not True for k in ('capturedInputReplacementVerified',
            'entryLibraryOperandsReplaced', 'derivedLibraryBuildComplete', 'derivedEntryBuildComplete')):
        raise ValueError('DEPLOYMENT_BUILD_FACT_MISMATCH')
    if [g['stage'] for g in value['linkLoadInputs']] != list(expected_paths):
        raise ValueError('DEPLOYMENT_LOAD_INPUT_STAGE_SET_INVALID')
    for group in value['linkLoadInputs']:
        folder = root/(group['stage']+'-logs') if group['stage'].startswith('baseline-') else root/group['stage']
        link = plan['library' if group['stage'].endswith('library') else 'entry']
        if implicit_inputs(folder/'link.map', link['directory']) != group['inputs']:
            raise ValueError('DEPLOYMENT_LOAD_INPUT_CHANGED')
    # Recomputed scope, not a caller-supplied approval boolean.
    if any(value.get(k) is not False for k in ('semanticApproval', 'productionAcceptanceComplete',
            'runtimeLibrarySelectionVerified', 'externalContractClosureComplete',
            'targetDependencyLinkClosureComplete', 'translationInstanceMappingVerified')):
        raise ValueError('DEPLOYMENT_UNSUPPORTED_APPROVAL')
    return value


def replay(path, output, timeout=300):
    original = check_result(path); fresh = execute(read(original['planPath']), output, timeout)
    # Paths and map headers change with the isolated output directory. Do not
    # strip differing bytes and call that an independent equivalence proof.
    def projection(value):
        result = []
        for artifact in value['artifacts']:
            raw = Path(artifact['path']).read_bytes(); elf = parse(raw)
            # Full ELF equality is mandatory here. A nondeterministic build is
            # an unresolved independent replay, not automatic equivalence.
            result.append((artifact['stage'], artifact['digest'], elf['machine'], elf['soname']))
        return result
    matched = projection(original) == projection(fresh)
    check_result(path)
    body = {'schemaVersion': 'riscv2x86.captured-deployment-replay.v1',
            'originalDeploymentIdentity': original['deploymentIdentity'],
            'freshDeploymentIdentity': fresh['deploymentIdentity'], 'artifactBytesReproduced': matched,
            'independentDeploymentRebuildComplete': matched,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    result = seal(body, 'replayIdentity')
    (Path(output)/'replay.json').write_text(json.dumps(result, indent=2)+'\n')
    return result
