"""Replayable source archive/object dependency inventory, never link approval."""
from pathlib import Path

from .native_dependency_evidence import archive_members, elf_symbols, closure, bytes_digest
from .native_audit_evidence import strict_json
from .project_build_records import identity
from .project_compile_context import digest
from .l3_trace_support import require_json_match

SCHEMA = 'riscv2x86.native-dependency-inventory.v1'


def read(path):
    return strict_json(Path(path).read_bytes())


def checked_records(path):
    from .project_build_capture import inventory
    value = read(path)
    if (value.get('schemaVersion') != 'riscv2x86.project-build-records.v1'
            or value.get('inventoryIdentity') != identity({k:v for k,v in value.items() if k != 'inventoryIdentity'})):
        raise ValueError('DEPENDENCY_ORIGINAL_BUILD_RECORDS_REQUIRED')
    fresh = inventory(value['captureConfig'], stage=value['stageSelection'])
    if not fresh['importComplete'] or fresh['unresolved'] or fresh['selectedRunFailures']:
        raise ValueError('DEPENDENCY_CAPTURE_REPLAY_INCOMPLETE')
    require_json_match(value['actions'], fresh['actions'], 'DEPENDENCY_CAPTURE_ACTIONS_CHANGED')
    for action in value['actions']:
        if action['actionIdentity'] != identity({k:v for k,v in action.items() if k != 'actionIdentity'}):
            raise ValueError('DEPENDENCY_CAPTURE_ACTION_IDENTITY_INVALID')
    return value


def analyze(root_raw, archive_raw, actions):
    root = elf_symbols(root_raw)
    rows = []; blockers = []; inspected = {}
    for member in archive_members(archive_raw):
        row = {k:v for k,v in member.items() if k != 'bytes'}
        row['memberId'] = str(row['headerOffset']) + ':' + row['digest']
        row['elf'] = elf_symbols(member['bytes'])
        if row['elf']['machine'] != root['machine'] or row['elf']['abiFlags'] != root['abiFlags']:
            blockers.append({'reason':'MEMBER_ARCHITECTURE_OR_FLAGS_DIFFER', 'memberId':row['memberId']})
        # Content identity finds candidates; exact archive argv edges are recorded separately.
        row['contentMatchingActions'] = []
        for action in actions:
            observed = action.get('observedOutput') or {}
            if observed.get('digest') != row['digest'] or action.get('kind') not in ('compile', 'assemble', 'copy'):
                continue
            path = Path(observed['path'])
            actual = str(path.resolve(strict=True))
            expected = observed['digest']
            if observed.get('resolvedPath') != actual:
                raise ValueError('DEPENDENCY_PROVIDER_PATH_CHANGED:' + str(path))
            if str(path) not in inspected:
                inspected[str(path)] = digest(path)
            if inspected[str(path)] != expected:
                raise ValueError('DEPENDENCY_PROVIDER_CONTENT_CHANGED:' + str(path))
            if action.get('exitStatusObserved') is not True or type(action.get('observedReturnCode')) is not int or action['observedReturnCode'] != 0:
                raise ValueError('DEPENDENCY_PROVIDER_SUCCESS_UNOBSERVED')
            row['contentMatchingActions'].append({
                'actionIdentity': action['actionIdentity'], 'kind':action['kind'],
                'path':str(path), 'resolvedPath':actual, 'digest':expected,
                'directory':action['directory'], 'arguments':action['arguments']})
        if not row['contentMatchingActions']:
            row['provenanceStatus'] = 'unbound'
        else:
            row['provenanceStatus'] = 'content-matches-captured-output'
        rows.append(row)
    graph = closure(root, rows)
    selected = set(graph['selectedObjects'])
    for row in rows:
        if row['memberId'] not in selected: continue
        if row['provenanceStatus'] == 'unbound':
            blockers.append({'reason':'SELECTED_MEMBER_SOURCE_UNBOUND', 'memberId':row['memberId']})
        elif len(row['contentMatchingActions']) > 1:
            blockers.append({'reason':'SELECTED_MEMBER_MULTIPLE_BUILD_IDENTITIES', 'memberId':row['memberId']})
    blockers.extend(graph['blockers'])
    for path, expected in inspected.items():
        if digest(path) != expected: raise ValueError('DEPENDENCY_CLOSING_PROVIDER_CHANGED:' + path)
    return {'rootElf':root, 'members':rows, 'graph':graph, 'blockers':blockers,
            'providerSnapshots':[{'path':p,'digest':h} for p,h in sorted(inspected.items())]}


def acquire(candidate_path, records_path, archive_path):
    paths = [Path(p).resolve(strict=True) for p in (candidate_path, records_path, archive_path)]
    candidate_path, records_path, archive_path = paths
    inputs = {str(p):digest(p) for p in paths}
    candidate = read(candidate_path)
    if candidate.get('schemaVersion') != 'riscv2x86.native-integer-candidate.v1':
        raise ValueError('DEPENDENCY_NATIVE_CANDIDATE_REQUIRED')
    if candidate.get('candidateIdentity') != identity({k:v for k,v in candidate.items() if k != 'candidateIdentity'}):
        raise ValueError('DEPENDENCY_CANDIDATE_IDENTITY_INVALID')
    if candidate.get('semanticApproval') is not False or candidate.get('productionAcceptanceComplete') is not False:
        raise ValueError('DEPENDENCY_CANDIDATE_SCOPE_INVALID')
    directory = Path(candidate['candidatePath']).parent
    for name, expected in candidate['artifactDigests'].items():
        if Path(name).name != name:
            raise ValueError('DEPENDENCY_CANDIDATE_ARTIFACT_NAME_INVALID')
        path = directory/name; inputs[str(path)] = expected
        if digest(path) != expected: raise ValueError('DEPENDENCY_CANDIDATE_ARTIFACT_CHANGED:' + name)
    root_path = directory/'source.o'; target_path = directory/'target.o'
    source_raw = root_path.read_bytes(); target_raw = target_path.read_bytes()
    if bytes_digest(source_raw) != candidate['sourceObjectDigest'] or bytes_digest(target_raw) != candidate['targetObjectDigest']:
        raise ValueError('DEPENDENCY_CANDIDATE_OBJECT_CHANGED')
    records = checked_records(records_path)
    detail = analyze(source_raw, archive_path.read_bytes(), records['actions'])
    target = elf_symbols(target_raw)
    if detail['rootElf']['machine'] != 243 or target['machine'] != 62:
        raise ValueError('DEPENDENCY_RV64_TO_X86_OBJECTS_REQUIRED')
    def signature(elf, field):
        return sorted((s['name'],s['binding'],s['type'],s['visibility']) for s in elf[field])
    definitions_match = signature(detail['rootElf'], 'definitions') == signature(target, 'definitions')
    blockers = detail['blockers']
    if not definitions_match: blockers.append({'reason':'SOURCE_TARGET_EXPORTED_SYMBOLS_DIFFER'})
    archive_actions = []
    for action in records['actions']:
        if action['kind'] != 'archive': continue
        # Preserve complete argv, cwd and IDs; do not infer GNU ar semantics by basename.
        archive_actions.append({k:action.get(k) for k in (
            'actionIdentity','directory','arguments','observedReturnCode','observedOutput')})
    for path, expected in inputs.items():
        if digest(path) != expected: raise ValueError('DEPENDENCY_CLOSING_INPUT_CHANGED:' + path)
    body = {'schemaVersion':SCHEMA,
            'candidatePath':str(candidate_path), 'recordsPath':str(records_path), 'archivePath':str(archive_path),
            'inputDigests':inputs, 'candidateIdentity':candidate['candidateIdentity'],
            'captureActionsReplayComplete':True, 'candidateArtifactIntegrityComplete':True,
            **detail, 'targetElf':target, 'exportedSymbolSignaturesMatch':definitions_match,
            'archiveActions':archive_actions, 'inventoryComplete':True,
            'status':'blocked' if blockers else 'inventory-only',
            'archiveActionSelectionVerified':False, 'targetDependencyCompatibilityVerified':False,
            'typedCallContractVerified':False, 'programObservationVerified':False,
            'semanticApproval':False, 'productionAcceptanceComplete':False,
            'requiredWork':['ARCHIVE_ACTION_AND_VARIANT_SELECTION', 'TARGET_DEPENDENCY_BUILD_CONTRACT',
                'TYPED_CALL_OBJECT_AND_EFFECT_CONTRACT', 'AUTHORIZED_TARGET_LINK',
                'CALIBRATED_PROGRAM_OBSERVATION', 'L1_L3_AND_INDEPENDENT_PROGRAM_AUDIT']}
    return dict(body, inventoryIdentity=identity(body))


def replay(value):
    if value.get('schemaVersion') != SCHEMA or value.get('inventoryIdentity') != identity(
            {k:v for k,v in value.items() if k != 'inventoryIdentity'}):
        raise ValueError('DEPENDENCY_INVENTORY_IDENTITY_INVALID')
    fresh = acquire(value['candidatePath'], value['recordsPath'], value['archivePath'])
    require_json_match(fresh, value, 'DEPENDENCY_INDEPENDENT_REPLAY_MISMATCH')
    return {'dependencyInventoryReplayComplete':True, 'inventoryIdentity':value['inventoryIdentity'],
            'semanticApproval':False, 'productionAcceptanceComplete':False}
