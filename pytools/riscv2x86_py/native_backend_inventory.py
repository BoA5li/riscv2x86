"""Static, versioned backend observations; never execute a manifest command.

Missing evidence and changed evidence are different observations. Every binding
and base reference remains explicit. A consistent replay can still be blocked.
"""
from collections import Counter
from pathlib import Path
import stat

from .native_audit_evidence import strict_json
from .native_dependency_evidence import bytes_digest
from .project_build_records import identity

SCHEMA = 'riscv2x86.native-backend-inventory.v2'
LEGACY_SCHEMA = 'riscv2x86.native-backend-inventory.v1'


def _observe(name):
    path = Path(name)
    try:
        mode = path.stat().st_mode
        if not stat.S_ISREG(mode):
            return {'status': 'not-regular-file'}
        resolved = str(path.resolve(strict=True))
        raw = path.read_bytes()
        return {'status': 'present', 'resolvedPath': resolved,
                'digest': bytes_digest(raw)}, raw
    except FileNotFoundError:
        return {'status': 'missing'}
    except OSError as exc:
        return {'status': 'unreadable', 'errorType': type(exc).__name__,
                'errno': exc.errno}


def _observation(name):
    result = _observe(name)
    return result if isinstance(result, tuple) else (result, None)


def diagnostic_summary(blockers, references=()):
    paths = {}
    for row in blockers:
        item = paths.setdefault(row['path'], {'path': row['path'], 'reasons': set(), 'owners': set()})
        item['reasons'].add(row['reason'])
        if row.get('owner') is not None: item['owners'].add(row['owner'])
    for edge in references:
        if edge['path'] in paths:
            paths[edge['path']]['owners'].add(edge['owner'])
    return {'blockerCount': len(blockers), 'affectedPathCount': len(paths),
            'reasonCounts': dict(sorted(Counter(row['reason'] for row in blockers).items())),
            'paths': [{'path': p, 'reasons': sorted(v['reasons']), 'owners': sorted(v['owners'])}
                      for p, v in sorted(paths.items())]}


def inspect(paths):
    roots = [str(Path(p).absolute()) for p in paths]
    queue = list(roots); rows = {}; blockers = []; observations = {}; raw_files = {}; edges = []

    def observe(name):
        if name not in observations:
            observation, raw = _observation(name)
            observations[name] = observation
            raw_files[name] = raw
        return observations[name]

    if not roots:
        blockers.append({'path': '<inventory>', 'reason': 'BACKEND_ROOTS_EMPTY'})
    while queue:
        name = queue.pop(0)
        if name in rows: continue
        if len(rows) >= 64: raise ValueError('BACKEND_REFERENCE_LIMIT_EXCEEDED')
        observation = observe(name)
        row = {'path': name, 'observation': observation}; rows[name] = row
        if observation['status'] != 'present':
            reason = {'missing': 'BACKEND_MANIFEST_MISSING',
                      'not-regular-file': 'BACKEND_MANIFEST_NOT_REGULAR',
                      'unreadable': 'BACKEND_MANIFEST_UNREADABLE'}[observation['status']]
            row['status'] = observation['status']
            blockers.append({'path': name, 'reason': reason, 'observation': observation})
            continue
        row.update(digest=observation['digest'], resolvedPath=observation['resolvedPath'])
        try:
            value = strict_json(raw_files[name])
            if not isinstance(value, dict) or not isinstance(value.get('schemaVersion'), str):
                raise ValueError('BACKEND_OBJECT_SCHEMA_REQUIRED')
        except (ValueError, UnicodeError) as exc:
            row.update(status='malformed', detail=str(exc))
            blockers.append({'path': name, 'reason': 'BACKEND_MANIFEST_MALFORMED'})
            continue
        row.update(status='read', schemaVersion=value['schemaVersion'])
        if 'backendIdentity' in value:
            row['manifestIdentityMatches'] = value['backendIdentity'] == identity(
                {k: v for k, v in value.items() if k != 'backendIdentity'})
            if not row['manifestIdentityMatches']:
                blockers.append({'path': name, 'reason': 'BACKEND_MANIFEST_IDENTITY_MISMATCH'})
        row['boundFiles'] = []
        files = value.get('files', {})
        if not isinstance(files, dict):
            blockers.append({'path': name, 'reason': 'BACKEND_FILES_SCHEMA_UNSUPPORTED'})
            files = {}
        for filename, expected in sorted(files.items()):
            if not isinstance(filename, str) or not Path(filename).is_absolute() or not isinstance(expected, str):
                blockers.append({'path': name, 'reason': 'BACKEND_FILE_BINDING_INVALID'})
                continue
            observation = observe(filename)
            item = {'path': filename, 'expectedDigest': expected,
                    'actualDigest': observation.get('digest'), 'observation': observation,
                    'matched': observation.get('digest') == expected and observation['status'] == 'present'}
            if not item['matched']:
                reason = {'missing': 'BACKEND_BOUND_FILE_MISSING',
                          'not-regular-file': 'BACKEND_BOUND_FILE_NOT_REGULAR',
                          'unreadable': 'BACKEND_BOUND_FILE_UNREADABLE',
                          'present': 'BACKEND_BOUND_FILE_DIGEST_MISMATCH'}[observation['status']]
                blockers.append({'path': filename, 'owner': name, 'reason': reason,
                                 'expectedDigest': expected, 'actualDigest': item['actualDigest'],
                                 'observation': observation})
            row['boundFiles'].append(item)
        if 'baseBackendPath' in value:
            base = value['baseBackendPath']; expected = value.get('baseBackendDigest')
            if not isinstance(base, str) or not Path(base).is_absolute() or not isinstance(expected, str):
                blockers.append({'path': name, 'reason': 'BACKEND_BASE_BINDING_INVALID'})
            else:
                base = str(Path(base).absolute())
                row['baseBackendPath'] = base
                edges.append({'owner': name, 'path': base, 'expectedDigest': expected})
                queue.append(base)
        row['calibrationValidationPerformed'] = False

    for edge in edges:
        observation = observations[edge['path']]
        edge['observation'] = observation
        edge['actualDigest'] = observation.get('digest')
        if observation['status'] != 'present':
            # Missing/unreadable is not a content comparison. The manifest row
            # carries one observation; all owner expectations remain in edges.
            edge['status'] = 'unavailable'
        elif observation['digest'] != edge['expectedDigest']:
            edge['status'] = 'digest-mismatch'
            blockers.append({'path': edge['path'], 'owner': edge['owner'],
                'reason': 'BASE_BACKEND_DIGEST_MISMATCH', 'expectedDigest': edge['expectedDigest'],
                'actualDigest': observation['digest']})
        else:
            edge['status'] = 'digest-matched'
    for name, expected in observations.items():
        actual, _ = _observation(name)
        if actual != expected:
            raise ValueError('BACKEND_INVENTORY_CLOSING_OBSERVATION_CHANGED:' + name)
    summary = diagnostic_summary(blockers, edges)
    body = {'schemaVersion': SCHEMA, 'roots': roots, 'manifests': list(rows.values()),
            'baseReferences': edges, 'blockers': blockers, 'diagnosticSummary': summary,
            'status': 'blocked' if blockers else 'inventory-only',
            'staticInventoryComplete': True, 'backendValidationPerformed': False,
            'programObservationCapabilityVerified': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, inventoryIdentity=identity(body))


def replay(value):
    if value.get('inventoryIdentity') != identity({k: v for k, v in value.items() if k != 'inventoryIdentity'}):
        raise ValueError('BACKEND_INVENTORY_IDENTITY_INVALID')
    schema = value.get('schemaVersion')
    if schema == LEGACY_SCHEMA:
        from .native_backend_inventory_v1 import inspect as legacy_inspect
        fresh = legacy_inspect(value['roots'])
    elif schema == SCHEMA:
        fresh = inspect(value['roots'])
    else:
        raise ValueError('BACKEND_INVENTORY_SCHEMA_UNSUPPORTED')
    if fresh != value: raise ValueError('BACKEND_INVENTORY_REPLAY_MISMATCH')
    summary = diagnostic_summary(value['blockers'], value.get('baseReferences', []))
    return {'staticBackendInventoryReplayComplete': True,
            'replayedInventoryIdentity': value['inventoryIdentity'], 'replayedSchemaVersion': schema,
            'replayedBlockerCount': len(value['blockers']), 'diagnosticSummary': summary,
            'status': 'blocked' if value['blockers'] else 'inventory-only',
            'backendValidationPerformed': False, 'programObservationCapabilityVerified': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
