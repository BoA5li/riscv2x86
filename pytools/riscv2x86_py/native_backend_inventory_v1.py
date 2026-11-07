"""Frozen Phase164 projection for replaying historical v1 inventories only.

New acquisitions must use native_backend_inventory.inspect (v2). Old diagnostics
are preserved exactly; they never validate calibration or grant acceptance.
"""
from pathlib import Path
from .native_audit_evidence import strict_json
from .native_dependency_evidence import bytes_digest
from .project_build_records import identity


def inspect(paths):
    queue = [(str(Path(p).absolute()), None) for p in paths]
    roots = [p for p, _ in queue]; rows = {}; blockers = []; snapshots = {}
    while queue:
        name, expected = queue.pop(0)
        if name in rows:
            if expected is not None and rows[name].get('digest') != expected:
                blockers.append({'path':name,'reason':'BASE_BACKEND_DIGEST_MISMATCH'})
            continue
        if len(rows) >= 64: raise ValueError('BACKEND_REFERENCE_LIMIT_EXCEEDED')
        path = Path(name)
        row = {'path':name}; rows[name] = row
        if not path.is_file():
            row['status'] = 'missing'
            blockers.append({'path':name,'reason':'BACKEND_MANIFEST_MISSING'}); continue
        raw = path.read_bytes(); sha = bytes_digest(raw); snapshots[name] = sha
        row.update(digest=sha, resolvedPath=str(path.resolve(strict=True)))
        if expected is not None and sha != expected:
            blockers.append({'path':name,'reason':'BASE_BACKEND_DIGEST_MISMATCH'})
        try:
            value = strict_json(raw)
            if not isinstance(value,dict) or not isinstance(value.get('schemaVersion'),str):
                raise ValueError('BACKEND_OBJECT_SCHEMA_REQUIRED')
        except (ValueError, UnicodeError) as exc:
            row.update(status='malformed', detail=str(exc))
            blockers.append({'path':name,'reason':'BACKEND_MANIFEST_MALFORMED'}); continue
        row.update(status='read',schemaVersion=value['schemaVersion'])
        if 'backendIdentity' in value:
            row['manifestIdentityMatches'] = value['backendIdentity'] == identity(
                {k:v for k,v in value.items() if k != 'backendIdentity'})
            if not row['manifestIdentityMatches']:
                blockers.append({'path':name,'reason':'BACKEND_MANIFEST_IDENTITY_MISMATCH'})
        row['boundFiles'] = []
        files = value.get('files', {})
        if not isinstance(files,dict):
            blockers.append({'path':name,'reason':'BACKEND_FILES_SCHEMA_UNSUPPORTED'})
            files = {}
        for filename, recorded in sorted(files.items()):
            if not isinstance(filename,str) or not Path(filename).is_absolute() or not isinstance(recorded,str):
                blockers.append({'path':name,'reason':'BACKEND_FILE_BINDING_INVALID'}); continue
            item = {'path':filename,'expectedDigest':recorded}
            p = Path(filename)
            if p.is_file():
                actual = bytes_digest(p.read_bytes()); snapshots[filename] = actual
                item.update(actualDigest=actual,matched=actual == recorded)
            else:item.update(actualDigest=None,matched=False)
            if not item['matched']:
                blockers.append({'path':filename,'owner':name,'reason':'BACKEND_BOUND_FILE_MISSING_OR_CHANGED'})
            row['boundFiles'].append(item)
        if 'baseBackendPath' in value:
            base = value['baseBackendPath']; expected_base = value.get('baseBackendDigest')
            if not isinstance(base,str) or not Path(base).is_absolute() or not isinstance(expected_base,str):
                blockers.append({'path':name,'reason':'BACKEND_BASE_BINDING_INVALID'})
            else:
                row['baseBackendPath'] = base
                queue.append((base,expected_base))
        row['calibrationValidationPerformed'] = False
    for name, expected in snapshots.items():
        if not Path(name).is_file() or bytes_digest(Path(name).read_bytes()) != expected:
            raise ValueError('BACKEND_INVENTORY_CLOSING_FILE_CHANGED:' + name)
    # Recheck negative observations, too.
    if any(Path(name).is_file() for name,r in rows.items() if r.get('status') == 'missing'):
        raise ValueError('BACKEND_INVENTORY_CLOSING_AVAILABILITY_CHANGED')
    body = {'schemaVersion':'riscv2x86.native-backend-inventory.v1', 'roots':roots,
            'manifests':list(rows.values()), 'blockers':blockers,
            'staticInventoryComplete':True, 'backendValidationPerformed':False,
            'programObservationCapabilityVerified':False,
            'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,inventoryIdentity=identity(body))


def replay(value):
    if value.get('inventoryIdentity') != identity({k:v for k,v in value.items() if k != 'inventoryIdentity'}):
        raise ValueError('BACKEND_INVENTORY_IDENTITY_INVALID')
    if inspect(value['roots']) != value: raise ValueError('BACKEND_INVENTORY_REPLAY_MISMATCH')
    return {'staticBackendInventoryReplayComplete':True, 'semanticApproval':False,
            'productionAcceptanceComplete':False}
