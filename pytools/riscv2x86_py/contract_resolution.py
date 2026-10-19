"""Inventory-time contract discovery. Discovery never grants semantic approval."""
from pathlib import Path
from hashlib import sha256
from .route_authority import content_identity


def resolve_contract_files(source, relative, specifications):
    source_digest = 'sha256:' + sha256(Path(source).read_bytes()).hexdigest()
    records = []
    for family, root, suffix in specifications:
        path = None if root is None else Path(root) / (relative + suffix)
        item = {'family': family, 'artifactPath': '' if path is None else str(path),
                'sourceDigest': source_digest, 'artifactDigest': '',
                'disposition': 'not_provided', 'semanticApproval': False}
        if path is not None:
            if not path.exists():
                item['disposition'] = 'not_found'
            elif not path.is_file():
                item['disposition'] = 'invalid'
                item['exceptionType'] = 'NotAFile'
            else:
                # Do not label an unparsed contract "accepted". Its consumer
                # must separately validate schema and semantic applicability.
                item['artifactDigest'] = 'sha256:' + sha256(path.read_bytes()).hexdigest()
                item['disposition'] = 'resolved_pending_validation'
        records.append(item)
    payload = {'schemaVersion': 'riscv2x86.contract-resolution.v1',
               'sourceRelativePath': relative, 'sourceDigest': source_digest,
               'contracts': records}
    return {**payload, 'resolutionIdentity': content_identity(payload)}
