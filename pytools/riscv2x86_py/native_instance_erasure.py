"""Instance-bound object erasure experiments under ORIGINAL compile profiles.

This is not a translator. It verifies the original materialization, replaces
one already source-excluded statement by an empty statement in isolated copies,
and compares each resulting ELF object byte-for-byte with its own baseline.
An invariant object is evidence of this edit's lack of object-byte influence
under these exact profiles, not execution coverage or a general semantic proof.
"""
import json
from pathlib import Path

from . import native_captured_deployment as d
from . import native_project_evaluation as project
from .native_external_providers import checked
from .verification_session import measured
from .compiler_native_instance_binding import bytes_identity


def mapped_ranges(source, target, edits, attempts, finding_id):
    """Recover ranges by replaying checked original edits, never text search.

    All edits are replayed to account for length changes before the subject.
    Required headers use the existing materializer's exact insertion policy.
    """
    from .candidate_materialization import _insert_headers
    selected = []; cursor = 0; parts = []; spans = {}; size = 0
    for edit in sorted(edits, key=lambda e: (e['beginOffset'], e['endOffset'])):
        begin, end = edit['beginOffset'], edit['endOffset']
        if (type(begin) is not int or type(end) is not int
                or not cursor <= begin < end <= len(source)):
            raise ValueError('ERASURE_EDIT_RANGE_INVALID')
        attempt = attempts.get(edit['attemptArtifactId'])
        if attempt is None or attempt.finding_id != edit['findingId']:
            raise ValueError('ERASURE_ORIGINAL_ATTEMPT_JOIN_REQUIRED')
        replacement = attempt.candidate_replacement.encode('utf-8')
        if (bytes_identity(source[begin:end]) != edit['sourceSliceDigest']
                or bytes_identity(replacement) != edit['candidateReplacementDigest']
                or bytes_identity(source) != edit['beforeFileDigest']
                or bytes_identity(target) != edit['afterFileDigest']):
            raise ValueError('ERASURE_EDIT_BYTES_CHANGED')
        prefix = source[cursor:begin]; parts.extend((prefix, replacement))
        size += len(prefix)
        if edit['findingId'] in spans:
            raise ValueError('ERASURE_FINDING_EDIT_AMBIGUOUS')
        spans[edit['findingId']] = [size, size + len(replacement)]
        size += len(replacement); cursor = end
        if edit['findingId'] == finding_id: selected.append([begin, end])
    if len(selected) != 1:
        raise ValueError('ERASURE_FINDING_EDIT_REQUIRED')
    parts.append(source[cursor:]); body = b''.join(parts)
    headers = tuple(sorted({h for e in edits for h in e['requiredHeaders']}))
    materialized = _insert_headers(body, headers)
    if materialized != target:
        raise ValueError('ERASURE_ORIGINAL_MATERIALIZATION_MISMATCH')
    shift = len(materialized) - len(body)
    return {'source': selected[0], 'target': [p + shift for p in spans[finding_id]]}


def empty_statement(raw, span):
    begin, end = span
    if type(begin) is not int or type(end) is not int or not 0 <= begin < end <= len(raw):
        raise ValueError('ERASURE_STATEMENT_RANGE_INVALID')
    # Keep byte offsets and line counts stable. Do not edit any original file.
    blank = bytearray(10 if b == 10 else 32 for b in raw[begin:end])
    first = next((i for i,b in enumerate(blank) if b != 10), None)
    if first is None: raise ValueError('ERASURE_EMPTY_STATEMENT_INVALID')
    blank[first] = ord(';')
    return raw[:begin] + bytes(blank) + raw[end:]


def subject(backend, finding, disposition):
    checked(disposition, 'dispositionIdentity')
    if not disposition['sourceConditionExcluded']:
        raise ValueError('ERASURE_CHECKED_SOURCE_EXCLUSION_REQUIRED')
    physical = finding.get('physicalEditBinding') or {}
    instance = physical.get('instanceBindingIdentity')
    if (not instance or disposition['instanceBindingIdentities'] != [instance]
            or disposition['fragmentId'] != finding['fragment']['id']
            or disposition['functionBindingIdentity'] != backend.selected['functionBindingIdentity']
            or disposition['project'] != d.snapshot(backend.config['typedProjectEntry']['specPath'])):
        raise ValueError('ERASURE_PHYSICAL_INSTANCE_BINDING_REQUIRED')
    from .physical_edit_binding import _check_binding
    _check_binding(physical)
    run = d.read(backend.spec['run']['path']); translation = d.read(run['translation']['path'])
    from .candidate_materialization import load_candidate_artifact_manifest
    from .translation_attempt import load_translation_attempt_archive
    manifest_ref = translation['candidateManifest']; archive_ref = translation['attemptArchive']
    for ref in (manifest_ref, archive_ref): d.verify_snapshot(ref)
    manifest = load_candidate_artifact_manifest(manifest_ref['path'])
    archive = load_translation_attempt_archive(archive_ref['path'])
    if (manifest.attempt_archive_id != archive.archive_id
            or manifest.translated_report_digest != translation['report']['digest']):
        raise ValueError('ERASURE_TRANSLATION_IDENTITY_MISMATCH')
    report = d.read(translation['report']['path']); index = physical['findingIndex']
    if (type(index) is not int or not 0 <= index < len(report['findings'])
            or report['findings'][index] != finding):
        raise ValueError('ERASURE_ORIGINAL_FINDING_JOIN_REQUIRED')
    finding_id = f'finding:{index}:{finding["fragment"]["id"]}'
    edits = [e.to_dict() for e in manifest.edits]
    # The captured project route owns one frozen preprocessed translation unit.
    if not edits or any(e['relativePath'] != 'input.i' for e in edits):
        raise ValueError('ERASURE_FROZEN_CPP_DOMAIN_REQUIRED')
    raw = {s: Path(b['input']['path']).read_bytes() for s,b in backend.builds.items()}
    ranges = mapped_ranges(raw['source'], raw['target'], edits,
                           {a.artifact_id: a for a in archive.attempts}, finding_id)
    if (physical['source'] != backend.builds['source']['input']
            or ranges['source'] != physical['physicalRange']
            or bytes_identity(raw['source'][slice(*ranges['source'])]) != physical['statementDigest']):
        raise ValueError('ERASURE_COMPILER_STATEMENT_RANGE_MISMATCH')
    binding = {'project': disposition['project'], 'fragmentId': finding['fragment']['id'],
        'instanceBindingIdentity': instance, 'functionBindingIdentity': disposition['functionBindingIdentity'],
        'physicalBindingIdentity': physical['physicalEditBindingIdentity'],
        'sourceDispositionIdentity': disposition['dispositionIdentity'],
        'manifest': manifest_ref, 'attemptArchive': archive_ref, 'ranges': ranges}
    return binding, raw


@measured('native-instance-erasure.inspect')
def inspect(backend, finding, disposition, output, *, readback=False):
    from .automatic_l2_operand import _emit
    backend.verify()
    binding, raw = subject(backend, finding, disposition)
    root = Path(output).resolve()
    if not readback: root.mkdir(parents=True, exist_ok=True)
    rows = []
    for side in ('source', 'target'):
        profile = backend.spec['profiles'][side]['compile']; build = backend.builds[side]
        folder = root/side
        if not readback: folder.mkdir(exist_ok=True)
        # Same basename preserves STT_FILE under ordinary non-debug builds.
        body = folder/Path(build['input']['path']).name; obj = folder/'input.o'
        _emit(body, empty_statement(raw[side], binding['ranges'][side]), readback)
        argv = [profile['compiler']['path'], *profile['flags'], '-c', str(body), '-o', str(obj)]
        command = folder/'command'
        if not readback and not (command/'execution.json').exists():
            project.command(argv, profile['directory'], profile['environment'], command, backend.spec['timeoutSeconds'])
        record = project.validate_execution_record(d.read(command/'execution.json'))
        if any(record[k] != v for k,v in {'arguments': argv, 'directory': profile['directory'],
                                         'environment': profile['environment']}.items()):
            raise ValueError('ERASURE_COMPILE_RECIPE_CHANGED')
        reason = ('ERASURE_COMPILE_UNAVAILABLE' if record['returnCode'] != 0 or record['failureReason'] else
                  'ERASURE_OBJECT_MISSING' if not obj.is_file() else
                  'ERASURE_OBJECT_DIFFERS' if d.digest(obj) != build['object']['digest'] else None)
        rows.append({'side': side, 'canonicalInput': build['input'], 'canonicalObject': build['object'],
            'profileIdentity': d.identity(profile), 'compiler': profile['compiler'],
            'erasedInput': d.snapshot(body), 'object': d.snapshot(obj) if obj.is_file() else None,
            'execution': d.snapshot(command/'execution.json'), 'reasonCode': reason,
            'objectByteInvariant': reason is None})
    backend.verify()
    # Recheck range-producing identities after compiler/tool boundaries.
    if subject(backend, finding, disposition) != (binding, raw):
        raise ValueError('ERASURE_SUBJECT_CHANGED')
    value = d.seal({'schemaVersion': 'riscv2x86.instance-object-erasure.v1', 'subject': binding,
        'sides': rows, 'objectErasureInvariant': all(r['objectByteInvariant'] for r in rows),
        'canonicalInstructionCoverageVerified': False, 'machineEliminationVerified': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False,
        'scope': 'single-source-excluded-statement-object-byte-invariance-under-recorded-profiles'}, 'erasureIdentity')
    path = root/'result.json'; _emit(path, json.dumps(value, indent=2, sort_keys=True)+'\n', readback)
    return {'receipt': d.snapshot(path), 'objectErasureInvariant': value['objectErasureInvariant'],
            'subject': binding, 'scope': value['scope']}
