"""Per-reference work ledger, derived from bytes and replayed parent evidence.

No interface or instruction semantics are inferred from a symbol's spelling.
There is deliberately no caller-supplied approval flag or contract whitelist.
"""
from pathlib import Path
import struct

from .native_external_providers import read, checked
from .native_external_requirements import replay_requirements
from .native_dependency_evidence import archive_members, bytes_digest
from .native_elf_runtime import parse
from .project_build_records import identity
from .project_compile_context import digest

SCHEMA = 'riscv2x86.native-reference-ledger.v1'


def _window(raw, relocation):
    elf = parse(raw)
    offset = struct.unpack_from('<Q', raw, 40)[0]
    size, count, names = struct.unpack_from('<HHH', raw, 58)
    table = [struct.unpack_from('<IIQQQQIIQQ', raw, offset+i*size) for i in range(count)]
    name_section = table[names]
    strings = raw[name_section[4]:name_section[4]+name_section[5]]
    found = []
    for index, section in enumerate(table):
        end = strings.index(b'\0', section[0])
        if strings[section[0]:end].decode('utf-8') == relocation['targetSection']:
            found.append((index, section))
    if len(found) != 1:
        raise ValueError('REFERENCE_LEDGER_SECTION_AMBIGUOUS')
    index, section = found[0]
    at = relocation['offset']
    if type(at) is not int or not 0 <= at < section[5] or section[1] == 8:
        raise ValueError('REFERENCE_LEDGER_SECTION_OFFSET_INVALID')
    # A bounded byte witness, NOT a decoded instruction or an instruction size.
    data = raw[section[4]+at:section[4]+min(section[5], at+16)]
    return {'sectionIndex': index, 'offset': at, 'bytes': data.hex(),
            'byteWindowDigest': bytes_digest(data), 'machine': elf['machine'],
            'instructionSemanticsVerified': False}


def derive(requirements, raws):
    checked(requirements, 'requirementsIdentity')
    if requirements.get('schemaVersion') != 'riscv2x86.native-external-requirements.v1':
        raise ValueError('REFERENCE_LEDGER_REQUIREMENTS_SCHEMA_INVALID')
    parents = []
    rows = []
    for req in requirements['requirements']:
        checked(req, 'requirementIdentity')
        parent = req['obligationIdentity']
        if parent in parents:
            raise ValueError('REFERENCE_LEDGER_DUPLICATE_PARENT')
        parents.append(parent)
        raw = raws[req['originalObligation']['object']]
        if bytes_digest(raw) != req['references']['objectDigest']:
            raise ValueError('REFERENCE_LEDGER_OBJECT_CHANGED')
        # Recompute relocation sites instead of trusting a rehashed sites list.
        from .native_external_requirements import reference_sites
        refs = reference_sites(raw, req['originalObligation']['symbol'])
        if refs != req['references']:
            raise ValueError('REFERENCE_LEDGER_REFERENCE_MISMATCH')
        for index, site in enumerate(refs['sites'] or [None]):
            reasons = list(req['requiredEvidence'])
            if site is not None and len(site['containingFunctions']) != 1:
                reasons.append('REFERENCE_FUNCTION_OWNERSHIP_UNRESOLVED')
            if site is not None:
                reasons.append('REFERENCE_INSTRUCTION_SEMANTICS_REQUIRED')
            body = {'parentObligationIdentity': parent,
                    'parentRequirementIdentity': req['requirementIdentity'],
                    'originalObligation': req['originalObligation'], 'referenceOrdinal': index,
                    'reference': site, 'objectRole': req['objectRole'],
                    'selectedBuildActionIdentities': [a['actionIdentity'] for a in req['selectedBuildActions']],
                    'byteWitness': None if site is None else _window(raw, site['relocation']),
                    'requiredEvidence': sorted(set(reasons)), 'status': 'pending',
                    'typedBehaviorContractVerified': False, 'crossIsaBehaviorMappingVerified': False}
            rows.append(dict(body, referenceIdentity=identity(body)))
    if len({r['referenceIdentity'] for r in rows}) != len(rows):
        raise ValueError('REFERENCE_LEDGER_DUPLICATE_REFERENCE')
    body = {'schemaVersion': SCHEMA, 'requirementsIdentity': requirements['requirementsIdentity'],
            'parentObligationIdentities': parents, 'references': rows,
            'parentObligationCount': len(parents), 'referenceCount': len(rows),
            'originalProviderBlockers': requirements['originalProviderBlockers'],
            'allOriginalObligationsPreserved': True, 'externalContractClosureComplete': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, ledgerIdentity=identity(body))


def acquire(requirements_path, output):
    path = Path(requirements_path).resolve(strict=True)
    before = digest(path)
    value = read(path)
    replay_dir = Path(output)/'requirements-replay'
    replay_dir.mkdir()
    replay_requirements(value, replay_dir)
    provider = read(value['providerPath'])
    dependencies = read(provider['dependencyPath'])
    candidate = read(dependencies['candidatePath'])
    directory = Path(candidate['candidatePath']).parent
    archive = Path(dependencies['archivePath']).read_bytes()
    if bytes_digest(archive) != dependencies['inputDigests'][str(Path(dependencies['archivePath']).resolve())]:
        raise ValueError('REFERENCE_LEDGER_ARCHIVE_CHANGED')
    raws = {'root': (directory/'source.o').read_bytes()}
    raws.update({str(m['headerOffset'])+':'+m['digest']: m['bytes'] for m in archive_members(archive)})
    result = derive(value, raws)
    for file, sha in dependencies['inputDigests'].items():
        if digest(file) != sha:
            raise ValueError('REFERENCE_LEDGER_CLOSING_INPUT_CHANGED')
    if digest(path) != before or digest(value['providerPath']) != value['providerDigest']:
        raise ValueError('REFERENCE_LEDGER_PARENT_CHANGED')
    body = {k: v for k, v in result.items() if k != 'ledgerIdentity'}
    body.update(requirementsPath=str(path), requirementsDigest=before)
    return dict(body, ledgerIdentity=identity(body))


def replay(value, output):
    checked(value, 'ledgerIdentity')
    if value.get('schemaVersion') != SCHEMA:
        raise ValueError('REFERENCE_LEDGER_SCHEMA_INVALID')
    if digest(value['requirementsPath']) != value['requirementsDigest']:
        raise ValueError('REFERENCE_LEDGER_REQUIREMENTS_CHANGED')
    if acquire(value['requirementsPath'], output) != value:
        raise ValueError('REFERENCE_LEDGER_REPLAY_MISMATCH')
    return {'referenceLedgerReplayComplete': True, 'ledgerIdentity': value['ledgerIdentity'],
            'parentObligationCount': value['parentObligationCount'], 'referenceCount': value['referenceCount'],
            'externalContractClosureComplete': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False}
