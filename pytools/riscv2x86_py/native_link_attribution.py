"""GNU bfd candidate input-section attribution, independently rebuilt.

Only explicit strong FUNC/OBJECT definitions in ordinary allocated sections are
supported. This establishes link-time ownership, not runtime binding, call ABI,
execution coverage, external contracts, or whole-program equivalence.
"""
from pathlib import Path
import re
import struct
from .native_external_providers import read, checked
from .native_elf_runtime import parse
from .native_link_evidence import audit, SCHEMA_V2, SCHEMA_V3
from .project_build_records import identity
from .project_compile_context import digest

SCHEMA = 'riscv2x86.native-candidate-link-attribution.v1'


def sections(raw):
    # parse() checks the supported ELF structure before this projection.
    parse(raw)
    off = struct.unpack_from('<Q', raw, 40)[0]
    size, count, names = struct.unpack_from('<HHH', raw, 58)
    rows = [struct.unpack_from('<IIQQQQIIQQ', raw, off+i*size) for i in range(count)]
    table = raw[rows[names][4]:rows[names][4]+rows[names][5]]
    result = []
    for row in rows:
        end = table.index(b'\0', row[0])
        result.append({'name': table[row[0]:end].decode('utf-8'), 'flags': row[2], 'size': row[5]})
    return result


def contributions(text):
    """Parse bfd input contributions, excluding discarded/debug map preambles."""
    if text.count('Linker script and memory map') != 1:
        raise ValueError('LINK_ATTRIBUTION_MAP_LAYOUT_UNSUPPORTED')
    lines = text.split('Linker script and memory map', 1)[1].splitlines()
    rows = []; pending = None
    for line in lines:
        if line == 'Cross Reference Table':break
        match = re.fullmatch(r' (\.[^\s]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+)', line)
        if match:
            section, address, size, owner = match.groups(); pending = None
        else:
            wrapped = re.fullmatch(r' (\.[^\s]+)\s*', line)
            if wrapped:
                pending = wrapped.group(1);continue
            match = re.fullmatch(r'\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+)', line)
            if not match or pending is None:
                pending = None;continue
            address, size, owner = match.groups();section = pending;pending = None
        rows.append({'section': section, 'address': int(address, 16),
                     'size': int(size, 16), 'owner': owner.strip()})
    return rows


def derive(value, directory):
    checked(value, 'linkBuildIdentity')
    if value.get('schemaVersion') not in (SCHEMA_V2, SCHEMA_V3):
        raise ValueError('LINK_ATTRIBUTION_V2_BUILD_REQUIRED')
    root = Path(directory)
    for name, expected in value['artifactDigests'].items():
        if Path(name).name != name or digest(root/name) != expected:
            raise ValueError('LINK_ATTRIBUTION_ARTIFACT_CHANGED')
    request = value['request'];candidate = read(request['candidatePath'])
    checked(candidate, 'candidateIdentity')
    if candidate['candidateIdentity'] != value['candidateIdentity']:
        raise ValueError('LINK_ATTRIBUTION_CANDIDATE_CHANGED')
    obj = Path(candidate['candidatePath']).parent/(request['side']+'.o')
    raw = obj.read_bytes()
    if digest(obj) != candidate[request['side']+'ObjectDigest']:
        raise ValueError('LINK_ATTRIBUTION_OBJECT_CHANGED')
    program = parse((root/'program').read_bytes())
    if program != value['outputElf']:
        raise ValueError('LINK_ATTRIBUTION_OUTPUT_CHANGED')
    elf = parse(raw);table = sections(raw)
    mapped = contributions((root/'link.map').read_text())
    stderr = (root/'link.stderr').read_text().splitlines()
    results = [];blockers = []
    for symbol in elf['staticSymbols']:
        if not symbol['name'] or not symbol['defined'] or symbol['binding'] == 0:continue
        name = symbol['name'];index = symbol['sectionIndex'];reason = None
        supported = (symbol['binding'] == 1 and symbol['type'] in (1, 2) and
                     0 < index < len(table) and table[index]['flags'] & 2 and
                     not table[index]['flags'] & 0x400 and symbol['size'] > 0)
        if not supported:
            reason = 'CANDIDATE_DEFINITION_KIND_UNSUPPORTED'
        else:
            section = table[index]
            own = [r for r in mapped if r['owner'] == str(obj) and
                   r['section'] == section['name'] and r['size'] == section['size']]
            final = [s for s in program['staticSymbols'] if s['name'] == name and s['defined']
                     and s['binding'] == 1 and s['type'] == symbol['type']]
            trace = [line for line in stderr if line.endswith(': definition of '+name)]
            exact_trace = [line for line in trace if line == str(obj)+': definition of '+name
                           or line.endswith(': '+str(obj)+': definition of '+name)]
            if len(own) != 1 or len(final) != 1 or len(trace) != 1 or len(exact_trace) != 1:
                reason = 'CANDIDATE_DEFINITION_ATTRIBUTION_AMBIGUOUS'
            elif (symbol['value']+symbol['size'] > section['size'] or
                  final[0]['value'] != own[0]['address']+symbol['value'] or
                  final[0]['size'] != symbol['size']):
                reason = 'CANDIDATE_DEFINITION_ADDRESS_OR_SIZE_MISMATCH'
        row = {'name': name, 'sourceSectionIndex': index, 'objectDigest': digest(obj),
               'linkTimeDefinitionAttributed': reason is None}
        if reason:
            blockers.append({'symbol': name, 'reason': reason})
        else:
            row.update(inputContribution=own[0], finalSymbol=final[0], trace=exact_trace[0])
        results.append(row)
    if not results:blockers.append({'reason': 'CANDIDATE_HAS_NO_SUPPORTED_DEFINITIONS'})
    body = {'schemaVersion': SCHEMA, 'linkBuildIdentity': value['linkBuildIdentity'],
            'candidateIdentity': candidate['candidateIdentity'], 'definitions': results,
            'blockers': blockers, 'candidateDefinitionAttributionVerified': not blockers,
            'proofScope': 'gnu-bfd-link-time-explicit-candidate-section-ownership',
            'actualLinkSelectionVerified': False, 'runtimeLibrarySelectionVerified': False,
            'typedCallContractVerified': False, 'translatedInstanceExecutionVerified': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, attributionIdentity=identity(body))


def acquire(link_path, output, timeout=300):
    original = Path(link_path).resolve(strict=True);before = digest(original);value = read(original)
    # Fresh link plus complete original artifact/receipt check. Never trust
    # externally asserted successful flags or a map without independent replay.
    audit(value, original.parent, output, timeout)
    result = derive(value, original.parent)
    if digest(original) != before:raise ValueError('LINK_ATTRIBUTION_RECEIPT_CHANGED')
    for path, expected in value['boundInputDigests'].items():
        if digest(path) != expected:raise ValueError('LINK_ATTRIBUTION_BOUND_INPUT_CHANGED')
    body = {k:v for k,v in result.items() if k != 'attributionIdentity'}
    body['independentLinkRebuildComplete'] = True
    return dict(body, attributionIdentity=identity(body))
