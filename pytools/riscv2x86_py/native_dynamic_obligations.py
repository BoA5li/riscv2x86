"""ELF-derived dynamic binding obligations; metadata never proves behavior.

Numeric relocation semantics are selected by ELF machine, not symbol names.
COPY destination storage is distinct from candidate initializer definitions.
"""
import struct
from pathlib import Path

from .native_elf_runtime import parse, candidates
from .native_captured_deployment import snapshot


def describe(path, *, legacy_v2=False):
    raw = Path(path).read_bytes(); elf = parse(raw)
    off = struct.unpack_from('<Q', raw, 40)[0]
    size, count, names = struct.unpack_from('<HHH', raw, 58)
    table = [struct.unpack_from('<IIQQQQIIQQ', raw, off+i*size) for i in range(count)]
    tags = []
    for sec in table:
        if sec[1] == 6:
            for at in range(sec[4], sec[4]+sec[5], 16):
                tag, value = struct.unpack_from('<qQ', raw, at)
                if tag == 0: break
                tags.append([tag, value])
    now = any(tag == 24 or tag == 30 and value & 8 or tag == 0x6ffffffb and value & 1
              for tag, value in tags)
    dyn_indices = {s['tableIndex'] for s in elf['dynamicSymbols']}
    shnames = table[names]; strings = raw[shnames[4]:shnames[4]+shnames[5]]
    links = {}
    for s in table:
        end = strings.index(b'\0', s[0])
        links[strings[s[0]:end].decode()] = s[6]
    semantics = {62: {1: 'absolute-address', 5: 'copy', 6: 'global-data',
                      7: 'jump-slot', 8: 'relative', 37: 'indirect-relative'},
                 243: {1: 'absolute-address', 2: 'absolute-address', 3: 'relative',
                       4: 'copy', 5: 'jump-slot'}}
    rows = []
    for r in elf['relocations']:
        if links[r['section']] not in dyn_indices:
            continue
        symbols = [s for s in elf['dynamicSymbols'] if s['entryIndex'] == r['symbolIndex']]
        if len(symbols) != 1:
            raise ValueError('DYNAMIC_OBLIGATION_SYMBOL_AMBIGUOUS')
        s = symbols[0]; role = semantics.get(elf['machine'], {}).get(r['type'], 'unsupported')
        rows.append({'relocation': r, 'symbol': s, 'role': role,
                     'bindingCanOccurBeforeCall': (role != 'jump-slot' or now) if legacy_v2 else binding_timing(role, now),
                     'behaviorContractVerified': False})
    return {'file': snapshot(path), 'elf': elf, 'dynamicTags': tags,
            'bindNowDeclared': bool(now), 'relocationObligations': rows}


def binding_timing(role, now):
    """Unknown relocation semantics have unknown timing, even with BIND_NOW."""
    if role == 'unsupported':
        return None
    return role != 'jump-slot' or bool(now)


def inspect(paths, *, legacy_v2=False):
    objects = [describe(p, legacy_v2=legacy_v2) for p in dict.fromkeys(paths)]
    providers = [{'path': o['file']['path'], 'digest': o['file']['digest'], 'elf': o['elf']} for o in objects]
    copies = []
    for obj in objects:
        for row in obj['relocationObligations']:
            if row['role'] != 'copy': continue
            s = row['symbol']; r = row['relocation']
            query = {'name': s['name'], 'machine': obj['elf']['machine'], 'type': s['type'],
                     'version': s['version']}
            available = candidates(query, [p for p in providers if p['path'] != obj['file']['path']])
            copies.append({'destination': obj['file'], 'destinationSymbol': s,
                           'relocation': r, 'initializerDefinitionCandidates': available,
                           'candidateSizesMatch': bool(available) and all(p['symbol']['size'] == s['size'] for p in available),
                           'destinationAddressMatches': r['offset'] == s['value'],
                           'actualInitializerSelectionVerified': False,
                           'storageAndBehaviorContractVerified': False})
    return {'objects': objects, 'copyRelocations': copies,
            'scope': 'elf-dynamic-metadata-and-definition-candidates-not-loader-emulation',
            'dynamicBindingClosureComplete': False}
