"""Read regular ar and ELF64-LE dependency evidence without invoking a linker.

Object symbol reachability is conservative. It is not archive extraction order,
runtime reachability, a type/effect contract, or permission to link a provider.
"""
import struct
from hashlib import sha256


def bytes_digest(raw):
    return 'sha256:' + sha256(raw).hexdigest()


def archive_members(raw):
    if raw[:8] != b'!<arch>\n':
        raise ValueError('DEPENDENCY_REGULAR_ARCHIVE_REQUIRED')
    result = []; offset = 8; long_names = None
    while offset < len(raw):
        header_offset = offset
        header = raw[offset:offset+60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('DEPENDENCY_ARCHIVE_HEADER_INVALID')
        try:
            text = header[48:58].decode('ascii').strip()
            if not text.isdecimal(): raise ValueError()
            size = int(text)
            name = header[:16].decode('ascii').rstrip()
        except (UnicodeError, ValueError) as exc:
            raise ValueError('DEPENDENCY_ARCHIVE_FIELD_INVALID') from exc
        offset += 60
        if offset+size > len(raw):
            raise ValueError('DEPENDENCY_ARCHIVE_TRUNCATED')
        data = raw[offset:offset+size]; offset += size
        if size & 1:
            if raw[offset:offset+1] != b'\n':
                raise ValueError('DEPENDENCY_ARCHIVE_PADDING_INVALID')
            offset += 1
        if name == '//':
            if long_names is not None: raise ValueError('DEPENDENCY_ARCHIVE_MULTIPLE_NAME_TABLES')
            long_names = data; continue
        if name in ('/', '/SYM64/'):
            continue
        if name.startswith('#1/'):
            count = name[3:]
            if not count.isdecimal() or int(count) > len(data):
                raise ValueError('DEPENDENCY_ARCHIVE_BSD_NAME_INVALID')
            count = int(count)
            name = data[:count].rstrip(b'\0').decode('utf-8')
            data = data[count:]
            if name in ('__.SYMDEF', '__.SYMDEF SORTED', '__.SYMDEF_64', '__.SYMDEF_64 SORTED'):
                continue
        elif name.startswith('/'):
            position = name[1:]
            if not position.isdecimal() or long_names is None:
                raise ValueError('DEPENDENCY_ARCHIVE_NAME_REFERENCE_INVALID')
            position = int(position)
            if position >= len(long_names) or (position and long_names[position-1:position] != b'\n'):
                raise ValueError('DEPENDENCY_ARCHIVE_NAME_REFERENCE_INVALID')
            end = long_names.find(b'/\n', position)
            if end < 0: raise ValueError('DEPENDENCY_ARCHIVE_NAME_REFERENCE_INVALID')
            name = long_names[position:end].decode('utf-8')
        else:
            name = name.removesuffix('/')
            if name in ('__.SYMDEF', '__.SYMDEF SORTED'):
                continue
        if not name or '\0' in name:
            raise ValueError('DEPENDENCY_ARCHIVE_NAME_INVALID')
        # Never extract member names into paths; retain duplicate names by offset.
        result.append({'name': name, 'headerOffset': header_offset,
                       'size': len(data), 'digest': bytes_digest(data), 'bytes': data})
    return result


def elf_symbols(raw):
    def chunk(offset, size):
        if offset < 0 or size < 0 or offset+size > len(raw):
            raise ValueError('DEPENDENCY_ELF_RANGE_INVALID')
        return raw[offset:offset+size]
    if len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('DEPENDENCY_ELF64_LE_REQUIRED')
    kind, machine = struct.unpack_from('<HH', raw, 16)
    if kind != 1: raise ValueError('DEPENDENCY_RELOCATABLE_REQUIRED')
    offset = struct.unpack_from('<Q', raw, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', raw, 58)
    if size != 64 or not count or strings >= count:
        raise ValueError('DEPENDENCY_ELF_SECTIONS_INVALID')
    sections = [struct.unpack('<IIQQQQIIQQ', chunk(offset+64*i, 64)) for i in range(count)]
    definitions = []; undefined = []; tables = 0
    for index, section in enumerate(sections):
        if section[1] != 2: continue
        tables += 1
        if section[9] != 24 or section[5] % 24 or section[6] >= count:
            raise ValueError('DEPENDENCY_ELF_SYMBOLS_INVALID')
        names_section = sections[section[6]]
        if names_section[1] != 3: raise ValueError('DEPENDENCY_ELF_STRINGS_INVALID')
        names = chunk(names_section[4], names_section[5])
        for entry in range(section[5]//24):
            name, info, other, shndx, value, length = struct.unpack(
                '<IBBHQQ', chunk(section[4]+entry*24, 24))
            if name >= len(names) or names.find(b'\0', name) < 0:
                raise ValueError('DEPENDENCY_ELF_SYMBOL_NAME_INVALID')
            label = names[name:names.index(b'\0', name)].decode('utf-8')
            binding = info >> 4
            if not label or binding == 0: continue
            if binding not in (1, 2, 10) or shndx == 0xffff:
                raise ValueError('DEPENDENCY_ELF_SYMBOL_BINDING_UNSUPPORTED')
            if 0 < shndx < 0xff00 and shndx >= count:
                raise ValueError('DEPENDENCY_ELF_SYMBOL_SECTION_INVALID')
            row = {'name': label, 'binding': binding, 'type': info & 15,
                   'visibility': other & 3, 'sectionIndex': shndx,
                   'value': value, 'size': length, 'tableIndex': index, 'entryIndex': entry}
            (undefined if shndx == 0 else definitions).append(row)
    if tables != 1: raise ValueError('DEPENDENCY_SINGLE_STATIC_SYMBOL_TABLE_REQUIRED')
    return {'machine': machine, 'elfType': kind,
            'abiFlags': struct.unpack_from('<I', raw, 48)[0],
            'definitions': definitions, 'undefined': undefined}


def closure(root, members):
    """Follow every undefined symbol; expose ambiguity instead of choosing bytes."""
    providers = {}
    for member in members:
        for symbol in member['elf']['definitions']:
            providers.setdefault(symbol['name'], []).append((member['memberId'], symbol))
    root_defs = {s['name'] for s in root['definitions']}
    objects = {'root': root, **{m['memberId']: m['elf'] for m in members}}
    queue = ['root']; selected = set(); edges = []; blockers = []
    while queue:
        current = queue.pop(0)
        if current in selected: continue
        selected.add(current)
        for symbol in objects[current]['definitions']:
            if symbol['binding'] != 1 or symbol['sectionIndex'] >= 0xff00:
                blockers.append({'reason': 'SPECIAL_DEFINITION_REQUIRES_LINK_CONTRACT',
                                 'object': current, 'symbol': symbol['name']})
        for symbol in objects[current]['undefined']:
            name = symbol['name']
            edge = {'object': current, 'symbol': name, 'binding': symbol['binding']}
            if name in root_defs:
                edge.update(resolution='root-definition', providers=['root'])
            else:
                matches = providers.get(name, [])
                ids = sorted({p for p, s in matches})
                edge['providers'] = ids
                if not matches:
                    edge['resolution'] = 'external-contract-required'
                elif len(matches) != 1 or matches[0][1]['binding'] != 1 or matches[0][1]['sectionIndex'] >= 0xff00:
                    edge['resolution'] = 'ambiguous-or-special-provider'
                else:
                    edge['resolution'] = 'unique-strong-provider'
                    queue.append(ids[0])
            if symbol['binding'] != 1:
                edge['resolution'] = 'weak-or-special-reference-contract-required'
            if edge['resolution'] not in ('root-definition', 'unique-strong-provider'):
                blockers.append({'reason': edge['resolution'], 'object': current, 'symbol': name})
            edges.append(edge)
    return {'selectedObjects': sorted(selected), 'edges': edges, 'blockers': blockers,
            'policy': 'conservative-object-symbol-reachability.v1',
            'actualLinkSelectionVerified': False}
