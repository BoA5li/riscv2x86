"""GNU bfd map symbol ownership, distinct from instruction correspondence.

Consumes the map of the checked link, not an arbitrary symbol-name join. A
resized contribution can establish ownership, but never proves a relocation
transform, runtime selection, function extent, ABI or instance execution.
"""
import re


def map_records(text):
    from .native_link_attribution import contributions
    contributions(text)  # enforce the same supported layout
    rows = []; pending = None; current = None
    for line in text.split('Linker script and memory map', 1)[1].splitlines():
        if line == 'Cross Reference Table': break
        regular = re.fullmatch(r' (\.[^\s]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+)', line)
        wrapped = re.fullmatch(r' (\.[^\s]+)\s*', line)
        continuation = re.fullmatch(r'\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+)', line)
        if regular or (pending and continuation):
            if regular: section, address, size, owner = regular.groups()
            else: section = pending; address, size, owner = continuation.groups()
            current = {'section': section, 'address': int(address, 16),
                       'size': int(size, 16), 'owner': owner.strip(), 'symbols': []}
            rows.append(current); pending = None
        elif wrapped:
            pending = wrapped.group(1); current = None
        else:
            symbol = re.fullmatch(r'\s+(0x[0-9a-fA-F]+)\s+([^\s=]+)\s*', line)
            if current is not None and symbol:
                current['symbols'].append({'address': int(symbol[1], 16), 'name': symbol[2]})
            else:
                # Do not attach assignments, fill rows, output sections, LOAD
                # directives or subsequent script symbols to the last object.
                current = None
            pending = None
    return rows


def definition(symbol, candidate, source_sections, final, final_sections, records):
    """Strict bounded explicit strong definition -> final map owner join."""
    index = symbol['sectionIndex']
    supported = (symbol['defined'] and symbol['binding'] == 1 and symbol['type'] in (1, 2)
                 and symbol['size'] > 0 and 0 < index < len(source_sections))
    sec = source_sections[index] if supported else {}
    supported = supported and bool(sec['flags'] & 2) and not sec['flags'] & (0x400 | 0x10 | 0x200)
    supported = supported and (symbol['type'] != 2 or bool(sec['flags'] & 4))
    owners = [r for r in records if supported and r['owner'] == str(candidate) and r['section'] == sec['name']]
    symbols = [s for s in final['staticSymbols'] if s['defined'] and s['name'] == symbol['name']
               and s['binding'] == 1 and s['type'] == symbol['type']]
    reason = None; join = None
    if not supported: reason = 'DEFINITION_KIND_UNSUPPORTED'
    elif symbol['value'] + symbol['size'] > sec['size']: reason = 'DEFINITION_SOURCE_RANGE_INVALID'
    elif len(owners) != 1: reason = 'DEFINITION_INPUT_CONTRIBUTION_NOT_UNIQUE'
    elif len(symbols) != 1: reason = 'DEFINITION_FINAL_SYMBOL_NOT_UNIQUE'
    else:
        owner, target = owners[0], symbols[0]
        at = owner['address']; end = at + owner['size']; start = target['value']
        matches = [s for s in owner['symbols'] if s['name'] == symbol['name'] and s['address'] == start]
        competing = [r for r in records if r is not owner and r['size'] > 0
                     and max(at, r['address']) < min(end, r['address'] + r['size'])]
        fsec = final_sections[target['sectionIndex']] if 0 < target['sectionIndex'] < len(final_sections) else None
        if len(matches) != 1: reason = 'DEFINITION_MAP_SYMBOL_OWNER_MISMATCH'
        elif competing: reason = 'DEFINITION_CONTRIBUTION_OVERLAP'
        elif not (owner['size'] > 0 and at <= start < start + target['size'] <= end):
            reason = 'DEFINITION_FINAL_RANGE_OUTSIDE_CONTRIBUTION'
        elif (fsec is None or not fsec['flags'] & 2 or fsec['type'] not in ((1,) if symbol['type'] == 2 else (1, 8))
              or not fsec['address'] <= at < end <= fsec['address'] + fsec['size']
              or (symbol['type'] == 2 and not fsec['flags'] & 4)):
            reason = 'DEFINITION_FINAL_SECTION_MISMATCH'
        else:
            join = {'inputContribution': {k: owner[k] for k in ('section', 'address', 'size', 'owner')},
                    'mapSymbol': matches[0], 'finalSymbol': target,
                    'layoutChanged': (owner['size'] != sec['size'] or start != at + symbol['value']
                                      or target['size'] != symbol['size'])}
    return {'verified': reason is None, 'reason': reason, 'ownership': join,
            'inputContributions': [{k: r[k] for k in ('section', 'address', 'size', 'owner')} for r in owners],
            'finalSymbols': symbols, 'instructionCorrespondenceVerified': False,
            'functionExtentVerified': False, 'runtimeBindingVerified': False,
            'scope': 'checked-link-map-explicit-strong-definition-ownership-only'}
