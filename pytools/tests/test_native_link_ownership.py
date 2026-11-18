"""Owner and extent are different claims, including resized contributions."""
from copy import deepcopy
import pytest
from riscv2x86_py.native_link_ownership import definition, map_records


def fixture():
    source = [{'name': '', 'flags': 0, 'size': 0},
              {'name': '.text', 'flags': 6, 'size': 80}]
    final_sections = [{'name': '', 'flags': 0, 'size': 0},
                      {'name': '.text', 'flags': 6, 'type': 1, 'address': 0x100, 'size': 128}]
    symbol = {'name': 'entry', 'defined': True, 'binding': 1, 'type': 2,
              'size': 48, 'value': 16, 'sectionIndex': 1}
    final = {'staticSymbols': [{**symbol, 'value': 0x108, 'size': 32}]}
    records = map_records('Linker script and memory map\n .text 0x100 0x38 body.o\n'
                          '                0x108 entry\n')
    return symbol, 'body.o', source, final, final_sections, records


def test_resized_and_shifted_map_owner_does_not_claim_instruction_or_extent_proof():
    row = definition(*fixture())
    assert row['verified'] and row['ownership']['layoutChanged']
    assert not row['instructionCorrespondenceVerified'] and not row['functionExtentVerified']
    assert not row['runtimeBindingVerified']


@pytest.mark.parametrize('change', ['owner', 'duplicate', 'symbol', 'overlap', 'range', 'final-section',
                                   'unsupported', 'source-range', 'duplicate-final'])
def test_ambiguous_or_unbound_ownership_rejects(change):
    args = list(deepcopy(fixture())); s, _, src, final, sections, records = args
    if change == 'owner': records[0]['owner'] = 'different.o'
    elif change == 'duplicate': records.append(deepcopy(records[0]))
    elif change == 'symbol': records[0]['symbols'][0]['address'] += 2
    elif change == 'overlap': records.append({**records[0], 'owner': 'other.o'})
    elif change == 'range': final['staticSymbols'][0]['size'] = 80
    elif change == 'final-section': sections[1]['flags'] = 2
    elif change == 'unsupported': s['binding'] = 2
    elif change == 'source-range': s['size'] = 100
    else: final['staticSymbols'].append(deepcopy(final['staticSymbols'][0]))
    assert not definition(*args)['verified']


def test_script_symbols_and_discarded_sections_cannot_acquire_an_owner():
    rows = map_records('Discarded input sections\n .text 0x100 0x20 bad.o\n 0x100 fake\n'
        'Linker script and memory map\n .text\n  0x100 0x20 body.o\n'
        '                0x108 entry\n *fill* 0x120 0x4\n                0x124 unowned\n'
        ' .data 0x200 0x10 data.o\n                0x200 assigned = .\n                0x200 not_owned\n')
    assert rows[0]['symbols'] == [{'address': 0x108, 'name': 'entry'}]
    assert rows[1]['symbols'] == []
