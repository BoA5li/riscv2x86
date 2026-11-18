"""Explicit finite region contracts; no post-hoc dropping of mismatches.

All allocated elements must have one declared role. Output and preservation
regions are observed; scratch has no specified final value. Roles apply to
regions in an allocation, so a shared output/scratch allocation is supported.
"""
import re
from . import native_api_contract as api


def regions(domain, interface, case):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', str(domain.get('sourceDigest', ''))):
        raise ValueError('API_DOMAIN_SOURCE_DIGEST_REQUIRED')
    rows = domain['regions']
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError('API_REGION_BUDGET_INVALID')
    objects = case['objects']; args = case['arguments']; ids = list(objects)
    coverage = {name: bytearray(len(obj['values'])) for name, obj in objects.items()}
    result = []
    for row in rows:
        api.fields(row, ('argument', 'offsetElements', 'lengthElements', 'mode'), 'API_REGION')
        index = row['argument']
        if (type(index) is not int or not 0 <= index < len(args)
                or interface['parameters'][index]['kind'] != 'pointer'):
            raise ValueError('API_REGION_POINTER_ARGUMENT_REQUIRED')
        if row['mode'] not in ('output', 'preserve', 'scratch'):
            raise ValueError('API_REGION_MODE_INVALID')
        if row['mode'] in ('output', 'scratch') and interface['parameters'][index]['const']:
            raise ValueError('API_REGION_WRITABLE_POINTER_REQUIRED')
        offset = api.expression(row['offsetElements'], args, objects)
        length = api.expression(row['lengthElements'], args, objects)
        arg = args[index]; oid = arg['object']; start = arg['offsetElements'] + offset if type(offset) is int else -1
        if (type(offset) is not int or offset < 0 or type(length) is not int or length <= 0
                or not 0 <= start < start + length <= len(objects[oid]['values'])):
            raise ValueError('API_REGION_OUTSIDE_OBJECT')
        if any(coverage[oid][start:start + length]):
            raise ValueError('API_REGION_OVERLAP')
        coverage[oid][start:start + length] = b'\x01' * length
        result.append({'object': oid, 'objectIndex': ids.index(oid), 'start': start,
                       'length': length, 'mode': row['mode']})
    if any(not all(row) for row in coverage.values()):
        raise ValueError('API_REGION_COVERAGE_INCOMPLETE')
    if interface['return']['kind'] == 'void' and not any(r['mode'] != 'scratch' for r in result):
        raise ValueError('API_NONEMPTY_OBSERVABLE_CONTRACT_REQUIRED')
    return result


def expected(domain, interface):
    result = []
    for index, case in enumerate(api.validate(domain, interface)):
        if interface['return']['kind'] != 'void':
            result.append({'label': f'case:{index}:return:', 'type': interface['return']})
        for row in case['regions']:
            if row['mode'] == 'scratch': continue
            obj = case['objects'][row['object']]
            for i in range(row['start'], row['start'] + row['length']):
                result.append({'label': f'case:{index}:object:{row["objectIndex"]}:{i}:',
                               'type': obj['type'], 'mode': row['mode'],
                               'initialValue': obj['values'][i] % 2**64})
        result.append({'label': f'case:{index}:complete:', 'completion': True})
    return result


def inspect_output(raw, interface, domain):
    """Return protocol completeness separately from preservation counterexamples."""
    rows = expected(domain, interface)
    try: lines = raw.decode('ascii').splitlines()
    except UnicodeDecodeError: lines = []
    if len(lines) != len(rows):
        return {'protocolComplete': False, 'preservationViolations': []}
    violations = []
    for line, row in zip(lines, rows):
        label = row['label']
        if not line.startswith(label):
            return {'protocolComplete': False, 'preservationViolations': []}
        value = line[len(label):]
        if not re.fullmatch(r'0|[1-9][0-9]{0,19}', value):
            return {'protocolComplete': False, 'preservationViolations': []}
        integer = int(value)
        if row.get('completion'):
            valid = integer == 1
        else:
            typ = row['type']; bits = typ['bits']
            valid = (0 <= integer < 2**bits if not typ['signed'] else
                     0 <= integer < 2**(bits - 1) or 2**64 - 2**(bits - 1) <= integer < 2**64)
        if not valid:
            return {'protocolComplete': False, 'preservationViolations': []}
        if row.get('mode') == 'preserve' and integer != row['initialValue']:
            violations.append({'location': label, 'expected': row['initialValue'], 'actual': integer})
    return {'protocolComplete': True, 'preservationViolations': violations}
