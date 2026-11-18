"""Native compiler tests of region contracts, not cross-ISA semantic proofs."""
from copy import deepcopy
from pathlib import Path
import shutil
import subprocess

import pytest
from riscv2x86_py import native_api_contract as api
from riscv2x86_py import native_api_projection as projection
from riscv2x86_py import native_original_api as original
from .test_native_api_contract import MODEL
from .test_native_original_api import native_pair

C = lambda n: {'constant': n}
SIG = {'type': {'qualType': 'void (unsigned long *, const unsigned long *, unsigned long *, long)'},
       'variadic': False, 'attributes': [], 'parameters': [{'qualType': x} for x in
           ['unsigned long *', 'const unsigned long *', 'unsigned long *', 'long']]}
INTERFACE = api.signature(SIG, MODEL)


def domain():
    return {'schemaVersion': api.SCHEMA_V2, 'sourceDigest': 'sha256:' + '1' * 64,
            'claimScope': 'bounded-api-under-declared-preconditions',
            'preconditions': [{'eq': [{'bitAnd': [{'element': [1, C(0)]}, C(1)]}, C(1)]},
                              {'fitsSigned': [C(64), {'shiftLeft': [{'argument': 3}, C(1)]}]}],
            'regions': [{'argument': i, 'offsetElements': C(0), 'lengthElements': {'argument': 3}, 'mode': mode}
                        for i, mode in [(0, 'output'), (1, 'preserve'), (2, 'scratch')]],
            'cases': [{'objects': [{'id': 'shared', 'type': 'unsigned long', 'alignment': 16, 'values': [0, 0, 0, 0]},
                                  {'id': 'input', 'type': 'unsigned long', 'alignment': 16, 'values': [3, 5]}],
                       'arguments': [{'object': 'shared', 'offsetElements': 0}, {'object': 'input', 'offsetElements': 0},
                                     {'object': 'shared', 'offsetElements': 2}, {'integer': 2}]}]}


def run(tmp, body, data=None):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('GCC required')
    data = data or domain(); text, _ = api.harness('work', INTERFACE, data)
    file = tmp / 'x.c'; file.write_text(body + '\n' + text)
    exe = tmp / 'x'; subprocess.run([cc, '-std=gnu11', '-O2', '-Werror', str(file), '-o', str(exe)], check=True, capture_output=True)
    result = subprocess.run([str(exe)], check=True, capture_output=True)
    return result.stdout


def body(scratch, corrupt=False):
    return ('void work(unsigned long *o,const unsigned long *in,unsigned long *w,long n){'
            + ('((unsigned long*)in)[0]++;' if corrupt else '')
            + 'for(long i=0;i<n;i++){o[i]=in[i]+1;w[i]=' + str(scratch) + ';}}')


def test_shared_allocation_has_distinct_output_and_scratch_roles(tmp_path):
    left = tmp_path / 'left'; left.mkdir(); right = tmp_path / 'right'; right.mkdir()
    a = run(left, body(7)); b = run(right, body(999))
    assert a == b and b'object:0:2:' not in a
    assert projection.inspect_output(a, INTERFACE, domain()) == {'protocolComplete': True, 'preservationViolations': []}
    assert api.output_protocol(a, INTERFACE, domain())


def test_equal_corruption_of_preserved_input_is_not_accepted(tmp_path):
    raw = run(tmp_path, body(7, corrupt=True))
    facts = projection.inspect_output(raw, INTERFACE, domain())
    assert facts['protocolComplete'] and facts['preservationViolations']
    rows = {}
    for side in original.SIDES:
        folder = tmp_path / ('run-' + side); folder.mkdir()
        (folder / 'stdout.log').write_bytes(raw); (folder / 'stderr.log').write_bytes(b'')
        rows['run-' + side] = {'returnCode': 0, 'failureReason': None}
    result = original.compare_runs(rows, tmp_path, {'interface': INTERFACE}, domain())
    assert not result['mismatches'] and result['processObservationStatus'] == 'failed'


@pytest.mark.parametrize('change', ['overlap', 'missing', 'scratch-only', 'const-output', 'bounds', 'bool', 'source', 'even'])
def test_invalid_region_or_input_contract_rejects(change):
    d = domain()
    if change == 'overlap': d['regions'].append(deepcopy(d['regions'][0]))
    elif change == 'missing': d['regions'].pop()
    elif change == 'scratch-only':
        d['regions'][0]['mode'] = 'scratch'; d['regions'][1]['mode'] = 'scratch'
    elif change == 'const-output': d['regions'][1]['mode'] = 'output'
    elif change == 'bounds': d['regions'][0]['lengthElements'] = C(7)
    elif change == 'bool': d['regions'][0]['argument'] = True
    elif change == 'source': d['sourceDigest'] = 'not-a-digest'
    else: d['cases'][0]['objects'][1]['values'][0] = 4
    with pytest.raises(ValueError): api.validate(d, INTERFACE)


def test_output_mismatch_remains_visible(tmp_path):
    raw = run(tmp_path, body(7))
    changed = raw.replace(b'object:0:0:4', b'object:0:0:9')
    assert raw != changed and api.output_protocol(changed, INTERFACE, domain())
    assert not api.output_protocol(raw.replace(b'case:0:complete:1\n', b''), INTERFACE, domain())
    assert not api.output_protocol(raw + b'case:0:object:0:2:7\n', INTERFACE, domain())


@pytest.mark.parametrize('expr,expected', [
    ({'ceilDivide': [C(65), C(64)]}, 2), ({'max': [C(3), C(10)]}, 10),
    ({'subtract': [C(2), C(5)]}, -3), ({'modulo': [C(5), C(2)]}, 1),
    ({'fitsSigned': [C(8), C(128)]}, False), ({'fitsUnsigned': [C(8), C(255)]}, True),
    ({'all': [{'eq': [C(1), C(1)]}, {'gt': [C(2), C(1)]}]}, True),
])
def test_bounded_generic_math(expr, expected):
    assert api.expression(expr, [], {}) == expected


@pytest.mark.parametrize('expr', [
    {'ceilDivide': [C(1), C(0)]}, {'bitAnd': [C(-1), C(1)]}, {'shiftLeft': [C(1), C(64)]},
    {'all': [C(1)]}, {'fitsSigned': [C(0), C(1)]}, {'element': [0, C(0)]},
])
def test_bad_math_is_not_silently_coerced(expr):
    with pytest.raises(ValueError): api.expression(expr, [], {})


def test_v2_domain_is_bound_to_original_source_and_checked_on_replay(native_pair):
    spec, request, builds, root, _ = native_pair
    d = original.d.read(request); data = d['domain']
    data.update(schemaVersion=api.SCHEMA_V2, sourceDigest=original.d.digest(Path(builds['source']).with_name('body.i')),
                regions=[{'argument': 0, 'offsetElements': C(0), 'lengthElements': C(1), 'mode': 'output'}])
    original.project.write(request, d)
    result = original.acquire(spec, request, root / 'v2', builds=builds)
    assert result['regionProjection'][0][0]['mode'] == 'output'
    assert original.check(root / 'v2/result.json') == result
    from riscv2x86_py import project_evidence_ledger
    ledger = project_evidence_ledger.inspect(root / 'v2/result.json')
    assert ledger['scope']['caseCount'] == 1 and all(not x['fullObligationDischarged'] for x in ledger['programObligations'])
    d['domain']['sourceDigest'] = 'sha256:' + '0' * 64; original.project.write(request, d)
    with pytest.raises(ValueError, match='SOURCE_MISMATCH'): original.request_context(spec, request)


def test_real_corpus_contract_data_uses_generic_operators_and_three_finite_cases():
    path = Path(__file__).resolve().parents[2] / 'experiment/contracts/gmp-sec-powm-pinned-finite-v2.json'
    data = original.d.read(path)
    types = ['unsigned long *', 'const unsigned long *', 'long', 'const unsigned long *',
             'unsigned long', 'const unsigned long *', 'long', 'unsigned long *']
    sig = {'type': {'qualType': 'void (' + ','.join(types) + ')'}, 'variadic': False, 'attributes': [],
           'parameters': [{'qualType': t} for t in types]}
    parsed = api.signature(sig, MODEL)
    assert len(api.validate(data, parsed)) == 3
    data['cases'][0]['objects'][-1]['values'].pop()
    with pytest.raises(ValueError): api.validate(data, parsed)


def test_pinned_corpus_shape_executes_eight_mixed_arguments_on_native_compiler(tmp_path):
    """Host-only ABI/projection test; this function is NOT a GMP replacement."""
    cc = shutil.which('gcc')
    if not cc: pytest.skip('GCC required')
    types = ['unsigned long *', 'const unsigned long *', 'long', 'const unsigned long *',
             'unsigned long', 'const unsigned long *', 'long', 'unsigned long *']
    sig = {'type': {'qualType': 'void (' + ','.join(types) + ')'}, 'variadic': False, 'attributes': [],
           'parameters': [{'qualType': t} for t in types]}
    interface = api.signature(sig, MODEL)
    data = original.d.read(Path(__file__).resolve().parents[2] / 'experiment/contracts/gmp-sec-powm-pinned-finite-v2.json')
    driver, _ = api.harness('mixed_entry', interface, data)
    impl = ('void mixed_entry(unsigned long *o,const unsigned long *b,long bn,const unsigned long *e,'
            'unsigned long bits,const unsigned long *m,long n,unsigned long *w){'
            'for(long i=0;i<10;i++)w[i]=bits+i; o[0]=b[0]+e[0]+m[0]+bn+n;}\n')
    source = tmp_path / 'test.c'; source.write_text(impl + driver)
    program = tmp_path / 'program'
    subprocess.run([cc, '-std=gnu11', '-O2', '-Werror', str(source), '-o', str(program)], check=True)
    raw = subprocess.check_output([str(program)])
    assert projection.inspect_output(raw, interface, data) == {'protocolComplete': True, 'preservationViolations': []}
    assert raw.count(b':complete:1\n') == 3
