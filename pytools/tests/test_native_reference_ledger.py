from copy import deepcopy
import shutil
import subprocess

import pytest

from riscv2x86_py.native_reference_ledger import derive
from riscv2x86_py.native_external_requirements import reference_sites
from riscv2x86_py.project_build_records import identity


def signed(body, key):
    return dict(body, **{key: identity(body)})


def fixture(tmp_path):
    cc = shutil.which('gcc')
    if cc is None: pytest.skip('native GCC required')
    source = tmp_path/'caller.c'
    source.write_text('extern int unrelated_global; extern int unrelated_call(int);'
                      'int f(void){return unrelated_call(unrelated_global);}')
    obj = tmp_path/'caller.o'
    subprocess.run([cc, '-c', str(source), '-o', str(obj)], check=True)
    raw = obj.read_bytes()
    rows = []
    for name in ('unrelated_global', 'unrelated_call', 'not_referenced'):
        body = {'obligationIdentity': name, 'originalObligation': {'object': 'root', 'symbol': name},
                'references': reference_sites(raw, name), 'objectRole': 'translated-root',
                'selectedBuildActions': [], 'requiredEvidence': ['TYPED_BEHAVIOR_CONTRACT_REQUIRED']}
        rows.append(signed(body, 'requirementIdentity'))
    body = {'schemaVersion': 'riscv2x86.native-external-requirements.v1',
            'requirements': rows, 'originalProviderBlockers': [{'reason': 'parent-blocker'}]}
    return raw, signed(body, 'requirementsIdentity')


def test_every_parent_and_reference_preserved_without_symbol_name_authority(tmp_path):
    raw, requirements = fixture(tmp_path)
    result = derive(requirements, {'root': raw})
    assert result['parentObligationCount'] == 3
    assert result['referenceCount'] >= 3
    assert set(result['parentObligationIdentities']) == {'unrelated_global', 'unrelated_call', 'not_referenced'}
    absent = [r for r in result['references'] if r['originalObligation']['symbol'] == 'not_referenced']
    assert len(absent) == 1 and absent[0]['byteWitness'] is None
    assert all(r['status'] == 'pending' for r in result['references'])
    assert not result['externalContractClosureComplete']
    assert result['originalProviderBlockers'] == requirements['originalProviderBlockers']


def test_changed_object_and_rehashed_reference_location_reject(tmp_path):
    raw, req = fixture(tmp_path)
    with pytest.raises(ValueError, match='OBJECT_CHANGED'):
        derive(req, {'root': raw+b'changed'})
    forged = deepcopy(req)
    forged['requirements'][0]['references']['sites'][0]['relocation']['offset'] += 1
    row = forged['requirements'][0]
    row['requirementIdentity'] = identity({k: v for k, v in row.items() if k != 'requirementIdentity'})
    forged['requirementsIdentity'] = identity({k: v for k, v in forged.items() if k != 'requirementsIdentity'})
    with pytest.raises(ValueError, match='REFERENCE_MISMATCH'):
        derive(forged, {'root': raw})
