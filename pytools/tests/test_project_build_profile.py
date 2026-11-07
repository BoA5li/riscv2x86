"""Role-bound target acquisition without changing the legacy source recipe."""
from copy import deepcopy
import json
import shutil
import pytest
from .test_project_acquisition_driver import fixture
from riscv2x86_py import project_acquisition as driver
from riscv2x86_py.project_build_profile import create, validate, targets
from riscv2x86_py.project_build_records import identity


def profile():
    roles = {k:shutil.which(v) for k,v in
             {'cc':'gcc','hostcc':'gcc','ar':'ar','ld':'ld','ranlib':'ranlib'}.items()}
    if not all(roles.values()):pytest.skip('native GNU tools required')
    return create('target', 'x86_64-linux-gnu', roles, '-O2 -fstack-protector-strong')


def test_profile_replays_and_role_or_rehashed_claim_rejects():
    value = profile();assert validate(value) == value
    forged = deepcopy(value);forged['abiCompatibilityVerified'] = True
    forged['profileIdentity'] = identity({k:v for k,v in forged.items() if k!='profileIdentity'})
    with pytest.raises(ValueError, match='REPLAY_MISMATCH'):validate(forged)
    with pytest.raises(ValueError, match='ROLE_MISMATCH'):
        create('source', 'riscv64-linux-gnu', {k:v['path'] for k,v in value['tools'].items()}, '-O2')


@pytest.mark.parametrize('goal', ['../test:x','/tmp:x','tests:VAR=value','tests:-f','tests:x:y','-C','tests:'])
def test_no_make_option_or_path_escape(goal):
    with pytest.raises(ValueError):targets([goal])


def test_target_profile_and_ordered_official_test_stages(tmp_path, monkeypatch):
    args = fixture(tmp_path, monkeypatch)
    value = profile();profile_path = tmp_path/'profile.json';profile_path.write_text(json.dumps(value))
    monkeypatch.setattr(driver, 'preflight', lambda project, tools=None:
        {'prerequisitesAvailable':True,'missing':[],
         'tools':[{'role':k,'path':v['path']} for k,v in value['tools'].items()]})
    assert driver.acquire(*args, 'gmp', build_profile=profile_path,
                          test_target=['tests:libtests.la','tests/mpz:t-powm']) == 0
    state = json.loads((args[-1]/'run-status.json').read_text())
    configure = next(s['command'] for s in state['stages'] if s['stage']=='configure')
    assert '--host=x86_64-linux-gnu' in configure
    assert 'CFLAGS=-O2 -fstack-protector-strong' in configure
    assert not any('rv64gc' in s for s in configure)
    tests = [s for s in state['stages'] if s['stage'].startswith('test-build-')]
    assert len(tests) == 2
    assert tests[0]['command'][-5:] == ['-C','tests','-j4','V=1','libtests.la']
    assert tests[1]['command'][-5:] == ['-C','tests/mpz','-j4','V=1','t-powm']
    imported = next(s['command'] for s in state['stages'] if s['stage']=='import')
    assert imported[imported.index('--stage')+1] == 'build'
    inspection = next(s['command'] for s in state['stages'] if s['stage']=='inspect')
    assert inspection[inspection.index('--target')+1] == 'x86_64'
    assert (args[-1]/'test-records-0.json').exists() and (args[-1]/'test-records.json').exists()
