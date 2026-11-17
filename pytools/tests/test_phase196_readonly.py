from copy import deepcopy
import json
import pytest
from riscv2x86_py import project_native_input as native
from riscv2x86_py.verification_session import pure, session
from .test_verification_session import receipt


def test_internal_readonly_cache_shares_without_ordinary_mutation():
    with session() as current:
        one = pure('read-only-fixture.v1', (b'key',), lambda: {'nodes': [{'value': 7}]}, readonly=True)
        two = pure('read-only-fixture.v1', (b'key',), lambda: pytest.fail('unexpected recomputation'), readonly=True)
        assert one is two
        for mutate in (lambda: one.update(value=8), lambda: one['nodes'].append(9),
                       lambda: one['nodes'][0].__setitem__('value', 9), lambda: one['nodes'].clear(),
                       lambda: one.__init__({}), lambda: one['nodes'].__init__([])):
            with pytest.raises(TypeError, match='READ_ONLY'):
                mutate()
        owned = deepcopy(one); owned['nodes'][0]['value'] = 9
        assert one['nodes'][0]['value'] == 7
        assert json.loads(json.dumps(one)) == {'nodes': [{'value': 7}]}
        assert not any(name.startswith('pure.copy.') for name in current.profile()['timings'])


def test_native_hot_readers_share_but_public_copies_and_live_checks_remain(tmp_path):
    value = receipt(tmp_path)
    with session():
        one = native.validate_artifacts(value, readonly=True)
        two = native.validate_artifacts(value, readonly=True)
        assert one['canonicalAst'] is two['canonicalAst']
        with pytest.raises(TypeError):
            one['canonicalAst']['inner'].clear()
        owned = native.validate_artifacts(value)
        owned['canonicalAst']['inner'].clear()
        assert native.validate_artifacts(value, readonly=True)['canonicalAst']['inner']
        (tmp_path / 'inspection-native-input.stderr').write_bytes(b'changed')
        with pytest.raises(ValueError, match='ARTIFACT_CHANGED'):
            native.validate_artifacts(value, readonly=True)


def test_readonly_and_owned_modes_never_alias_and_no_cache_stays_readonly():
    for budget in (0, 1024 * 1024):
        with session(budget):
            shared = pure('mode.v1', (b'key',), lambda: {'a': []}, readonly=True)
            owned = pure('mode.v1', (b'key',), lambda: {'a': []})
            owned['a'].append('owned')
            assert shared['a'] == []
            with pytest.raises(TypeError):
                shared['a'].append('blocked')
