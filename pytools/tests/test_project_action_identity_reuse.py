"""Only pure hashes reuse; fresh file bytes and comparisons remain mandatory."""
import os
import pytest
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py.verification_session import session


def records(path):
    action = p.d.seal({'kind': 'compile', 'arguments': ['compiler','-c','input.c']}, 'actionIdentity')
    p.write(path, {'schemaVersion': 'riscv2x86.project-build-records.v1', 'actions': [action]})
    return action


def test_identity_derivation_reuses_fresh_identical_content_without_caching_validation(tmp_path, monkeypatch):
    path = tmp_path / 'records.json'; action = records(path)
    calls = []; original = p.d.identity
    def counted(value): calls.append(value); return original(value)
    monkeypatch.setattr(p.d, 'identity', counted)
    with session(1024 * 1024) as verification:
        first = p.checked_source_actions(path)
        first[0]['kind'] = 'caller mutation'
        assert p.checked_source_actions(path) == [action]
        assert len(calls) == 1
        assert verification.profile()['memoization']['project-source-action-canonical-identities.v1']['hits'] == 1
        before = path.stat(); value = p.d.read(path)
        value['actions'][0]['kind'] = 'altered-content'
        p.write(path, value); os.utime(path, ns=(before.st_atime_ns,before.st_mtime_ns))
        with pytest.raises(ValueError, match='IDENTITY_INVALID'): p.checked_source_actions(path)
        assert len(calls) == 2


def test_cache_and_no_cache_rederive_same_actions_and_reject_invalid_schema(tmp_path):
    path = tmp_path / 'records.json'; records(path)
    with session(1024 * 1024): cached = p.checked_source_actions(path)
    with session(0): uncached = p.checked_source_actions(path)
    assert cached == uncached
    p.write(path, {'schemaVersion': 'wrong', 'actions': cached})
    with pytest.raises(ValueError, match='SCHEMA_INVALID'): p.checked_source_actions(path)
