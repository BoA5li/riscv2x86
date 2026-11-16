"""Pure memoization is an optimization, never a validation-result cache."""
import json
import os
import pytest

from riscv2x86_py.verification_session import pure, session, measured
from riscv2x86_py import project_native_input as native
from riscv2x86_py.project_build_records import identity


def test_same_bytes_reuse_but_changed_bytes_and_policy_do_not(tmp_path):
    path = tmp_path / 'input'; path.write_bytes(b'one')
    calls = []
    def read():
        raw = path.read_bytes()
        return pure('fixture.v1', (raw,), lambda: calls.append(raw) or {'raw': raw})
    with session() as active:
        first = read(); first['raw'] = b'caller mutation'
        assert read() == {'raw': b'one'} and calls == [b'one']
        before = path.stat()
        path.write_bytes(b'two')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert read() == {'raw': b'two'}
        assert pure('fixture.v2', (b'two',), lambda: 'different policy') == 'different policy'
        assert active.profile()['memoization']['fixture.v1']['hits'] == 1
    assert active.profile()['retainedCacheBytes'] == 0
    with session():
        read()
    assert calls == [b'one', b'two', b'two']


def test_exceptions_are_not_cached_and_disabled_or_small_budgets_keep_results():
    calls = []
    def fail():
        calls.append(1)
        raise ValueError('invalid current bytes')
    with session():
        for _ in range(2):
            with pytest.raises(ValueError):
                pure('failure.v1', (b'x',), fail)
    assert len(calls) == 2
    for budget in (0, 1):
        with session(budget) as active:
            assert pure('large.v1', (b'x',), lambda: [1, 2]) == [1, 2]
            assert pure('large.v1', (b'x',), lambda: [3, 4]) == [3, 4]
            assert active.profile()['memoization']['large.v1']['budgetSkips'] == 2


def test_nested_spans_count_calls_failures_and_restore_an_outer_session():
    @measured('inner')
    def inner(fail=False):
        if fail:
            raise ValueError('fixture')
    @measured('outer')
    def outer():
        inner()
        with pytest.raises(ValueError):
            inner(True)
    with session() as parent:
        outer()
        with session() as child:
            inner()
        assert child.profile()['timings']['inner']['calls'] == 1
        inner()
    profile = parent.profile()
    assert profile['timings']['inner']['calls'] == 3
    assert profile['timings']['inner']['failedCalls'] == 1
    for row in profile['timings'].values():
        assert 0 <= row['exclusiveSeconds'] <= row['inclusiveSeconds']
    assert profile['wallSeconds'] >= profile['timings']['outer']['inclusiveSeconds']


def receipt(tmp_path, literal='one'):
    """Protocol bytes only; no simulated compiler result is a semantic proof."""
    raw = {'kind': 'TranslationUnitDecl', 'id': '0x123', 'inner': [
        {'kind': 'StringLiteral', 'value': literal}]}
    expanded = b'int fixture;\n'
    canonical = native.canonical_ast(raw)
    analysis = {'nativeInputDigest': native.bytes_identity(expanded)}
    analysis_id = identity(analysis)
    inventory = native.ast_inventory(canonical, analysis_id)
    def write(name, data):
        path = tmp_path / name; path.write_bytes(data)
        return str(path), native.bytes_identity(data)
    commands = []
    for stage, data in (('inspection-native-input', json.dumps(raw).encode()), ('native-expanded', expanded)):
        stdout, stdout_digest = write(stage + '.stdout', data)
        stderr, stderr_digest = write(stage + '.stderr', b'')
        commands.append({'stage': stage, 'stdoutPath': stdout, 'stdoutDigest': stdout_digest,
                         'stderrPath': stderr, 'stderrDigest': stderr_digest,
                         'stdinIdentity': native.bytes_identity(expanded)})
    ast_path, ast_digest = write('canonical.json', json.dumps(canonical).encode())
    inv_path, inv_digest = write('inventory.json', json.dumps(inventory).encode())
    value = {'schemaVersion': native.SCHEMA, 'commands': commands,
             'analysisInput': analysis, 'analysisInputIdentity': analysis_id,
             'canonicalAstPath': ast_path, 'canonicalAstDigest': ast_digest,
             'canonicalAstIdentity': identity(canonical),
             'inventoryPath': inv_path, 'inventoryDigest': inv_digest,
             'inventoryIdentity': inventory['inventoryIdentity']}
    value['nativeInputIdentity'] = identity(value)
    return value


def test_native_artifact_rederivation_reuses_only_pure_graph_and_keeps_checks(tmp_path):
    value = receipt(tmp_path)
    uncached = native.validate_artifacts(value)
    with session() as active:
        first = native.validate_artifacts(value)
        first['canonicalAst']['inner'][0]['value'] = 'caller-mutation'
        assert native.validate_artifacts(value) == uncached
        stats = active.profile()['memoization']['native-canonical-graph-and-inventory.v1']
        assert stats['hits'] == 1
        # A changed current file is still rejected on a warm cache.
        stderr = tmp_path / 'inspection-native-input.stderr'
        stderr.write_bytes(b'tampered')
        with pytest.raises(ValueError, match='ARTIFACT_CHANGED'):
            native.validate_artifacts(value)
        stderr.write_bytes(b'')
        # A coherent new input at the same paths receives a new pure key.
        changed = receipt(tmp_path, 'two')
        result = native.validate_artifacts(changed)
        assert result['canonicalAst']['inner'][0]['value'] == 'two'
        assert active.profile()['memoization']['native-canonical-graph-and-inventory.v1']['misses'] == 2


def test_resealed_inventory_cannot_claim_facts_not_rederived_from_ast(tmp_path):
    from pathlib import Path
    value = receipt(tmp_path)
    with session():
        native.validate_artifacts(value)
        path = Path(value['inventoryPath'])
        inventory = json.loads(path.read_text())
        inventory['semanticApproval'] = True
        inventory['inventoryIdentity'] = identity({k: v for k, v in inventory.items() if k != 'inventoryIdentity'})
        path.write_text(json.dumps(inventory))
        value['inventoryDigest'] = native.bytes_identity(path.read_bytes())
        value['inventoryIdentity'] = inventory['inventoryIdentity']
        value['nativeInputIdentity'] = identity({k: v for k, v in value.items() if k != 'nativeInputIdentity'})
        with pytest.raises(ValueError, match='INVENTORY_BINDING_INVALID'):
            native.validate_artifacts(value)
