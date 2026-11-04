"""Entry identity replaces file function count, without extending joint effects."""
from copy import deepcopy
import pytest

from riscv2x86_py.l3_joint_spec import spec
from tests.test_l3_joint_program import fixture


@pytest.mark.parametrize('before', [False, True])
def test_unrelated_export_does_not_change_joint_spec(tmp_path, before):
    _, findings, function = fixture(tmp_path)
    baseline = spec(findings, [function])
    other = {'name': 'unrelated_export', 'functionId': 'sha256:' + 'f' * 64}
    functions = [other, function] if before else [function, other]
    assert spec(findings, functions) == baseline


def test_duplicate_entry_identity_is_still_rejected(tmp_path):
    _, findings, function = fixture(tmp_path)
    with pytest.raises(ValueError, match='ENTRY_IDENTITY_AMBIGUOUS'):
        spec(findings, [function, deepcopy(function)])


def test_unrelated_export_does_not_authorize_calls_or_unproved_shell(tmp_path):
    _, findings, function = fixture(tmp_path)
    function.pop('compilerJointScope')
    with pytest.raises(ValueError, match='COMPILER_SCOPE_REQUIRED'):
        spec(findings, [function, {'functionId': 'other'}])


def test_findings_from_another_function_are_not_silently_filtered(tmp_path):
    _, findings, function = fixture(tmp_path)
    findings[-1]['fragment']['compilerFragmentAuthority']['functionIdentity'] = 'other'
    with pytest.raises(ValueError, match='ONE_ENTRY_REQUIRED'):
        spec(findings, [function, {'functionId': 'other'}])


def test_inventory_registers_joint_providers_despite_an_extra_export(tmp_path, monkeypatch):
    import json
    from riscv2x86_py import automatic_batch_cli as auto, l3_mechanism_selection, l3_joint_backend
    from riscv2x86_py.l3_trace_support import identity, digest
    data, _, function = fixture(tmp_path)
    source = tmp_path / 'input.c'
    source.write_bytes(data)
    front = tmp_path / 'frontend'
    front.write_text('fixture')
    front.chmod(0o755)
    other = {'name': 'extra', 'functionId': identity('extra'), 'sourceDigest': digest(source),
             'arity': 1, 'parameterTypes': ['unsigned long'], 'returnType': 'unsigned long',
             'pointerParameters': [], 'l2OperandBoundary': {'complete': False}}
    monkeypatch.setattr(auto, 'inspect_entry_points', lambda *a: (False, [other, function]))
    backend = tmp_path / 'backend.json'
    backend.write_text('{}')
    selection = tmp_path / 'selections.json'
    selection.write_text('{}')
    monkeypatch.setattr(l3_mechanism_selection, 'load', lambda *a: {'joint': {
        'path': str(backend), 'digest': digest(backend), 'backendIdentity': identity('backend')}})
    monkeypatch.setattr(l3_joint_backend, 'validate', lambda *a: {
        'backendIdentity': identity('backend'), 'sourceExecutor': 'rv', 'targetExecutor': 'x86'})
    directory = tmp_path / 'inventory'
    auto.prepare_automatic_inventory(source, directory, frontend=front, l3_mechanism_selections=selection)
    descriptor = json.loads((directory / 'cases/input/riscv2x86-evaluation.json').read_text())
    validators = descriptor['request']['runtimeRegistryTemplate']['validators']
    providers = validators['L2']['config']['providers']
    assert providers and all(p['config']['mode'] == 'joint-program-functions' for p in providers)
    assert validators['L3']['type'] == 'l3-mechanism-route'
