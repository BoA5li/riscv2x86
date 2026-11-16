"""Profile publication is separate from evidence and retains original exits."""
import importlib.util
import json
from pathlib import Path
import pytest
from riscv2x86_py.verification_session import measured


def cli():
    path = Path(__file__).resolve().parents[2] / 'experiment/automate_native_project.py'
    spec = importlib.util.spec_from_file_location('profiled_project_cli', path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


@pytest.mark.parametrize('result', [0, 1, 2])
def test_profile_is_valid_json_and_does_not_change_operation_result(tmp_path, monkeypatch, result):
    module = cli()
    @measured('fixture.execute')
    def execute(args):
        return result
    monkeypatch.setattr(module, 'execute', execute)
    profile = tmp_path / 'profile.json'
    assert module.main(['resume', '--output', str(tmp_path / 'campaign'),
                        '--profile-output', str(profile), '--verification-cache-mib', '0']) == result
    value = json.loads(profile.read_text())
    assert value['wallSeconds'] >= 0
    assert value['timings']['fixture.execute']['calls'] == 1
    assert value['cacheBudgetBytes'] == 0
    assert 'semanticApproval' not in value


def test_profile_cannot_pollute_or_overwrite_evidence_output(tmp_path, monkeypatch):
    module = cli()
    called = []
    monkeypatch.setattr(module, 'execute', lambda args: called.append(1))
    root = tmp_path / 'campaign'; root.mkdir()
    with pytest.raises(SystemExit):
        module.main(['resume', '--output', str(root), '--profile-output', str(root / 'profile.json')])
    existing = tmp_path / 'profile.json'; existing.write_text('preserve')
    with pytest.raises(SystemExit):
        module.main(['resume', '--output', str(root), '--profile-output', str(existing)])
    assert existing.read_text() == 'preserve' and not called


def test_profile_rejects_invalid_memory_budgets_before_execution(tmp_path, monkeypatch):
    module = cli()
    called = []
    monkeypatch.setattr(module, 'execute', lambda args: called.append(1))
    with pytest.raises(SystemExit):
        module.main(['resume', '--output', str(tmp_path / 'campaign'), '--verification-cache-mib', '-1'])
    assert not called
