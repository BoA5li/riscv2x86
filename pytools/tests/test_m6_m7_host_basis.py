"""Host collection records facts and errors; old success labels grant nothing."""
import importlib.util
import json
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[2] / 'experiment/collect_m6_m7_basis.py'
spec = importlib.util.spec_from_file_location('m6_m7_host_basis', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_verified_input_is_not_relabelled_as_independent_acceptance(tmp_path):
    evaluation = tmp_path / 'evaluation.json'
    evaluation.write_text(json.dumps({'status': 'verified', 'attempts': [{'fragmentId': 'f',
        'validation': {'layers': [{'level': 'L2', 'status': 'verified',
            'detail': json.dumps({'schemaVersion': 'old-environment-observation'})}]}}]}))
    result = module.evaluation_record(evaluation)
    assert result['status'] == 'verified' and result['independentAuditPerformed'] is False
    assert result['attempts'][0]['layers'][0]['detailSchema'] == 'old-environment-observation'


def test_backend_label_does_not_become_calibration_evidence(tmp_path):
    backend = tmp_path / 'backend.json'
    backend.write_text(json.dumps({'schemaVersion': 'fixture', 'semanticApproval': True}))
    result = module.backend_record(backend)
    assert result['declaredFields']['semanticApproval'] is True
    assert result['formalBackendValidationPerformed'] is False


@pytest.mark.parametrize('detail', ['invalid-json', None, '{"reasonCodes":["blocked"]}'])
def test_detail_is_data_and_missing_observation_remains_missing(tmp_path, detail):
    path = tmp_path / 'evaluation.json'
    path.write_text(json.dumps({'attempts': [{'validation': {'layers': [
        {'level': 'L3', 'status': 'inconclusive', 'detail': detail}]}}]}))
    assert module.evaluation_record(path)['attempts'][0]['layers'][0]['detailSchema'] is None


def test_missing_explicit_files_report_errors_without_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(module.shutil, 'which', lambda name: None)
    monkeypatch.setattr(module, 'command', lambda argv: {'command': argv, 'returnCode': 0})
    result = module.collect(repository=tmp_path, backends=[tmp_path / 'missing.json'])
    assert len(result['errors']) == 1
    assert result['executionPerformed'] is False and result['semanticApproval'] is False
    assert result['productionAcceptanceComplete'] is False
    assert all(not tool['available'] for tool in result['tools'].values())
