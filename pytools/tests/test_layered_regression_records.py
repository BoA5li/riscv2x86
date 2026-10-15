import importlib.util
from pathlib import Path


def test_record_extraction_preserves_partial_and_nested_records():
    path = Path(__file__).resolve().parents[2] / 'experiment/run_layered_regression.py'
    spec = importlib.util.spec_from_file_location('layered_regression', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = {'dimensions': [{'executionDisposition': 'precondition_rejected',
                              'evidenceProductionDisposition': 'not_produced'},
                             {'authorityIdentity': 'example',
                              'child': {'sourceObservationIdentity': 'source'}}]}
    records = list(module.collect_records(payload))
    assert [record['jsonPath'] for record in records] == [
        '$.dimensions[0]', '$.dimensions[1]', '$.dimensions[1].child']
    assert records[0]['record'] == payload['dimensions'][0]
    assert 'status' not in records[1]['record']
