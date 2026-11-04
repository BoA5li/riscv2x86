"""Consumer integration fixtures. These do not replace real SYSTEM production tests."""
from copy import deepcopy
import json
import pytest

from riscv2x86_py import l3_system_route as route
from riscv2x86_py.l3_policy_evidence import consume_system
from riscv2x86_py.l3_trace_support import identity
from tests.test_l3_system_route import accepted_fixture


def bounded_fixture(tmp_path, monkeypatch):
    report, calls = accepted_fixture(tmp_path, monkeypatch)
    from riscv2x86_py.l3_system_intent import profile
    from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
    spec = {'fragmentId': 'fragment:0', 'programId': 'program:system',
            'relationIdentity': identity('relation'), 'specIdentity': identity('spec'),
            'proofIdentity': identity('proof'), 'requiredProperties': [
                {'propertyId': p, 'dimension': 'synchronization', 'unit': 'fragment'}
                for p in sorted(route.POLICY['properties'])]}
    manifest = classify_l3_requirements({'findings': [{'fragment': {'id': 'fragment:0'},
        'translationOutcome': 'emitted', 'l3IntentProfile': profile(spec, identity('producer'))}]}).to_dict()
    report['translationEvaluationLink']['l3Requirements'] = manifest
    report['translationEvaluationLink']['findings'] = [{'fragmentId': 'fragment:0'}]
    report['attempts'][0]['translationOutcome'] = 'emitted'
    layer = report['attempts'][0]['validation']['layers'][-1]
    detail = json.loads(layer['detail'])
    detail['systemIntent']['requirementManifest'] = manifest
    detail = route._seal({k: v for k, v in detail.items() if k != 'evidenceIdentity'})
    layer.update(detail=json.dumps(detail), evidenceIdentity=detail['evidenceIdentity'])
    monkeypatch.setattr(route, 'intent_evidence', lambda *a: deepcopy(detail['systemIntent']))
    return report, calls


def test_bounded_evidence_has_separate_scope_and_coverage(tmp_path, monkeypatch):
    report, calls = bounded_fixture(tmp_path, monkeypatch)
    from riscv2x86_py.l3_coverage import summarize_l3_case, merge_l3_coverage
    coverage = summarize_l3_case(report, [])
    assert calls == ['rebuilt']  # one full audit per coverage consumption
    counts = coverage['counts']
    assert counts['attempted'] == counts['completeExecution'] == counts['boundedSystemIntentVerified'] == 1
    assert counts['notRun'] == counts['architecturalIntentVerified'] == counts['diagnosticVerified'] == 0
    assert coverage['boundedSystemEvidence']['fragments'][0]['claimScope'] == 'bounded-controlled-environment-intent'
    assert merge_l3_coverage([{'l3Coverage': coverage}])['counts']['boundedSystemIntentVerified'] == 1


@pytest.mark.parametrize('mutation', ['marker-only', 'unknown-schema', 'missing-property',
    'extra-property', 'duplicate-attempt', 'wrong-manifest', 'wrong-scope', 'wrong-policy',
    'not-run', 'stale-program', 'boolean-return', 'wrong-environment'])
def test_consumer_rejects_incomplete_or_rehashed_evidence(tmp_path, monkeypatch, mutation):
    report, _ = bounded_fixture(tmp_path, monkeypatch)
    layers = report['attempts'][0]['validation']['layers']
    detail = json.loads(layers[-1]['detail'])
    if mutation == 'marker-only': detail = {'systemL3': True, 'status': 'verified'}
    elif mutation == 'unknown-schema': detail['schemaVersion'] = 'unreviewed'
    elif mutation in {'missing-property', 'extra-property'}:
        manifest = report['translationEvaluationLink']['l3Requirements']
        from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
        from riscv2x86_py.l3_system_intent import profile
        properties = list(manifest['requirements'][0]['requiredProperties'])
        if mutation == 'missing-property': properties.pop()
        else: properties.append({'propertyId': 'unproved', 'dimension': 'synchronization', 'unit': 'fragment'})
        spec = {'fragmentId': 'fragment:0', 'programId': 'program:system',
                'relationIdentity': identity('relation'), 'specIdentity': identity('spec'),
                'proofIdentity': identity('proof'), 'requiredProperties': properties}
        manifest = classify_l3_requirements({'findings': [{'fragment': {'id': 'fragment:0'},
            'translationOutcome': 'emitted', 'l3IntentProfile': profile(spec, identity('producer'))}]}).to_dict()
        report['translationEvaluationLink']['l3Requirements'] = manifest
        detail['systemIntent']['requirementManifest'] = manifest
        monkeypatch.setattr(route, 'intent_evidence', lambda *a: deepcopy(detail['systemIntent']))
    elif mutation == 'duplicate-attempt': report['attempts'].append(deepcopy(report['attempts'][0]))
    elif mutation == 'wrong-manifest': report['translationEvaluationLink']['l3Requirements']['requirements'] = []
    elif mutation == 'wrong-scope': detail['claimScope'] = 'architectural_intent'
    elif mutation == 'wrong-policy': detail['policy'] = dict(detail['policy'], excluded=[])
    elif mutation == 'not-run': layers[2]['status'] = 'not_run'
    elif mutation == 'stale-program':
        from pathlib import Path
        Path(detail['programs']['source']['path']).write_bytes(b'changed')
    elif mutation == 'boolean-return':
        obs = detail['observation']; obs['executions']['target']['returnCode'] = False
        obs['evidenceIdentity'] = identity({k: v for k, v in obs.items() if k != 'evidenceIdentity'})
    elif mutation == 'wrong-environment': detail['environmentId'] = 'other'
    detail = route._seal({k: v for k, v in detail.items() if k != 'evidenceIdentity'})
    layers[-1].update(detail=json.dumps(detail), evidenceIdentity=detail['evidenceIdentity'])
    with pytest.raises((ValueError, KeyError)):
        consume_system(report)


def test_coverage_never_accepts_a_persisted_summary_as_evidence(tmp_path, monkeypatch):
    report, _ = bounded_fixture(tmp_path, monkeypatch)
    saved = consume_system(report)
    report['attempts'][0]['validation']['layers'][-1]['detail'] = json.dumps(saved)
    with pytest.raises(ValueError): consume_system(report)


def test_paper_layer_map_retains_bounded_scope(tmp_path, monkeypatch):
    report, _ = bounded_fixture(tmp_path, monkeypatch)
    from riscv2x86_py.paper_evaluation import _validation_maps
    assert _validation_maps(report, {'fragment:0'})[0]['L3'] == 'bounded_verified'
    report['attempts'][0]['validation']['layers'][2]['status'] = 'not_run'
    assert _validation_maps(report, {'fragment:0'})[0]['L3'] == 'inconclusive'


@pytest.mark.parametrize('sidecar', ['valid', 'missing', 'mismatch'])
def test_batch_summary_consumes_bounded_policy(tmp_path, monkeypatch, sidecar):
    report, _ = bounded_fixture(tmp_path, monkeypatch)
    from riscv2x86_py import batch_evaluation_cli as batch
    from tests.test_batch_evaluation_cli import _fixture, _descriptor
    request, _, _ = _fixture(tmp_path)
    corpus = tmp_path / 'corpus'
    _descriptor(corpus / 'system', 'system', request)
    output = tmp_path / 'batch'
    def evaluate(*args, work_directory, **kwargs):
        work_directory.mkdir(parents=True)
        if sidecar != 'missing':
            raw = report['translationEvaluationLink']['l3Requirements']
            if sidecar == 'mismatch': raw = dict(raw, manifestIdentity=identity('other'))
            (work_directory / 'system.l3-requirements.json').write_text(json.dumps(raw))
        return deepcopy(report)
    monkeypatch.setattr(batch, 'run_evaluation', evaluate)
    monkeypatch.setattr(batch, 'persist_evaluation_result', lambda result, path: path.write_text(json.dumps(result)))
    monkeypatch.setattr(batch, '_l2_coverage_diagnostics', lambda *a: {})
    result = batch.run_batch_evaluation(corpus, output, jobs=1)
    case, = result['cases']
    assert result['statusCounts'] == ({'verified': 1} if sidecar == 'valid' else {'inconclusive': 1})
    if sidecar == 'valid':
        assert case['programValidationLevels']['L3'] == 'verified'
        assert case['l3FragmentResults'] == []  # no fabricated generic evidence
        assert case['l3ProgramResults'] == []
        assert case['l3BoundedSystemResults'][0]['policyId'] == route.POLICY['policyId']
        assert result['l3BoundedSystemVerifiedProgramCount'] == 1
        assert result['l3ArchitecturalIntentVerifiedProgramCount'] == 0
    else:
        assert 'l3.summary.authoritative-evidence-not-verified' in case['reasonCodes']


def test_paper_corpus_counts_bounded_evidence_separately(tmp_path, monkeypatch):
    from riscv2x86_py import paper_evaluation as paper
    from tests.test_paper_evaluation import _manifest
    value = _manifest(tmp_path)
    base = json.loads((tmp_path / 'result.json').read_text())
    artifacts = tmp_path / 'artifacts'; artifacts.mkdir()
    report, _ = bounded_fixture(artifacts, monkeypatch)
    report.update({key: base[key] for key in ('validationUnit', 'validationGroupId',
        'selectedAttemptIds', 'environmentProvenance', 'reasonCodes')})
    value['programs'][0]['validations'][0]['expectedEnvironmentId'] = report['targetEnvironment']['environmentId']
    monkeypatch.setattr(paper, '_load_evaluation', lambda path: report)
    result = paper.aggregate_paper_corpus(paper.paper_manifest_from_dict(value), manifest_directory=tmp_path)
    assert result['integrityStatus'] == 'verified', result.get('errors')
    metrics = result['metrics']
    assert metrics['l3BoundedSystemIntentVerifiedAmongRequired']['numerator'] == 1
    assert metrics['l3BoundedSystemVerifiedRate']['numerator'] == 1
    assert metrics['l3CompleteExecutionCoverage']['numerator'] == 1
    assert metrics['l3ArchitecturalIntentVerifiedAmongRequired']['numerator'] == 0
    assert metrics['l3VerifiedRate']['numerator'] == 0
    assert set(metrics) == set(result['metricDefinitions'])


@pytest.mark.parametrize('summarized', [False, True])
def test_cli_acceptance_requires_both_batch_and_independent_audit(tmp_path, monkeypatch, summarized):
    import sys
    from riscv2x86_py import automatic_batch_cli as auto
    report, _ = bounded_fixture(tmp_path, monkeypatch)
    output = tmp_path / 'cli'; output.mkdir()
    (output / 'evaluation.json').write_text(json.dumps(report))
    monkeypatch.setattr(sys, 'argv', ['auto', '--input', 'any.c', '--frontend', 'frontend',
        '--output-directory', str(output), '--require-l3'])
    monkeypatch.setattr(auto, 'prepare_automatic_inventory', lambda *a, **k: {})
    monkeypatch.setattr(auto, 'run_batch_evaluation', lambda *a, **k: {
        'batchIdentity': identity('batch'), 'caseCount': 1,
        'statusCounts': {'verified' if summarized else 'inconclusive': 1},
        'cases': [{'caseId': 'arbitrary', 'resultPath': 'evaluation.json'}]})
    assert auto.main() == (0 if summarized else 1)
    acceptance = json.loads((output / 'l3-production-acceptance.json').read_text())
    assert acceptance['independentResultAuditComplete'] is True
    assert acceptance['batchSummaryComplete'] is summarized
    assert acceptance['productionAcceptanceComplete'] is summarized


def test_readonly_host_inspector_replays_and_checks_summary(tmp_path, monkeypatch):
    import runpy
    from pathlib import Path
    from riscv2x86_py.l3_coverage import summarize_l3_case
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    report, _ = bounded_fixture(tmp_path, monkeypatch)
    root = tmp_path / 'production'; configured = root / 'configured'; configured.mkdir(parents=True)
    path = configured / 'evaluation.json'; path.write_text(json.dumps(report))
    coverage = summarize_l3_case(report, [])
    batch = {'caseCount': 1, 'statusCounts': {'verified': 1},
        'l3BoundedSystemVerifiedProgramCount': 1, 'l3ArchitecturalIntentVerifiedProgramCount': 0,
        'cases': [{'status': 'verified', 'resultPath': 'evaluation.json',
            'programValidationLevels': dict.fromkeys(('L0', 'L1', 'L2', 'L3'), 'verified'),
            'l3Coverage': coverage, 'l3BoundedSystemResults': [coverage['boundedSystemEvidence']]}]}
    batch_path = configured / 'batch-evaluation.json'; batch_path.write_text(json.dumps(batch))
    acceptance = dict.fromkeys(('productionAcceptanceComplete', 'independentResultAuditComplete', 'batchSummaryComplete'), True)
    acceptance['evaluations'] = [dict(audit_evaluation(report), caseId='any')]
    (configured / 'l3-production-acceptance.json').write_text(json.dumps(acceptance))
    state = {'schemaVersion': 'riscv2x86.controlled-system-production-run.v2',
        'currentStage': 'complete', 'blockers': [], 'originalLinuxUserEquivalent': False,
        'physicalMicroarchitectureEquivalenceClaimed': False,
        **dict.fromkeys(('productionAcceptanceComplete', 'executionComplete',
                        'independentResultAuditComplete', 'boundedSystemL3Complete'), True),
        'productionAcceptance': [{'resultPath': str(batch_path)}]}
    (root / 'run-status.json').write_text(json.dumps(state))
    inspect = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'experiment/inspect_system_l3_acceptance.py'))['inspect']
    assert inspect(root, expected_runs=1)['productionAcceptanceComplete'] is True
    assert inspect(root, expected_runs=2)['productionAcceptanceComplete'] is False
    batch['cases'][0]['l3BoundedSystemResults'][0]['fragments'][0]['evidenceIdentity'] = identity('other')
    batch_path.write_text(json.dumps(batch))
    assert inspect(root, expected_runs=1)['productionAcceptanceComplete'] is False
    path.write_text('{}')
    assert inspect(root, expected_runs=1)['productionAcceptanceComplete'] is False
