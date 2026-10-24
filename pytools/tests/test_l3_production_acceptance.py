"""Acceptance audit fixtures, not platform measurements."""
from copy import deepcopy
import json

import pytest

from riscv2x86_py.l3_production_acceptance import audit_evaluation
from riscv2x86_py.l3_execution_context import L3ExecutionContext
from riscv2x86_py.l3_evidence_closure import identity
from tests.test_l3_authoritative_consumption import facts, closed, signed
from tests.test_l3_production_ingress import program, PROOF


def evaluated(tmp_path):
    profile, manifest = facts()
    source, target = program(tmp_path, 'source'), program(tmp_path, 'target')
    context = L3ExecutionContext.create(source, target)
    reports = {'source': {'measured': [1, 2]}, 'target': {'measured': [3, 4]}}
    fragment = closed(manifest['requirements'][0], reports)
    from dataclasses import asdict
    from riscv2x86_py.translation_validation import TranslationArtifact
    from riscv2x86_py.validation_status import PreservationMode
    artifact = TranslationArtifact('fragment:0', 'source-model', 'plan', 'constraints', PROOF,
        PreservationMode.ARCHITECTURE_EQUIVALENT, PROOF, 'runtime', 'v1', 'recipe', (), 'memory', 'c',
        effect_relation_set_identity=manifest['requirements'][0]['approvedTargetRelationIdentity'],
        renderer_semantic_contract_id='reviewed-renderer:v1')
    for dimension in fragment['dimensionResults'].values():
        dimension['translationArtifactIdentity'] = artifact.identity
        dimension['sourceArtifactIdentity'] = source.artifact_digest
        dimension['targetArtifactIdentity'] = target.artifact_digest
        signed(dimension)
    signed(fragment)
    from dataclasses import asdict
    return {'status': 'verified', 'translationEvaluationLink': {'l3Requirements': manifest},
        'sourceProgramArtifact': asdict(source), 'targetProgramArtifact': asdict(target),
        'attempts': [{'status': 'verified', 'fragmentId': profile['fragmentId'], 'translationArtifact': dict(asdict(artifact),
            preservation_mode=artifact.preservation_mode.value, ignored_source_state=[]), 'validation': {'status': 'verified', 'layers': [
            *[{'level': level, 'status': 'verified', 'evidenceIdentity': PROOF} for level in ('L0', 'L1', 'L2')],
            {'level': 'L3', 'status': 'verified', 'evidenceIdentity': PROOF,
             'detail': json.dumps({'providerDetail': json.dumps({'fragmentResult': fragment,
                'platformReports': reports, 'executionBindings': {side: context.request_binding(side)
                                                  for side in ('source', 'target')}})})}]}}]}


def test_complete_selected_scope_can_pass_with_actual_artifact_bindings(tmp_path):
    result = audit_evaluation(evaluated(tmp_path))
    assert result['status'] == 'verified'
    assert not result['physicalMicroarchitectureEquivalenceClaimed']
    assert len(result['fragments']) == 1


@pytest.mark.parametrize('mutation', ['no-l3', 'not-run', 'no-observation', 'stale-program',
                                     'old-invocation', 'missing-fragment', 'unknown-intent', 'partial'])
def test_prior_layers_or_self_consistent_hashes_cannot_replace_production_evidence(tmp_path, mutation):
    value = evaluated(tmp_path)
    layers = value['attempts'][0]['validation']['layers']
    if mutation == 'no-l3': layers.pop()
    if mutation == 'not-run': layers[-1]['status'] = 'not_run'
    if mutation == 'missing-fragment': value['attempts'] = []
    if mutation == 'unknown-intent':
        from riscv2x86_py.l3_intent_requirements import classify_l3_requirements
        value['translationEvaluationLink']['l3Requirements'] = classify_l3_requirements(
            {'findings': [{'fragment': {'id': 'fragment:0'}, 'translationOutcome': 'emitted'}]}).to_dict()
    if mutation in {'no-observation', 'stale-program', 'old-invocation', 'partial'}:
        raw = json.loads(json.loads(layers[-1]['detail'])['providerDetail'])
        if mutation == 'no-observation': raw.pop('executionBindings')
        if mutation == 'stale-program': raw['executionBindings']['source']['program']['artifactDigest'] = PROOF
        if mutation == 'old-invocation': raw['executionBindings']['target']['invocationId'] = 'previous'
        if mutation == 'partial': raw['fragmentResult']['dimensionResults'] = {}; signed(raw['fragmentResult'])
        layers[-1]['detail'] = json.dumps(raw)
    with pytest.raises((ValueError, KeyError)): audit_evaluation(value)


@pytest.mark.parametrize('complete', [True, False])
def test_required_l3_goal_cannot_succeed_on_architectural_batch_status(tmp_path, monkeypatch, complete):
    import sys
    from riscv2x86_py import automatic_batch_cli as auto
    value = evaluated(tmp_path)
    if not complete:
        value['attempts'][0]['validation']['layers'].pop()
    output = tmp_path / 'batch'; output.mkdir()
    (output / 'evaluation.json').write_text(json.dumps(value))
    monkeypatch.setattr(sys, 'argv', ['auto', '--input', 'selected.c', '--frontend', 'frontend',
                                     '--output-directory', str(output), '--require-l3'])
    monkeypatch.setattr(auto, 'prepare_automatic_inventory', lambda *a, **k: {})
    monkeypatch.setattr(auto, 'run_batch_evaluation', lambda *a, **k: {
        'batchIdentity': PROOF, 'caseCount': 1, 'statusCounts': {'verified': 1},
        'cases': [{'caseId': 'arbitrary-input', 'resultPath': 'evaluation.json'}]})
    assert auto.main() == (0 if complete else 2)
    acceptance = json.loads((output/'l3-production-acceptance.json').read_text())
    assert acceptance['productionAcceptanceComplete'] is complete
