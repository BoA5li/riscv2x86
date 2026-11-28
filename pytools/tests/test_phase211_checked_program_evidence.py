"""Real host build/decoder receipts; compiler ingress remains fixture-owned.

These tests never claim cross-ISA ABI/access/intent or program approval.
"""
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
from types import SimpleNamespace

import pytest
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py import native_original_evaluation as bridge
from riscv2x86_py import native_project_l2 as l2
from riscv2x86_py import program_machine_inventory as machines
from riscv2x86_py import program_checked_evidence as evidence
from riscv2x86_py.program_claim_consumption import consume
from riscv2x86_py.verification_session import session
from riscv2x86_py.translation_validation import ValidationLevel
from .test_native_captured_deployment import captured
from .test_native_project_evaluation import toy_project


@pytest.fixture
def receipt_pair(toy_project):
    root, _, spec, programs = toy_project
    builds = {side: p.build_record(programs[side], spec, side) for side in ('source', 'target')}
    refs = evidence.references(root / 'project.json', builds)
    return root, spec, programs, builds, refs


def test_checked_builds_enter_subclaims_without_approving_program(receipt_pair):
    _, spec, _, _, refs = receipt_pair
    result = consume(spec['projectEvaluationIdentity'], {}, project_evidence=refs)
    assert [c['kind'] for c in result['claims']] == ['recorded-project-builds']
    rows = {r['reasonCode']: r for r in result['obligations']}
    assert rows['THREE_COMPILE_CONTEXT_REFINEMENT_REQUIRED']['missingProofFacts'] == ['three-context-semantic-refinement']
    assert rows['DEPENDENCY_CALL_AND_EFFECT_CLOSURE_REQUIRED']['missingProofFacts'] == ['actual-call-selection-and-effects']
    assert all(not r['fullObligationDischarged'] for r in result['obligations'])


def test_formal_receipt_mode_ignores_caller_stage_flags(receipt_pair):
    _, spec, _, _, refs = receipt_pair
    value = consume(spec['projectEvaluationIdentity'], {'completedStages': ['machine-inventory']},
                    project_evidence=refs)
    assert {c['kind'] for c in value['claims']} == {'recorded-project-builds'}


def test_claim_identity_is_bound_to_actual_build_receipts(receipt_pair):
    root, spec, _, builds, refs = receipt_pair
    initial = consume(spec['projectEvaluationIdentity'], {}, project_evidence=refs)
    (root / 'fresh').mkdir()
    fresh = {side: p.build_side(root / 'project.json', side, builds[side]['input']['path'],
                                root / 'fresh' / side) for side in ('source', 'target')}
    other = evidence.references(root / 'project.json', fresh)
    changed = consume(spec['projectEvaluationIdentity'], {}, project_evidence=other)
    assert initial['scopeIdentity'] != changed['scopeIdentity']
    assert initial['claims'][0]['claimIdentity'] != changed['claims'][0]['claimIdentity']


@pytest.fixture
def inventory_receipt(receipt_pair, monkeypatch):
    root, spec, programs, builds, refs = receipt_pair
    from riscv2x86_py import native_original_applicability as app
    ast = {'kind': 'TranslationUnitDecl', 'inner': [
        {'kind': 'FunctionDecl', 'id': 'compiler-value', 'mangledName': 'value'}]}
    records = [{'functionAstPath': [0], 'instanceBindingIdentity': 'instance'}]
    # Only frontend context is owned here. Real SLEIGH decoding, original
    # build receipt checks and the inventory checker execute on host ELF bytes.
    monkeypatch.setattr(app, 'context', lambda path: (spec, ast, records, b'', {}))
    machines.acquire(root / 'project.json', builds, root / 'machine.json')
    refs = dict(refs, machineInventory=d.snapshot(root / 'machine.json'))
    return root, spec, programs, builds, refs


def test_real_bounded_inventory_is_consumed_without_becoming_abi_proof(inventory_receipt):
    _, spec, _, _, refs = inventory_receipt
    result = consume(spec['projectEvaluationIdentity'], {}, project_evidence=refs)
    assert {c['kind'] for c in result['claims']} == {'recorded-project-builds', 'bounded-machine-inventory'}
    abi = next(r for r in result['obligations'] if r['reasonCode'] == 'ACTUAL_MACHINE_ABI_REQUIRED')
    assert abi['missingProofFacts'] == ['complete-machine-call-and-exit-contract']
    assert not abi['fullObligationDischarged'] and not result['semanticApproval']
    with session(0): uncached = evidence.inspect(spec['projectEvaluationIdentity'], refs)
    with session(): cached = evidence.inspect(spec['projectEvaluationIdentity'], refs)
    assert cached == uncached


@pytest.mark.parametrize('change', ['project', 'swap-builds', 'extra-approval', 'relocated-build'])
def test_unbound_subclaim_receipts_reject(receipt_pair, change):
    root, spec, _, _, refs = receipt_pair
    refs = deepcopy(refs); project_id = spec['projectEvaluationIdentity']
    if change == 'project': project_id = 'different-project'
    elif change == 'swap-builds': refs['builds']['source'] = refs['builds']['target']
    elif change == 'extra-approval': refs['machineAbiClosureVerified'] = True
    else:
        copy = root / 'copied-build.json'; copy.write_bytes(Path(refs['builds']['source']['path']).read_bytes())
        refs['builds']['source'] = d.snapshot(copy)
    with pytest.raises(ValueError): evidence.inspect(project_id, refs)


def test_changed_build_rejects_even_with_an_operation_cache(receipt_pair):
    _, spec, programs, _, refs = receipt_pair
    with session():
        evidence.inspect(spec['projectEvaluationIdentity'], refs)
        path = Path(programs['target'].artifact_path)
        path.write_bytes(path.read_bytes() + b'changed')
        with pytest.raises(ValueError): evidence.inspect(spec['projectEvaluationIdentity'], refs)


def test_original_readback_rederives_observations_and_consumption(receipt_pair, monkeypatch):
    root, _, programs, _, _ = receipt_pair
    from riscv2x86_py import native_experiment_driver as driver
    original_command = driver.command
    monkeypatch.setattr(driver, 'command', lambda argv, *args:
        original_command(argv[3:] if argv[:2] == ['/usr/bin/env', '-L'] else argv, *args))
    work = root / 'verification'; work.mkdir()
    layer = p.factory({'specPath': str(root / 'project.json'), 'workDirectory': str(work / 'observed'), 'level': 'L1'})(
        level=ValidationLevel.L1,
        source_program_artifact=programs['source'], target_program_artifact=programs['target'])
    result = {'attempts': [{'attemptArtifactId': 'subject', 'validation': {'layers': [{
        'level': 'L1', 'status': layer.status.value, 'evidenceIdentity': layer.evidence_identity, 'detail': layer.detail}]}}],
        **{side + 'ProgramArtifact': asdict(programs[side]) for side in programs}}
    request = SimpleNamespace(runtime_registry_template={'validators': {'L1': {'type': 'original-captured-project',
        'config': {'specPath': str(root / 'project.json'), 'workDirectory': '${WORK_DIR}/observed'}}}})
    bridge.check_project_machine_inventory(result, request, work)
    parsed = json.loads(layer.detail)
    parsed['obligationAssessment']['claimConsumption']['claims'].clear()
    p.write(work / 'observed/obligation-assessment.json', parsed['obligationAssessment'])
    raw = result['attempts'][0]['validation']['layers'][0]
    raw['detail'] = json.dumps(parsed); raw['evidenceIdentity'] = d.digest(work / 'observed/obligation-assessment.json')
    with pytest.raises(ValueError, match='ASSESSMENT_REDERIVATION'):
        bridge.check_project_machine_inventory(result, request, work)


def test_default_catalogue_resolves_requirements_without_api_execution(tmp_path):
    from .test_evaluation_runner import _setup
    from riscv2x86_py.l2_eligibility import classify_l2_requirements
    from riscv2x86_py.validation_runtime_registry import validation_runtime_registry_from_dict, VALIDATION_RUNTIME_REGISTRY_SCHEMA
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    request, _, attempt = _setup(tmp_path / 'input')
    report = d.read(request.translated_report); manifest = tmp_path / 'requirements.json'
    from .l2_profile_fixtures import profile_dict
    report['findings'][0]['l2SemanticProfile'] = profile_dict(attempt.fragment_id)
    p.write(Path(request.translated_report), report)
    p.write(manifest, classify_l2_requirements(report))
    descriptor = l2.planning_descriptor(manifest, request.translated_report, tmp_path / 'resolved.json')
    descriptor['config']['fragmentId'] = attempt.fragment_id
    registry = validation_runtime_registry_from_dict({'schemaVersion': VALIDATION_RUNTIME_REGISTRY_SCHEMA,
        'version': 'original-project.v1', 'validators': {'L2': descriptor}})
    # Missing eligibility/provider authority remains inconclusive, never pass.
    result = registry.layer_validators[ValidationLevel.L2](level=ValidationLevel.L2,
        translation_artifact=SimpleNamespace(fragment_id=attempt.fragment_id))
    assert result.status is ValidationStatus.INCONCLUSIVE
    assert (tmp_path / 'resolved.json').is_file()


def test_native_requirement_manifest_is_derived_not_caller_certified(toy_project):
    from riscv2x86_py.l2_eligibility import classify_l2_requirements
    root, _, spec, _ = toy_project
    report = root / 'report.json'; p.write(report, {'findings': []})
    translation = root / 'native-translation.json'; p.write(translation, {'report': d.snapshot(report)})
    run = root / 'native-run.json'; p.write(run, {'translation': d.snapshot(translation)})
    spec['run'] = d.snapshot(run); p.write(root / 'project.json', spec)
    manifest = root / 'requirements.json'; p.write(manifest, classify_l2_requirements(d.read(report)))
    assert l2.checked_requirements(root / 'project.json', report, manifest)['requirements'] == []
    other = root / 'other-report.json'; other.write_bytes(report.read_bytes())
    with pytest.raises(ValueError, match='AUDITED_REPORT_MISMATCH'):
        l2.checked_requirements(root / 'project.json', other, manifest)
    from riscv2x86_py import evaluation
    config = l2.planning_descriptor(manifest, other, root / 'resolution.json')['config']
    request = SimpleNamespace(runtime_registry_template={'validators': {
        'L0': {'type': 'original-captured-project', 'config': {'specPath': str(root / 'project.json')}},
        'L1': {'type': 'original-captured-project', 'config': {'specPath': str(root / 'project.json')}},
        'L2': {'type': 'requirement-driven', 'config': config}}})
    with pytest.raises(ValueError, match='PROFILE_REPORT_MISMATCH'):
        evaluation._native_l2_requirements(request, report)
    changed = d.read(manifest); changed['classificationPolicy'] = 'unapproved-policy'
    changed = d.seal({k: v for k, v in changed.items() if k != 'manifestIdentity'}, 'manifestIdentity')
    p.write(manifest, changed)
    with pytest.raises(ValueError): l2.checked_requirements(root / 'project.json', report, manifest)
