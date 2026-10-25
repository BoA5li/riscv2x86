"""Protocol/security fixtures only; these do not claim physical L3 validation."""
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from riscv2x86_py.l3_intent_ingress import (
    digest, producer_manifest, validate_manifest, produce_intents, validate_receipt,
)
from riscv2x86_py.l3_intent_requirements import _hash, classify_l3_requirements
from riscv2x86_py.l3_execution_context import L3ExecutionContext
from riscv2x86_py.translation_validation import ProgramArtifact, ValidationLayerResult, ValidationLevel, ValidationProfile
from riscv2x86_py.validation_status import ValidationStatus
from tests.test_l3_provider_resolution import _facts, PROOF, RELATION


def program(tmp_path, side):
    path = tmp_path / side
    path.write_bytes((side + ' test artifact').encode())
    return ProgramArtifact(side, str(path), 'executable', digest(path), PROOF)


def test_report_roundtrip_preserves_intent_and_rejects_wrong_fragment(tmp_path):
    from riscv2x86_py.schema import Finding, AsmFragment, load_report, save_report
    profile, _ = _facts()
    finding = Finding(fragment=AsmFragment(id='fragment:0'), l3IntentProfile=profile,
                      l3IntentReceipt={'test': 'transport-only'})
    path = tmp_path / 'report.json'
    save_report([finding], str(path))
    restored = load_report(str(path))[0]
    assert restored.l3IntentProfile == profile
    assert restored.l3IntentReceipt == finding.l3IntentReceipt
    restored.fragment.id = 'another'
    with pytest.raises(ValueError, match='fragment identity mismatch'):
        restored.to_dict()


@pytest.mark.parametrize('mutation', ['tool', 'source', 'policy', 'identity'])
def test_manifest_is_not_a_mutable_tool_or_source_alias(tmp_path, mutation):
    source = tmp_path / 'input.c'; source.write_text('void f(void){}')
    tool = tmp_path / 'producer.py'; tool.write_text('pass')
    value = producer_manifest(source, [sys.executable, str(tool)], 'fixture producer, no platform claim')
    validate_manifest(value, source)
    if mutation == 'tool': tool.write_text('print(1)')
    if mutation == 'source': source.write_text('void g(void){}')
    if mutation == 'policy': value['trustPolicy'] = 'automatic-approved'
    if mutation == 'identity': value['producerIdentity'] = PROOF
    with pytest.raises(ValueError): validate_manifest(value, source)


@pytest.fixture
def ingress(tmp_path, monkeypatch):
    import riscv2x86_py.mechanism_route_checks as checks
    import riscv2x86_py.translation_attempt as attempts
    import riscv2x86_py.translation_artifact_binding as binding
    source = tmp_path / 'renamed.c'; source.write_text('void renamed(void){}')
    profile, _ = _facts()
    finding = {'fragment': {'id': 'fragment:0'}, 'translationOutcome': 'emitted'}
    report = tmp_path / 'translated.json'; report.write_text(json.dumps({'findings': [finding]}))
    artifact = SimpleNamespace(fragment_id='fragment:0', proof_identity=PROOF,
                               effect_relation_set_identity=RELATION, identity=PROOF,
                               to_dict=lambda: {'proofIdentity': PROOF})
    monkeypatch.setattr(checks, 'compiler_bound_finding', lambda *a: (finding, {}))
    monkeypatch.setattr(attempts, 'load_translation_attempt_archive', lambda *a: object())
    monkeypatch.setattr(binding, 'artifacts_from_report', lambda *a: {'finding:0:fragment:0': artifact})
    # This tool only exercises ingress. The compiler/proof checks above are stubs.
    tool = tmp_path / 'producer.py'
    tool.write_text('import json,sys\nr=json.load(sys.stdin)\np=' + repr(profile) + '\n'
        'p["producer"]["producerIdentity"]=r["producerIdentity"]\n'
        'from riscv2x86_py.l3_intent_requirements import _hash\n'
        'p["profileIdentity"]=_hash({k:v for k,v in p.items() if k!="profileIdentity"})\n'
        'print(json.dumps({"schemaVersion":"riscv2x86.l3-intent-producer-response.v1",'
        '"requestIdentity":r["requestIdentity"],"profiles":[p]}))\n')
    manifest = tmp_path / 'producer.json'
    def seal():
        value = producer_manifest(source, [sys.executable, str(tool)], 'protocol fixture only')
        manifest.write_text(json.dumps(value))
    seal()
    return source, report, manifest, tool, artifact, seal


def test_selected_producer_closes_real_bindings_and_receipt_replays(ingress):
    source, report, manifest, tool, artifact, seal = ingress
    data = produce_intents(source, report, manifest)
    finding = data['findings'][0]
    transcript = json.loads(report.with_name(report.name + '.l3-intent-production.json').read_text())
    request = transcript['request']
    assert request['requestIdentity'] == _hash({k:v for k,v in request.items() if k != 'requestIdentity'})
    assert classify_l3_requirements(data).requirements[0]['eligibilityStatus'] == 'eligible'
    validate_receipt(finding, artifact, source, report)
    finding['l3IntentReceipt']['translationArtifactIdentity'] = RELATION
    receipt = finding['l3IntentReceipt']
    receipt['receiptIdentity'] = _hash({k:v for k,v in receipt.items() if k != 'receiptIdentity'})
    with pytest.raises(ValueError, match='binding-mismatch'):
        validate_receipt(finding, artifact, source, report)


@pytest.mark.parametrize('replacement', ['wrong-proof', 'missing-fragment', 'stale-request', 'nonzero'])
def test_producer_response_cannot_rebind_or_hide_candidates(ingress, replacement):
    source, report, manifest, tool, artifact, seal = ingress
    text = tool.read_text()
    if replacement == 'wrong-proof': text = text.replace('p["profileIdentity"]=', 'p["producer"]["proofIdentity"]="'+ RELATION +'"\np["profileIdentity"]=')
    if replacement == 'missing-fragment': text = text.replace('"profiles":[p]', '"profiles":[]')
    if replacement == 'stale-request': text = text.replace('"requestIdentity":r["requestIdentity"]', '"requestIdentity":"old"')
    if replacement == 'nonzero': text = 'raise SystemExit(75)'
    tool.write_text(text); seal()
    with pytest.raises(ValueError): produce_intents(source, report, manifest)
    assert json.loads(report.read_text())['findings'][0].get('l3IntentProfile') is None


@pytest.mark.parametrize('bad', ['none', 'old-invocation', 'wrong-artifact', 'mutated-program', 'deleted-program', 'valid'])
def test_observer_must_echo_this_invocation_and_actual_program(tmp_path, monkeypatch, bad):
    import riscv2x86_py.l3_experiment_runner as subject
    from tests.test_l3_experiment_runner import _write, _config, _report, PROOF as TEST_PROOF
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    path, fingerprint, _ = _write(tmp_path)
    source, target = program(tmp_path, 'source'), program(tmp_path, 'target')
    context = L3ExecutionContext.create(source, target)
    monkeypatch.setattr(subject, 'run_l2_effect_trace_differential', lambda *a, **k:
        ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED, PROOF))
    seen = []
    def runner(command, stdin, timeout):
        request = json.loads(stdin); seen.append(request)
        actual = request['executionBinding']['program']
        assert digest(actual['artifactPath']) == actual['artifactDigest']
        response = _report(request)
        if bad != 'none': response['executionBinding'] = request['executionBinding']
        if bad == 'old-invocation': response['executionBinding']['invocationId'] = 'old'
        if bad == 'wrong-artifact': response['executionBinding']['program']['artifactDigest'] = RELATION
        if bad == 'mutated-program': Path(source.artifact_path).write_bytes(b'changed')
        if bad == 'deleted-program': Path(source.artifact_path).unlink()
        return subject.CommandResult(0, json.dumps(response), '')
    result = subject.run_l3_experiment_validation(_config(path, fingerprint),
        validation_plan=SimpleNamespace(profile=ValidationProfile.MICROARCH,
                                         experiment_contract_id='cache-direction-v1'),
        translation_artifact=SimpleNamespace(translation_plan_id='plan-3', proof_identity=TEST_PROOF),
        source_program_artifact=source, target_program_artifact=target,
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        l3_execution_context=context, l3_command_runner=runner)
    assert result.status is (ValidationStatus.VERIFIED if bad == 'valid' else ValidationStatus.INCONCLUSIVE)
    assert len(seen) == (2 if bad == 'valid' else 1)
    if bad == 'valid':
        assert set(json.loads(result.detail)['executionBindings']) == {'source', 'target'}


def test_context_rejects_other_build_and_invocations_are_distinct(tmp_path):
    source, target = program(tmp_path, 'source'), program(tmp_path, 'target')
    first, second = [L3ExecutionContext.create(source, target) for _ in range(2)]
    assert first.identity != second.identity
    with pytest.raises(ValueError, match='binding-mismatch'): first.validate(target, source)


def test_rehashed_profile_and_receipt_must_replay_selected_semantic_producer(ingress):
    source, report, manifest, tool, artifact, seal = ingress
    data = produce_intents(source, report, manifest)
    finding = data['findings'][0]
    profile = finding['l3IntentProfile']
    profile['sourceIntent'] = 'unapproved replacement of experimental obligations'
    profile['profileIdentity'] = _hash({k: v for k,v in profile.items() if k != 'profileIdentity'})
    receipt = finding['l3IntentReceipt']
    receipt['profileIdentity'] = profile['profileIdentity']
    receipt['receiptIdentity'] = _hash({k:v for k,v in receipt.items() if k != 'receiptIdentity'})
    with pytest.raises(ValueError, match='producer-replay-mismatch'):
        validate_receipt(finding, artifact, source, report)


def test_normal_evaluation_supplies_actual_build_context(tmp_path, monkeypatch):
    """Exercise the normal evaluator bridge; no L3 pass is fabricated here."""
    import riscv2x86_py.evaluation as subject
    from tests.test_evaluation_runner import _setup
    request, source, attempt = _setup(tmp_path)
    plan_path = Path(request.validation_plan)
    plan = json.loads(plan_path.read_text())
    plan.update(profile='microarch', experimentContractId='explicit-fixture-experiment')
    plan_path.write_text(json.dumps(plan))
    original = subject.run_translation_validation
    seen = []
    def capture(*args, **kwargs):
        context = kwargs['l3_execution_context']
        assert isinstance(context, L3ExecutionContext)
        context.validate(args[1], args[2])
        for side in ('source', 'target'):
            actual = context.binding(side)
            assert digest(actual['artifactPath']) == actual['artifactDigest']
        seen.append(context.identity)
        return original(*args, **kwargs)
    monkeypatch.setattr(subject, 'run_translation_validation', capture)
    result = subject.run_evaluation(request, work_directory=tmp_path/'run')
    assert len(seen) == 1
    assert result['status'] == 'inconclusive'  # No registered L0/L3 evidence.


def test_producer_timeout_is_a_typed_precondition_failure(ingress, monkeypatch):
    import subprocess
    import riscv2x86_py.l3_intent_ingress as subject
    source, report, manifest, tool, artifact, seal = ingress
    def timeout(*args, **kwargs): raise subprocess.TimeoutExpired(args[0], 1)
    monkeypatch.setattr(subject.subprocess, 'run', timeout)
    with pytest.raises(ValueError, match='producer-timed-out'):
        produce_intents(source, report, manifest)
    assert json.loads(report.read_text())['findings'][0].get('l3IntentProfile') is None


@pytest.mark.parametrize('malformed', ['', 'duplicate', 'not-list', 'wrong-profile'])
def test_bounded_refusal_protocol_preserves_unknown_and_replays(ingress, malformed):
    source, report, manifest, tool, artifact, seal = ingress
    text = tool.read_text()
    marker = 'p["profileIdentity"]='
    text = text.replace(marker, 'p.update(intentKind="unknown",experimentClasses=[],requiredProperties=[],sourceCapabilities=[],targetCapabilities=[],complete=False)\n'+marker)
    text = text.replace('print(json.dumps(',
        'd={"schemaVersion":"riscv2x86.l3-intent-disposition.v1","fragmentId":p["fragmentId"],'
        '"profileIdentity":p["profileIdentity"],"status":"unsupported","reasonCodes":["bounded-route-only"]}\n'
        'd["dispositionIdentity"]=_hash(d)\nprint(json.dumps(')
    text = text.replace('response.v1', 'response.v2').replace('"profiles":[p]', '"profiles":[p],"dispositions":[d]')
    if malformed == 'duplicate':text=text.replace('"dispositions":[d]', '"dispositions":[d,d]')
    if malformed == 'not-list':text=text.replace('"dispositions":[d]', '"dispositions":{}')
    if malformed == 'wrong-profile':text=text.replace('"profileIdentity":p["profileIdentity"]','"profileIdentity":"'+RELATION+'"')
    tool.write_text(text);seal()
    if malformed:
        with pytest.raises(ValueError):produce_intents(source,report,manifest)
        return
    data=produce_intents(source,report,manifest)
    requirement=classify_l3_requirements(data).requirements[0]
    assert requirement['eligibilityStatus']=='inconclusive'
    assert 'l3.intent.unsupported' in requirement['reasonCodes']
    report.write_text(json.dumps(data))
    validate_receipt(data['findings'][0],artifact,source,report)
    assert produce_intents(source,report,manifest,replay=True)['findings'][0]['l3IntentDisposition']==data['findings'][0]['l3IntentDisposition']


def test_terminal_upstream_refusal_does_not_invent_an_intent_profile(ingress, monkeypatch):
    import riscv2x86_py.translation_artifact_binding as binding
    source,report,manifest,tool,artifact,seal=ingress
    data={'findings':[{'fragment':{'id':'fragment:0'},'translationOutcome':'unsupported'}]}
    report.write_text(json.dumps(data))
    monkeypatch.setattr(binding,'artifacts_from_report',lambda *args:{})
    assert produce_intents(source,report,manifest)==data
    assert not report.with_name(report.name+'.l3-intent-production.json').exists()
