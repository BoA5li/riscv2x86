"""Real original pipeline/evaluator; fixture compiler ingress/assembler only.

Copy-builds below intentionally do NOT constitute L0 or real GMP validation.
The missing real L0 provider must stay inconclusive after the bridge executes.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pypcode
import pytest

from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_original_pipeline as route
from riscv2x86_py import native_original_evaluation as bridge
from riscv2x86_py import native_original_corpus as corpus
from .test_native_original_pipeline import adapted
from .test_evaluation_runner import _setup
from .test_ghidra_preflight import payload

REAL_RUN = subprocess.run


@pytest.fixture
def original_run(adapted, monkeypatch):
    from riscv2x86_py import pipeline
    from riscv2x86_py.assemble import AssembleResult
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.ghidra_pythonrun_bridge import PythonRunRegisterNameResolver
    root, prepared, _, _ = adapted
    launcher = Path(os.environ['GHIDRA_INSTALL_DIR']) / 'support/pythonRun'
    launcher.write_text('#!' + sys.executable + '\nprint(' + repr(json.dumps(payload())) + ')\n')
    frontend = route.subprocess.run
    ctx = pypcode.Context('RISCV:LE:64:default'); names = {}
    for name in ('a0', 'a1', 'a2'):
        v = ctx.registers[name]; names[('register', v.offset, v.size)] = name
    resolver = PythonRunRegisterNameResolver(names)
    facts = TranslationRuntimeFacts(rv_to_operand_index={'a0': 0, 'a1': 1, 'a2': 2},
                                    operand_width_bits={0: 64, 1: 64, 2: 64})
    monkeypatch.setattr(pipeline, 'assemble', lambda *a, **k: AssembleResult(
        True, bytes.fromhex('33b5c502'), [], translation_runtime_facts=facts))
    def run(command, **kwargs):
        if '--report-json' in command: return frontend(command, **kwargs)
        if 'riscv2x86_py.cli' in command:
            stats = pipeline.run(command[command.index('--in') + 1], command[command.index('--out') + 1],
                                 register_name_resolver=resolver, verify_enabled=False)
            return SimpleNamespace(returncode=0, stdout=json.dumps(stats).encode(), stderr=b'')
        return REAL_RUN(command, **kwargs)
    monkeypatch.setattr(route.subprocess, 'run', run)
    route.run(root / 'bundle.json', root / 'run')
    request, _, _ = _setup(root / 'template')
    def build(value):
        return {'artifactId': value.artifact_id, 'artifactKind': value.artifact_kind,
                'outputRelativePath': value.output_relative_path, 'command': list(value.command)}
    raw = {'schemaVersion': request.schema_version, 'sourceRoot': request.source_root,
           'sourceRelativePath': request.source_relative_path, 'targetRelativePath': request.target_relative_path,
           'translatedReport': request.translated_report, 'attemptArchive': request.attempt_archive,
           'validationPlan': request.validation_plan, 'targetEnvironment': request.target_environment,
           'runtimeRegistryTemplate': request.runtime_registry_template, 'translationArtifacts': {},
           'sourceBuild': build(request.source_build), 'targetBuild': build(request.target_build),
           'translationCommand': [], 'comparisonPolicy': request.comparison_policy,
           'validationUnit': 'program', 'validationGroupId': '', 'selectedAttemptIds': []}
    file = root / 'template.json'; file.write_text(json.dumps(raw))
    return root, root / 'run/result.json', file


def test_real_original_evaluator_is_invoked_and_missing_l0_is_not_a_pass(original_run):
    root, run, template = original_run
    value = bridge.acquire(run, template, root / 'evaluated')
    assert value['originalEvaluationInvoked']
    assert value['facts']['evaluationStatus'] == 'inconclusive'
    assert value['facts']['sourceBuildReported'] and value['facts']['targetBuildReported']
    assert not value['facts']['runtimeLayerReported']
    attempt = value['facts']['attempts'][0]
    assert attempt['reasonCodes'] == ['validation.layer-runner-missing:L0']
    assert attempt['layers'][0]['level'] == 'L0'
    assert not value['semanticApproval'] and not value['independentProgramAuditPerformed']
    assert bridge.check(root / 'evaluated/result.json') == value
    target = root / 'evaluated/evaluation/candidate-staging/input.i'
    assert b'mulq' in target.read_bytes()
    assert b'mulhu' in (root / 'run/input/source/input.i').read_bytes()


def test_readiness_is_explicit_about_missing_contract_and_runners(original_run):
    _, run, template = original_run
    value = bridge.inspect(run)
    assert value['gaps'] == ['EXPLICIT_ORIGINAL_EVALUATION_REQUEST_REQUIRED']
    value = bridge.inspect(run, template)
    assert value['requiredLevels'] == ['L0', 'L1', 'L2']
    assert value['gaps'] == ['ORIGINAL_LAYER_RUNNER_NOT_DECLARED:' + x for x in ('L0', 'L1', 'L2')]
    assert not value['semanticApproval']


def test_build_failure_and_diagnostics_survive_without_false_layer_completion(original_run):
    root, run, template = original_run
    raw = d.read(template); raw['targetBuild']['command'] = [sys.executable, '-c', 'raise SystemExit(7)']
    template.write_text(json.dumps(raw))
    value = bridge.acquire(run, template, root / 'failed-build')
    assert value['facts']['evaluationStatus'] == 'failed'
    assert value['facts']['reasonCodes'] == ['evaluation.target-build-failed']
    assert not value['facts']['attempts'][0]['layers']
    assert bridge.check(root / 'failed-build/result.json') == value


@pytest.mark.parametrize('change', ['artifact', 'file-added', 'plan', 'rehashed-summary'])
def test_record_check_rejects_changed_evidence_and_claims(original_run, change):
    root, run, template = original_run
    value = bridge.acquire(run, template, root / 'evaluated')
    path = root / 'evaluated/result.json'
    if change == 'artifact':
        (root / 'evaluated/evaluation/build/target').write_text('changed')
    elif change == 'file-added':
        (root / 'evaluated/evaluation/unrecorded.txt').write_text('unexpected')
    elif change == 'plan':
        plan = Path(d.read(template)['validationPlan']); plan.write_text(plan.read_text() + ' ')
    else:
        value['facts']['evaluationStatus'] = 'verified'
        value = d.seal({k: v for k, v in value.items() if k != 'originalEvaluationIdentity'}, 'originalEvaluationIdentity')
        path.write_text(json.dumps(value))
    with pytest.raises(ValueError): bridge.check(path)


def make_plan(root, template=None, count=3):
    seeds = [{'seedId': 'seed/' + str(i), 'bundlePath': str(root / 'bundle.json'),
              'requestPath': str(template) if template else None} for i in range(count)]
    file = root / 'corpus-input.json'; file.write_text(json.dumps({'schemaVersion': corpus.INPUT, 'seeds': seeds}))
    corpus.freeze(file, root / 'corpus-plan.json')
    return root / 'corpus-plan.json'


def test_corpus_keeps_denominator_resumes_checked_receipts_and_does_not_regenerate(original_run, monkeypatch):
    root, run, _ = original_run
    plan = make_plan(root)
    calls = []
    real_run = route.run
    def counted(*a, **k): calls.append(a); return real_run(*a, **k)
    monkeypatch.setattr(route, 'run', counted)
    value = corpus.execute(plan, root / 'corpus', max_seeds=1)
    assert value['statusCounts'] == {'not_run': 2, 'translation_complete': 1}
    assert value['attemptOutcomeCounts'] == {'emitted': 1}
    assert len(value['records']) == 3 and not value['allSeedsProcessed']
    value = corpus.execute(plan, root / 'corpus', max_seeds=2, resume=True)
    assert value['statusCounts'] == {'translation_complete': 3}
    assert value['allSeedsProcessed'] and len(calls) == 3
    assert not value['productionAcceptanceComplete']
    corpus.execute(plan, root / 'corpus', max_seeds=2, resume=True)
    assert len(calls) == 3


def test_unsupported_attempt_remains_visible_in_corpus_without_dropping_seed(adapted, monkeypatch):
    from .test_native_original_pipeline import backend_fixture
    from riscv2x86_py.schema import TranslationOutcome
    root, prepared, _, raw = adapted
    launcher = Path(os.environ['GHIDRA_INSTALL_DIR']) / 'support/pythonRun'
    launcher.write_text('#!' + sys.executable + '\nprint(' + repr(json.dumps(payload())) + ')\n')
    backend_fixture(monkeypatch, prepared, raw, outcome=TranslationOutcome.UNSUPPORTED)
    plan = make_plan(root, count=2)
    state = corpus.execute(plan, root / 'corpus', max_seeds=1)
    assert state['statusCounts'] == {'blocked': 1, 'not_run': 1}
    assert state['attemptOutcomeCounts'] == {'unsupported': 1}
    assert state['records'][0]['translationOutcomes'] == ['unsupported']
    assert state['records'][0]['run'] is None and state['records'][0]['translation'] is not None
    assert corpus.check_progress(root / 'corpus/progress.json') == state


def test_failed_seed_retained_retry_reuses_only_checked_translation(original_run, monkeypatch):
    root, _, template = original_run
    plan = make_plan(root, template, count=2)
    original = bridge.acquire; calls = []
    def broken(*a, **k): calls.append(a); raise RuntimeError('fixture evaluation interrupted')
    monkeypatch.setattr(bridge, 'acquire', broken)
    state = corpus.execute(plan, root / 'corpus', max_seeds=1)
    assert state['records'][0]['status'] == 'blocked'
    assert state['records'][0]['run'] is not None
    monkeypatch.setattr(bridge, 'acquire', original)
    monkeypatch.setattr(route, 'run', lambda *a, **k: pytest.fail('checked translation must not be regenerated'))
    state = corpus.execute(plan, root / 'corpus', max_seeds=1, resume=True, retry_blocked=True)
    assert state['statusCounts'] == {'evaluation_inconclusive': 1, 'not_run': 1}
    assert len(state['records']) == 2


def test_corpus_changed_plan_or_contract_cannot_resume(original_run):
    root, _, template = original_run
    plan = make_plan(root, template, count=1)
    corpus.execute(plan, root / 'corpus')
    raw = d.read(template); raw['comparisonPolicy'] = 'foreign-policy'; template.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match='CHANGED'):
        corpus.execute(plan, root / 'corpus', resume=True)


def test_cli_preserves_nonzero_for_inconclusive_but_check_means_integrity(original_run):
    root, run, template = original_run
    file = Path(__file__).resolve().parents[2] / 'experiment/evaluate_native_original.py'
    spec = importlib.util.spec_from_file_location('original_evaluate_cli', file)
    cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
    assert cli.main(['inspect', '--run', str(run)]) == 2
    assert cli.main(['evaluate', '--run', str(run), '--request', str(template), '--output', str(root / 'ev')]) == 1
    assert cli.main(['check', '--input', str(root / 'ev/result.json')]) == 0


def test_original_readiness_uses_real_artifact_and_authority_consumer(original_run):
    from riscv2x86_py.program_validation_obligations import original_layer_readiness
    _, run, _ = original_run
    value = original_layer_readiness({'run': {'path': str(run)}})
    assert len(value['instances']) == 1
    row = value['instances'][0]
    assert row['originalProvider'] == 'automatic-l2-operand-differential'
    assert not row['authorityComplete'] and not row['authorityConsumerReady']
    assert row['reasonCode']
    assert not row['canonicalExecutionCoverageVerified']
    assert row['l3Applicability'] == 'requires-original-intent-validation'
