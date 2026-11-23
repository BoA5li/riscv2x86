"""Native adapter campaign tests; original RISC-V ingress is fixture-owned."""
from pathlib import Path

import pytest
from riscv2x86_py import native_api_campaign as c
from riscv2x86_py import native_original_api as a
from riscv2x86_py import program_validation_obligations as obligations
from .test_native_original_api import native_pair, domain


@pytest.fixture
def api_campaign(native_pair, monkeypatch):
    spec, _, builds, root, _ = native_pair
    config = root / 'configuration.json'; a.project.write(config, {'fixture': 'configuration'})
    dom = root / 'domain.json'; a.project.write(dom, domain())
    calls = []
    monkeypatch.setattr(c.campaign, 'replan_configuration', lambda path: ('diagnostic', {'fixture': 'plan'}, a.d.snapshot(config)))
    def prepare(plan, output, **kwargs):
        calls.append(kwargs)
        output = Path(output); output.mkdir(exist_ok=True)
        a.project.write(output / 'diagnostic-plan.json', plan)
        a.project.write(output / 'progress.json', {'fixture': 'already-checked-upstream-ingress'})
    monkeypatch.setattr(c.diagnostic, 'execute', prepare)
    monkeypatch.setattr(a, 'from_progress', lambda path, **kwargs:
        (str(spec), dict(builds), {'sourceExcludedInstanceCount': 1, 'canonicalInstructionCoverageVerified': False})
        if kwargs.get('with_applicability') else (str(spec), dict(builds)))
    monkeypatch.setattr(obligations, 'original_layer_readiness', lambda spec: {
        'scope': 'fixture-original-authority-consumer',
        'instances': [{'authorityConsumerReady': False, 'reasonCode': 'L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED'}]})
    # This fixture owns only campaign orchestration and host API execution.
    # The original typed operand backend and its rejected observations have
    # separate tests; do not manufacture an L2 pass here.
    monkeypatch.setattr(c, 'l2_attempt', lambda root, reference, **kwargs:
        (reference, {'originalLogicalOperandsVerified': False,
                     'instances': [{'status': 'inconclusive', 'detail': {'reasonCode': 'FIXTURE_NO_ASM_AUTHORITY'}}]}))
    # This fixture owns preparation ingress; it contains no original translated
    # report. Real per-instance accounting has separate adversarial tests.
    from riscv2x86_py import native_evaluation_coverage as coverage
    monkeypatch.setattr(coverage, 'from_spec', lambda *args: coverage.summarize(
        {'findings': []}, {'instances': []}, {'instances': []}))
    return config, dom, root / 'main.c', root, calls


def test_one_command_executes_contract_build_comparison_and_independent_check(api_campaign):
    config, dom, basis, root, calls = api_campaign
    out = root / 'campaign'
    result = c.execute(config, dom, [0], [basis], out)
    assert result['processObservationStatus'] == 'observed-agreement'
    assert result['caseCount'] == 1 and len(calls) == 1
    assert calls[0]['stop_after'] == 'preparation'
    assert c.check(out / 'result.json') == result
    assert c.execute(config, dom, [0], [basis], out, resume=True) == result
    assert len(calls) == 1  # no repeated preparation or process execution
    assert not result['formalValidationPerformed'] and result['formalMatrixCellsExecuted'] == 0
    assert not result['originalLayerReadiness']['instances'][0]['authorityConsumerReady']


def test_resume_preserves_failed_attempt_and_creates_a_new_execution(api_campaign, monkeypatch):
    config, dom, basis, root, calls = api_campaign
    out = root / 'campaign'; original = a.acquire
    def failed(spec, request, output, **kwargs):
        Path(output).mkdir(); (Path(output) / 'failure.log').write_text('fixture acquisition failure')
        raise ValueError('fixture failure')
    monkeypatch.setattr(a, 'acquire', failed)
    with pytest.raises(ValueError, match='fixture failure'): c.execute(config, dom, [0], [basis], out)
    assert not (out / 'result.json').exists()
    monkeypatch.setattr(a, 'acquire', original)
    result = c.execute(config, dom, [0], [basis], out, resume=True)
    assert result['processObservationStatus'] == 'observed-agreement'
    assert (out / 'attempts/000000/failure.log').read_text() == 'fixture acquisition failure'
    assert result['result']['path'].endswith('attempts/000001/result.json')


def test_changed_domain_cannot_resume_a_campaign_under_old_identity(api_campaign):
    config, dom, basis, root, _ = api_campaign; out = root / 'campaign'
    c.execute(config, dom, [0], [basis], out)
    data = a.d.read(dom); data['cases'][0]['arguments'][1]['integer'] = 7; a.project.write(dom, data)
    with pytest.raises(ValueError, match='INPUT_CHANGED'): c.execute(config, dom, [0], [basis], out, resume=True)
    with pytest.raises(ValueError): c.check(out / 'result.json')


def test_resealed_program_approval_or_wrong_result_cannot_pass_independent_check(api_campaign):
    config, dom, basis, root, _ = api_campaign; out = root / 'campaign'
    value = c.execute(config, dom, [0], [basis], out)
    value['semanticApproval'] = True
    a.project.write(out / 'result.json', a.d.seal({k: v for k, v in value.items() if k != 'apiCampaignIdentity'}, 'apiCampaignIdentity'))
    with pytest.raises(ValueError, match='REDERIVATION'): c.check(out / 'result.json')


def test_one_campaign_derivation_checks_inner_result_once(api_campaign, monkeypatch):
    config, dom, basis, root, _ = api_campaign; out = root / 'campaign'
    result = c.execute(config, dom, [0], [basis], out)
    calls = []; original = a.check
    def checked(path):
        calls.append(str(path)); return original(path)
    monkeypatch.setattr(a, 'check', checked)
    assert c.derive(out, result['result']) == result
    assert calls == [result['result']['path']]
    # Independent invocations recheck; nothing is cached as a validity flag.
    assert c.derive(out, result['result']) == result
    assert len(calls) == 2


def test_replay_uses_original_pipeline_in_fresh_output_and_rejects_changed_selectors(api_campaign):
    config, dom, basis, root, calls = api_campaign; old = root / 'old'
    c.execute(config, dom, [0], [basis], old)
    value = c.replay(old / 'result.json', root / 'new')
    assert len(calls) == 2
    assert value['bodyLinkAttributionComplete'] and value['linkAttributedObservationStatus'] == 'observed-agreement'
    assert value['result']['path'].startswith(str(root / 'new'))
    assert not value['semanticApproval']
    data = a.d.read(dom); data['cases'][0]['arguments'][1]['integer'] = 7; a.project.write(dom, data)
    with pytest.raises(ValueError, match='INPUT_CHANGED'): c.replay(old / 'result.json', root / 'changed')
    assert not (root / 'changed').exists()
