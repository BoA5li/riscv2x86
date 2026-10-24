"""Canonical production schemas across L3 consumers; no hardware claims."""
from copy import deepcopy
from itertools import permutations
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py.l3_evidence_closure import (
    close_fragment, parse_fragment, validate_fragment_against_requirement,
    aggregate_statuses, close_program, identity,
)
from riscv2x86_py.l3_coverage import summarize_l3_case
from riscv2x86_py.l3_intent_requirements import (
    _hash, classify_l3_requirements, parse_l3_requirement_manifest,
)
from riscv2x86_py.paper_evaluation import _validation_maps
from tests.test_l3_evidence_closure import dimension
from tests.test_l3_provider_resolution import (
    _facts, _contract, _provider, _resolve, PROOF, SOURCE, TARGET,
)


def signed(value, key='resultIdentity', hashfn=identity):
    value[key] = hashfn({k: v for k, v in value.items() if k != key})
    return value


def facts(two=False):
    profile, _ = _facts()
    if two:
        profile['requiredProperties'].append(
            {'propertyId': 'property:control', 'dimension': 'control_flow', 'unit': 'fragment'})
        profile = signed(profile, 'profileIdentity', _hash)
    manifest = classify_l3_requirements({'findings': [{'fragment': {'id': 'fragment:0'},
        'translationOutcome': 'emitted', 'l3IntentProfile': profile}]}).to_dict()
    return profile, manifest


def closed(requirement, reports=None, *, scope='architectural_intent', status='verified'):
    items = []
    for prop in requirement['requiredProperties']:
        d = dimension(prop['propertyId'], prop['dimension'], scope=scope,
                      l2='architectural' if scope == 'architectural_intent' else 'approved_functional_relation')
        for k in ('fragmentId', 'programId', 'profileIdentity', 'requirementIdentity'):
            d[k] = requirement[k]
        d['unit'] = prop['unit']
        d['status'] = status
        d['reasonCodes'] = ['comparison:counterexample'] if status == 'failed' else []
        if reports:
            for side in ('source', 'target'):
                d[side + 'ReportIdentity'] = identity(reports[side])
        items.append(signed(d))
    return close_fragment(requirement, items, claim_scope=scope)


def evaluation(manifest, fragment, reports):
    return {'translationEvaluationLink': {'l3Requirements': manifest},
        'attempts': [{'fragmentId': fragment['fragmentId'], 'validation': {'layers': [
            {'level': 'L3', 'status': 'verified', 'evidenceIdentity': PROOF,
             'detail': json.dumps({'fragmentResult': fragment, 'platformReports': reports})}]}}]}


@pytest.mark.parametrize('mutation', ['delete', 'dimension', 'unit'])
def test_rehashed_self_consistent_result_cannot_redefine_authoritative_properties(mutation):
    _, manifest = facts(two=True)
    req = manifest['requirements'][0]
    reports = {'source': {'event': 1}, 'target': {'event': 2}}
    result = closed(req, reports)
    if mutation == 'delete':
        result['requiredProperties'].remove('property:control')
        del result['dimensionResults']['property:control']
    else:
        d = result['dimensionResults']['property:control']
        d[mutation] = 'access_pattern' if mutation == 'dimension' else 'campaign'
        signed(d)
    signed(result)
    # Old self-parser still serves internal consistency, not authority.
    assert parse_fragment(result)['status'] == 'verified'
    with pytest.raises(ValueError):
        validate_fragment_against_requirement(result, req)
    with pytest.raises(ValueError):
        summarize_l3_case(evaluation(manifest, result, reports), [result])
    assert _validation_maps(evaluation(manifest, result, reports), {'fragment:0'})[0]['L3'] == 'inconclusive'


def test_canonical_result_counts_and_partial_remains_partial():
    _, manifest = facts(two=True); req = manifest['requirements'][0]
    result = closed(req)
    assert summarize_l3_case({'translationEvaluationLink': {'l3Requirements': manifest}}, [result])['counts']['architecturalIntentVerified'] == 1
    partial = close_fragment(req, [result['dimensionResults']['property:access']], claim_scope='architectural_intent')
    assert validate_fragment_against_requirement(partial, req)['status'] == 'inconclusive'
    assert summarize_l3_case({'translationEvaluationLink': {'l3Requirements': manifest}}, [partial])['counts']['completeExecution'] == 0
    failed = deepcopy(result['dimensionResults']['property:access'])
    failed.update(status='failed', reasonCodes=['counterexample'])
    partial = close_fragment(req, [signed(failed)], claim_scope='architectural_intent')
    assert validate_fragment_against_requirement(partial, req)['status'] == 'failed'
    assert close_program('program:0', ['fragment:0', 'missing'], [partial], claim_scope='architectural_intent')['status'] == 'failed'


@pytest.mark.parametrize('statuses,expected', [
    (['failed', 'verified'], 'failed'), (['inconclusive', 'verified'], 'inconclusive'),
    (['not_run', 'verified'], 'inconclusive'), (['not_run', 'not_run'], 'not_run'),
    (['diagnostic_verified', 'verified'], 'inconclusive'),
    (['not_applicable', 'verified'], 'verified'),
])
def test_aggregation_is_order_independent(statuses, expected):
    for order in permutations(statuses):
        assert aggregate_statuses(order) == expected


@pytest.mark.parametrize('change', ['duplicate', 'unit', 'eligibility'])
def test_rehashed_invalid_requirement_is_rejected(change):
    _, manifest = facts(); req = manifest['requirements'][0]
    if change == 'duplicate': req['requiredProperties'] *= 2
    elif change == 'unit': req['requiredProperties'][0]['unit'] = 'unmeasured'
    else: req['intentKind'] = 'none'
    signed(req, 'requirementIdentity', _hash); signed(manifest, 'manifestIdentity', _hash)
    with pytest.raises(ValueError): parse_l3_requirement_manifest(manifest)


def test_stale_context_and_report_cannot_be_rehashed_to_success():
    _, manifest = facts(); req = manifest['requirements'][0]
    reports = {'source': {'v': 1}, 'target': {'v': 2}}
    result = closed(req, reports)
    with pytest.raises(ValueError, match='context mismatch'):
        validate_fragment_against_requirement(result, req, expected_context={'contractIdentity': SOURCE})
    with pytest.raises(ValueError, match='report content'):
        validate_fragment_against_requirement(result, req, source_report={'v': 'different'})


def test_explicit_v7_property_binding_rejects_selector_weakening(tmp_path):
    from riscv2x86_py.l3_property_bindings import PROPERTY_CONTRACT_SCHEMA, validate_property_bindings
    from riscv2x86_py.l3_experiment_runner import load_experiment_contract
    profile, _ = _facts()
    profile['requiredProperties'].append(dict(profile['requiredProperties'][0], propertyId='property:other'))
    signed(profile, 'profileIdentity', _hash)
    manifest = classify_l3_requirements({'findings': [{'fragment': {'id': 'fragment:0'},
        'translationOutcome': 'emitted', 'l3IntentProfile': profile}]}).to_dict()
    path = tmp_path / 'contract.json'; digest = _contract(path, profile, manifest['requirements'][0])
    assert _resolve(profile, manifest, [_provider(path, digest)])['bindingStatus'] != 'resolved'
    raw = json.loads(path.read_text())
    raw['baseSchemaVersion'] = raw['schemaVersion']; raw['schemaVersion'] = PROPERTY_CONTRACT_SCHEMA
    raw['propertyBindings'] = [dict(prop, comparatorId='logical-access-contract.v1', obligationIds=['access:0'])
                               for prop in profile['requiredProperties']]
    path.write_text(json.dumps(raw))
    contract = load_experiment_contract(path)
    validate_property_bindings(contract, manifest['requirements'][0]['requiredProperties'])
    from hashlib import sha256
    provider = _provider(path, 'sha256:' + sha256(path.read_bytes()).hexdigest())
    provider['contractSchemas'] = [PROPERTY_CONTRACT_SCHEMA]
    assert _resolve(profile, manifest, [provider])['bindingStatus'] == 'resolved'
    raw['propertyBindings'][0]['obligationIds'] = []
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match='obligations-mismatch'):
        validate_property_bindings(load_experiment_contract(path), manifest['requirements'][0]['requiredProperties'])


@pytest.mark.parametrize('mutation', ['none', 'delete', 'unit', 'source-report'])
def test_registry_rechecks_external_obligations_even_for_registered_provider(tmp_path, mutation):
    from hashlib import sha256
    from riscv2x86_py.l3_provider_resolution import build_l3_capability_registry_validator, REGISTRY_SCHEMA
    from riscv2x86_py.l3_experiment_runner import load_experiment_contract
    from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    profile, manifest = facts(two=True); req = manifest['requirements'][0]
    path = tmp_path / 'contract.json'; _contract(path, profile, req)
    raw = json.loads(path.read_text())
    from tests.test_l3_experiment_runner import CONTROL
    raw['experimentClasses'] = ['control_flow', 'memory_access']
    raw['requiredControlFlow'] = [CONTROL]
    path.write_text(json.dumps(raw)); contract = load_experiment_contract(path)
    provider = _provider(path, 'sha256:' + sha256(path.read_bytes()).hexdigest(), validator='other-registered')
    provider.update(experimentClasses=raw['experimentClasses'], propertyDimensions=['access_pattern','control_flow'])
    reports = {'source': {'v': 1}, 'target': {'v': 2}}
    fragment = closed(req, reports)
    for d in fragment['dimensionResults'].values():
        d.update(contractIdentity=contract.identity, sourceArtifactIdentity=SOURCE,
                 targetArtifactIdentity=TARGET)
        signed(d)
    signed(fragment)
    if mutation == 'delete':
        fragment['requiredProperties'].remove('property:control')
        del fragment['dimensionResults']['property:control']; signed(fragment)
    elif mutation == 'unit':
        fragment['dimensionResults']['property:control']['unit'] = 'program'
        signed(fragment['dimensionResults']['property:control']); signed(fragment)
    elif mutation == 'source-report': reports['source']['v'] = 'stale'
    result = ValidationLayerResult(ValidationLevel.L3, ValidationStatus.VERIFIED, PROOF,
        json.dumps({'fragmentResult': fragment, 'platformReports': reports}))
    validator = build_l3_capability_registry_validator({
        'schemaVersion': REGISTRY_SCHEMA, 'providers': [provider], 'executionProfile':'rv64-to-x86',
        'environmentId':'environment:0','sourceCapabilities':['source-trace'],
        'targetCapabilities':['target-trace']}, {'other-registered': lambda config: lambda **kw: result})
    outcome = validator(translation_artifact=SimpleNamespace(fragment_id='fragment:0', proof_identity=PROOF,
        translation_plan_id='plan:0',identity=PROOF), validation_plan=SimpleNamespace(experiment_contract_id='experiment:0'),
        target_environment={'environmentId':'environment:0'}, source_program_artifact=SimpleNamespace(artifact_digest=SOURCE),
        target_program_artifact=SimpleNamespace(artifact_digest=TARGET),
        l3_intent_profile=profile, l3_requirement_manifest=manifest,
        prior_layer_results=tuple(ValidationLayerResult(level, ValidationStatus.VERIFIED, PROOF,
            json.dumps({'claimScope':'architectural'}) if level is ValidationLevel.L2 else '')
            for level in (ValidationLevel.L0,ValidationLevel.L1,ValidationLevel.L2)))
    assert outcome.status.value == ('verified' if mutation == 'none' else 'inconclusive')


@pytest.mark.parametrize("explicit_properties", [False, True])
def test_actual_subprocess_reports_close_through_registry_and_paper(tmp_path, explicit_properties):
    """Actual subprocess protocol, synthetic measurements and explicit L2 fixture."""
    from hashlib import sha256
    from riscv2x86_py.l3_experiment_runner import ExperimentRunnerConfig, build_l3_experiment_validator
    from riscv2x86_py.l3_provider_resolution import build_l3_capability_registry_validator, REGISTRY_SCHEMA
    from riscv2x86_py.translation_validation import ValidationLayerResult, ValidationLevel, ValidationProfile
    from riscv2x86_py.validation_status import ValidationStatus, PreservationMode
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    from tests.test_l3_experiment_runner import ENV
    profile, manifest = facts(); req = manifest['requirements'][0]
    if explicit_properties:
        profile['requiredProperties'].append(dict(profile['requiredProperties'][0], propertyId='property:other'))
        signed(profile, 'profileIdentity', _hash)
        manifest = classify_l3_requirements({'findings':[{'fragment':{'id':'fragment:0'},
            'translationOutcome':'emitted','l3IntentProfile':profile}]}).to_dict()
        req = manifest['requirements'][0]
    path = tmp_path / 'contract.json'; digest = _contract(path, profile, req)
    contract = json.loads(path.read_text())
    contract['knownNonEquivalences'] = sorted(set(contract['knownNonEquivalences'] + profile['notClaimedProperties']))
    if explicit_properties:
        from riscv2x86_py.l3_property_bindings import PROPERTY_CONTRACT_SCHEMA
        contract['baseSchemaVersion'] = contract['schemaVersion']
        contract['schemaVersion'] = PROPERTY_CONTRACT_SCHEMA
        contract['propertyBindings'] = [dict(p, comparatorId='logical-access-contract.v1', obligationIds=['access:0'])
                                       for p in profile['requiredProperties']]
    path.write_text(json.dumps(contract))
    digest = 'sha256:' + sha256(path.read_bytes()).hexdigest()
    script = tmp_path / 'synthetic_observer.py'
    script.write_text('import json,sys\nr=json.load(sys.stdin)\nc='+repr(contract)+'\ne='+repr(ENV)+'''\njson.dump({
        'schemaVersion':'riscv2x86.l3-experiment-report.v1','side':r['side'],'runnerId':r['runnerId'],
        'contractIdentity':r['contractIdentity'],'calibrationProtocol':r['calibrationProtocol'],
        'randomSeed':r['randomSeed'],'affinityPolicy':r['affinityPolicy'],'noisePolicy':r['noisePolicy'],
        'warmupsCompleted':r['warmupCount'],'environment':e,'logicalAccesses':c['requiredAccessPattern'],
        'controlFlow':[],'syncObservations':[],'metricSamples':{}},sys.stdout)
''')
    import sys
    command = (sys.executable, str(script))
    config = ExperimentRunnerConfig('effect', None, object(), str(path), digest,
        'source:runner', 'target:runner', command, command, 10)
    provider = _provider(path, digest)
    provider['config'].update(sourceCommand=list(command), targetCommand=list(command))
    provider['contractSchemas'] = [contract['schemaVersion']]
    validator = build_l3_capability_registry_validator({
        'schemaVersion':REGISTRY_SCHEMA,'providers':[provider],'executionProfile':'rv64-to-x86',
        'environmentId':'environment:0','sourceCapabilities':['source-trace'],
        'targetCapabilities':['target-trace']}, {'l3-experiment-contract': lambda _: build_l3_experiment_validator(config)})
    kwargs = dict(translation_artifact=SimpleNamespace(fragment_id='fragment:0',proof_identity=PROOF,
        translation_plan_id='plan:0',identity=PROOF,preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT),
        validation_plan=SimpleNamespace(experiment_contract_id='experiment:0',profile=ValidationProfile.MICROARCH),
        target_environment={'environmentId':'environment:0'},source_program_artifact=SimpleNamespace(artifact_digest=SOURCE),
        target_program_artifact=SimpleNamespace(artifact_digest=TARGET),l3_intent_profile=profile,l3_requirement_manifest=manifest,
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        prior_layer_results=tuple(ValidationLayerResult(level,ValidationStatus.VERIFIED,PROOF,
            json.dumps({'claimScope':'architectural'}) if level is ValidationLevel.L2 else '')
            for level in (ValidationLevel.L0,ValidationLevel.L1,ValidationLevel.L2)))
    result = validator(**kwargs)
    assert result.status.value == 'verified', result.detail
    detail = json.loads(result.detail); fragment = detail['fragmentResult']
    report = {'translationEvaluationLink': {'l3Requirements':manifest}, 'attempts':[
        {'fragmentId':'fragment:0','validation':{'layers':[{'level':'L3','status':'verified',
         'evidenceIdentity':result.evidence_identity,'detail':result.detail}]}}]}
    assert summarize_l3_case(report,[fragment])['counts']['architecturalIntentVerified'] == 1
    assert _validation_maps(report,{'fragment:0'})[0]['L3'] == 'verified'
    # The same subprocess now contradicts the logical access obligation.
    script.write_text(script.read_text().replace("c['requiredAccessPattern']", '[]'))
    assert validator(**kwargs).status.value != 'verified'


@pytest.mark.parametrize('bad_status', ['failed', 'inconclusive', 'not_run'])
@pytest.mark.parametrize('bad_first', [True, False])
def test_batch_program_groups_do_not_overwrite_earlier_result(tmp_path, monkeypatch, bad_status, bad_first):
    from riscv2x86_py import batch_evaluation_cli as batch
    from tests.test_evaluation_runner import _setup
    from tests.test_batch_evaluation_cli import _request_value
    request, _, _ = _setup(tmp_path / 'fixture')
    profiles = []
    for i in range(2):
        p, _ = facts()
        p.update(fragmentId=f'fragment:{i}', programId=f'program:{i}')
        signed(p, 'profileIdentity', _hash); profiles.append(p)
    manifest = classify_l3_requirements({'findings': [dict(fragment={'id':p['fragmentId']},
        translationOutcome='emitted', l3IntentProfile=p) for p in profiles]}).to_dict()
    results = []; attempts = []
    reports = {'source':{'v':1},'target':{'v':2}}
    for i, req in enumerate(manifest['requirements']):
        status = bad_status if i == (0 if bad_first else 1) else 'verified'
        f = closed(req, reports)
        if status != 'verified':
            for d in f['dimensionResults'].values():
                d.update(status=status, reasonCodes=['test:comparison'] if status != 'not_run' else [])
                signed(d)
            f = close_fragment(req, list(f['dimensionResults'].values()), claim_scope='architectural_intent')
        results.append(f)
        attempts.append({'fragmentId':req['fragmentId'],'translationOutcome':'emitted','validation':{'layers':[
            {'level':'L3','status':status,'evidenceIdentity':PROOF,
             'detail':json.dumps({'fragmentResult':f,'platformReports':reports})}]}})
    raw = {'status':'verified','attempts':attempts,
        'translationEvaluationLink':{'l3Requirements':manifest}}
    def execute(request, work_directory):
        work_directory.mkdir(parents=True)
        (work_directory/'translated.l3-requirements.json').write_text(json.dumps(manifest))
        return raw
    monkeypatch.setattr(batch, 'run_evaluation', execute)
    descriptor = tmp_path/'case.json'; descriptor.write_text('{}')
    case = {'caseId':'case','category':'test','descriptorIdentity':PROOF,
            'descriptor':str(descriptor),'request':_request_value(request)}
    summary = batch._run_case(case, tmp_path/'batch')
    assert summary['programValidationLevels']['L3'] == ('failed' if bad_status=='failed' else 'inconclusive')
    assert summary['l3Coverage']['counts']['architecturalIntentVerified'] == 1
    assert summary['status'] == ('failed' if bad_status == 'failed' else 'inconclusive')
    assert 'l3.summary.authoritative-evidence-not-verified' in summary['reasonCodes']


@pytest.mark.parametrize('status', ['not_run', 'inconclusive', 'failed'])
def test_paper_does_not_upgrade_unexecuted_layers(status):
    report = {'attempts':[{'fragmentId':'fragment:0','validation':{'layers':[
        {'level':'L3','status':status,'detail':'unavailable'}]}}]}
    assert _validation_maps(report,{'fragment:0'})[0]['L3'] == status


def test_repeated_invocation_does_not_inflate_coverage():
    from tests.test_l3_batch_coverage import _evaluation
    report, _ = _evaluation()
    attempt = {'fragmentId':'fragment:0','validation':{'layers':[
        {'level':'L3','status':'inconclusive','detail':json.dumps({
            'providerInvoked':True,'providerId':'observer','providerKind':'explicit','executionIdentity':PROOF})}]}}
    report['attempts'] = [attempt, deepcopy(attempt)]
    counts = summarize_l3_case(report,[])
    assert counts['counts']['attempted'] == 1
    assert counts['providerInvocationCounts'] == {'explicit':1}
