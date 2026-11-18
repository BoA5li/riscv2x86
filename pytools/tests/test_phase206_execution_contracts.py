"""Contract joins and pure derivation optimizations grant no machine proof."""
from copy import deepcopy
import json
import pytest
from riscv2x86_py.native_instance_execution import classify
from riscv2x86_py import native_call_obligations as calls
from riscv2x86_py import project_native_input as native
from riscv2x86_py.verification_session import session, ReadOnlyDict, ReadOnlyList
from .test_phase199_context_obligations import fixture
from .test_native_project_l2_entry import backend
from .test_native_original_api import native_pair

MODEL = {'__SIZEOF_INT__': '4', '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8'}


def subject():
    finding = {'fragment': {'id': 'fragment'}, 'physicalEditBinding': {'astPath': [1, 2]}}
    selected = {'instanceBindingIdentities': ['i'], 'functionBindingIdentity': 'function'}
    app = {'project': {'digest': 'project'}, 'facts': {'instances': [
        {'instanceBindingIdentity': 'i', 'astPath': [1, 2],
         'sourceGuardClassification': 'excluded-under-compiler-query-contracts'}]}}
    return finding, selected, app


def test_exclusion_never_grants_elimination_or_execution_and_unknown_is_retained():
    finding, selected, app = subject()
    value = classify(finding, selected, app, app['project'])
    assert value['sourceConditionExcluded']
    assert not value['machineEliminationVerified'] and not value['canonicalInstructionCoverageVerified']
    app['facts']['instances'][0]['sourceGuardClassification'] = 'unknown'
    changed = classify(finding, selected, app, app['project'])
    assert changed['disposition'] == 'execution-evidence-required'
    assert changed['dispositionIdentity'] != value['dispositionIdentity']


@pytest.mark.parametrize('mutation', ['project', 'instance', 'ast', 'duplicate', 'missing'])
def test_no_fallback_to_unrelated_or_ambiguous_instance(mutation):
    f, selected, app = subject()
    if mutation == 'project': app['project'] = {'digest': 'other'}
    elif mutation == 'instance': app['facts']['instances'][0]['instanceBindingIdentity'] = 'other'
    elif mutation == 'ast': f['physicalEditBinding']['astPath'] = [9]
    elif mutation == 'duplicate': app['facts']['instances'] *= 2
    else: app['facts']['instances'].clear()
    with pytest.raises(ValueError): classify(f, selected, app, {'digest': 'project'})


def test_original_project_backend_consumes_applicability_instead_of_invocation_boolean(backend, monkeypatch):
    from riscv2x86_py import native_original_applicability as module
    from riscv2x86_py import native_captured_deployment as d
    from riscv2x86_py.native_project_l2_entry import ProjectEntry
    config, _, _, _, root = backend
    f, _, app = subject()
    selected = ProjectEntry(config).selected
    app['facts']['instances'][0]['instanceBindingIdentity'] = selected['instanceBindingIdentities'][0]
    app['project'] = d.snapshot(config['typedProjectEntry']['specPath'])
    path = root / 'app.json'; path.write_text(json.dumps(app))
    config['typedProjectEntry']['applicabilityPath'] = str(path)
    checked = []
    def check(path):
        checked.append(path)
        return d.read(path)  # fixture-owned upstream checker only
    monkeypatch.setattr(module, 'check', check)
    entry = ProjectEntry(config)
    assert entry.instance_disposition(f)['sourceConditionExcluded']
    assert len(checked) == 1
    # Readback follows the same checked contract and rejects changed identity.
    app['project'] = {'digest': 'changed'}; path.write_text(json.dumps(app))
    with pytest.raises(ValueError): ProjectEntry(config, readback=True).instance_disposition(f)


def test_registered_expect_rule_updates_current_source_view_without_closing_calls():
    ast, records = fixture()
    def lit(n): return {'kind': 'IntegerLiteral', 'value': str(n), 'type': {'qualType': 'long'}}
    call = {'kind': 'CallExpr', 'type': {'qualType': 'long'}, 'inner': [
        {'kind': 'ImplicitCastExpr', 'castKind': 'BuiltinFnToFnPtr', 'inner': [
            {'kind': 'DeclRefExpr', 'referencedDecl': {'id': 'builtin', 'kind': 'FunctionDecl', 'name': '__builtin_expect'}}]},
        lit(3), lit(1)]}
    ast['inner'][0]['inner'][0]['inner'].append(call)
    result = calls.derive(ast, records['records'], b'', MODEL, [])
    row = next(r for r in result['calls'] if r['callAstPath'] == [0, 0, 3])
    assert row['localValueContractChecked']
    assert row['localBuiltinContract']['physicalBranchPredictionEquivalenceClaimed'] is False
    assert not row['callEffectClosureVerified'] and not row['machineAbiVerified']
    assert any(r['reason'] == 'builtin-contract-required' for r in result['rootCallObligations'][0]['unresolvedCalls'])
    current = result['checkedRootCallObligations'][0]
    assert current['remainingSourceResolutionCount'] == 1
    assert not current['abiClosureVerified'] and not current['effectClosureVerified']
    call['inner'][0]['castKind'] = 'FunctionToPointerDecay'
    changed = calls.derive(ast, records['records'], b'', MODEL, [])
    assert not next(r for r in changed['calls'] if r['callAstPath'] == [0, 0, 3])['localValueContractChecked']


def test_fused_canonical_readonly_construction_preserves_identity_and_public_ownership():
    raw = {'kind': 'TranslationUnitDecl', 'id': '0x10', 'inner': [
        {'kind': 'VarDecl', 'id': '0x11', 'type': {'qualType': 'int'}}]}
    mutable = native.canonical_ast(raw)
    frozen = native.canonical_ast(raw, readonly=True)
    assert native.identity(mutable) == native.identity(frozen)
    assert isinstance(frozen, ReadOnlyDict) and isinstance(frozen['inner'], ReadOnlyList)
    for budget in (0, 1024 * 1024):
        with session(budget):
            graph = native._native_graph(json.dumps(raw).encode(), 'analysis')
            assert isinstance(graph['canonicalAst']['inner'][0], ReadOnlyDict)
            with pytest.raises(TypeError): graph['canonicalAst']['inner'].clear()
            owned = deepcopy(graph); owned['canonicalAst']['inner'].clear()
            assert graph['canonicalAst']['inner']


def test_original_validator_honors_bound_exclusion_without_diagnostic_keyword(backend, monkeypatch):
    from riscv2x86_py import native_original_applicability as module
    from riscv2x86_py import native_captured_deployment as d
    from riscv2x86_py import automatic_l2_operand as runner
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    from .test_automatic_l2_operand import _artifact
    config, entry, _, _, root = backend
    finding, _, app = subject()
    app['project'] = d.snapshot(config['typedProjectEntry']['specPath'])
    app['facts']['instances'][0]['instanceBindingIdentity'] = entry.selected['instanceBindingIdentities'][0]
    path = root / 'app.json'; path.write_text(json.dumps(app))
    config['typedProjectEntry']['applicabilityPath'] = str(path)
    config.update(workDirectory=str(root/'original-work'), replayDirectory=str(root/'original-replay'), seed=0)
    monkeypatch.setattr(module, 'check', lambda p: d.read(p))
    finding['fragment']['enclosingFunction'] = config['functions'][0]['name']
    # Own only upstream proof ingress; exercise the original validator gate.
    monkeypatch.setattr(runner, '_finding', lambda *a: finding)
    monkeypatch.setattr(runner, '_authority', lambda *a, **kw: ({'fixture': 'authority ingress'}, ''))
    validate = runner.build_auto_l2_operand_validator(config)
    for kwargs in ({}, {'source_instance_excluded': False}):
        result = validate(level=ValidationLevel.L2, comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
                          translation_artifact=_artifact(), **kwargs)
        detail = json.loads(result.detail)
        assert detail['reasonCode'] == 'L2_TYPED_SOURCE_INSTANCE_EXCLUDED'
        assert detail['instanceExecutionDisposition']['sourceConditionExcluded']
        assert detail['evidenceProductionDisposition'] == 'not_produced'
        assert not (root/'original-work').exists()
