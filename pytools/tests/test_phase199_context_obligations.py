"""Pure context reuse must not turn source classification into execution proof."""
from copy import deepcopy
import pytest
from riscv2x86_py import project_native_binding as binding
from riscv2x86_py import native_call_obligations as calls
from riscv2x86_py.verification_session import readonly_json, session
from riscv2x86_py.project_build_records import identity


def fixture():
    def call(ref):
        return {'kind': 'CallExpr', 'inner': [{'kind': 'ImplicitCastExpr',
            'castKind': 'FunctionToPointerDecay', 'inner': [{'kind': 'DeclRefExpr',
            'referencedDecl': {'id': ref, 'kind': 'FunctionDecl', 'name': 'same_name'}}]}]}
    external = call('external')
    ast = {'kind': 'TranslationUnitDecl', 'inner': [
        {'kind': 'FunctionDecl', 'id': 'entry', 'name': 'renamable', 'inner': [
            {'kind': 'CompoundStmt', 'inner': [call('helper'), {'kind': 'IfStmt', 'inner': [
                {'kind': 'IntegerLiteral', 'value': '0', 'type': {'qualType': 'int'}}, external]},
                {'kind': 'GCCAsmStmt'}]}]},
        {'kind': 'FunctionDecl', 'id': 'helper', 'name': 'same_name', 'inner': [
            {'kind': 'CompoundStmt', 'inner': [call('missing')]}]}]}
    records = [{'functionAstPath': [0], 'astPath': [0, 0, 2], 'instanceBindingIdentity': 'instance', 'analysisInputIdentity': 'analysis'}]
    return ast, {'records': records}


def test_context_reuse_keys_all_inputs_and_returns_owned_copies():
    ast, records = fixture()
    artifacts = {'canonicalAst': readonly_json(ast), 'canonicalAstIdentity': identity(ast)}
    with session() as active:
        first = binding._contexts_checked(artifacts, records, 'analysis', None)
        first['functions'].clear()
        second = binding._contexts_checked(artifacts, records, 'analysis', None)
        assert len(second['functions']) == 2
        assert active.profile()['memoization']['native-call-contexts.v1']['hits'] == 1
        changed = deepcopy(records); changed['records'].clear()
        assert not binding._contexts_checked(artifacts, changed, 'analysis', None)['asmOwningFunctionContexts']
        binding._contexts_checked(artifacts, records, 'other-analysis', None)
        changed_ast = deepcopy(ast); changed_ast['inner'][1]['name'] = 'changed'
        changed_artifacts = {'canonicalAst': readonly_json(changed_ast), 'canonicalAstIdentity': identity(changed_ast)}
        assert binding._contexts_checked(changed_artifacts, records, 'analysis', None) != second
        with pytest.raises(ValueError, match='SCHEMA_UNSUPPORTED'):
            binding._contexts_checked(artifacts, records, 'analysis', 'unsupported')
    with session() as independent:
        assert binding._contexts_checked(artifacts, records, 'analysis', None) == second
        assert independent.profile()['memoization']['native-call-contexts.v1']['misses'] == 1


def test_zero_budget_and_missing_validated_token_do_not_reuse():
    ast, records = fixture()
    for artifact in ({'canonicalAst': ast}, {'canonicalAst': readonly_json(ast), 'canonicalAstIdentity': identity(ast)}):
        with session(0) as active:
            a = binding._contexts_checked(artifact, records, 'analysis', None)
            b = binding._contexts_checked(artifact, records, 'analysis', None)
            assert a == b
            assert active.profile()['memoization'].get('native-call-contexts.v1', {}).get('hits', 0) == 0


def test_each_reachable_call_is_retained_and_exclusion_is_not_effect_proof():
    ast, records = fixture()
    result = calls.derive(ast, records['records'], b'', {'__SIZEOF_INT__': '4', '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8'}, [])
    assert result['callSiteCount'] == 3
    assert result['sourceExcludedCallSiteCount'] == 1
    assert result['witnessedQueryCallSiteCount'] == 0
    assert {r['resolution'] for r in result['calls']} == {'emitted-definition', 'external-summary-required'}
    assert all(not r['machineAbiVerified'] and not r['callEffectClosureVerified'] for r in result['calls'])
    assert not result['semanticApproval']
    ast['inner'][0]['inner'][0]['inner'].append({'kind': 'LabelStmt'})
    assert calls.derive(ast, records['records'], b'', {'__SIZEOF_INT__': '4', '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8'}, [])['sourceExcludedCallSiteCount'] == 0


def test_query_consumption_requires_exact_typed_occurrence_and_keeps_effects_open():
    from riscv2x86_py.native_integer_contracts import builtin_contract
    ast, records = fixture()
    query = {'kind': 'CallExpr', 'type': {'qualType': 'int'}, 'inner': [
        {'kind': 'ImplicitCastExpr', 'castKind': 'BuiltinFnToFnPtr', 'inner': [
            {'kind': 'DeclRefExpr', 'referencedDecl': {'id': 'builtin',
                'kind': 'FunctionDecl', 'name': '__builtin_constant_p'}}]},
        {'kind': 'IntegerLiteral', 'value': '17', 'type': {'qualType': 'long'}}]}
    ast['inner'][0]['inner'][0]['inner'].append(query)
    model = {'__SIZEOF_INT__': '4', '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8'}
    answer = {'query': {'astPath': [0, 0, 3], 'contract': builtin_contract(query, model, lambda ref: ref)},
              'sourceAndTargetWitnessVerified': True}
    value = calls.derive(ast, records['records'], b'', model, [answer])
    assert value['callSiteCount'] == 4 and value['witnessedQueryCallSiteCount'] == 1
    row = next(r for r in value['calls'] if r['callAstPath'] == [0, 0, 3])
    assert row['queryWitnessIdentity'] == identity(answer)
    assert not row['callEffectClosureVerified']
    failed = deepcopy(answer); failed['sourceAndTargetWitnessVerified'] = False
    assert calls.derive(ast, records['records'], b'', model, [failed])['witnessedQueryCallSiteCount'] == 0
    with pytest.raises(ValueError, match='DUPLICATE_QUERY_WITNESS'):
        calls.derive(ast, records['records'], b'', model, [answer, answer])
    changed = deepcopy(ast); changed['inner'][0]['inner'][0]['inner'][3]['inner'][1]['value'] = '18'
    with pytest.raises(ValueError, match='QUERY_SUBJECT_MISMATCH'):
        calls.derive(changed, records['records'], b'', model, [answer])


def test_rehashed_context_claim_is_rejected_even_on_a_warm_pure_cache(tmp_path, monkeypatch):
    import json
    import sys
    from pathlib import Path
    from .test_native_instance_binding import protocol
    from riscv2x86_py.project_compile_context import digest
    path, _, _ = protocol(tmp_path, monkeypatch)
    original = binding.native_input.validate_artifacts
    def validated(receipt, *, readonly=False):
        value = original(receipt, readonly=readonly)
        return {**value, 'canonicalAstIdentity': identity(value['canonicalAst']),
                'canonicalAst': readonly_json(value['canonicalAst'])}
    monkeypatch.setattr(binding.native_input, 'validate_artifacts', validated)
    bundle = binding.acquire(path, sys.executable, tmp_path/'capture')
    with session() as active:
        binding.validate_artifacts(bundle)
        context_path = Path(bundle['contextsPath'])
        stored = json.loads(context_path.read_text())
        stored['callEffectClosureVerified'] = True
        stored['contextInventoryIdentity'] = identity({k:v for k,v in stored.items()
                                                       if k != 'contextInventoryIdentity'})
        context_path.write_text(json.dumps(stored))
        bundle['contextsDigest'] = digest(context_path)
        bundle['contextInventoryIdentity'] = stored['contextInventoryIdentity']
        bundle['bindingBundleIdentity'] = identity({k:v for k,v in bundle.items()
                                                    if k != 'bindingBundleIdentity'})
        with pytest.raises(ValueError, match='DERIVATION_MISMATCH'):
            binding.validate_artifacts(bundle)
        assert active.profile()['memoization']['native-call-contexts.v1']['hits'] == 1


def test_recursive_obligation_and_missing_analysis_identity_are_not_dropped():
    ast, records = fixture()
    callee = ast['inner'][0]['inner'][0]['inner'][0]['inner'][0]['inner'][0]['referencedDecl']
    callee['id'] = 'entry'
    model = {'__SIZEOF_INT__': '4', '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8'}
    result = calls.derive(ast, records['records'], b'', model, [])
    assert any(row['reason'] == 'RECURSIVE_EFFECT_SUMMARY_REQUIRED'
               for root in result['rootCallObligations'] for row in root['unresolvedCalls'])
    records['records'][0].pop('analysisInputIdentity')
    with pytest.raises(ValueError, match='ANALYSIS_IDENTITY_REQUIRED'):
        calls.derive(ast, records['records'], b'', model, [])
