"""Original proof/consumer integration, not full GMP execution evidence."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import pytest

from riscv2x86_py import operand_permutation_proof as permutation
from riscv2x86_py import wide_integer_target as wide
from riscv2x86_py import project_native_binding as binding
from riscv2x86_py.l2_scalar_authority import assess_scalar_authority_materializability
from riscv2x86_py.l2_effect_proof import identity
from riscv2x86_py.phase6d_common import (
    run_semantic_proof_gate, TargetSemanticCatalog, CompilerCapabilityModel)
from riscv2x86_py.schema import load_report
from riscv2x86_py.verification_session import session, readonly_json
from .test_wide_integer_original import build, lower
from .test_l2_scalar_authority import _finding, _function, _boundary
from .test_native_instance_binding import example


def proved(tmp_path, width=64):
    model = build(tmp_path, width)
    fragment = load_report(str(tmp_path/'input.json'))[0].fragment
    _, request, _ = lower(model)
    old = request.approved_plan
    proof = run_semantic_proof_gate(source_model=model, preservation_decision=model.preservation,
        candidate_plan=old.plan, constraints=old.constraints, target_environment=request.target_environment,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({old.plan.kind}),
            frozenset({wide.CONTRACT}), 'wide-test-v1'),
        compiler_capabilities=CompilerCapabilityModel(True, False), fragment_id=fragment.id)
    assert proof.approved
    approved = replace(old, proof=proof)
    e = proof.evidence; effects = proof.l2_effect_proof_facts
    approval = {'proofStatus': 'approved', 'sourceFragmentId': fragment.id,
        'sourceModelId': e.source_model_id, 'preservationDecisionId': e.preservation_decision_id,
        'planId': e.plan_id, 'constraintsId': e.constraints_id,
        'targetEnvironmentId': e.target_environment_id, 'targetCatalogVersion': e.target_catalog_version,
        'proofIdentity': effects.proof_identity, 'rendererContractIdentity': effects.renderer_contract_identity,
        'rendererSemanticContractId': wide.CONTRACT, 'architectureSemanticsPreserved': True,
        'shellSemanticsPreserved': True, 'l2EffectProofFacts': effects.to_dict()}
    raw = json.loads((tmp_path/'input.json').read_text())['findings'][0]['fragment']
    result = permutation.export(model, approved, fragment, approval)
    return model, approved, fragment, approval, raw, result


@pytest.mark.parametrize('width', [32, 64])
def test_real_pcode_original_proof_exports_and_consumer_checks_relation(tmp_path, width):
    _, _, _, approval, raw, result = proved(tmp_path, width)
    value = permutation.consume(result, raw, approval)
    assert value['proofIdentity'] == approval['proofIdentity']
    assert result['relation']['allowedOperandPermutations'] == [[0, 1, 2], [0, 2, 1]]
    finding = _finding(); finding['fragment'] = raw
    finding['approvalArtifact'] = dict(approval, operandPermutationProof=result)
    function = _function(); function['arity'] = 8
    reasons = assess_scalar_authority_materializability(finding, function, _boundary()).reason_codes
    assert 'L2_SCALAR_OPERAND_PERMUTATION_PROOF_REQUIRED' not in reasons
    assert 'L2_SCALAR_OPERAND_PERMUTATION_PROOF_INVALID' not in reasons
    assert 'L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED' in reasons


@pytest.mark.parametrize('mutation', ['kind', 'width', 'relation', 'binding', 'fragment', 'type', 'effect'])
def test_rehashed_projection_changes_do_not_reuse_proof(tmp_path, mutation):
    _, _, _, approval, raw, result = proved(tmp_path)
    if mutation == 'kind': result['operation']['kind'] = 'subtraction'
    elif mutation == 'width': result['operation']['widthBits'] = 32
    elif mutation == 'relation': result['relation']['allowedOperandPermutations'] = [[0, 1, 2]]
    elif mutation == 'binding': result['bindings']['proofIdentity'] = 'sha256:'+'0'*64
    elif mutation == 'fragment': raw['id'] = 'another-independent-fragment'
    elif mutation == 'type': raw['inputs'][0]['compilerType']['widthBits'] = 32
    elif mutation == 'effect':
        effect = approval['l2EffectProofFacts']; effect['complete'] = False
        effect['factsIdentity'] = identity({k:v for k,v in effect.items() if k != 'factsIdentity'})
    result['factsIdentity'] = identity({k:v for k,v in result.items() if k != 'factsIdentity'})
    with pytest.raises(ValueError): permutation.consume(result, raw, approval)


def test_current_lemma_failure_never_consumes_an_approved_label(tmp_path, monkeypatch):
    _, _, _, approval, raw, result = proved(tmp_path)
    monkeypatch.setattr(wide, 'bitvector_lemma', lambda width: False)
    with pytest.raises(ValueError, match='LEMMA_REQUIRED'):
        permutation.consume(result, raw, approval)


def test_export_rejects_changed_model_or_target_constraint(tmp_path):
    model, approved, fragment, approval, _, _ = proved(tmp_path)
    changed = replace(model, operand_permutations=((0, 1, 2),))
    with pytest.raises(ValueError): permutation.export(changed, approved, fragment, approval)
    changed = replace(approved, constraints=replace(approved.constraints,
        preserve_cc_clobber=False))
    with pytest.raises(ValueError): permutation.export(model, changed, fragment, approval)


def test_missing_projection_keeps_original_refusal():
    finding = _finding(); finding['fragment']['inputs'] = [{'constraint':'%r'}, {'constraint':'r'}]
    decision = assess_scalar_authority_materializability(finding, _function(), _boundary())
    assert 'L2_SCALAR_OPERAND_PERMUTATION_PROOF_REQUIRED' in decision.reason_codes


def test_replay_compares_exact_original_projection_beyond_a_local_commutativity_lemma(tmp_path):
    from riscv2x86_py import native_original_pipeline as route, native_captured_deployment as d
    _, _, _, approval, raw, result = proved(tmp_path)
    first = tmp_path/'original-report.json'; second = tmp_path/'replayed-report.json'
    first.write_text(json.dumps({'findings':[{'fragment':raw,
        'approvalArtifact':dict(approval, operandPermutationProof=result)}]}))
    changed=deepcopy(result)
    changed['operation']['inputOperandIndexes'].reverse()
    changed['factsIdentity']=identity({k:v for k,v in changed.items() if k!='factsIdentity'})
    # Both orders satisfy the same registered local lemma. The exact source
    # projection must still be rederived by the original backend replay.
    permutation.consume(changed, raw, approval)
    second.write_text(json.dumps({'findings':[{'fragment':raw,
        'approvalArtifact':dict(approval, operandPermutationProof=changed)}]}))
    assert route._permutation_projection_snapshot({'report':d.snapshot(first)}) != route._permutation_projection_snapshot({'report':d.snapshot(second)})


def test_binding_pure_cache_is_owned_and_all_current_inputs_are_in_the_key():
    ast, report, raw = example(name='arbitrary_owner')
    artifacts = {'canonicalAst': readonly_json(ast), 'canonicalAstIdentity': identity(ast)}
    with session() as active:
        one = binding._derive_checked(artifacts, report, raw, 'analysis')
        one['records'].clear()
        assert binding._derive_checked(artifacts, report, raw, 'analysis')['records']
        assert active.profile()['memoization']['native-compiler-instance-bindings.v1']['hits'] == 1
        changed = deepcopy(report); changed['findings'][0]['fragment']['inputs'][0]['exprText'] = 'wrong'
        with pytest.raises(ValueError): binding._derive_checked(artifacts, changed, raw, 'analysis')
        with pytest.raises(ValueError): binding._derive_checked(artifacts, report, raw.replace(b'mulhu', b'wrong'), 'analysis')
        changed = deepcopy(ast); changed['inner'][0]['inner'][0]['inner'].clear()
        with pytest.raises(ValueError): binding._derive_checked(
            {'canonicalAst':readonly_json(changed), 'canonicalAstIdentity':identity(changed)}, report, raw, 'analysis')


def test_owned_ast_without_validated_readonly_graph_token_gets_no_reuse():
    ast, report, raw = example()
    with session() as active:
        binding._derive_checked({'canonicalAst': ast, 'canonicalAstIdentity': identity(ast)}, report, raw, 'analysis')
        assert 'native-compiler-instance-bindings.v1' not in active.profile()['memoization']


def test_eight_argument_typedef_interface_produces_explicit_requirements_not_admission(tmp_path):
    from riscv2x86_py.automatic_batch_cli import entry_points_from_ast
    from riscv2x86_py.l2_execution_requirements import plan
    ast, _, raw = example(name='different_interface')
    function = ast['inner'][0]
    function['type'] = {'qualType':'void (pointer_alias, count_alias)'}
    parameters = [{'kind':'ParmVarDecl', 'id':'argument:'+str(i), 'name':'argument_'+str(i),
        'range':{'begin':{'offset':i, 'tokLen':1}, 'end':{'offset':i, 'tokLen':1}},
        'type':{'qualType':'pointer_alias' if i in (0, 3, 7) else 'count_alias'}} for i in range(8)]
    function['inner'] = parameters + function['inner']
    ast['inner'] = [
        {'kind':'TypedefDecl','name':'pointer_alias','type':{'qualType':'unsigned long *'}},
        {'kind':'TypedefDecl','name':'count_alias','type':{'qualType':'unsigned long'}}, function]
    path=tmp_path/'unit.i';path.write_bytes(raw)
    _, rows = entry_points_from_ast(ast, path, owning_nodes=[function], source_bytes=raw)
    row = rows[0]
    assert row['arity'] == 8 and row['compilerHarnessSignatureSupported'] is False
    value = plan(row, 'independent-fragment')
    assert not value['executionAuthorityGranted']
    objects = [r for r in value['requests'] if r['reasonCode'].startswith('POINTER_OBJECT_')]
    assert [r['subject']['parameterIndex'] for r in objects] == [0, 3, 7]
    assert all(r['subject']['canonicalType'] == 'unsigned long *' for r in objects)
    assert all('objectSizeBytes' not in r['subject'] for r in objects)
    assert 'FRAGMENT_VALUE_AND_EFFECT_OBSERVATION_REQUIRED' in {r['reasonCode'] for r in value['requests']}
    changed=deepcopy(row);changed['compilerExecutionSignature']['sourceDigest']='other-source'
    signature=changed['compilerExecutionSignature']
    signature['signatureIdentity']=identity({k:v for k,v in signature.items() if k!='signatureIdentity'})
    assert plan(changed, 'independent-fragment')['compilerSignature'] is None
