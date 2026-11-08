"""Real GCC CPP with an explicit mocked inspection/source-binding boundary.

These tests verify acquisition/rederivation and rejection, not cross-ISA proof.
"""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from .test_project_native_input import fixture as input_fixture
from riscv2x86_py import native_context_bridge as bridge
from riscv2x86_py import project_native_input as native
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.native_dynamic_obligations import binding_timing
from riscv2x86_py.native_audit_evidence import parse_target_ast
from riscv2x86_py.project_build_records import identity


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    # Existing input fixture executes real native GCC CPP/dependency scans;
    # only the Clang inspection protocol is mocked. No translator is certified.
    context, _, _ = input_fixture(tmp_path, monkeypatch)
    source = native.acquire(context, sys.executable, tmp_path/'source-input', target='x86_64')
    source = d.seal({**{k:v for k,v in source.items() if k != 'nativeInputIdentity'},
                     'target': 'riscv64', 'analysisInput': {**source['analysisInput'], 'target': 'riscv64'},
                     'analysisInputIdentity': identity({**source['analysisInput'], 'target': 'riscv64'})}, 'nativeInputIdentity')
    inventory = native.ast_inventory(d.read(source['canonicalAstPath']), source['analysisInputIdentity'])
    Path(source['inventoryPath']).write_text(json.dumps(inventory))
    source['inventoryDigest'] = d.digest(source['inventoryPath'])
    source['inventoryIdentity'] = inventory['inventoryIdentity']
    source = d.seal({k:v for k,v in source.items() if k != 'nativeInputIdentity'}, 'nativeInputIdentity')
    artifacts = native.validate_artifacts(source)
    subprocess.run([context['nativeCompiler'], '-c', context['sourcePath'], '-o', context['outputPath']], check=True)
    raw = artifacts['inputBytes']; span = [raw.index(b'return'), raw.index(b'return')+6]
    edit = {'instanceBindingIdentity': 'fixture-binding', 'sourceRange': span,
            'sourceDigest': native.bytes_identity(raw[span[0]:span[1]]), 'replacement': 'return'}
    candidate_path = tmp_path/'candidate.i'; candidate_path.write_bytes(raw)
    command_rows = []
    ast_command = artifacts['stages']['inspection-native-input']
    ast = parse_target_ast(Path(ast_command['stdoutPath']).read_bytes())
    (tmp_path/'target-ast.json').write_text(json.dumps(ast))
    for stage, stdin in [('source-object-build', native.bytes_identity(raw)),
                         ('target-object-build', d.digest(candidate_path)), ('target-ast', d.digest(candidate_path))]:
        command_rows.append({**ast_command, 'stage': stage, 'stdinIdentity': stdin})
    candidate = {'candidateIdentity': 'fixture-candidate', 'candidatePath': str(candidate_path),
                 'candidateDigest': d.digest(candidate_path), 'edits': [edit],
                 'commands': command_rows, 'targetAstIdentity': identity(ast),
                 'artifactDigests': {'target-ast.json': d.digest(tmp_path/'target-ast.json')}}
    plan = {'deploymentPlanIdentity': 'fixture-plan',
            'originalObject': d.snapshot(context['outputPath'])}
    plan_path = tmp_path/'plan.json'; plan_path.write_text(json.dumps(plan))
    bindings = {'bindingInventoryIdentity': 'fixture-bindings', 'records': [
        {'instanceBindingIdentity': 'fixture-binding', 'physicalStatementRange': span,
         'statementDigest': edit['sourceDigest'], 'functionAstPath': [0]}]}
    contexts = {'contextInventoryIdentity': 'fixture-contexts'}
    # The unit boundary supplies already-validated source-chain data. Production
    # uses deployment.validate + binding.validate_artifacts + validate_context.
    monkeypatch.setattr(bridge, 'inputs', lambda _: (candidate, source, artifacts, context, bindings, contexts))
    result = bridge.acquire(plan_path, tmp_path/'bridge', clang=sys.executable)
    return tmp_path, plan, candidate, source, artifacts, context, bindings, contexts, result


def test_native_target_acquisition_and_full_rederivation(prepared):
    root, _, _, _, _, _, _, _, result = prepared
    assert result['sourceContentLineageVerified']
    assert result['targetNativeInputAcquired']
    assert len(result['instances']) == 1
    assert result['instances'][0]['sourceFunctionAstPath'] == [0]
    assert bridge.check(root/'bridge/result.json') == result
    for key in ('targetContextCompatibilityVerified', 'entryAbiContractComplete',
                'legalObjectInputContractComplete', 'outputTerminationContractComplete',
                'translatedInstanceExecutionVerified', 'l0L3AcceptanceComplete', 'semanticApproval'):
        assert result[key] is False
    assert {row['status'] for row in result['obligations']} == {'inconclusive'}


@pytest.mark.parametrize('key,value', [('entryAbiContractComplete', True),
                                      ('instances', []), ('sourceContentLineageVerified', False)])
def test_rehashed_conclusions_are_rejected(prepared, key, value):
    root, *_, result = prepared
    result[key] = value
    (root/'bridge/result.json').write_text(json.dumps(d.seal(
        {k:v for k,v in result.items() if k != 'contextBridgeIdentity'}, 'contextBridgeIdentity')))
    with pytest.raises(ValueError, match='REDERIVATION_MISMATCH'):
        bridge.check(root/'bridge/result.json')


def test_native_target_log_mutation_is_rejected(prepared):
    root, *_ = prepared
    (root/'bridge/target-native-input/native-expanded.stdout').write_bytes(b'changed')
    with pytest.raises(ValueError, match='ARTIFACT_CHANGED'):
        bridge.check(root/'bridge/result.json')


def test_input_and_instance_mismatch_are_not_hidden(prepared):
    root, plan, candidate, source, artifacts, context, bindings, contexts, _ = prepared
    target = d.read(root/'bridge/target-native-input/native-input.json')
    target_artifacts = native.validate_artifacts(target)
    wrong = deepcopy(candidate); wrong['edits'][0]['instanceBindingIdentity'] = 'different'
    with pytest.raises(ValueError, match='INSTANCE_BINDING_MISMATCH'):
        bridge.derive(plan, wrong, source, artifacts, context, target, target_artifacts, bindings, contexts)
    wrong = deepcopy(candidate); wrong['commands'][0]['stdinIdentity'] = 'different'
    with pytest.raises(ValueError, match='FROZEN_INPUT_MISMATCH'):
        bridge.derive(plan, wrong, source, artifacts, context, target, target_artifacts, bindings, contexts)


def test_different_source_content_retains_lineage_blocker(prepared):
    root, plan, candidate, source, artifacts, context, bindings, contexts, _ = prepared
    target = d.read(root/'bridge/target-native-input/native-input.json')
    target_artifacts = native.validate_artifacts(target)
    wrong = deepcopy(source); wrong['context']['sourceDigest'] = 'different'
    result = bridge.derive(plan, candidate, wrong, artifacts, context, target, target_artifacts, bindings, contexts)
    assert not result['sourceContentLineageVerified']
    assert any(r['reasonCode'] == 'SOURCE_CONTENT_LINEAGE_MISMATCH' for r in result['obligations'])


@pytest.mark.parametrize('role,now,expected', [('unsupported', False, None),
    ('unsupported', True, None), ('jump-slot', False, False), ('jump-slot', True, True),
    ('copy', False, True), ('relative', False, True)])
def test_unknown_binding_time_is_not_inferred_from_now(role, now, expected):
    assert binding_timing(role, now) is expected


def test_runtime_report_must_belong_to_exact_plan(monkeypatch):
    from riscv2x86_py import native_deployment_observation as observation
    monkeypatch.setattr(observation, 'check_observation', lambda _: {'deploymentPath': 'fixture'})
    monkeypatch.setattr(d, 'check_result', lambda _: {'deploymentPlanIdentity': 'other-plan'})
    with pytest.raises(ValueError, match='OBSERVATION_PLAN_MISMATCH'):
        bridge.observation_inventory('fixture', {'deploymentPlanIdentity': 'expected-plan'})


def test_declaration_names_do_not_grant_abi_or_object_authority():
    ast = {'kind': 'TranslationUnitDecl', 'inner': [{'kind': 'FunctionDecl',
        'id': 'node:1', 'name': 'any_name', 'variadic': True,
        'inner': [{'kind': 'ParmVarDecl', 'id': 'node:2', 'name': 'arg',
                   'type': {'qualType': 'void *'}}]}]}
    row = bridge.declarations(ast, 'ast-a')[0]
    assert row['variadic'] and len(row['parameters']) == 1
    assert not row['abiContractVerified'] and not row['objectContractVerified']
    assert bridge.declarations(ast, 'ast-b')[0]['evidenceIdentity'] != row['evidenceIdentity']


def test_changed_native_dependency_is_rejected(prepared):
    root, *_ = prepared
    header = root/'renamed-header.h'
    header.write_text(header.read_text()+'\n#define LATER_CHANGE 1\n')
    with pytest.raises(ValueError, match='INPUT_DEPENDENCY_CHANGED'):
        bridge.check(root/'bridge/result.json')
