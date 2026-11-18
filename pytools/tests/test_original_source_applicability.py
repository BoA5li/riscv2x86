"""Guard/model tests with a mocked compiler ingress; literal probes use real GCC.
No executable RISC-V, canonical machine elimination or GMP proof is claimed.
"""
from copy import deepcopy
import os
from pathlib import Path
import shutil

import pytest
from riscv2x86_py import native_original_applicability as app
from riscv2x86_py import native_project_evaluation as p
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import program_validation_obligations as obligations

MODEL = {'__SIZEOF_INT__': '4', '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8'}
INT = {'qualType': 'int'}


def literal(value, typ=INT):
    return {'kind': 'IntegerLiteral', 'type': typ, 'value': str(value)}


def tree():
    raw = b'__builtin_constant_p(123L)'
    arg = literal(123, {'qualType': 'long'})
    arg['range'] = {'begin': {'offset': 21, 'tokLen': 4}, 'end': {'offset': 21, 'tokLen': 4}}
    # Compute physical positions from this fixture's literal bytes, not an asm
    # text search in production. The production range is supplied by the AST.
    arg['range']['begin']['offset'] = arg['range']['end']['offset'] = raw.index(b'123L')
    call = {'kind': 'CallExpr', 'type': INT,
        'range': {'begin': {'offset': 0, 'tokLen': 20}, 'end': {'offset': len(raw)-1, 'tokLen': 1}},
        'inner': [{'kind': 'ImplicitCastExpr', 'castKind': 'BuiltinFnToFnPtr', 'inner': [
            {'kind': 'DeclRefExpr', 'referencedDecl': {'kind': 'FunctionDecl', 'id': 'builtin:1',
                                                     'name': '__builtin_constant_p'}}]}, arg]}
    cond = {'kind': 'BinaryOperator', 'opcode': '!=', 'type': INT, 'inner': [call, literal(1)]}
    ast = {'kind': 'TranslationUnitDecl', 'inner': [{'kind': 'FunctionDecl', 'inner': [
        {'kind': 'IfStmt', 'inner': [cond, {'kind': 'GCCAsmStmt'}]}]}]}
    records = [{'astPath': [0, 0, 1], 'functionAstPath': [0], 'instanceBindingIdentity': 'fixture-instance', 'analysisInputIdentity': 'analysis'}]
    return ast, records, raw


@pytest.fixture
def probe_context(tmp_path, monkeypatch):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('real GCC required for static-assert witnesses')
    ast, records, raw = tree()
    profile = {'compiler': d.snapshot(cc), 'flags': ['-x', 'cpp-output', '-O2'],
               'directory': str(tmp_path), 'environment': {'PATH': os.environ['PATH']}}
    spec = {'profiles': {'source': {'compile': deepcopy(profile)}, 'target': {'compile': deepcopy(profile)}}, 'timeoutSeconds': 30}
    specfile = tmp_path / 'project.json'; p.write(specfile, spec)
    monkeypatch.setattr(app, 'context', lambda path: (spec, ast, records, raw, MODEL))
    monkeypatch.setattr(obligations, 'original_layer_readiness', lambda spec: {'scope': 'fixture-readiness', 'instances': []})
    return tmp_path, specfile, spec, ast, records, raw


def test_real_literal_query_witnesses_classify_source_only(probe_context):
    root, specfile, _, _, _, _ = probe_context
    value = app.acquire(specfile, root / 'app')
    assert value['facts']['sourceExcludedInstanceCount'] == 1
    assert value['queries'][0]['sourceAndTargetWitnessVerified']
    assert not value['facts']['canonicalInstructionCoverageVerified']
    assert value['facts']['instances'][0]['canonicalMachineDisposition'] == 'unknown'
    assert app.check(root / 'app/result.json') == value
    assert not value['semanticApproval']


def test_width_mismatch_cannot_become_a_verified_query(probe_context):
    root, specfile, spec, _, _, _ = probe_context
    # Deliberately mismatched compiler data model at the fixture boundary.
    spec['profiles']['target']['compile']['flags'].append('-m32')
    value = app.acquire(specfile, root / 'app')
    assert not value['queries'][0]['sourceAndTargetWitnessVerified']
    assert value['facts']['sourceExcludedInstanceCount'] == 0
    value['queries'][0]['sourceAndTargetWitnessVerified'] = True
    p.write(root / 'app/result.json', d.seal({k: v for k, v in value.items() if k != 'sourceApplicabilityIdentity'}, 'sourceApplicabilityIdentity'))
    with pytest.raises(ValueError, match='REDERIVATION_MISMATCH'): app.check(root / 'app/result.json')


def test_unstructured_entry_does_not_infer_unreachable_branch(probe_context):
    root, specfile, _, ast, _, _ = probe_context
    ast['inner'][0]['inner'].append({'kind': 'LabelStmt'})
    value = app.acquire(specfile, root / 'app')
    assert value['facts']['sourceExcludedInstanceCount'] == 0
    assert value['facts']['instances'][0]['unstructuredControlFlow']


def test_nonliteral_or_nonbuiltin_call_remains_unknown():
    ast, records, raw = tree()
    call = ast['inner'][0]['inner'][0]['inner'][0]['inner'][0]
    call['inner'][0]['castKind'] = 'FunctionToPointerDecay'
    _, _, queries = app.obligations(ast, records, raw, MODEL)
    assert queries == []
    assert app.facts(ast, records, raw, MODEL, [])['sourceExcludedInstanceCount'] == 0


def test_probe_change_is_rejected_without_recompiling(probe_context):
    root, specfile, _, _, _, _ = probe_context
    app.acquire(specfile, root / 'app')
    file = root / 'app/query-000000/query.c'; file.write_text('int unrelated;\n')
    with pytest.raises(ValueError, match='PROBE_CHANGED'): app.check(root / 'app/result.json')


def test_literal_false_short_circuit_does_not_need_variable_values():
    ast, records, raw = tree()
    condition = ast['inner'][0]['inner'][0]['inner'][0]
    condition.update(opcode='&&', inner=[literal(0), {'kind': 'DeclRefExpr', 'type': INT,
                     'referencedDecl': {'kind': 'ParmVarDecl', 'id': 'parameter:n'}}])
    value = app.facts(ast, records, raw, MODEL, [])
    assert value['sourceExcludedInstanceCount'] == 1
    assert not value['canonicalInstructionCoverageVerified']
