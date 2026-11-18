"""Typed admission is not an asm, memory safety or machine ABI proof."""
from copy import deepcopy
from types import SimpleNamespace
import subprocess
import shutil

import pytest
from riscv2x86_py import l2_typed_entry as t
from riscv2x86_py.l2_execution_requirements import export_signature
from riscv2x86_py.automatic_l2_operand import _traces
from .test_native_original_api import selected, domain, TYPES


def function():
    selection, ast, _ = selected()
    fn = {'functionId': 'function-17', 'nativeCompilerDeclarationId': 'declaration-17',
          'sourceDigest': selection['sourceDigest'], 'name': 'exercise',
          'arity': 8, 'parameterTypes': TYPES, 'returnType': 'void',
          'l2OperandBoundary': {'parameterDeclarationIds': ['parameter-' + str(i) for i in range(8)]}}
    fn['compilerExecutionSignature'] = export_signature(fn, ast['inner'][0], lambda typ: typ)
    return fn, selection


def test_eight_parameter_pointer_void_contract_uses_finite_cases_not_cartesian():
    fn, selection = function()
    entry = t.bind(fn, selection, domain())
    assert entry['sampleCount'] == 1
    assert entry['pointerParameterIndices'] == [0]
    assert t.validate(entry, fn) == entry
    assert not entry.get('machineAbiClosureVerified', False)


@pytest.mark.parametrize('mutation', ['declaration', 'digest', 'type', 'void', 'variadic', 'kind', 'width'])
def test_typed_admission_requires_exact_original_compiler_identity(mutation):
    fn, selection = function()
    if mutation == 'declaration': selection['compilerDeclarationIdentity'] = 'another-declaration'
    if mutation == 'digest': selection['sourceDigest'] = 'sha256:' + '0' * 64
    if mutation == 'type': selection['interface']['parameters'][1]['cType'] = 'long'
    if mutation == 'void': selection['interface']['return']['cType'] = 'unsigned long'
    if mutation == 'variadic': selection['signature']['variadic'] = True
    if mutation == 'kind': selection['interface']['parameters'][0]['kind'] = 'integer'
    if mutation == 'width': selection['interface']['parameters'][1]['bits'] = 32
    with pytest.raises(ValueError): t.bind(fn, selection, domain())


def test_observer_cannot_consume_pointer_token_or_void_completion_as_operand():
    fn, selection = function(); entry = t.bind(fn, selection, domain())
    for binding in (SimpleNamespace(parameter_index=0, closure_kind='parameter', observation_kind='function_parameter'),
                    SimpleNamespace(parameter_index=None, closure_kind='sink', observation_kind='function_return')):
        with pytest.raises(ValueError):
            t.validate_observations(entry, SimpleNamespace(authority=SimpleNamespace(bindings=[binding])))
    t.validate_observations(entry, SimpleNamespace(authority=SimpleNamespace(bindings=[
        SimpleNamespace(parameter_index=1, closure_kind='parameter', observation_kind='function_parameter')])))
    with pytest.raises(ValueError, match='NONINTEGER_OPERAND'):
        t.validate_observations(entry, SimpleNamespace(authority=SimpleNamespace(bindings=[])),
                                [{'typeKind': 'pointer'}])


def test_real_host_execution_keeps_original_internal_and_boundary_trace_protocol(tmp_path):
    cc = shutil.which('gcc')
    if cc is None: pytest.skip('native GCC required')
    from .test_native_original_api import BODY
    fn, selection = function(); entry = t.bind(fn, selection, domain())
    driver = tmp_path / 'driver.c'
    driver.write_text(t.wrapper(entry) + BODY)
    exe = tmp_path / 'driver'
    subprocess.run([cc, '-std=gnu11', '-Werror', str(driver), '-o', str(exe)], check=True, capture_output=True)
    result = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
    rows = _traces(result.stdout, 'exercise', 8, sample_count=1)
    assert rows == ((1 << 32, 1, 2, 3, 4, 5, 6, 7, 0),)
    assert _traces(result.stdout, 'exercise', 8) is None  # legacy still requires its complete domain
    assert 'case:0:object:0:0:31\n' in result.stdout
    assert _traces(result.stdout * 2, 'exercise', 8, sample_count=1) is None


def test_typed_admission_does_not_drop_other_original_authority_obligations():
    from riscv2x86_py.l2_scalar_authority import assess_scalar_authority_materializability as assess
    from .test_l2_scalar_authority import _finding, _boundary
    fn, selection = function(); entry = t.bind(fn, selection, domain())
    finding = _finding(); boundary = _boundary()
    legacy = assess(finding, fn, boundary)
    typed = assess(finding, fn, boundary, typed_entry=entry)
    assert 'L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED' in legacy.reason_codes
    assert 'L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED' not in typed.reason_codes
    finding['approvalArtifact'].pop('planId')
    rejected = assess(finding, fn, boundary, typed_entry=entry)
    assert not rejected.materializable and rejected.reason_codes
    bad = deepcopy(entry); bad['sampleCount'] = 100
    assert not assess(_finding(), fn, boundary, typed_entry=bad).materializable


def test_proof_sidecar_does_not_depend_on_legacy_wrapper_arity(tmp_path):
    from .test_automatic_l2_operand import _function, _artifact, attach_effect_proof, profile_dict
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.automatic_l2_operand import _authority
    fn = _function(); fn['arity'] = 8
    fn['parameterTypes'] += ['uint64_t'] * 6
    fn['l2OperandBoundary']['parameterDeclarationIds'] += ['unused-' + str(i) for i in range(6)]
    finding = {'fragment': {'id': 'fragment', 'enclosingFunction': 'add',
        'outputs': [{'constraint': '=&r', 'symbolicName': 'dst', 'isEarlyClobber': True}],
        'inputs': [{'constraint': 'r', 'symbolicName': 'lhs'}, {'constraint': 'r', 'symbolicName': 'rhs'}]},
        'approvalArtifact': {'proofStatus': 'approved', 'architectureSemanticsPreserved': True,
            'shellSemanticsPreserved': True, 'sourceModelId': 'model', 'constraintsId': 'constraint',
            'preservationDecisionId': 'decision', 'planId': 'plan', 'targetEnvironmentId': 'environment',
            'targetCatalogVersion': 'catalog'}, 'l2SemanticProfile': profile_dict('fragment')}
    for i in range(6):
        declaration = 'unused-' + str(i); boundary = fn['l2OperandBoundary']
        boundary['asmOperandDeclarationIds'].append(declaration)
        boundary['asmOperandValueNodeIdentities'].append('sha256:' + str(i + 4) * 64)
        boundary['declarations'][declaration] = {'name': 'arg' + str(i), 'type': 'uint64_t'}
        boundary['declarationReferenceCounts'][declaration] = 1
        finding['fragment']['inputs'].append({'constraint': 'r', 'symbolicName': 'arg' + str(i)})
    finding['l2SemanticProfile']['operandShape']['inputCount'] = 8
    from riscv2x86_py.project_build_records import identity
    finding['l2SemanticProfile']['profileIdentity'] = identity({k:v for k,v in finding['l2SemanticProfile'].items() if k != 'profileIdentity'})
    attach_effect_proof(finding['approvalArtifact'], 'fragment')
    frontend = tmp_path / 'frontend'; frontend.write_bytes(b'fixture-proof-producer')
    count = materialize_automatic_l2_authority({'findings': [finding]}, [fn], frontend)
    assert count == 1, str(finding['approvalArtifact']['l2MaterializationDecision']['reasonCodes'])
    approval = finding['approvalArtifact']
    assert approval['l2AuthoritySidecar']['complete']
    assert not approval['l2ScalarAuthorityDecision']['materializable']
    assert approval['l2ScalarAuthorityDecision']['reasonCodes'] == ['L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED']
    # Existing scalar consumers still reject; exporting a proof does not grant
    # a new executable domain or a pointer/numeric operand relation.
    assert _authority(finding, [fn], _artifact())[1] == 'L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED'
