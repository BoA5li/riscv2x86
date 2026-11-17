"""Generic compiler facts and live-byte checks, not GMP acceptance evidence."""
from copy import deepcopy
import os
from pathlib import Path
import pytest

from riscv2x86_py.automatic_batch_cli import (
    _l2_operand_boundary_facts, _compiler_type_alias_resolver)
from riscv2x86_py.compiler_expression import bind_expression_operands, CompilerExpressionError
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.verification_session import ContentBytes, pure, session
from riscv2x86_py import project_native_input as native
from .test_compiler_expression_contracts import candidate, expr, node, ctype, S, F
from .test_native_instance_binding import example
from .test_verification_session import receipt
from .test_l2_scalar_authority import _finding, _function, _boundary
from .test_native_original_pipeline import adapted
from riscv2x86_py.l2_scalar_authority import assess_scalar_authority_materializability


def typed_function(canonical, *, desugared=True):
    ast, report, raw = example(name='arbitrary_owner')
    function = ast['inner'][0]
    asm = function['inner'][0]['inner'][0]
    asm.update(numOutputs=1, numInputs=2, outputConstraints=['=r'], inputConstraints=['%r', 'r'])
    declarations = []
    for i, expression in enumerate(asm['inner']):
        typ = {'qualType': 'renamed_word'}
        if desugared:
            typ['desugaredQualType'] = canonical
        expression.update(type=deepcopy(typ), valueCategory='lvalue')
        reference = expression['referencedDecl']
        reference['type'] = deepcopy(typ)
        declarations.append({'kind': 'VarDecl', 'id': reference['id'],
            'name': reference['name'], 'type': deepcopy(typ),
            'range': deepcopy(expression['range'])})
    function['inner'][0]['inner'] = declarations + [asm]
    return function, asm, raw


@pytest.mark.parametrize('canonical,width,sign', [
    ('unsigned long', 64, 'unsigned'), ('long', 64, 'signed'),
    ('unsigned int', 32, 'unsigned'), ('int', 32, 'signed')])
@pytest.mark.parametrize('desugared', [True, False])
def test_typedef_carriers_use_compiler_canonical_types(canonical, width, sign, desugared):
    function, asm, raw = typed_function(canonical, desugared=desugared)
    root = {'inner': [{'kind': 'TypedefDecl', 'name': 'renamed_word',
        'type': {'qualType': 'second_alias'}}, {'kind': 'TypedefDecl', 'name': 'second_alias',
        'type': {'qualType': canonical}}, function]}
    before = deepcopy(root)
    facts = _l2_operand_boundary_facts(function, source_digest=S, function_identity=F,
        source_file='/arbitrary/unit.i', source_bytes=raw, type_resolver=_compiler_type_alias_resolver(root))
    result = facts['fragmentCandidates'][0]
    assert result['complete']
    assert len(result['valueNodes']) == 3
    assert all(n['widthBits'] == width and n['signedness'] == sign for n in result['valueNodes'])
    assert root == before


def test_conflicting_declaration_and_expression_types_do_not_create_a_carrier():
    function, asm, raw = typed_function('unsigned long')
    asm['inner'][0]['type']['desugaredQualType'] = 'unsigned int'
    result = _l2_operand_boundary_facts(function, source_digest=S, function_identity=F,
        source_bytes=raw)['fragmentCandidates'][0]
    assert not result['complete']
    assert 'TYPE_MISMATCH' in result['operandSlotFacts']['slots'][0]['detail']


def join_fixture(constraints):
    value = candidate(expr(node()))
    slots = value['compilerExpressionFacts']
    slots['slots'] = [dict(deepcopy(slots['slots'][0]), operandIndex=i) for i in range(3)]
    slots['factsIdentity'] = identity({k:v for k,v in slots.items() if k != 'factsIdentity'})
    operands = [{'constraint': c, 'compilerType': ctype()} for c in constraints]
    return value, {'id': 'arbitrary_fragment', 'outputs': operands[:1], 'inputs': operands[1:]}


def test_whole_gnu_relation_is_preserved_and_not_promoted_to_semantic_proof():
    value, fragment = join_fixture(['=r', '%r', 'r'])
    joined = bind_expression_operands(value, fragment, source_digest=S, function_identity=F)
    relation = joined['gnuOperandRelation']
    assert relation['allowedOperandPermutations'] == [[0, 1, 2], [0, 2, 1]]
    assert relation['semanticCommutativityProofRequired']
    assert joined['operands'][1]['sourceConstraint'] == '%r'
    assert joined['complete'] and not joined['semanticRouteApproved']


@pytest.mark.parametrize('constraints', [['=r', 'r', '%r'], ['=r', '%r', '%r'], ['%=r', 'r', 'r']])
def test_invalid_relations_are_not_flattened(constraints):
    value, fragment = join_fixture(constraints)
    with pytest.raises(CompilerExpressionError):
        bind_expression_operands(value, fragment, source_digest=S, function_identity=F)


def test_relation_join_does_not_authorize_unproved_l2_or_eight_argument_harness():
    finding = _finding(); finding['fragment']['inputs'] = [{'constraint':'%r'}, {'constraint':'r'}]
    function = _function(); function['arity'] = 8
    decision = assess_scalar_authority_materializability(finding, function, _boundary())
    assert not decision.materializable
    assert 'L2_SCALAR_OPERAND_PERMUTATION_PROOF_REQUIRED' in decision.reason_codes
    assert 'L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED' in decision.reason_codes


def test_content_key_uses_actual_bytes_and_is_immutable(tmp_path):
    path = tmp_path/'value'; path.write_bytes(b'one')
    with session() as active:
        one = ContentBytes(path.read_bytes())
        assert pure('content.v1', (one,), lambda: 'one') == 'one'
        assert pure('content.v1', (ContentBytes(b'one'),), lambda: pytest.fail('miss')) == 'one'
        previous = path.stat(); path.write_bytes(b'two')
        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        assert pure('content.v1', (ContentBytes(path.read_bytes()),), lambda: 'two') == 'two'
        assert active.profile()['memoization']['content.v1']['hits'] == 1
        for mutate in (lambda: setattr(one, 'digest', b'forged'),
                       lambda: one.__init__(b'two'), lambda: delattr(one, 'raw')):
            with pytest.raises(TypeError): mutate()


@pytest.mark.parametrize('budget', [0, 256*1024*1024])
def test_current_artifacts_are_read_once_and_tampering_still_rejects(tmp_path, monkeypatch, budget):
    value = receipt(tmp_path)
    counts = {}; original = Path.read_bytes
    def read(path):
        counts[str(path)] = counts.get(str(path), 0) + 1
        return original(path)
    monkeypatch.setattr(Path, 'read_bytes', read)
    with session(budget):
        native.validate_artifacts(value, readonly=True)
        assert counts and set(counts.values()) == {1}
        path = tmp_path/'inspection-native-input.stderr'
        path.write_bytes(b'changed')
        with pytest.raises(ValueError, match='ARTIFACT_CHANGED'):
            native.validate_artifacts(value, readonly=True)


@pytest.mark.parametrize('changed_artifact', ['source', 'frontendReport'])
def test_report_reuses_checked_context_but_public_source_and_byte_checks_remain(adapted, monkeypatch, changed_artifact):
    from riscv2x86_py import native_original_pipeline as route
    from riscv2x86_py import physical_edit_binding as physical
    from riscv2x86_py.schema import load_report
    root, prepared, _, _ = adapted
    # The fixture completed the real adapter check before entering this block.
    report = prepared['frontendReport']['path']
    finding = load_report(report)[0]
    def reacquire(*args, **kwargs):
        raise RuntimeError('fresh-context-requested')
    monkeypatch.setattr(route, 'check_input', reacquire)
    physical._validate_report_checked(prepared, report)
    with pytest.raises(RuntimeError, match='fresh-context-requested'):
        physical.source_path(finding, Path(prepared['source']['path']).parent)
    Path(prepared[changed_artifact]['path']).write_bytes(b'changed')
    with pytest.raises(ValueError):
        physical._validate_report_checked(prepared, report)
