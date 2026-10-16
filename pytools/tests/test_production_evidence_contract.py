"""Independent artifact mutations must fail even when a summary says verified."""
import copy
import json
from types import SimpleNamespace
import pytest
from riscv2x86_py.l2_evidence_reader import (
    load_case_evaluation_result, read_l2_fragment_results, _identity)
from riscv2x86_py.l2_results import L2FragmentResult
from riscv2x86_py.l2_dimensions import L2Dimension
from riscv2x86_py.evaluation import EVALUATION_RESULT_SCHEMA
from riscv2x86_py.compiler_provenance import bind_compiler_provenance
from riscv2x86_py.schema import _frag_from, Finding
from tests.test_production_route_authority import _compiler_authority


def case_artifact(tmp_path):
    closed = L2FragmentResult.close(fragment_id='frag', requirement_identity='sha256:'+'1'*64,
        required_dimensions=(L2Dimension.LOGICAL_OPERANDS,), dimension_results=()).to_dict()
    attempt = {'attemptArtifactId': 'attempt:one', 'fragmentId': 'frag',
        'validation': {'layers': [{'level': 'L2', 'status': 'inconclusive',
                                  'detail': json.dumps(closed)}]}}
    value = {'schemaVersion': EVALUATION_RESULT_SCHEMA, 'status': 'inconclusive',
             'attempts': [attempt]}
    value['evaluationIdentity'] = _identity(value)
    path = tmp_path / 'cases' / 'one' / 'evaluation-result.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(value))
    summary = {'caseId': 'one', 'status': 'inconclusive',
               'resultPath': 'cases/one/evaluation-result.json',
               'evaluationIdentity': value['evaluationIdentity']}
    return path, value, summary


def test_reader_uses_case_artifact_not_summary(tmp_path):
    _, _, summary = case_artifact(tmp_path)
    value = load_case_evaluation_result(tmp_path, summary)
    result, = read_l2_fragment_results(value)
    assert result[0] == 'attempt:one'
    assert result[1].fragment_id == 'frag'


@pytest.mark.parametrize('mutation', ['outside', 'wrong-case', 'missing', 'identity', 'status'])
def test_artifact_ingress_rejects_wrong_or_stale_result(tmp_path, mutation):
    path, value, summary = case_artifact(tmp_path)
    if mutation == 'outside': summary['resultPath'] = '../elsewhere.json'
    if mutation == 'wrong-case': summary['caseId'] = 'two'
    if mutation == 'missing': path.unlink()
    if mutation == 'identity':
        value['status'] = 'verified'
        path.write_text(json.dumps(value))
    if mutation == 'status': summary['status'] = 'verified'
    with pytest.raises(ValueError): load_case_evaluation_result(tmp_path, summary)


@pytest.mark.parametrize('mutation', ['malformed', 'fragment', 'duplicate'])
def test_typed_reader_rejects_invalid_layer_evidence(tmp_path, mutation):
    _, value, _ = case_artifact(tmp_path)
    attempt = value['attempts'][0]
    if mutation == 'malformed': attempt['validation']['layers'][0]['detail'] = '{bad'
    if mutation == 'fragment': attempt['fragmentId'] = 'other'
    if mutation == 'duplicate': value['attempts'].append(copy.deepcopy(attempt))
    with pytest.raises(ValueError): read_l2_fragment_results(value)


def operands():
    # Independent canonical consumer values, not copied out of the closure.
    return (
        SimpleNamespace(operand_index=0, declaration_id='sha256:'+'5'*64,
            value_node_identity='sha256:'+'6'*64, access_mode='read_write', width_bits=64, signedness='unsigned'),
        SimpleNamespace(operand_index=1, declaration_id='sha256:'+'2'*64,
            value_node_identity='sha256:'+'3'*64, access_mode='input', width_bits=64, signedness='unsigned'))


def test_actual_consumer_joins_closed_provenance():
    authority = _compiler_authority()
    fragment = {'id': 'source.c:7:3', 'compilerFragmentAuthority': authority}
    # These fields survive backend report parsing and serialization.
    fragment = Finding(fragment=_frag_from(fragment)).to_dict()['fragment']
    sidecar = SimpleNamespace(fragment_id='source.c:7:3', operands=operands(), authority_identity='sha256:'+'9'*64)
    bound = bind_compiler_provenance(fragment, sidecar)
    assert bound['canonicalAuthorityIdentity'] == 'sha256:'+'9'*64
    assert bound['compilerCandidateIdentity'] == authority['candidate']['candidateIdentity']
    unsigned = dict(bound); unsigned.pop('consumptionIdentity')
    assert bound['consumptionIdentity'] == _identity(unsigned)


@pytest.mark.parametrize('field', ['declaration_id', 'value_node_identity', 'access_mode', 'width_bits', 'signedness'])
def test_provenance_cannot_be_copied_onto_different_consumer(field):
    ops = operands()
    setattr(ops[0], field, 32 if field == 'width_bits' else 'wrong')
    with pytest.raises(ValueError, match='CANONICAL_OPERAND_MISMATCH'):
        bind_compiler_provenance({'id':'source.c:7:3', 'compilerFragmentAuthority':_compiler_authority()},
            SimpleNamespace(fragment_id='source.c:7:3', operands=ops, authority_identity='sha256:'+'9'*64))


def test_stale_compiler_envelope_is_rejected():
    authority = _compiler_authority()
    authority['sourceDigest'] = 'sha256:'+'8'*64
    with pytest.raises(ValueError, match='IDENTITY_MISMATCH'):
        bind_compiler_provenance({'id':'source.c:7:3', 'compilerFragmentAuthority':authority},
            SimpleNamespace(fragment_id='source.c:7:3', operands=operands(), authority_identity='sha256:'+'9'*64))


def test_location_join_uses_same_resolver_as_materializer(tmp_path):
    from riscv2x86_py.automatic_translation_command import _inject_compiler_fragment_authority
    authority = _compiler_authority()
    candidate = authority['candidate']
    fragment = {'id':'/tmp/source.c:7:3', 'fileName':'/tmp/source.c',
                'beginOffset':0, 'endOffset':0,
                'outputs':[{'constraint':'+r'}], 'inputs':[{'constraint':'r'}]}
    # Existing C++ and JSON-AST range exporters need not have identical end-token conventions.
    path = tmp_path / 'raw.json'
    path.write_text(json.dumps({'findings':[{'fragment':fragment}]}))
    function = {'sourceDigest':authority['sourceDigest'], 'functionId':authority['functionIdentity'],
                'l2OperandBoundary':{'fragmentCandidates':[candidate]}}
    _inject_compiler_fragment_authority(path, tmp_path/'source.c', (function,))
    actual = json.loads(path.read_text())['findings'][0]['fragment']
    assert actual['compilerFragmentJoin']['disposition'] == 'matched'
    assert actual['compilerFragmentBinding']['candidateIdentity'] == candidate['candidateIdentity']
    assert Finding(fragment=_frag_from(actual)).to_dict()['fragment']['compilerFragmentBinding'] == actual['compilerFragmentBinding']


def test_missing_candidate_is_explicit_not_silently_dropped(tmp_path):
    from riscv2x86_py.automatic_translation_command import _inject_compiler_fragment_authority
    path = tmp_path / 'raw.json'
    path.write_text(json.dumps({'findings':[{'fragment':{'id':'unknown:1:1'}}]}))
    _inject_compiler_fragment_authority(path, tmp_path/'source.c', ())
    fragment = json.loads(path.read_text())['findings'][0]['fragment']
    assert fragment['compilerFragmentJoin']['disposition'] == 'missing'
    assert 'compilerFragmentAuthority' not in fragment


def test_ambiguous_candidate_is_rejected(tmp_path):
    from riscv2x86_py.automatic_translation_command import _inject_compiler_fragment_authority
    candidate = _compiler_authority()['candidate']
    path = tmp_path / 'raw.json'
    path.write_text(json.dumps({'findings':[{'fragment':{'id':'/tmp/source.c:7:3'}}]}))
    function = {'sourceDigest':candidate['fragmentBindingKey']['sourceDigest'],
                'functionId':candidate['fragmentBindingKey']['functionIdentity'],
                'l2OperandBoundary':{'fragmentCandidates':[candidate, copy.deepcopy(candidate)]}}
    with pytest.raises(ValueError, match='AMBIGUOUS'):
        _inject_compiler_fragment_authority(path, tmp_path/'source.c', (function,))


def snapshot():
    candidate = copy.deepcopy(_compiler_authority()['candidate'])
    key = candidate['fragmentBindingKey']
    candidate['candidateIdentity'] = _identity({'schemaVersion':'riscv2x86.compiler-fragment-binding-key.v2', **key})
    value = {'schemaVersion':'riscv2x86.compiler-candidates.v1',
             'sourceDigest':key['sourceDigest'], 'frontendReportIdentity':'sha256:'+'a'*64,
             'functions':[{'functionId':key['functionIdentity'], 'sourceDigest':key['sourceDigest'],
                           'l2OperandBoundary':{'fragmentCandidates':[candidate]}}]}
    value['manifestIdentity'] = _identity(value)
    return value


def test_snapshot_validates_original_candidate_content():
    from riscv2x86_py.compiler_provenance import validate_compiler_snapshot
    value = snapshot()
    assert len(validate_compiler_snapshot(value)) == 1
    value['functions'][0]['l2OperandBoundary']['fragmentCandidates'][0]['operandCarriers'][0]['widthBits'] = 8
    with pytest.raises(ValueError, match='SNAPSHOT_IDENTITY_INVALID'):
        validate_compiler_snapshot(value)


def test_resigned_snapshot_cannot_hide_wrong_function_join():
    from riscv2x86_py.compiler_provenance import validate_compiler_snapshot
    value = snapshot()
    value['functions'][0]['functionId'] = 'other-function'
    value['manifestIdentity'] = _identity({k:v for k,v in value.items() if k!='manifestIdentity'})
    with pytest.raises(ValueError, match='CANDIDATE_INVALID'):
        validate_compiler_snapshot(value)


def test_rehashed_envelope_cannot_claim_a_different_source():
    authority = _compiler_authority()
    authority['sourceDigest'] = 'sha256:'+'8'*64
    authority['authorityIdentity'] = _identity({k:v for k,v in authority.items() if k!='authorityIdentity'})
    with pytest.raises(ValueError, match='SOURCE_BINDING_MISMATCH'):
        bind_compiler_provenance({'id':'source.c:7:3', 'compilerFragmentAuthority':authority},
            SimpleNamespace(fragment_id='source.c:7:3', operands=operands(), authority_identity='sha256:'+'9'*64))
