"""Independent byte-range expectations and cross-entry mutation checks."""
from copy import deepcopy
from hashlib import sha256
import json
import pytest
from riscv2x86_py.fragment_source_range import (
    bind_fragment_source_range, validate_fragment_source_range, identity,
    FragmentRangeError, AUTHORITY_SCHEMA,
)


def fixture(suffix=b';'):
    prefix='/*中文*/\n'.encode()
    source=prefix+b'asm("")'+suffix+b'\nreturn;'
    begin=len(prefix)
    end=begin+7
    key={'sourceDigest':'sha256:'+sha256(source).hexdigest(),
         'functionIdentity':'sha256:'+'4'*64,'beginOffset':begin,'endOffset':end}
    fragment={'id':'source.c:2:1','astBeginOffset':begin,'astEndOffset':end,
              'beginOffset':begin,'endOffset':end+len(suffix)}
    return source,key,fragment


def validate(binding,key,fragment):
    validate_fragment_source_range(binding,key,fragment_id=fragment['id'],
        source_digest=key['sourceDigest'],begin_offset=fragment['beginOffset'],
        end_offset=fragment['endOffset'],frontend_fragment=fragment)


@pytest.mark.parametrize('suffix',[b'',b';',b' ;',b'\n\t;',b' /*ok*/ ;',b' //ok\n;',b'/**/ /* **/;'])
def test_ranges_keep_ast_and_replacement_distinct(suffix):
    source,key,fragment=fixture(suffix)
    binding=bind_fragment_source_range(fragment,key,source)
    # Expected byte positions are independent of the production range binder.
    assert binding['astNodeRange']==[11,18]
    assert binding['replacementRange']==[11,18+len(suffix)]
    validate(binding,key,fragment)


@pytest.mark.parametrize('suffix',[b'x;',b';;',b'/*unterminated;',b'//no newline;',b'\x00;'])
def test_extra_token_or_invalid_trivia_rejected(suffix):
    source,key,fragment=fixture(suffix)
    with pytest.raises(FragmentRangeError,match='SUFFIX_INVALID'):
        bind_fragment_source_range(fragment,key,source)


@pytest.mark.parametrize('field,value',[
    ('astBeginOffset',10),('astEndOffset',19),('beginOffset',10),('endOffset',20)])
def test_current_frontend_range_cannot_be_replaced_by_authority_self_check(field,value):
    source,key,fragment=fixture()
    binding=bind_fragment_source_range(fragment,key,source)
    fragment[field]=value
    with pytest.raises(FragmentRangeError):validate(binding,key,fragment)


def test_stale_identity_and_rehashed_bad_relation_rejected():
    source,key,fragment=fixture()
    binding=bind_fragment_source_range(fragment,key,source)
    binding['suffixHex']='78'
    with pytest.raises(FragmentRangeError,match='BINDING_IDENTITY'):validate(binding,key,fragment)
    binding['bindingIdentity']=identity({k:v for k,v in binding.items() if k!='bindingIdentity'})
    with pytest.raises(FragmentRangeError,match='SUFFIX_INVALID'):validate(binding,key,fragment)


def test_digest_and_macro_range_rejected():
    source,key,fragment=fixture()
    with pytest.raises(FragmentRangeError,match='SOURCE_DIGEST'):bind_fragment_source_range(fragment,key,source+b'x')
    fragment['astBeginOffset']=-1
    with pytest.raises(FragmentRangeError,match='RANGE_INVALID'):bind_fragment_source_range(fragment,key,source)


def v3_atomic_fixture():
    from tests.test_production_route_authority import _compiler_authority,_atomic
    from riscv2x86_py.atomic_authority import atomic_runtime_object_from_compiler_authority
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.semantic_authority import SemanticAuthorityError
    authority=_compiler_authority()
    source=b' '*100+b'x'*40+b';'
    digest='sha256:'+sha256(source).hexdigest()
    old=authority['sourceDigest']
    authority=json.loads(json.dumps(authority).replace(old,digest))
    key=authority['fragmentBindingKey']
    candidate=authority['candidate']
    old_id=candidate['candidateIdentity']
    new_id=identity({'schemaVersion':'riscv2x86.compiler-fragment-binding-key.v2',**key})
    authority=json.loads(json.dumps(authority).replace(old_id,new_id))
    candidate=authority['candidate']
    candidate['closureIdentity']=identity({k:v for k,v in candidate.items() if k!='closureIdentity'})
    for obj in authority['memoryObjectBindings'].values():
        obj['bindingIdentity']=identity({k:v for k,v in obj.items() if k!='bindingIdentity'})
    fragment={'id':authority['fragmentId'],'astBeginOffset':100,'astEndOffset':140,
              'beginOffset':100,'endOffset':141}
    authority['schemaVersion']=AUTHORITY_SCHEMA
    authority['sourceRangeBinding']=bind_fragment_source_range(fragment,key,source)
    authority['authorityIdentity']=identity({k:v for k,v in authority.items() if k!='authorityIdentity'})
    return authority, fragment, source


def test_atomic_v3_consumes_range_relation_but_rejects_wrong_current_fragment():
    from tests.test_production_route_authority import _atomic
    from riscv2x86_py.atomic_authority import atomic_runtime_object_from_compiler_authority
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.semantic_authority import SemanticAuthorityError
    authority,fragment,source=v3_atomic_fixture()
    digest=authority['sourceDigest']
    def consume(current):
        return atomic_runtime_object_from_compiler_authority(authority,
            fragment_id=fragment['id'],source_digest=digest,begin_offset=100,
            end_offset=current['endOffset'],frontend_fragment=current,
            runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1},
                operand_width_bits={0:64,1:64}),atomic_operation=_atomic())
    assert consume(fragment)[1].authority_complete
    wrong={**fragment,'endOffset':140}
    with pytest.raises(SemanticAuthorityError,match='REPLACEMENT_RANGE_MISMATCH'):consume(wrong)


def test_production_injection_builds_v3_and_recomputes_identity(tmp_path):
    from riscv2x86_py.automatic_translation_command import _inject_compiler_fragment_authority
    authority,fragment,source=v3_atomic_fixture()
    candidate=authority['candidate']
    fragment.update(fileName='/tmp/source.c',outputs=[{'constraint':'+r'}],inputs=[{'constraint':'r'}],
        compilerFragmentBinding={'candidateIdentity':candidate['candidateIdentity']})
    path=tmp_path/'report.json'
    path.write_text(json.dumps({'findings':[{'fragment':fragment}]}))
    src=tmp_path/'source.c';src.write_bytes(source)
    function={'functionId':authority['functionIdentity'],'sourceDigest':authority['sourceDigest'],
        'l2OperandBoundary':{'fragmentCandidates':[candidate],
            'memoryObjectBindings':authority['memoryObjectBindings']}}
    _inject_compiler_fragment_authority(path,src,(function,))
    produced=json.loads(path.read_text())['findings'][0]['fragment']['compilerFragmentAuthority']
    assert produced['schemaVersion']==AUTHORITY_SCHEMA
    assert produced['sourceRangeBinding']['astNodeRange']==[100,140]
    assert produced['sourceRangeBinding']['replacementRange']==[100,141]
    assert produced['authorityIdentity']==identity({k:v for k,v in produced.items() if k!='authorityIdentity'})


def test_l2_replay_rejects_current_fragment_range_mutation():
    from tests.test_l2_atomic_production import atomic_finding
    from riscv2x86_py.l2_atomic_authority import materialize_atomic_authority
    finding,functions,_,_=atomic_finding()
    assert materialize_atomic_authority(finding,functions,'sha256:'+'f'*64) is not None
    finding['fragment']['endOffset']=141
    assert materialize_atomic_authority(finding,functions,'sha256:'+'f'*64) is None


def test_range_binding_unknown_fields_and_schema_rejected():
    source,key,fragment=fixture()
    binding=bind_fragment_source_range(fragment,key,source)
    for changed in ({**binding,'unknown':True},{**binding,'schemaVersion':'v0'}):
        with pytest.raises(FragmentRangeError):validate(changed,key,fragment)


@pytest.mark.parametrize('trivia',['', ' \n\t', ' /* boundary */ ', ' // boundary\n'])
def test_real_clang_and_frontend_export_same_ast_range(tmp_path,trivia):
    from tests.test_l2_real_production_chain import _tools,_assert_frontend_accepts
    from riscv2x86_py.automatic_batch_cli import inspect_entry_points
    from riscv2x86_py.automatic_translation_command import _inject_compiler_fragment_authority
    frontend=_tools()
    source=tmp_path/'source.c'
    source.write_text('/* 中文 byte offsets */\n#include <stdint.h>\n'
        'uint64_t probe(uint64_t value){\n'
        '__asm__ volatile("" : "+r"(value))'+trivia+';\nreturn value; }\n')
    _assert_frontend_accepts(frontend,source,tmp_path)
    _,functions=inspect_entry_points(source)
    report=tmp_path/'syntax-report.json'
    _inject_compiler_fragment_authority(report,source,functions)
    fragment=json.loads(report.read_text())['findings'][0]['fragment']
    authority=fragment['compilerFragmentAuthority']
    assert authority['schemaVersion']==AUTHORITY_SCHEMA
    binding=authority['sourceRangeBinding']
    data=source.read_bytes()
    assert data[binding['astNodeRange'][1]:binding['replacementRange'][1]]==(trivia+';').encode()
    validate(binding,authority['fragmentBindingKey'],{**fragment,'id':authority['fragmentId']})


def test_v3_proof_materializer_and_provenance_consume_the_same_range():
    from tests.test_l2_atomic_production import atomic_finding
    from riscv2x86_py.l2_atomic_authority import materialize_atomic_authority
    from riscv2x86_py.compiler_provenance import bind_compiler_provenance
    authority,fragment,source=v3_atomic_fixture()
    finding,functions,_,_=atomic_finding(compiler_override=authority)
    sidecar=materialize_atomic_authority(finding,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    assert bind_compiler_provenance(finding['fragment'],sidecar)['compilerAuthorityIdentity']==authority['authorityIdentity']
    finding['fragment']['endOffset']=140
    assert materialize_atomic_authority(finding,functions,'sha256:'+'f'*64) is None
    with pytest.raises(FragmentRangeError,match='REPLACEMENT_RANGE_MISMATCH'):
        bind_compiler_provenance(finding['fragment'],sidecar)
