from copy import deepcopy
import json
from pathlib import Path
import pytest
from riscv2x86_py import native_audit_evidence as evidence
from riscv2x86_py import project_native_input as native
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py.l3_trace_support import require_json_match


def ast():
    return {'kind':'TranslationUnitDecl','id':'0x100','inner':[
        {'kind':'VarDecl','id':'0x110','name':'a','type':{'qualType':'unsigned long'},
         'inner':[{'kind':'AnnotateAttr','annotation':'0xfeed'}]},
        {'kind':'VarDecl','id':'0x120','name':'b','type':{'qualType':'unsigned long'}},
        {'kind':'DeclRefExpr','id':'0x130','referencedDecl':{'kind':'VarDecl','id':'0x110','name':'a'}},
        {'kind':'IntegerLiteral','id':'0x140','type':{'qualType':'int'},'value':'64','opaqueHexValue':'0xbeef'}]}


def rename(value, offset):
    if isinstance(value,dict):
        return {k:('0x'+format(int(v,16)+offset,'x') if k in native.REFERENCE_KEYS and isinstance(v,str)
                   else rename(v,offset)) for k,v in value.items()}
    if isinstance(value,list): return [rename(v,offset) for v in value]
    return value


def receipt(directory, node):
    directory.mkdir()
    stdout=directory/'target-ast.stdout';stdout.write_text(json.dumps(node))
    canonical=native.canonical_ast(node)
    artifact=directory/'target-ast.json';artifact.write_text(json.dumps(canonical,indent=2))
    stderr=directory/'target-ast.stderr';stderr.write_bytes(b'')
    other=directory/'model.stdout';other.write_bytes(b'fixed model bytes')
    def command(stage,out):
        return {'stage':stage,'command':['compiler',str(directory/'file.i')],'returnCode':0,
            'stdinIdentity':'fixed-input','stdoutPath':str(out),'stdoutDigest':digest(out),
            'stderrPath':str(stderr),'stderrDigest':digest(stderr)}
    return {'candidatePath':str(directory/'candidate.i'),'targetAstIdentity':identity(canonical),
        'artifactDigests':{'target-ast.json':digest(artifact)},
        'commands':[command('model',other),command('target-ast',stdout)]}


def test_reference_renaming_and_json_layout_preserve_complete_graph(tmp_path):
    left=receipt(tmp_path/'left',ast());right=receipt(tmp_path/'right',rename(ast(),0x7000))
    raw=Path(right['commands'][1]['stdoutPath']);raw.write_text(json.dumps(rename(ast(),0x7000),indent=4))
    right['commands'][1]['stdoutDigest']=digest(raw)
    assert left['commands'][1]['stdoutDigest']!=right['commands'][1]['stdoutDigest']
    assert evidence.command_projection(left)==evidence.command_projection(right)


@pytest.mark.parametrize('change',['literal','type','attribute','reference','alias-collision','opaque-hex','new-field','opcode','node-order'])
def test_semantic_and_graph_changes_are_not_ignored(tmp_path,change):
    original=ast();altered=rename(original,0x9000)
    if change=='literal':altered['inner'][3]['value']='63'
    elif change=='type':altered['inner'][0]['type']['qualType']='long'
    elif change=='attribute':altered['inner'][0]['inner'][0]['annotation']='different'
    elif change=='reference':altered['inner'][2]['referencedDecl']['id']=altered['inner'][1]['id']
    elif change=='alias-collision':altered['inner'][1]['id']=altered['inner'][0]['id']
    elif change=='opaque-hex':altered['inner'][3]['opaqueHexValue']='0xdead'
    elif change=='new-field':altered['newSemanticField']=True
    elif change=='opcode':altered['inner'][3]['opcode']='changed'
    else:altered['inner'][0],altered['inner'][1]=altered['inner'][1],altered['inner'][0]
    left=receipt(tmp_path/'left',original);right=receipt(tmp_path/'right',altered)
    with pytest.raises(ValueError,match='COMMAND_MISMATCH'):
        require_json_match(evidence.command_projection(left),evidence.command_projection(right),'COMMAND_MISMATCH')


def test_raw_stream_integrity_is_still_required(tmp_path):
    value=receipt(tmp_path/'original',ast())
    Path(value['commands'][1]['stdoutPath']).write_text(json.dumps(rename(ast(),4096)))
    with pytest.raises(ValueError,match='COMMAND_ARTIFACT_CHANGED'):evidence.command_projection(value)


def test_rehashed_changed_ast_cannot_use_cached_canonical_identity(tmp_path):
    value=receipt(tmp_path/'original',ast());changed=ast();changed['inner'][3]['value']='900'
    command=value['commands'][1];path=Path(command['stdoutPath'])
    path.write_text(json.dumps(changed));command['stdoutDigest']=digest(path)
    with pytest.raises(ValueError,match='RAW_CANONICAL_AST_MISMATCH'):evidence.command_projection(value)


@pytest.mark.parametrize('stream,index',[('stdout',0),('stderr',1)])
def test_other_stdout_and_all_stderr_remain_byte_exact(tmp_path,stream,index):
    left=receipt(tmp_path/'left',ast());right=receipt(tmp_path/'right',rename(ast(),4096))
    command=right['commands'][index];path=Path(command[stream+'Path']);path.write_bytes(b'changed output')
    command[stream+'Digest']=digest(path)
    if stream=='stderr':right['commands'][0]['stderrDigest']=digest(path)
    with pytest.raises(ValueError,match='COMMAND_MISMATCH'):
        require_json_match(evidence.command_projection(left),evidence.command_projection(right),'COMMAND_MISMATCH')


@pytest.mark.parametrize('text,reason',[
    ('{"kind":"TranslationUnitDecl","kind":"TranslationUnitDecl"}','DUPLICATE_AST_JSON_KEY'),
    ('{"kind":"TranslationUnitDecl","x":NaN}','NONFINITE_AST_JSON'),
    ('{"kind":"OtherDecl"}','TRANSLATION_UNIT_REQUIRED'),
    ('{"kind":"TranslationUnitDecl","id":"bad"}','AST_REFERENCE_INVALID')])
def test_malformed_ast_is_rejected(text,reason):
    with pytest.raises(ValueError,match=reason):evidence.parse_target_ast(text)


def test_target_ast_stage_must_be_unique(tmp_path):
    value=receipt(tmp_path/'original',ast());value['commands'].append(deepcopy(value['commands'][1]))
    with pytest.raises(ValueError,match='SINGLE_TARGET_AST_STAGE_REQUIRED'):evidence.command_projection(value)
