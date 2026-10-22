"""AST protocol tests; source ASTs are explicit fixtures, not production proof."""
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py.controlled_system_scope import scope,target_scope
from riscv2x86_py.system_instruction_ingress import digest


def fixture(tmp_path,monkeypatch):
    source=tmp_path/'name.c';source.write_text('void alternate(void){__asm__ volatile("ecall" ::: "memory");}')
    ast={'kind':'FunctionDecl','id':'0x123','name':'alternate','type':{'qualType':'void (void)'},
        'inner':[{'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt','id':'0x456',
            'range':{'begin':{'offset':21},'end':{'offset':58}}}]}]}
    root={'inner':[ast]}
    from riscv2x86_py import controlled_system_scope as module
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout=json.dumps(root),stderr=''))
    finding={'sourceDigest':digest(source.read_bytes()),'fragment':{'enclosingFunction':'alternate','id':'frag',
        'isVolatile':True,'clobbers':['memory'],'astBeginOffset':21,'astEndOffset':58,
        'compilerFragmentAuthority':{'functionIdentity':'compiler-scope-fixture'}}}
    return source,root,finding


def test_scope_identity_excludes_nondeterministic_ast_pointer_ids(tmp_path,monkeypatch):
    source,root,finding=fixture(tmp_path,monkeypatch)
    first=scope(source,finding,sys.executable)
    root['inner'][0]['id']='0x999';root['inner'][0]['inner'][0]['inner'][0]['id']='0xabc'
    assert scope(source,finding,sys.executable)==first


@pytest.mark.parametrize('mutation',['global','argument','extra-statement','asm-begin','output','nonvolatile','clobber','attribute','file-asm'])
def test_source_scope_rejects_unproven_shapes(tmp_path,monkeypatch,mutation):
    source,root,finding=fixture(tmp_path,monkeypatch);fn=root['inner'][0]
    if mutation=='global':root['inner'].append({'kind':'VarDecl'})
    if mutation=='argument':fn['inner'].append({'kind':'ParmVarDecl'})
    if mutation=='extra-statement':fn['inner'][0]['inner'].append({'kind':'ReturnStmt'})
    if mutation=='asm-begin':finding['fragment']['astBeginOffset']=20
    if mutation=='output':finding['fragment']['outputs']=[{}]
    if mutation=='nonvolatile':finding['fragment']['isVolatile']=False
    if mutation=='clobber':finding['fragment']['clobbers']=[]
    if mutation=='attribute':fn['inner'].append({'kind':'ConstructorAttr'})
    if mutation=='file-asm':root['inner'].append({'kind':'FileScopeAsmDecl'})
    with pytest.raises(ValueError,match='SYSTEM_SCOPE_'):scope(source,finding,sys.executable)


@pytest.mark.parametrize('mutation',['none','wrong-callee','extra-statement','global','parameter','argument'])
def test_target_scope_requires_exact_single_approved_call(tmp_path,monkeypatch,mutation):
    source,root,finding=fixture(tmp_path,monkeypatch);fn=root['inner'][0]
    call={'kind':'CallExpr','inner':[{'kind':'ImplicitCastExpr','inner':[{'kind':'DeclRefExpr',
        'referencedDecl':{'kind':'FunctionDecl','name':'registered_adapter'}}]}]}
    fn['inner'][0]['inner']=[call]
    if mutation=='wrong-callee':call['inner'][0]['inner'][0]['referencedDecl']['name']='unapproved'
    if mutation=='extra-statement':fn['inner'][0]['inner'].append({'kind':'ReturnStmt'})
    if mutation=='global':root['inner'].append({'kind':'VarDecl'})
    if mutation=='parameter':fn['inner'].append({'kind':'ParmVarDecl'})
    if mutation=='argument':call['inner'].append({'kind':'IntegerLiteral','value':'1'})
    if mutation=='none':target_scope(source,'alternate','registered_adapter',sys.executable,tmp_path)
    else:
        with pytest.raises(ValueError,match='SYSTEM_TARGET_SCOPE_'):
            target_scope(source,'alternate','registered_adapter',sys.executable,tmp_path)
