"""Extra definitions are not calls; startup effects still require closure."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
from riscv2x86_py import controlled_system_scope as scope_module
from riscv2x86_py.system_instruction_ingress import digest


def case(tmp_path, monkeypatch, *, constructor=False, target=False):
    path=tmp_path/'input.c'; path.write_text('source fixture')
    asm={'kind':'GCCAsmStmt','range':{'begin':{'offset':0},'end':{'offset':1}}}
    call={'kind':'CallExpr','inner':[{'kind':'ImplicitCastExpr','inner':[{
        'kind':'DeclRefExpr','referencedDecl':{'kind':'FunctionDecl','name':'adapter'}}]}]}
    fn={'kind':'FunctionDecl','name':'entry','type':{'qualType':'void (void)'},
        'inner':[{'kind':'CompoundStmt','inner':[call if target else asm]}]}
    other={'kind':'FunctionDecl','name':'unrelated','type':{'qualType':'void (void)'},
        'inner':([{'kind':'ConstructorAttr'}] if constructor else [])+[{'kind':'CompoundStmt','inner':[]}]}
    ast={'kind':'TranslationUnitDecl','inner':[other,fn]}
    monkeypatch.setattr(scope_module.subprocess,'run',lambda *a,**k:SimpleNamespace(
        returncode=0,stdout=json.dumps(ast),stderr=''))
    finding={'sourceDigest':digest(path.read_bytes()),'fragment':{'id':'fragment','enclosingFunction':'entry',
        'isVolatile':True,'clobbers':['memory'],'compilerFragmentAuthority':{'functionIdentity':'identity'}}}
    return path,finding,ast


@pytest.mark.parametrize('target',[False,True])
def test_unrelated_export_does_not_change_bounded_entry_scope(tmp_path,monkeypatch,target):
    path,finding,_=case(tmp_path,monkeypatch,target=target)
    if target:scope_module.target_scope(path,'entry','adapter',sys.executable,tmp_path)
    else:assert scope_module.scope(path,finding,sys.executable)['functionSymbol']=='entry'


@pytest.mark.parametrize('target',[False,True])
def test_uncalled_constructor_is_not_ignored(tmp_path,monkeypatch,target):
    path,finding,_=case(tmp_path,monkeypatch,target=target,constructor=True)
    with pytest.raises(ValueError,match='STARTUP_EFFECT_CLOSURE_REQUIRED'):
        if target:scope_module.target_scope(path,'entry','adapter',sys.executable,tmp_path)
        else:scope_module.scope(path,finding,sys.executable)


def test_source_call_is_still_not_a_sole_asm(tmp_path,monkeypatch):
    path,finding,ast=case(tmp_path,monkeypatch,target=True)
    with pytest.raises(ValueError,match='VOID_SINGLE_VOLATILE_MEMORY_ASM_REQUIRED'):
        scope_module.scope(path,finding,sys.executable)


def test_duplicate_entry_definition_remains_ambiguous(tmp_path,monkeypatch):
    path,finding,ast=case(tmp_path,monkeypatch)
    ast['inner'].append(deepcopy(ast['inner'][1]))
    with pytest.raises(ValueError,match='FUNCTION_UNSUPPORTED'):
        scope_module.scope(path,finding,sys.executable)
