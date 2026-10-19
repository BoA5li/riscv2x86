from copy import deepcopy
import pytest
from riscv2x86_py.compiler_instruction_sync_scope import instruction_sync_scope,validate_scope
from riscv2x86_py.route_authority import content_identity


def ast():return {'name':'renameable','type':{'qualType':'void (void)'},'inner':[
    {'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt'}]}]}


def scope(node):return instruction_sync_scope(node,source_digest='sha256:'+'1'*64,
    function_identity='sha256:'+'2'*64,source_range=lambda n:(10,20))


@pytest.mark.parametrize('extra',[{'kind':'CallExpr'},{'kind':'IfStmt'},{'kind':'GCCAsmStmt'},
    {'kind':'DeclStmt'},{'kind':'ReturnStmt','inner':[{'kind':'IntegerLiteral'}]}])
def test_extra_effect_or_control_flow_never_counts_as_executed_sync(extra):
    node=ast();node['inner'][0]['inner'].append(extra)
    assert scope(node) is None


def test_pure_void_return_and_source_range_join():
    node=ast();node['inner'][0]['inner'].append({'kind':'ReturnStmt'})
    value=scope(node)
    f={'enclosingFunction':'renameable','compilerFragmentAuthority':{'sourceDigest':'sha256:'+'1'*64,
        'functionIdentity':'sha256:'+'2'*64,'fragmentBindingKey':{'beginOffset':10,'endOffset':20}}}
    assert validate_scope(value,f,'sha256:'+'1'*64)==value
    for field in ('asmBegin','asmEnd','functionIdentity','functionSymbol','sourceDigest'):
        changed=deepcopy(value);changed[field]=11 if field.startswith('asm') else 'foreign'
        changed['scopeIdentity']=content_identity({k:v for k,v in changed.items() if k!='scopeIdentity'})
        with pytest.raises(ValueError,match='BINDING_MISMATCH'):validate_scope(changed,f,'sha256:'+'1'*64)
