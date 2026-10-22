"""Bounded AST observation scope, independent of asm spelling and case names."""
from .semantic_content import semantic_identity

SCHEMA='riscv2x86.compiler-time-return-scope.v1'


def time_return_scope(function, *, source_digest, function_identity, source_range):
    from .automatic_batch_cli import _asm_output_identity, _decl_identity
    if any(x.get('kind')=='ParmVarDecl' for x in function.get('inner',[])): return None
    bodies=[x for x in function.get('inner',[]) if x.get('kind')=='CompoundStmt']
    if len(bodies)!=1:return None
    statements=bodies[0].get('inner',[])
    if [x.get('kind') for x in statements]!=['DeclStmt','GCCAsmStmt','ReturnStmt']:return None
    declarations=statements[0].get('inner',[])
    if len(declarations)!=1 or declarations[0].get('kind')!='VarDecl' or declarations[0].get('inner'):
        return None
    declaration=declarations[0];typ=declaration.get('type',{})
    if typ.get('desugaredQualType',typ.get('qualType')) not in {'unsigned long','unsigned long long'}:
        return None
    asm=statements[1]
    if asm.get('isAsmGoto'):return None
    children=statements[2].get('inner',[])
    if len(children)!=1:return None
    returned=children[0]
    while returned.get('kind') in {'ImplicitCastExpr','ParenExpr'}:
        if returned.get('kind')=='ImplicitCastExpr' and returned.get('castKind') not in {'LValueToRValue','NoOp'}:
            return None
        inner=returned.get('inner',[])
        if len(inner)!=1:return None
        returned=inner[0]
    if returned.get('kind')!='DeclRefExpr':return None
    if not declaration.get('id') or _asm_output_identity(asm)!=declaration['id'] or _decl_identity(children[0])!=declaration['id']:
        return None
    extent=source_range(asm)
    if extent is None:return None
    payload={'schemaVersion':SCHEMA,'sourceDigest':source_digest,'functionIdentity':function_identity,
        'functionSymbol':function.get('name'),'asmBegin':extent[0],'asmEnd':extent[1],
        'scope':'u64-no-parameters-one-local-one-asm-direct-return'}
    return {**payload,'scopeIdentity':semantic_identity(payload)}


def validate_scope(value, fragment, source_digest):
    from .compiler_instruction_sync_scope import validate_scope as sync_scope
    # Reuse the common source/function/range join, keeping distinct schemas.
    if (not isinstance(value,dict) or value.get('schemaVersion')!=SCHEMA
            or value.get('scope')!='u64-no-parameters-one-local-one-asm-direct-return'
            or value.get('scopeIdentity')!=semantic_identity({k:v for k,v in value.items() if k!='scopeIdentity'})):
        raise ValueError('TIME_FUNCTION_SCOPE_INVALID')
    proxy=dict(value);proxy['schemaVersion']='riscv2x86.compiler-instruction-sync-scope.v1'
    proxy['scope']='void_no_parameters_sole_asm_optional_void_return'
    proxy['scopeIdentity']=semantic_identity({k:v for k,v in proxy.items() if k!='scopeIdentity'})
    sync_scope(proxy,fragment,source_digest)
    if (fragment.get('inputs') or len(fragment.get('outputs',[]))!=1
            or fragment['outputs'][0].get('constraint')!='=r' or not fragment.get('isVolatile')
            or fragment.get('clobbers')):
        raise ValueError('TIME_FUNCTION_SHELL_UNSUPPORTED')
    return value
