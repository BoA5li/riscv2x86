"""AST-derived function-entry observation scope; no source text matching."""
from .route_authority import content_identity

SCHEMA='riscv2x86.compiler-instruction-sync-scope.v1'


def instruction_sync_scope(function,*,source_digest,function_identity,source_range):
    if function.get('type',{}).get('qualType') not in {'void (void)','void ()'}:
        return None
    if any(x.get('kind')=='ParmVarDecl' for x in function.get('inner',[])):return None
    bodies=[x for x in function.get('inner',[]) if x.get('kind')=='CompoundStmt']
    if len(bodies)!=1:return None
    statements=bodies[0].get('inner',[])
    if (not statements or statements[0].get('kind')!='GCCAsmStmt'
            or len(statements)>2 or (len(statements)==2 and
                (statements[1].get('kind')!='ReturnStmt' or statements[1].get('inner')))):
        return None
    asm=statements[0]
    if asm.get('inner') or asm.get('isAsmGoto'):return None
    extent=source_range(asm)
    if extent is None:return None
    payload={'schemaVersion':SCHEMA,'sourceDigest':source_digest,'functionIdentity':function_identity,
        'functionSymbol':function.get('name'),'asmBegin':extent[0],'asmEnd':extent[1],
        'scope':'void_no_parameters_sole_asm_optional_void_return'}
    return {**payload,'scopeIdentity':content_identity(payload)}


def validate_scope(value,fragment,source_digest):
    fields={'schemaVersion','sourceDigest','functionIdentity','functionSymbol','asmBegin','asmEnd','scope','scopeIdentity'}
    if (not isinstance(value,dict) or set(value)!=fields or value['schemaVersion']!=SCHEMA
            or value['scopeIdentity']!=content_identity({k:v for k,v in value.items() if k!='scopeIdentity'})
            or value['scope']!='void_no_parameters_sole_asm_optional_void_return'):
        raise ValueError('ISS_FUNCTION_SCOPE_INVALID')
    authority=fragment.get('compilerFragmentAuthority') or {};key=authority.get('fragmentBindingKey') or {}
    if (value['sourceDigest']!=source_digest or value['sourceDigest']!=authority.get('sourceDigest')
            or value['functionIdentity']!=authority.get('functionIdentity')
            or value['functionSymbol']!=fragment.get('enclosingFunction')
            or (value['asmBegin'],value['asmEnd'])!=(key.get('beginOffset'),key.get('endOffset'))):
        raise ValueError('ISS_FUNCTION_SCOPE_BINDING_MISMATCH')
    return value
