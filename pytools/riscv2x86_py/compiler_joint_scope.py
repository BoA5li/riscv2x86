"""Compiler AST scope for direct uint64 carriers and a typed private object.

This is an executable observation grammar, not approval of asm or of a route.
It never infers instructions from source text. Each asm is proved separately.
"""
from .compiler_program_regions import export as regions
from .compiler_memory_signature import type_fact
from .compiler_value_flow import identity


def export(node, *, source_digest, function_identity, source_range, resolve):
    scope=regions(node,source_digest=source_digest,function_identity=function_identity,source_range=source_range)
    if scope is None:return None
    params=[x for x in node.get('inner',[]) if x.get('kind')=='ParmVarDecl']
    facts=[type_fact(resolve(x.get('type',{}).get('qualType',''))) for x in params]
    if not 1<=len(params)<=4 or any(x is None for x in facts):return None
    pointers=[i for i,x in enumerate(facts) if x['kind']=='pointer']
    if len(pointers)!=1:return None
    def scalar(x):return x and x.get('kind')=='integer' and x.get('widthBits')==64 and x.get('signed') is False
    p=facts[pointers[0]]
    pointee=p['pointee']
    if (pointee.get('kind')!='integer' or pointee.get('widthBits') not in (8,16,32,64)
            or p.get('pointeeQualifiers') or any(i!=pointers[0] and not scalar(x) for i,x in enumerate(facts))):return None
    result=type_fact(resolve(node.get('type',{}).get('qualType','').split(' (',1)[0]))
    if not scalar(result):return None
    statements=next(x for x in node['inner'] if x.get('kind')=='CompoundStmt')['inner']
    declared=set(x.get('id') for x in params)
    def reference(x):
        while x.get('kind') in {'ParenExpr','ImplicitCastExpr'}:
            c=x.get('inner',[])
            if len(c)!=1 or x.get('kind')!='ParenExpr' and x.get('castKind') not in {'NoOp','LValueToRValue'}:return None
            if resolve(x.get('type',{}).get('qualType',''))!=resolve(c[0].get('type',{}).get('qualType','')):return None
            x=c[0]
        return x.get('referencedDecl',{}).get('id') if x.get('kind')=='DeclRefExpr' else None
    # Input/output roles come from the frontend join later. Here all GNU asm
    # expressions must remain direct declared carriers; no address side effects.
    for s in statements:
        if s.get('kind')=='DeclStmt':
            for d in s.get('inner',[]):
                if not scalar(type_fact(resolve(d.get('type',{}).get('qualType','')))):return None
                declared.add(d.get('id'))
                if d.get('inner'):return None
        elif s.get('kind')=='GCCAsmStmt':
            if any(reference(e) not in declared for e in s.get('inner',[])):return None
        elif s.get('kind')=='ReturnStmt':
            if len(s.get('inner',[]))!=1 or reference(s['inner'][0]) not in declared:return None
        else:return None
    legacy=scalar(pointee)
    body={'schemaVersion':'riscv2x86.compiler-joint-scope.v1' if legacy else 'riscv2x86.compiler-joint-scope.v2','sourceDigest':source_digest,
        'functionIdentity':function_identity,'sites':scope['sites'],'pointerParameter':pointers[0],
        'parameterTypes':facts,'resultType':result,'scope':'direct-unsigned64-private-object-regions' if legacy else 'direct-integer-object-unsigned64-carrier-regions'}
    return dict(body,scopeIdentity=identity(body))
