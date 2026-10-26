"""Direct compound-statement, pure C shell regions from compiler AST offsets."""
from .compiler_value_flow import identity


def export(node,*,source_digest,function_identity,source_range):
    bodies=[n for n in node.get('inner',[]) if n.get('kind')=='CompoundStmt']
    if len(bodies)!=1:return None
    statements=bodies[0].get('inner',[]);sites=[]
    declarations={n.get('id') for n in node.get('inner',[]) if n.get('kind')=='ParmVarDecl'}
    def pure(n):
        k=n.get('kind');children=n.get('inner',[])
        if k in {'IntegerLiteral','CharacterLiteral'}:return True
        if k=='DeclRefExpr':return n.get('referencedDecl',{}).get('id') in declarations
        return k in {'ParenExpr','ImplicitCastExpr','CStyleCastExpr'} and (k=='ParenExpr' or n.get('castKind') in {'NoOp','LValueToRValue','IntegralCast'}) and len(children)==1 and pure(children[0])
    for index,n in enumerate(statements):
        k=n.get('kind')
        if k=='DeclStmt':
            for d in n.get('inner',[]):
                if d.get('kind')!='VarDecl' or d.get('storageClass') or 'volatile' in d.get('type',{}).get('qualType','').split():return None
                if any(not pure(c) for c in d.get('inner',[])):return None
                declarations.add(d.get('id'))
        elif k=='GCCAsmStmt':
            extent=source_range(n)
            if not extent:return None
            sites.append({'begin':extent[0],'end':extent[1]})
        elif k=='ReturnStmt':
            if index!=len(statements)-1 or len(n.get('inner',[]))!=1 or not pure(n['inner'][0]):return None
        else:return None
    if not statements or statements[-1].get('kind')!='ReturnStmt' or not 2<=len(sites)<=16:return None
    body={'schemaVersion':'riscv2x86.compiler-program-regions.v1','sourceDigest':source_digest,
          'functionIdentity':function_identity,'sites':sites,'scope':'direct-acyclic-pure-shell'}
    return dict(body,scopeIdentity=identity(body))
