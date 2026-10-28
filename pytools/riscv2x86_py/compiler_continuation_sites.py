"""Compiler AST statement sites for a bounded asm-goto observation harness.

Only direct compound-statement children are insertable. No token search is
used to discover a label, operand, statement boundary or branch predicate.
"""
from .compiler_value_flow import identity


def continuation_sites(function, *, source_digest, function_identity, source_range,
                       asm_operands, declaration_id):
    params=[x for x in function.get('inner',[]) if x.get('kind')=='ParmVarDecl']
    if len(params)!=1:
        return None
    sites=[]; labels=[]
    def walk(node,parent=None):
        if node.get('kind')=='GCCAsmStmt': sites.append((node,parent))
        if node.get('kind')=='LabelStmt': labels.append((node,parent))
        for child in node.get('inner',[]):
            if isinstance(child,dict): walk(child,node)
    walk(function)
    if len(sites)!=1:
        return None
    asm,parent=sites[0]
    if parent is None or parent.get('kind')!='CompoundStmt':
        return None
    children=parent.get('inner',[])
    index=next(i for i,n in enumerate(children) if n is asm)
    if index+1>=len(children): return None
    expressions=list(asm_operands(asm))
    if len(expressions)!=1 or declaration_id(expressions[0])!=params[0].get('id'):
        return None
    asm_extent=source_range(asm); next_extent=source_range(children[index+1])
    if asm_extent is None or next_extent is None: return None
    records=[]
    for label,owner in labels:
        sub=label.get('inner',[])
        extent=source_range(sub[0]) if len(sub)==1 else None
        if owner is None or owner.get('kind')!='CompoundStmt' or extent is None:
            return None
        records.append({'label':label.get('name'),'statementBegin':extent[0]})
    if not records or any(not isinstance(x['label'],str) or not x['label'] for x in records): return None
    payload={'schemaVersion':'riscv2x86.compiler-continuation-sites.v1',
        'sourceDigest':source_digest,'functionIdentity':function_identity,
        'asmBegin':asm_extent[0],'fallthroughBegin':next_extent[0],
        'inputParameterIndex':0,'inputIdentifier':params[0].get('name'),
        'labels':records,'scope':'single_parameter_single_asm_direct_compound'}
    return {**payload,'siteFactsIdentity':identity(payload)}


def atomic_function_scope(function, *, source_digest, function_identity, source_range):
    """A before/after-call observation equals the sole asm RMW only in this scope."""
    bodies=[x for x in function.get('inner',[]) if x.get('kind')=='CompoundStmt']
    if len(bodies)!=1:return None
    statements=bodies[0].get('inner',[])
    asm=[x for x in statements if x.get('kind')=='GCCAsmStmt']
    if len(asm)!=1:return None
    declarations={x.get('id') for x in function.get('inner',[]) if x.get('kind')=='ParmVarDecl'}
    declarations.update(d.get('id') for s in statements if s.get('kind')=='DeclStmt' for d in s.get('inner',[]))
    def pure_leaf(expression, references):
        kind=expression.get('kind')
        if kind in {'IntegerLiteral','CharacterLiteral'}:return True
        if kind=='DeclRefExpr':return references and expression.get('referencedDecl',{}).get('id') in declarations
        if kind in {'ParenExpr','ImplicitCastExpr','CStyleCastExpr'}:
            children=expression.get('inner',[])
            return (len(children)==1 and (kind=='ParenExpr' or expression.get('castKind') in
                {'NoOp','LValueToRValue','IntegralCast'}) and pure_leaf(children[0],references))
        return False
    for statement in statements:
        kind=statement.get('kind')
        if kind not in {'DeclStmt','GCCAsmStmt','ReturnStmt'}:return None
        if kind=='ReturnStmt' and any(not pure_leaf(x,True) for x in statement.get('inner',[])):return None
        if kind=='DeclStmt':
            for declaration in statement.get('inner',[]):
                if declaration.get('kind')!='VarDecl' or declaration.get('storageClass'):return None
                if 'volatile' in str(declaration.get('type',{}).get('qualType','')).split():return None
                for initializer in declaration.get('inner',[]):
                    if not pure_leaf(initializer,False):return None
    if sum(x.get('kind')=='ReturnStmt' for x in statements)>1:return None
    extent=source_range(asm[0])
    if extent is None:return None
    payload={'schemaVersion':'riscv2x86.compiler-atomic-function-scope.v1',
        'sourceDigest':source_digest,'functionIdentity':function_identity,
        'asmBegin':extent[0],'asmEnd':extent[1],
        'scope':'single_asm_no_other_memory_or_control_effects'}
    return {**payload,'scopeIdentity':identity(payload)}


def memory_store_function_scope(function, *, source_digest, function_identity, source_range, pointer_parameter_indexes=(0,)):
    """Sole asm with void return or return of an indexed parameter object.

    This additional C read is outside the observed asm region. Its exact
    object/index is exposed for the deployment consumer to bind to the store.
    """
    params=[n for n in function.get('inner',[]) if n.get('kind')=='ParmVarDecl']
    bodies=[n for n in function.get('inner',[]) if n.get('kind')=='CompoundStmt']
    if len(params)!=2 or len(bodies)!=1:return None
    statements=bodies[0].get('inner',[])
    kinds=[n.get('kind') for n in statements]
    if kinds not in (['GCCAsmStmt'],['GCCAsmStmt','ReturnStmt']):return None
    extent=source_range(statements[0])
    if extent is None:return None
    if len(statements)==1 or not statements[1].get('inner'):
        payload={'schemaVersion':'riscv2x86.compiler-store-function-scope.v1',
            'sourceDigest':source_digest,'functionIdentity':function_identity,
            'asmBegin':extent[0],'asmEnd':extent[1],'scope':'single_asm_void'}
        return dict(payload,scopeIdentity=identity(payload))
    def strip(node):
        while node.get('kind') in {'ParenExpr','ImplicitCastExpr'}:
            if node.get('kind')=='ImplicitCastExpr' and node.get('castKind') not in {'LValueToRValue','NoOp'}:return {}
            children=node.get('inner',[])
            if len(children)!=1:return {}
            node=children[0]
        return node
    returned=statements[1].get('inner',[])
    if len(returned)!=1:return None
    outer=returned[0]
    if outer.get('kind')=='ImplicitCastExpr' and outer.get('castKind')=='IntegralCast':
        inner=outer.get('inner',[])
        if len(inner)!=1:return None
        outer=inner[0]
    array=strip(outer); children=array.get('inner',[])
    if array.get('kind')!='ArraySubscriptExpr' or len(children)!=2:return None
    base,index=strip(children[0]),strip(children[1])
    positions=[i for i,p in enumerate(params) if p.get('id')==base.get('referencedDecl',{}).get('id')]
    if (base.get('kind')!='DeclRefExpr' or len(positions)!=1 or positions[0] not in pointer_parameter_indexes
            or index.get('kind')!='IntegerLiteral'):return None
    try:offset=int(index['value'])
    except (KeyError,TypeError,ValueError):return None
    if offset<0:return None
    extent=source_range(statements[0])
    if extent is None:return None
    payload={'schemaVersion':'riscv2x86.compiler-store-function-scope.v1',
        'sourceDigest':source_digest,'functionIdentity':function_identity,
        'asmBegin':extent[0],'asmEnd':extent[1], 'returnObjectParameterIndex':positions[0],
        'returnElementIndex':offset,'scope':'single_asm_and_bound_object_return'}
    return {**payload,'scopeIdentity':identity(payload)}
