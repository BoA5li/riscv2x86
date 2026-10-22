"""Compiler AST scope for the bounded SYSTEM function observer."""
import json
from pathlib import Path
import subprocess
from .semantic_content import semantic_identity
from .system_instruction_ingress import digest


def scope(source, finding, clang):
    source=Path(source).resolve()
    if digest(source.read_bytes())!=finding.get('sourceDigest'):raise ValueError('SYSTEM_SCOPE_SOURCE_CHANGED')
    command=[str(clang),'--target=riscv64','-march=rv64i','-mabi=lp64','-Xclang','-ast-dump=json','-fsyntax-only',str(source)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=120,check=False)
    if result.returncode:raise ValueError('SYSTEM_SCOPE_AST_FAILED:'+result.stderr[-1000:])
    root=json.loads(result.stdout);functions=[]
    for node in root.get('inner',[]):
        if node.get('kind')=='FileScopeAsmDecl':raise ValueError('SYSTEM_SCOPE_FILE_ASM_UNSUPPORTED')
        body=[n for n in node.get('inner',[]) if n.get('kind')=='CompoundStmt']
        if node.get('kind')=='FunctionDecl' and body:
            functions.append((node,body[0]))
        if node.get('kind')=='VarDecl' and not node.get('loc',{}).get('includedFrom'):
            raise ValueError('SYSTEM_SCOPE_GLOBAL_OBJECT_UNSUPPORTED')
    fragment=finding['fragment'];name=fragment.get('enclosingFunction')
    if len(functions)!=1 or functions[0][0].get('name')!=name:
        raise ValueError('SYSTEM_SCOPE_FUNCTION_UNSUPPORTED')
    function,body=functions[0]
    if (function.get('type',{}).get('qualType') not in ('void (void)','void ()')
            or any(n.get('kind')=='ParmVarDecl' or n.get('kind','').endswith('Attr') for n in function.get('inner',[]))
            or len(body.get('inner',[]))!=1 or body['inner'][0].get('kind')!='GCCAsmStmt'
            or fragment.get('inputs') or fragment.get('outputs') or fragment.get('gotoLabels')
            or not fragment.get('isVolatile') or sorted(fragment.get('clobbers',[]))!=['memory']):
        raise ValueError('SYSTEM_SCOPE_VOID_SINGLE_VOLATILE_MEMORY_ASM_REQUIRED')
    ast=body['inner'][0];begin=ast['range']['begin'].get('offset');end=ast['range']['end'].get('offset')
    if (begin!=fragment.get('astBeginOffset',begin) or end!=fragment.get('astEndOffset',end)):
        # Clang producer versions can disagree on end-token ownership. Binding
        # by the already replayed compiler candidate still requires exact begin.
        if begin!=fragment.get('astBeginOffset'):raise ValueError('SYSTEM_SCOPE_ASM_RANGE_MISMATCH')
    def stable(node):
        if isinstance(node,dict):return {k:stable(v) for k,v in node.items() if k not in {'id','previousDecl','parentDeclContextId'}}
        if isinstance(node,list):return [stable(v) for v in node]
        return node
    value={'schemaVersion':'riscv2x86.controlled-system-scope.v1','sourceDigest':finding['sourceDigest'],
        'fragmentId':fragment.get('id') or fragment.get('fragmentId'),'functionSymbol':name,
        'functionIdentity':fragment['compilerFragmentAuthority']['functionIdentity'],
        'astIdentity':semantic_identity(stable(function)),'astCompilerDigest':digest(Path(clang).read_bytes()),
        'asmBegin':begin,'asmEnd':end}
    value['scopeIdentity']=semantic_identity(value)
    return value


def target_scope(target, symbol, callable_identifier, clang, implementation):
    """Reject target-only branches/objects outside the approved single call."""
    command=[str(clang),'--target=x86_64-linux-gnu','-I',str(implementation),
        '-include',str(Path(implementation)/'controlled_system.h'),'-Xclang','-ast-dump=json',
        '-fsyntax-only',str(Path(target).resolve())]
    result=subprocess.run(command,capture_output=True,text=True,timeout=120,check=False)
    if result.returncode:raise ValueError('SYSTEM_TARGET_SCOPE_AST_FAILED:'+result.stderr[-1000:])
    root=json.loads(result.stdout);functions=[]
    for node in root.get('inner',[]):
        if node.get('kind')=='FileScopeAsmDecl':raise ValueError('SYSTEM_TARGET_SCOPE_FILE_ASM_UNSUPPORTED')
        body=[n for n in node.get('inner',[]) if n.get('kind')=='CompoundStmt']
        if node.get('kind')=='FunctionDecl' and body:functions.append((node,body[0]))
        if node.get('kind')=='VarDecl' and not node.get('loc',{}).get('includedFrom'):
            raise ValueError('SYSTEM_TARGET_SCOPE_GLOBAL_OBJECT_UNSUPPORTED')
    if len(functions)!=1 or functions[0][0].get('name')!=symbol:
        raise ValueError('SYSTEM_TARGET_SCOPE_FUNCTION_UNSUPPORTED')
    function,body=functions[0];statements=body.get('inner',[])
    if (function.get('type',{}).get('qualType') not in ('void (void)','void ()')
            or any(n.get('kind')=='ParmVarDecl' or n.get('kind','').endswith('Attr') for n in function.get('inner',[]))
            or len(statements)!=1 or statements[0].get('kind')!='CallExpr'
            or len(statements[0].get('inner',[]))!=1):
        raise ValueError('SYSTEM_TARGET_SCOPE_SINGLE_CALL_REQUIRED')
    callee=statements[0]['inner'][0]
    if callee.get('kind')=='ImplicitCastExpr' and len(callee.get('inner',[]))==1:callee=callee['inner'][0]
    if (callee.get('kind')!='DeclRefExpr' or callee.get('referencedDecl',{}).get('kind')!='FunctionDecl'
            or callee['referencedDecl'].get('name')!=callable_identifier):
        raise ValueError('SYSTEM_TARGET_SCOPE_CALLEE_MISMATCH')
