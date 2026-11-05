"""Enumerate asm occurrences in the entire inspection AST, not native execution.

Header bodies and macro locations are retained. Raw location records may omit
files or require spelling/expansion resolution; they are evidence, not an edit
range or a completed source-instance binding. No declaration pointers are used.
"""
from copy import deepcopy
from pathlib import Path

from .compiler_function_types import stable_type
from .project_build_records import identity

KINDS = {'GCCAsmStmt', 'MSAsmStmt', 'FileScopeAsmDecl'}


def has_macro(value):
    if isinstance(value,dict):
        return any(k in value for k in ('spellingLoc','expansionLoc')) or any(has_macro(v) for v in value.values())
    return isinstance(value,list) and any(has_macro(v) for v in value)


def derive(ast, *, context, dependency_identity, compiler_digest, target):
    if target not in {'riscv64','x86_64'}:raise ValueError('ASM_ACTIVATION_TARGET_UNSUPPORTED')
    if not isinstance(ast,dict) or ast.get('kind')!='TranslationUnitDecl':
        raise ValueError('ASM_ACTIVATION_TRANSLATION_UNIT_REQUIRED')
    rows=[]
    def visit(node,path,function=None):
        if not isinstance(node,dict):raise ValueError('ASM_ACTIVATION_AST_NODE_INVALID')
        if node.get('kind')=='FunctionDecl':
            function={'name':node.get('name'),'type':stable_type(node.get('type',{})),
                      'location':deepcopy(node.get('loc',{})),
                      'range':deepcopy(node.get('range',{}))}
        if node.get('kind') in KINDS:
            location={'location':deepcopy(node.get('loc',{})),
                      'range':deepcopy(node.get('range',{}))}
            body={'ordinal':len(rows),'astPath':path,'kind':node['kind'],
                  'enclosingFunction':deepcopy(function),**location,
                  'macroLocationPresent':has_macro(location),
                  'sourceInstanceBinding':'not_assessed','semanticApproval':False}
            rows.append(dict(body,activationIdentity=identity({**body,
                'contextIdentity':context['contextIdentity'],'dependencyIdentity':dependency_identity,
                'compilerDigest':compiler_digest,'target':target})))
        children=node.get('inner',[])
        if not isinstance(children,list):raise ValueError('ASM_ACTIVATION_AST_CHILDREN_INVALID')
        for index,child in enumerate(children):visit(child,[*path,index],function)
    visit(ast,[])
    body={'schemaVersion':'riscv2x86.inspection-asm-activation.v1',
          'contextIdentity':context['contextIdentity'],
          'sourcePath':str(Path(context['sourcePath']).resolve()),'sourceDigest':context['sourceDigest'],
          'dependencyIdentity':dependency_identity,'compilerDigest':compiler_digest,'target':target,
          'scope':'whole-inspection-translation-unit-ast-including-header-and-macro-occurrences',
          'instances':rows,'inspectionAstTraversalComplete':True,
          'nativeCompilerActivationConfirmed':False,'sourceInstanceBindingComplete':False,
          'asmInstanceInventoryComplete':False,'endToEndEligibilityAssessed':False,
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,inventoryIdentity=identity(body))


def validate(value,context,dependency_identity,compiler_digest,target):
    if (value.get('schemaVersion')!='riscv2x86.inspection-asm-activation.v1'
            or value.get('inventoryIdentity')!=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
            or value.get('contextIdentity')!=context['contextIdentity']
            or value.get('sourcePath')!=str(Path(context['sourcePath']).resolve())
            or value.get('sourceDigest')!=context['sourceDigest']
            or value.get('dependencyIdentity')!=dependency_identity
            or value.get('compilerDigest')!=compiler_digest or value.get('target')!=target
            or value.get('inspectionAstTraversalComplete') is not True
            or any(value.get(k) is not False for k in ('nativeCompilerActivationConfirmed',
                'sourceInstanceBindingComplete','asmInstanceInventoryComplete','endToEndEligibilityAssessed',
                'semanticApproval','productionAcceptanceComplete'))):
        raise ValueError('ASM_ACTIVATION_INVENTORY_INVALID')
    paths=set()
    if not isinstance(value.get('instances'),list):raise ValueError('ASM_ACTIVATION_INSTANCES_INVALID')
    for ordinal,row in enumerate(value['instances']):
        path=row.get('astPath')
        if (type(row.get('ordinal')) is not int or row['ordinal']!=ordinal
                or not isinstance(path,list) or any(type(i) is not int or i<0 for i in path)
                or tuple(path) in paths or row.get('kind') not in KINDS
                or row.get('semanticApproval') is not False or row.get('sourceInstanceBinding')!='not_assessed'
                or type(row.get('macroLocationPresent')) is not bool
                or row['macroLocationPresent']!=has_macro({'location':row.get('location'),'range':row.get('range')})
                or row.get('activationIdentity')!=identity({
                    **{k:v for k,v in row.items() if k!='activationIdentity'},
                    'contextIdentity':context['contextIdentity'],'dependencyIdentity':dependency_identity,
                    'compilerDigest':compiler_digest,'target':target})):
            raise ValueError('ASM_ACTIVATION_INSTANCE_INVALID')
        paths.add(tuple(path))
    return value
