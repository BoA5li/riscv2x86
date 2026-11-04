"""Discovery of primary-file function types, not harness eligibility or proof.

Unlike integer-only entry selection, retain floating, void, aggregate, variadic
and internal-linkage functions in the denominator and report missing contracts.
Header bodies remain in the dependency inventory, not independent test entries.
"""
from pathlib import Path
import re
from .project_build_records import identity
from .compiler_call_inventory import extent


def describe(node):
    facts = dict(node.get('type', {}))
    canonical = facts.get('desugaredQualType', facts.get('qualType', ''))
    plain = re.sub(r'\b(const|volatile|restrict|_Atomic)\b', '', canonical)
    plain = ' '.join(plain.split())
    result = {'compilerType':facts, 'canonicalType':canonical, 'kind':'unclassified',
              'widthBits':None, 'proofOrCallContractAvailable':False}
    if plain in {'float', 'double'}:
        result.update(kind='binary-floating', widthBits=32 if plain=='float' else 64,
                      format='ieee754-binary32' if plain=='float' else 'ieee754-binary64')
    elif plain == 'void': result['kind']='void'
    elif '*' in plain: result['kind']='pointer'
    elif re.fullmatch(r'(?:unsigned |signed )?(?:char|short(?: int)?|int|long(?: int)?|long long(?: int)?)', plain):
        result['kind']='integer'
    return result


def derive(ast, *, source_path, dependency_identity, target):
    if target not in {'riscv64', 'x86_64'}: raise ValueError('PROJECT_TYPE_TARGET_UNSUPPORTED')
    source = str(Path(source_path).resolve()); current_file = source; functions=[]
    for node in ast.get('inner', []):
        loc = node.get('loc', {})
        if loc.get('file'): current_file = str(Path(loc['file']).resolve())
        if (node.get('kind') != 'FunctionDecl' or current_file != source or loc.get('includedFrom')
                or not any(n.get('kind')=='CompoundStmt' for n in node.get('inner', []))):
            continue
        # Return type spelling is retained even when typedef/function-pointer
        # syntax requires a future compiler type exporter.
        typ = node.get('type', {}); spelling=typ.get('desugaredQualType',typ.get('qualType',''))
        match = re.fullmatch(r'([^()]+) \((.*)\)', spelling)
        returned = describe({'type':{'qualType':match[1]}}) if match else describe({})
        params=[describe(n) for n in node.get('inner', []) if n.get('kind')=='ParmVarDecl']
        reasons=[]
        if any(t['kind']=='binary-floating' for t in [returned,*params]):
            reasons.extend(['PROJECT_FLOAT_TRANSLATION_PROOF_REQUIRED',
                            'PROJECT_FLOAT_ABI_AND_STATE_OBSERVATION_REQUIRED'])
        if node.get('variadic'): reasons.append('PROJECT_VARIADIC_CALL_CONTRACT_REQUIRED')
        if node.get('storageClass')=='static': reasons.append('PROJECT_INTERNAL_ENTRY_ADAPTER_REQUIRED')
        if any(t['kind']=='unclassified' for t in [returned,*params]): reasons.append('PROJECT_TYPED_CALL_CONTRACT_REQUIRED')
        body={'name':node.get('name'), 'compilerFunctionType':typ,
              'sourceRange':extent(node), 'returnType':returned, 'parameterTypes':params,
              'variadic':bool(node.get('variadic')), 'linkage':node.get('storageClass','external'),
              'capabilityPrerequisites':reasons,
              'translationAndEvaluationEligibility':'not_assessed', 'semanticApproval':False}
        functions.append(dict(body, functionTypeIdentity=identity({**body,
            'dependencyIdentity':dependency_identity,'target':target})))
    body={'schemaVersion':'riscv2x86.compiler-function-types.v1','sourcePath':source,
          'dependencyIdentity':dependency_identity,'target':target,'functions':functions,
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body, inventoryIdentity=identity(body))
