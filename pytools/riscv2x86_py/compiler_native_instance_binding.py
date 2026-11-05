"""Join native-input AST occurrences to compiler API operand exports.

All byte ranges refer to the frozen preprocessed input, never original macros.
The existing Clang Tooling frontend supplies asm strings, constraints and type
facts; no asm statement is located or decoded by a text search. This module
does not grant semantic, edit, call-effect, ABI or production authority.
"""
from copy import deepcopy

from .project_build_records import identity
from .project_native_input import bytes_identity
from .gnu_operand_relations import derive as operand_relations
from .fragment_source_range import _TRIVIA

SCHEMA = 'riscv2x86.native-compiler-instance-bindings.v1'
ASM_KINDS = {'GCCAsmStmt', 'MSAsmStmt', 'FileScopeAsmDecl'}


def byte_range(node, length):
    result = []
    for key in ('begin', 'end'):
        loc = node.get('range', {}).get(key, {})
        if any(k in loc for k in ('spellingLoc', 'expansionLoc')):
            raise ValueError('NATIVE_BINDING_UNEXPECTED_MACRO_RANGE')
        offset = loc.get('offset'); size = loc.get('tokLen')
        if type(offset) is not int or type(size) is not int or offset < 0 or size < 1:
            raise ValueError('NATIVE_BINDING_PHYSICAL_BYTE_RANGE_REQUIRED')
        result.append(offset + (size if key == 'end' else 0))
    if not 0 <= result[0] < result[1] <= length:
        raise ValueError('NATIVE_BINDING_BYTE_RANGE_INVALID')
    return result


def _nodes(ast):
    def visit(node, path, function=None):
        if not isinstance(node, dict):
            raise ValueError('NATIVE_BINDING_AST_NODE_INVALID')
        if node.get('kind') == 'FunctionDecl':
            function = path
        yield node, path, function
        children = node.get('inner', [])
        if not isinstance(children, list):
            raise ValueError('NATIVE_BINDING_AST_CHILDREN_INVALID')
        for i, child in enumerate(children):
            yield from visit(child, [*path, i], function)
    return list(visit(ast, []))


def _references(node):
    found = []
    for value, path, _ in _nodes(node):
        if value.get('kind') == 'DeclRefExpr':
            declaration = value.get('referencedDecl')
            if not isinstance(declaration, dict) or not isinstance(declaration.get('id'), str):
                raise ValueError('NATIVE_BINDING_DECLARATION_REFERENCE_REQUIRED')
            found.append({'expressionPath': path, 'declaration': deepcopy(declaration)})
    return found


def derive(ast, frontend_report, raw, analysis_input_identity):
    if ast.get('kind') != 'TranslationUnitDecl' or not isinstance(raw, bytes):
        raise ValueError('NATIVE_BINDING_TRANSLATION_UNIT_REQUIRED')
    nodes = _nodes(ast)
    node_at = {tuple(path): node for node, path, _ in nodes}
    occurrences = [(n, p, fn) for n, p, fn in nodes if n.get('kind') in ASM_KINDS]
    by_range = {}
    for node, path, function in occurrences:
        if node['kind'] != 'GCCAsmStmt':
            raise ValueError('NATIVE_BINDING_ASM_KIND_EXPORT_REQUIRED:' + node['kind'])
        extent = tuple(byte_range(node, len(raw)))
        if extent in by_range:
            raise ValueError('NATIVE_BINDING_DUPLICATE_AST_RANGE')
        by_range[extent] = (node, path, function)
    findings = frontend_report.get('findings')
    if not isinstance(findings, list):
        raise ValueError('NATIVE_BINDING_FRONTEND_FINDINGS_REQUIRED')
    exported = [f for f in findings if f.get('subjectKind') == 'AsmFragment']
    if len(exported) != len(occurrences):
        raise ValueError('NATIVE_BINDING_ASM_COVERAGE_MISMATCH')
    records = []; seen = set()
    for finding in exported:
        fragment = finding.get('fragment')
        if not isinstance(fragment, dict):
            raise ValueError('NATIVE_BINDING_FRAGMENT_EXPORT_REQUIRED')
        extent = [fragment.get('astBeginOffset'), fragment.get('astEndOffset')]
        if any(type(i) is not int for i in extent) or tuple(extent) not in by_range:
            raise ValueError('NATIVE_BINDING_FRONTEND_AST_RANGE_MISMATCH')
        key = tuple(extent)
        if key in seen:
            raise ValueError('NATIVE_BINDING_DUPLICATE_FRONTEND_RANGE')
        seen.add(key); node, path, function = by_range[key]
        if finding.get('fromMacroExpansion') is not False:
            raise ValueError('NATIVE_BINDING_FRONTEND_DOMAIN_MISMATCH')
        start = finding.get('rewriteBeginOffset'); stop = finding.get('rewriteEndOffset')
        if (type(start) is not int or type(stop) is not int or start != extent[0]
                or not extent[1] <= stop <= len(raw)
                or fragment.get('beginOffset') != start or fragment.get('endOffset') != stop):
            raise ValueError('NATIVE_BINDING_STATEMENT_RANGE_INVALID')
        if raw[start:stop].decode('utf-8') != finding.get('rawSourceText'):
            raise ValueError('NATIVE_BINDING_STATEMENT_BYTES_MISMATCH')
        suffix = raw[extent[1]:stop]
        if suffix and _TRIVIA.fullmatch(suffix) is None:
            raise ValueError('NATIVE_BINDING_STATEMENT_SUFFIX_INVALID')
        outputs = fragment.get('outputs'); inputs = fragment.get('inputs')
        if not isinstance(outputs, list) or not isinstance(inputs, list):
            raise ValueError('NATIVE_BINDING_OPERAND_LIST_REQUIRED')
        expressions = node.get('inner', [])
        if len(expressions) != len(outputs) + len(inputs):
            raise ValueError('NATIVE_BINDING_OPERAND_AST_ARITY_MISMATCH')
        operands = []; type_blockers = []
        for index, (operand, expression) in enumerate(zip(outputs + inputs, expressions)):
            if not isinstance(operand, dict) or operand.get('isOutput') is not (index < len(outputs)):
                raise ValueError('NATIVE_BINDING_OPERAND_ROLE_MISMATCH')
            span = byte_range(expression, len(raw))
            if not extent[0] <= span[0] < span[1] <= extent[1]:
                raise ValueError('NATIVE_BINDING_OPERAND_OUTSIDE_ASM')
            if raw[span[0]:span[1]].decode('utf-8') != operand.get('exprText'):
                raise ValueError('NATIVE_BINDING_OPERAND_BYTES_MISMATCH')
            if not isinstance(operand.get('constraint'), str) or not operand['constraint']:
                raise ValueError('NATIVE_BINDING_CONSTRAINT_EXPORT_REQUIRED')
            typ = operand.get('compilerType')
            if not isinstance(typ, dict) or not typ.get('schemaVersion'):
                raise ValueError('NATIVE_BINDING_COMPILER_TYPE_EXPORT_REQUIRED')
            type_error = None
            try:
                if typ['schemaVersion'] == 'riscv2x86.clang-operand-type.v2':
                    from .compiler_floating_type import parse
                    parse(typ)
                else:
                    from .compiler_operand_type import compiler_operand_type_from_dict
                    compiler_operand_type_from_dict(typ)
            except ValueError as exc:
                type_error = str(exc)
                type_blockers.append({'stage': 'compiler-type-contract',
                    'operandIndex': index, 'detail': type_error})
            operands.append({'operandIndex': index, 'compilerExport': deepcopy(operand),
                'expressionRange': span, 'expressionAst': deepcopy(expression),
                'declarationReferences': _references(expression),
                'compilerTypeContractComplete': type_error is None,
                'compilerTypeContractBlocker': type_error})
        text = fragment.get('rawAsmText')
        if not isinstance(text, str) or type(fragment.get('isVolatile')) is not bool:
            raise ValueError('NATIVE_BINDING_ASM_EXPORT_INCOMPLETE')
        clobbers = fragment.get('clobbers')
        if not isinstance(clobbers, list) or any(not isinstance(c, str) for c in clobbers):
            raise ValueError('NATIVE_BINDING_CLOBBER_EXPORT_REQUIRED')
        relation = None; blockers = list(type_blockers)
        try:
            relation = operand_relations([p['constraint'] for p in outputs], [p['constraint'] for p in inputs])
        except ValueError as exc:
            blockers.append({'stage': 'constraint-semantics', 'detail': str(exc)})
        if relation is not None and relation['semanticCommutativityProofRequired']:
            blockers.append({'stage': 'constraint-semantics', 'detail': 'OPERAND_PERMUTATION_PROOF_REQUIRED'})
        enclosing = None; ancestry = []
        for count in range(len(path)-1, -1, -1):
            parent_path = path[:count]; parent = node_at[tuple(parent_path)]
            ancestry.append({'astPath': parent_path, 'kind': parent.get('kind')})
            if enclosing is None and parent.get('kind') == 'CompoundStmt':
                enclosing = {'astPath': parent_path, 'ast': deepcopy(parent),
                    'physicalRange': None, 'sourceText': None, 'rangeBlocker': None}
                try:
                    span = byte_range(parent, len(raw))
                    enclosing['physicalRange'] = span
                    enclosing['sourceText'] = raw[span[0]:span[1]].decode('utf-8')
                except ValueError as exc:
                    enclosing['rangeBlocker'] = str(exc)
        blockers.extend([
            {'stage': 'source-semantics', 'detail': 'SOURCE_INSTRUCTION_AND_C_CONTEXT_PROOF_REQUIRED'},
            {'stage': 'materialization', 'detail': 'DERIVED_TARGET_EDIT_AUTHORIZATION_REQUIRED'},
            {'stage': 'program-call', 'detail': 'ENTRY_OBJECT_CALL_AND_LINK_CONTRACT_REQUIRED'},
            {'stage': 'evaluation', 'detail': 'L0_L3_EXECUTION_AND_INDEPENDENT_AUDIT_REQUIRED'}])
        # The entire fragment is retained, including unknown exported fields.
        # Diagnostic presumed source names do not authorize an original edit.
        body = {'analysisInputIdentity': analysis_input_identity, 'astPath': path,
            'functionAstPath': function, 'physicalAstRange': extent,
            'physicalStatementRange': [start, stop],
            'statementDigest': bytes_identity(raw[start:stop]),
            'frontendFragment': deepcopy(fragment), 'operands': operands,
            'typedOperandContractsComplete': not type_blockers,
            'ancestry': ancestry, 'enclosingCompound': enclosing,
            'constraintRelation': relation, 'blockers': blockers,
            'locationDomain': 'native-preprocessed-input',
            'derivedInputInstanceBindingComplete': True,
            'originalSourceInstanceBindingComplete': False,
            'editAuthorizationComplete': False, 'semanticApproval': False}
        records.append(dict(body, instanceBindingIdentity=identity(body)))
    if seen != set(by_range):
        raise ValueError('NATIVE_BINDING_ASM_COVERAGE_INCOMPLETE')
    records.sort(key=lambda r: r['physicalAstRange'])
    body = {'schemaVersion': SCHEMA, 'analysisInputIdentity': analysis_input_identity,
        'nativeInputDigest': bytes_identity(raw), 'records': records,
        'occurrenceCount': len(records), 'allEmittedAstAsmOccurrencesBound': True,
        'locationDomain': 'native-preprocessed-input',
        'originalSourceInstanceBindingComplete': False, 'macroArgumentGraphComplete': False,
        'editAuthorizationComplete': False, 'endToEndEligibilityAssessed': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, bindingInventoryIdentity=identity(body))


def call_contexts(ast, bindings, analysis_input_identity):
    """Export reachable AST declarations/effects, never infer pointer domains."""
    nodes = _nodes(ast); declarations = {}; definitions = {}; asm_owners = {}
    for node, path, function in nodes:
        if node.get('kind') == 'FunctionDecl' and node.get('id'):
            declarations[node['id']] = node
            if any(c.get('kind') == 'CompoundStmt' for c in node.get('inner', [])):
                definitions[tuple(path)] = (node, path)
    def family(ref):
        seen = set()
        while ref in declarations and declarations[ref].get('previousDecl'):
            if ref in seen:
                raise ValueError('NATIVE_CONTEXT_REDECLARATION_CYCLE')
            seen.add(ref); ref = declarations[ref]['previousDecl']
        return ref
    by_family = {}
    for key, (node, _) in definitions.items():
        root = family(node['id'])
        if root in by_family:
            raise ValueError('NATIVE_CONTEXT_MULTIPLE_DEFINITIONS')
        by_family[root] = key
    functions = []; grouped = {}
    for node, path, owner in nodes:
        if owner is not None:
            grouped.setdefault(tuple(owner), []).append((node, path))
    for key, (node, path) in definitions.items():
        related = grouped.get(key, [])
        calls = []
        for call, call_path in related:
            if call.get('kind') != 'CallExpr':
                continue
            children = call.get('inner', []); callee = children[0] if children else {}
            while callee.get('kind') in {'ImplicitCastExpr', 'ParenExpr'}:
                inner = callee.get('inner', [])
                if (len(inner) != 1 or (callee['kind'] == 'ImplicitCastExpr'
                        and callee.get('castKind') not in {'FunctionToPointerDecay', 'NoOp'})):
                    callee = {}; break
                callee = inner[0]
            ref = callee.get('referencedDecl', {}) if callee.get('kind') == 'DeclRefExpr' else {}
            direct = ref.get('kind') == 'FunctionDecl' and isinstance(ref.get('id'), str)
            target = by_family.get(family(ref['id'])) if direct else None
            calls.append({'astPath': call_path, 'targetDeclaration': deepcopy(ref) if direct else None,
                'targetFunctionAstPath': list(target) if target is not None else None,
                'argumentCount': max(0, len(children)-1),
                'resolution': 'emitted-definition' if target is not None else
                    'external-summary-required' if direct else 'indirect-target-proof-required'})
        rows = [r['instanceBindingIdentity'] for r in bindings['records'] if r['functionAstPath'] == path]
        body = {'astPath': path, 'declarationId': node['id'], 'name': node.get('name'),
            'compilerType': deepcopy(node.get('type', {})),
            'parameters': [deepcopy(c) for c in node.get('inner', []) if c.get('kind') == 'ParmVarDecl'],
            'attributes': [deepcopy(c) for c in node.get('inner', []) if c.get('kind', '').endswith('Attr')],
            'bodyAstPaths': [p for n, p in related if n.get('kind') == 'CompoundStmt' and len(p) == len(path)+1],
            'bodySyntaxKinds': sorted({n.get('kind', '') for n, _ in related}),
            'asmInstanceBindings': rows, 'calls': calls,
            'typedCallContractAvailable': False, 'effectClosureVerified': False, 'abiClosureVerified': False}
        functions.append(dict(body, functionContextIdentity=identity({**body, 'analysisInputIdentity': analysis_input_identity})))
        if rows:
            asm_owners[key] = functions[-1]['functionContextIdentity']
    by_path = {tuple(f['astPath']): f for f in functions}; roots = []
    for path, fid in asm_owners.items():
        active = set(); visited = set(); problems = []
        def visit(key):
            if key in active:
                problems.append({'reason': 'RECURSIVE_EFFECT_SUMMARY_REQUIRED', 'functionAstPath': list(key)}); return
            if key in visited:
                return
            visited.add(key); active.add(key)
            for call in by_path[key]['calls']:
                target = call['targetFunctionAstPath']
                if target is None:
                    problems.append({'reason': call['resolution'], 'callAstPath': call['astPath']})
                else:
                    visit(tuple(target))
            active.remove(key)
        visit(path)
        roots.append({'functionContextIdentity': fid,
            'reachableFunctionContexts': [by_path[p]['functionContextIdentity'] for p in sorted(visited)],
            'unresolvedCalls': problems, 'callTargetGraphResolved': not problems,
            'formalEvaluationEntrySelected': False, 'legalInputObjectDomainProvided': False,
            'effectClosureVerified': False, 'abiClosureVerified': False})
    globals_needed = [p for n, p, owner in nodes if
        (owner is None and n.get('kind') in {'CallExpr', 'GCCAsmStmt', 'FileScopeAsmDecl'}) or
        n.get('kind') in {'ConstructorAttr', 'DestructorAttr', 'IFuncAttr', 'AliasAttr'}]
    body = {'schemaVersion': 'riscv2x86.native-call-contexts.v1',
        'analysisInputIdentity': analysis_input_identity, 'functions': functions,
        'asmOwningFunctionContexts': roots, 'globalEffectCandidatePaths': globals_needed,
        'callEffectClosureVerified': False, 'buildLinkClosureVerified': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, contextInventoryIdentity=identity(body))
