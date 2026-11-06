"""Replayable native translation obligations, not execution or edit authority.

Re-derive v2 call evidence even for a validated Phase160/v1 bundle. Preserve all
reachable builtin arguments, external declaration contracts and object/control
syntax. Inspect captured link outputs by ELF metadata, never compiler filenames
or project-specific test names. Current files are not historical build evidence.
"""
from collections import Counter
from copy import deepcopy
from pathlib import Path

from .compiler_native_instance_binding import call_contexts, _nodes
from .project_build_records import identity
from .project_compile_context import digest
from .project_native_binding import read, validate_artifacts, build_basis
from . import project_native_input

SCHEMA = 'riscv2x86.native-development-basis.v1'


def link_output(action):
    args = action['arguments']; outputs = []; blockers = []; index = 1
    # This is a diagnostic projection, never a link-command rewriting grammar.
    while index < len(args):
        arg = args[index]
        if arg == '-o':
            if index+1 == len(args) or args[index+1].startswith('-'):
                blockers.append('LINK_OUTPUT_ARGUMENT_INVALID'); break
            outputs.append(args[index+1]); index += 2; continue
        if arg.startswith('-o') and len(arg) > 2:
            outputs.append(arg[2:])
        if arg.startswith('@'):
            blockers.append('LINK_RESPONSE_FILE_REQUIRES_CAPTURED_EXPANSION')
        index += 1
    if len(outputs) > 1:
        blockers.append('LINK_OUTPUT_AMBIGUOUS')
    if not outputs:
        blockers.append('LINK_EXPLICIT_OUTPUT_REQUIRED')
    path = None
    if len(outputs) == 1 and not blockers:
        candidate = Path(outputs[0])
        path = str((candidate if candidate.is_absolute() else Path(action['directory'])/candidate).absolute())
    return path, sorted(set(blockers))


def inspect_link(action):
    from .l3_trace_support import Elf
    path, blockers = link_output(action)
    artifact = None
    if path is not None:
        try:
            before = digest(path); elf = Elf(path)
            if digest(path) != before:
                raise ValueError('LINK_OUTPUT_CHANGED_DURING_INSPECTION')
            artifact = {'path': path, 'digest': before, 'elfType': elf.type,
                'elfMachine': elf.machine,
                'hasDefinedMainSymbol': 'main' in elf.symbols,
                'metadataOnly': True, 'historicalOutputBindingVerified': False}
        except (OSError, ValueError) as exc:
            blockers.append('LINK_OUTPUT_INSPECTION_REQUIRED:' + type(exc).__name__ + ':' + str(exc))
    return {'actionIdentity': action['actionIdentity'], 'directory': action['directory'],
        'arguments': deepcopy(action['arguments']), 'explicitOutputPath': path,
        'observedReturnCode': action.get('observedReturnCode'),
        'exitStatusObserved': action['exitStatusObserved'],
        'sharedFlagPresent': '-shared' in action['arguments'],
        'currentArtifact': artifact, 'blockers': blockers,
        'testEntryVerified': False, 'linkClosureVerified': False}


def acquire(bundle_path, records_path):
    bundle_path = Path(bundle_path).resolve(strict=True)
    before = digest(bundle_path); bundle = read(bundle_path)
    bindings, _ = validate_artifacts(bundle)
    basis = build_basis(bundle, records_path)
    receipt = read(bundle['nativeInputReceiptPath'])
    artifacts = project_native_input.validate_artifacts(receipt)
    ast = artifacts['canonicalAst']
    contexts = call_contexts(ast, bindings, receipt['analysisInputIdentity'])
    node_at = {tuple(path): node for node, path, _ in _nodes(ast)}
    declaration_at = {node['id']: node for node in node_at.values()
                      if node.get('kind') == 'FunctionDecl' and node.get('id')}
    reachable = {fid for root in contexts['asmOwningFunctionContexts']
                 for fid in root['reachableFunctionContexts']}
    functions = []; calls = []; syntax = []
    relevant = {'ArraySubscriptExpr', 'UnaryOperator', 'MemberExpr', 'BinaryOperator',
        'CompoundAssignOperator', 'ForStmt', 'WhileStmt', 'DoStmt', 'IfStmt',
        'SwitchStmt', 'ReturnStmt', 'GotoStmt', 'IndirectGotoStmt', 'CallExpr'}
    for function in contexts['functions']:
        if function['functionContextIdentity'] not in reachable:
            continue
        functions.append(deepcopy(function))
        path = function['astPath']
        for node, relative, _ in _nodes(node_at[tuple(path)]):
            if node.get('kind') in relevant:
                syntax.append({'functionContextIdentity': function['functionContextIdentity'],
                    'astPath': path+relative, 'kind': node['kind'],
                    'opcode': node.get('opcode'), 'type': deepcopy(node.get('type')),
                    'range': deepcopy(node.get('range')), 'nodeIdentity': identity(node)})
        for call in function['calls']:
            if call['resolution'] == 'emitted-definition':
                continue
            row = deepcopy(call)
            row['functionContextIdentity'] = function['functionContextIdentity']
            target = call['targetDeclaration']
            row['targetDeclarationAst'] = deepcopy(declaration_at.get(target['id'])) if target else None
            row['ancestorPath'] = [
                {'astPath': call['astPath'][:length],
                 'kind': node_at[tuple(call['astPath'][:length])].get('kind')}
                for length in range(len(call['astPath'])-1, len(path)-1, -1)]
            parent = node_at[tuple(call['astPath'][:-1])]
            row['immediateParentAst'] = deepcopy(parent)
            calls.append(row)
    links = [inspect_link(action) for action in basis['linkAndArchiveActions'] if action['kind'] == 'link']
    body = {'schemaVersion': SCHEMA, 'bindingBundlePath': str(bundle_path),
        'bindingBundleDigest': before, 'bindingBundleIdentity': bundle['bindingBundleIdentity'],
        'analysisInputIdentity': bundle['analysisInputIdentity'],
        'contextInventoryIdentity': contexts['contextInventoryIdentity'],
        'buildRecordsPath': basis['recordsPath'], 'buildRecordsDigest': basis['recordsDigest'],
        'selectedNativeCompileActionPresent': basis['selectedNativeCompileActionPresent'],
        'unresolvedBuildRecords': basis['unresolvedBuildRecords'],
        'occurrenceCount': bindings['occurrenceCount'],
        'instanceBindings': bindings['records'], 'reachableFunctions': functions,
        'entryCandidates': contexts['asmOwningFunctionContexts'], 'callObligations': calls,
        'globalEffectCandidatePaths': contexts['globalEffectCandidatePaths'],
        'callResolutionCounts': dict(Counter(call['resolution'] for call in calls)),
        'syntaxObligations': syntax, 'syntaxCounts': dict(Counter(row['kind'] for row in syntax)),
        'linkActions': links,
        'requiredWork': ['COMPOSITION_SEMANTICS_PROOF_REQUIRED',
            'ORIGINAL_MACRO_PROVENANCE_OR_EXPLICIT_DERIVED_TU_SCOPE_REQUIRED',
            'PROOF_BOUND_TARGET_EDIT_AUTHORIZATION_REQUIRED',
            'FORMAL_ENTRY_OBJECT_INPUT_OUTPUT_AND_LINK_CONTRACT_REQUIRED',
            'L0_L3_EXECUTION_AND_INDEPENDENT_AUDIT_REQUIRED'],
        'formalEvaluationEntrySelected': False, 'legalInputObjectDomainProvided': False,
        'compositionProofComplete': False, 'editAuthorizationComplete': False,
        'buildLinkClosureVerified': False, 'semanticApproval': False,
        'productionAcceptanceComplete': False}
    # Re-check frozen bundle/input and records after scanning mutable link files.
    validate_artifacts(bundle)
    if digest(bundle_path) != before or digest(basis['recordsPath']) != basis['recordsDigest']:
        raise ValueError('NATIVE_DEVELOPMENT_INPUT_CHANGED')
    return dict(body, developmentBasisIdentity=identity(body))


def replay(value):
    if (not isinstance(value, dict) or value.get('schemaVersion') != SCHEMA
            or value.get('developmentBasisIdentity') != identity({
                k: v for k, v in value.items() if k != 'developmentBasisIdentity'})):
        raise ValueError('NATIVE_DEVELOPMENT_BASIS_INVALID')
    from .l3_trace_support import require_json_match
    fresh = acquire(value['bindingBundlePath'], value['buildRecordsPath'])
    require_json_match(fresh, value, 'NATIVE_DEVELOPMENT_REPLAY_MISMATCH')
    return {'nativeDevelopmentBasisReplayComplete': True,
        'developmentBasisIdentity': value['developmentBasisIdentity'],
        'freshCompilerReplayPerformed': False, 'semanticApproval': False,
        'productionAcceptanceComplete': False}
