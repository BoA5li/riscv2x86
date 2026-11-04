"""Compiler AST call-target inventory. Resolution is NOT effect or ABI approval.

Separate all primary-file definitions (including static helpers) from harness
entries. Header/external bodies, function pointers and recursive components are
explicit unresolved prerequisites. No caller is authorized to execute by this
module. Inspect again under the actual build command before making such claims.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess

from .compiler_value_flow import identity

SCHEMA = 'riscv2x86.compiler-call-inventory.v1'
CLOSURE = 'riscv2x86.static-call-target-closure.v1'


def walk(node):
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get('inner', []):
        yield from walk(child)


def extent(node):
    result = []
    for part in ('begin', 'end'):
        item = node.get('range', {}).get(part, {})
        # Macro spellings and expansions need a separate compiler provenance
        # relation; never treat one of their offsets as an ordinary call site.
        if 'expansionLoc' in item or 'spellingLoc' in item:
            return None
        offset = item.get('offset')
        if type(offset) is not int or offset < 0:
            return None
        token = item.get('tokLen', 0)
        if type(token) is not int or token < 0:
            return None
        result.append(offset + (token if part == 'end' else 0))
    return result if result[0] < result[1] else None


def symbol(node):
    name = node.get('mangledName') or node.get('name')
    typ = node.get('type', {}).get('qualType')
    if not isinstance(name, str) or not name or not isinstance(typ, str) or not typ:
        raise ValueError('CALL_INVENTORY_DECLARATION_INCOMPLETE')
    return {'name': name, 'type': typ}


def direct_callee(node):
    # This is an identity-preserving AST unwrap, not a points-to analysis.
    while node.get('kind') in {'ParenExpr', 'ImplicitCastExpr'}:
        children = node.get('inner', [])
        if len(children) != 1 or (node['kind'] == 'ImplicitCastExpr' and
                node.get('castKind') not in {'FunctionToPointerDecay', 'NoOp'}):
            return None
        node = children[0]
    reference = node.get('referencedDecl', {})
    if node.get('kind') == 'DeclRefExpr' and reference.get('kind') == 'FunctionDecl':
        return reference
    return None


def derive(root, *, source_path, source_digest):
    source_path = str(Path(source_path).resolve())
    if not isinstance(root, dict) or root.get('kind') != 'TranslationUnitDecl':
        raise ValueError('CALL_INVENTORY_TRANSLATION_UNIT_REQUIRED')
    if (not isinstance(source_digest, str) or len(source_digest) != 71 or
            not source_digest.startswith('sha256:') or
            any(c not in '0123456789abcdef' for c in source_digest[7:])):
        raise ValueError('CALL_INVENTORY_SOURCE_DIGEST_INVALID')
    declarations = {n['id']: symbol(n) for n in walk(root)
                    if n.get('kind') == 'FunctionDecl' and n.get('id')}
    definitions = []
    current_file = source_path
    global_initializers = []
    for node in root.get('inner', []):
        loc = node.get('loc', {})
        if loc.get('file'):
            current_file = str(Path(loc['file']).resolve())
        primary = current_file == source_path and not loc.get('includedFrom')
        if not primary:
            continue
        if node.get('kind') == 'VarDecl' and any(n.get('kind') in
                {'CallExpr', 'GCCAsmStmt', 'StmtExpr'} for n in walk(node)):
            global_initializers.append({'name': node.get('name', ''), 'sourceRange': extent(node)})
        if node.get('kind') != 'FunctionDecl':
            continue
        bodies = [n for n in node.get('inner', []) if n.get('kind') == 'CompoundStmt']
        if not bodies:
            continue
        if len(bodies) != 1:
            raise ValueError('CALL_INVENTORY_FUNCTION_BODY_AMBIGUOUS')
        body = {'symbol': symbol(node), 'sourceRange': extent(node),
                'linkage': 'internal' if node.get('storageClass') == 'static' else 'external',
                'attributes': sorted(n['kind'] for n in node.get('inner', [])
                                     if n.get('kind', '').endswith('Attr')),
                'calls': [], 'effectSyntax': sorted({n['kind'] for n in walk(bodies[0])
                    if n.get('kind') in {'GCCAsmStmt', 'CallExpr', 'IfStmt', 'ForStmt',
                        'WhileStmt', 'DoStmt', 'SwitchStmt', 'GotoStmt', 'IndirectGotoStmt',
                        'ArraySubscriptExpr', 'MemberExpr', 'StmtExpr', 'VAArgExpr'}})}
        for index, call in enumerate(n for n in walk(bodies[0]) if n.get('kind') == 'CallExpr'):
            children = call.get('inner', [])
            target = direct_callee(children[0]) if children else None
            target_symbol = (declarations.get(target.get('id'), symbol(target))
                             if target else None)
            body['calls'].append({'ordinal': index, 'sourceRange': extent(call),
                'target': target_symbol, 'argumentCount': max(0, len(children) - 1),
                'resolution': 'direct-declaration' if target else 'indirect-or-unresolved'})
        body['functionIdentity'] = identity({'sourceDigest': source_digest,
            'symbol': body['symbol'], 'sourceRange': body['sourceRange']})
        definitions.append(body)
    definitions.sort(key=lambda n: (n['symbol']['name'], n['symbol']['type'], n['functionIdentity']))
    if len({identity(n['symbol']) for n in definitions}) != len(definitions):
        raise ValueError('CALL_INVENTORY_DEFINITION_AMBIGUOUS')
    body = {'schemaVersion': SCHEMA, 'sourcePath': source_path,
        'sourceDigest': source_digest, 'functions': definitions,
        'globalInitializerCandidates': global_initializers,
        'scope': 'primary-file-compiler-ast-static-call-targets-only',
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, inventoryIdentity=identity(body))


def closure(inventory, root_identity):
    if (inventory.get('schemaVersion') != SCHEMA or
            inventory.get('inventoryIdentity') != identity({k: v for k, v in inventory.items()
                                                           if k != 'inventoryIdentity'}) or
            inventory.get('semanticApproval') is not False or
            inventory.get('productionAcceptanceComplete') is not False):
        raise ValueError('CALL_INVENTORY_IDENTITY_INVALID')
    functions = inventory['functions']
    matches = [f for f in functions if f['functionIdentity'] == root_identity]
    if len(matches) != 1:
        raise ValueError('CALL_INVENTORY_ROOT_IDENTITY_REQUIRED')
    by_symbol = {identity(f['symbol']): f for f in functions}
    if len(by_symbol) != len(functions):
        raise ValueError('CALL_INVENTORY_DEFINITION_AMBIGUOUS')
    visited, active, reasons, edges = set(), set(), [], []

    def visit(fn):
        fid = fn['functionIdentity']
        if fid in active:
            reasons.append({'reasonCode': 'M6_RECURSIVE_SUMMARY_REQUIRED', 'functionIdentity': fid})
            return
        if fid in visited:
            return
        visited.add(fid)
        active.add(fid)
        if fn['sourceRange'] is None:
            reasons.append({'reasonCode': 'M6_FUNCTION_SOURCE_RANGE_REQUIRED', 'functionIdentity': fid})
        for attr in fn['attributes']:
            if attr in {'ConstructorAttr', 'DestructorAttr', 'AliasAttr', 'IFuncAttr'}:
                reasons.append({'reasonCode': 'M6_LINK_OR_STARTUP_EFFECT_REQUIRED',
                                'functionIdentity': fid, 'attribute': attr})
        for call in fn['calls']:
            target = by_symbol.get(identity(call['target'])) if call['target'] else None
            edge = {'caller': fid, 'callSite': call,
                    'callee': target['functionIdentity'] if target else None}
            edges.append(edge)
            code = ('M6_INDIRECT_CALL_TARGET_PROOF_REQUIRED' if call['target'] is None else
                    'M6_EXTERNAL_OR_HEADER_CALLEE_SUMMARY_REQUIRED' if target is None else
                    'M6_CALL_SITE_SOURCE_RANGE_REQUIRED' if call['sourceRange'] is None else None)
            if code:
                reasons.append({'reasonCode': code, 'functionIdentity': fid,
                                'callOrdinal': call['ordinal']})
            if target:
                visit(target)
        active.remove(fid)

    visit(matches[0])
    # Constructors run even when there is no explicit edge from the root.
    if inventory['globalInitializerCandidates'] or any(
            set(f['attributes']) & {'ConstructorAttr', 'DestructorAttr'} for f in functions):
        reasons.append({'reasonCode': 'M6_TRANSLATION_UNIT_STARTUP_CLOSURE_REQUIRED'})
    body = {'schemaVersion': CLOSURE, 'inventoryIdentity': inventory['inventoryIdentity'],
        'rootFunctionIdentity': root_identity, 'reachableFunctions': sorted(visited),
        'notStaticallyReachedFunctions': sorted(f['functionIdentity'] for f in functions
                                               if f['functionIdentity'] not in visited),
        'calls': edges, 'unresolvedPrerequisites': reasons,
        'staticCallTargetsResolved': not reasons,
        'effectClosureStatus': 'not_proved', 'abiClosureStatus': 'not_proved',
        'executionStatus': 'not_run', 'independentAuditStatus': 'not_run',
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, closureIdentity=identity(body))


def inspect_source(source, *, clang, target='riscv64', compile_args=(), timeout=60):
    if target not in {'riscv64', 'x86_64'}:
        raise ValueError('CALL_INVENTORY_TARGET_UNSUPPORTED')
    path = Path(source).resolve()
    before = path.read_bytes()
    compiler = Path(shutil.which(clang) or clang).resolve()
    compiler_digest = 'sha256:' + sha256(compiler.read_bytes()).hexdigest()
    command = [str(compiler), '--target=' + target + '-linux-gnu', '-std=gnu11',
               *compile_args, '-fsyntax-only', '-Xclang', '-ast-dump=json', str(path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise ValueError('CALL_INVENTORY_COMPILER_FAILED: ' + result.stderr[-6000:])
    if path.read_bytes() != before or 'sha256:' + sha256(compiler.read_bytes()).hexdigest() != compiler_digest:
        raise ValueError('CALL_INVENTORY_INPUT_CHANGED')
    inventory = derive(json.loads(result.stdout), source_path=path,
                       source_digest='sha256:' + sha256(before).hexdigest())
    return {'inventory': inventory, 'compilerCommand': command,
        'compilerDigest': compiler_digest, 'astDigest': identity(json.loads(result.stdout)),
        'dependencyClosureVerified': False, 'semanticApproval': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--target', choices=['riscv64', 'x86_64'], default='riscv64')
    parser.add_argument('--compile-arg', action='append', default=[])
    parser.add_argument('--root-function', required=True)
    parser.add_argument('--bind-dependencies', action='store_true',
                        help='bind compiler-emitted header dependencies; not effect, ABI or link approval')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        inspector = inspect_source
        if args.bind_dependencies:
            from .compiler_call_dependencies import acquire
            inspector = acquire
        result = inspector(args.source, clang=args.clang, target=args.target, compile_args=args.compile_arg)
        matches = [f for f in result['inventory']['functions']
                   if f['symbol']['name'] == args.root_function]
        if len(matches) != 1:
            raise ValueError('CALL_INVENTORY_ROOT_NAME_AMBIGUOUS_OR_MISSING')
        result['closure'] = closure(result['inventory'], matches[0]['functionIdentity'])
        destination = Path(args.output)
        with destination.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
        print(json.dumps({'output': str(destination),
            'functionCount': len(result['inventory']['functions']),
            'staticCallTargetsResolved': result['closure']['staticCallTargetsResolved'],
            'semanticApproval': False, 'productionAcceptanceComplete': False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'inconclusive', 'detail': str(exc), 'semanticApproval': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
