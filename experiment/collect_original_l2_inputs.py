#!/usr/bin/env python3
"""Copy checked-content analysis inputs; execute no compiler/test/validator.

This is an export for diagnosis, never a proof receipt or an admission path.
It works from an already completed preparation checkpoint.
"""
import argparse
import hashlib
import json
from pathlib import Path


def collect(root, output):
    root, output = Path(root).resolve(strict=True), Path(output).absolute()
    if output.exists():
        raise FileExistsError(output)
    references = []
    def read(path, digest=None, resolved=None):
        path = Path(path)
        actual_path = str(path.resolve(strict=True))
        raw = path.read_bytes()
        actual = 'sha256:' + hashlib.sha256(raw).hexdigest()
        if digest is not None and actual != digest:
            raise ValueError('ANALYSIS_INPUT_CHANGED:' + str(path))
        if resolved is not None and actual_path != resolved:
            raise ValueError('ANALYSIS_INPUT_RESOLUTION_CHANGED:' + str(path))
        value = json.loads(raw)
        references.append({'path': str(path), 'resolvedPath': actual_path, 'digest': actual})
        return value
    def ref(row):
        return read(row['path'], row['digest'], row['resolvedPath'])
    progress = read(root/'preparation/progress.json')
    run = ref(progress['checkpoints']['original'])
    prepared, translation = ref(run['input']), ref(run['translation'])
    if translation['input'] != run['input'] or prepared['bundle'] != run['bundle']:
        raise ValueError('ANALYSIS_ORIGINAL_RUN_JOIN_MISMATCH')
    bundle = ref(run['bundle'])
    receipt = read(bundle['nativeInputReceiptPath'], bundle['nativeInputReceiptDigest'])
    contexts = None
    gaps = []
    if bundle.get('contextsPath') and bundle.get('contextsDigest'):
        contexts = read(bundle['contextsPath'], bundle['contextsDigest'])
    else:
        gaps.append('NATIVE_CALL_CONTEXT_INVENTORY_NOT_SUPPLIED')
    applicability = None
    if 'applicability' in progress['checkpoints']:
        applicability = ref(progress['checkpoints']['applicability'])
    else:
        gaps.append('CHECKED_APPLICABILITY_CHECKPOINT_NOT_SUPPLIED')
    report = ref(translation['report'])
    backend = ref(translation['backendReport'])
    frontend = ref(prepared['frontendReport'])
    bindings = ref(prepared['bindings'])
    ast = read(receipt['canonicalAstPath'], receipt['canonicalAstDigest'])
    owners = []
    paths = sorted({tuple(r['functionAstPath']) for r in bindings['records']
                    if r.get('functionAstPath') is not None})
    owner_paths = set(paths)
    reachable_ids = set()
    if contexts is not None:
        for row in contexts['asmOwningFunctionContexts']:
            reachable_ids.update(row['reachableFunctionContexts'])
        if reachable_ids - {r['functionContextIdentity'] for r in contexts['functions']}:
            raise ValueError('ANALYSIS_REACHABLE_FUNCTION_CONTEXT_MISSING')
        paths = sorted(owner_paths | {tuple(row['astPath']) for row in contexts['functions']
            if row['functionContextIdentity'] in reachable_ids})
    reachable = []
    for path in paths:
        node = ast
        for index in path:
            if type(index) is not int or index < 0:
                raise ValueError('ANALYSIS_FUNCTION_AST_PATH_INVALID')
            node = node['inner'][index]
        if node.get('kind') != 'FunctionDecl':
            raise ValueError('ANALYSIS_FUNCTION_AST_OWNER_REQUIRED')
        exported = {'functionAstPath': list(path), 'functionAst': node}
        reachable.append(exported)
        if path in owner_paths:
            owners.append(exported)
    scope = 'content-bound-analysis-export-not-independent-proof-or-semantic-approval'
    files = {
        '01-l2-details.json': {'scope': scope, 'translatedReport': report,
            'backendReport': backend, 'frontendReport': frontend,
            'instanceBindings': bindings, 'callContexts': contexts,
            'recordedApplicability': applicability,
            'collectionGaps': gaps,
            'nativeInputConfiguration': {key: receipt.get('analysisInput', {}).get(key)
                for key in ('contextIdentity', 'sourceDigest', 'nativeInputDigest',
                            'inspectionArguments', 'dataModels')}},
        '02-owning-function-asts.json': {'scope': scope,
            'canonicalAstDigest': receipt['canonicalAstDigest'], 'owners': owners,
            'reachableFunctions': reachable,
            'reachabilityScope': 'compiler-declaration-graph-not-runtime-call-coverage'},
    }
    # Recheck resolution and bytes at the end; the copied JSON itself was
    # decoded from the content whose expected digest was checked above.
    for row in references:
        path = Path(row['path'])
        if (str(path.resolve(strict=True)) != row['resolvedPath']
                or 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() != row['digest']):
            raise ValueError('ANALYSIS_INPUT_CHANGED_DURING_EXPORT:' + str(path))
    output.mkdir(parents=True, exist_ok=False)
    manifest = []
    for name, value in files.items():
        raw = (json.dumps(value, indent=2, ensure_ascii=False)+'\n').encode('utf-8')
        (output/name).write_bytes(raw)
        manifest.append({'file': name, 'bytes': len(raw),
                         'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()})
    (output/'manifest.json').write_text(json.dumps({'scope': scope,
        'files': manifest, 'inputReferences': references}, indent=2)+'\n', encoding='utf-8')
    return [str(output/name) for name in (*files, 'manifest.json')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostic-root', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps({'paths': collect(args.diagnostic_root, args.output)}, ensure_ascii=False))
    except (ValueError, KeyError, IndexError, OSError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc)}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
