"""Diagnostic export is content-bound and never an approval receipt."""
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest

SCRIPT = Path(__file__).resolve().parents[2]/'experiment/collect_original_l2_inputs.py'
spec = importlib.util.spec_from_file_location('original_l2_input_collection', SCRIPT)
collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)


@pytest.fixture
def inputs(tmp_path):
    def save(name, value):
        path=tmp_path/name;path.write_text(json.dumps(value));return snapshot(path)
    def snapshot(path):
        return {'path':str(path),'resolvedPath':str(path.resolve()),
                'digest':'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()}
    ast=save('ast.json', {'kind':'TranslationUnitDecl','inner':[
        {'kind':'FunctionDecl','id':'canonical-owner','inner':[{'kind':'CompoundStmt'}]}]})
    receipt=save('receipt.json', {'canonicalAstPath':ast['path'],'canonicalAstDigest':ast['digest']})
    bundle=save('bundle.json', {'nativeInputReceiptPath':receipt['path'],'nativeInputReceiptDigest':receipt['digest']})
    bindings=save('bindings.json', {'records':[{'functionAstPath':[0]}]})
    report=save('report.json', {'functions':[], 'findings':[]})
    prepared=save('prepared.json', {'bundle':bundle,'frontendReport':report,'bindings':bindings})
    translation=save('translation.json', {'input':prepared,'report':report,'backendReport':report})
    run=save('run.json', {'input':prepared,'translation':translation,'bundle':bundle})
    root=tmp_path/'diagnostic';(root/'preparation').mkdir(parents=True)
    (root/'preparation/progress.json').write_text(json.dumps({'checkpoints':{'original':run}}))
    return root,tmp_path/'collection',ast


def test_collects_exact_function_owner_and_manifest_without_execution(inputs):
    root,output,_=inputs
    paths=collector.collect(root,output)
    assert len(paths)==3
    value=json.loads((output/'02-owning-function-asts.json').read_text())
    assert value['owners'][0]['functionAstPath']==[0]
    assert value['owners'][0]['functionAst']['id']=='canonical-owner'
    assert 'not-independent-proof' in value['scope']
    details=json.loads((output/'01-l2-details.json').read_text())
    assert details['callContexts'] is None
    assert details['collectionGaps'] == ['NATIVE_CALL_CONTEXT_INVENTORY_NOT_SUPPLIED',
        'CHECKED_APPLICABILITY_CHECKPOINT_NOT_SUPPLIED']
    manifest=json.loads((output/'manifest.json').read_text())
    for row in manifest['files']:
        raw=(output/row['file']).read_bytes()
        assert 'sha256:'+hashlib.sha256(raw).hexdigest()==row['digest']
    with pytest.raises(FileExistsError):collector.collect(root,output)


def test_changed_ast_is_rejected_before_output_creation(inputs):
    root,output,ast=inputs
    Path(ast['path']).write_text('{"kind":"different"}')
    with pytest.raises(ValueError,match='INPUT_CHANGED'):collector.collect(root,output)
    assert not output.exists()


def test_unresolved_original_checkpoint_is_not_silently_omitted(inputs):
    root,output,_=inputs
    (root/'preparation/progress.json').write_text('{"checkpoints":{}}')
    with pytest.raises(KeyError):collector.collect(root,output)
    assert not output.exists()


def test_resolved_file_identity_is_checked_even_when_content_matches(inputs):
    root,output,_=inputs
    path=root/'preparation/progress.json';value=json.loads(path.read_text())
    value['checkpoints']['original']['resolvedPath']='/different-original-run.json'
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='RESOLUTION_CHANGED'):collector.collect(root,output)


def test_reachable_helper_bodies_are_exported_by_context_identity(inputs):
    root, output, ast_ref = inputs
    ast_path = Path(ast_ref['path']); ast = json.loads(ast_path.read_text())
    ast['inner'].append({'kind':'FunctionDecl','id':'helper','inner':[{'kind':'CompoundStmt'}]})
    ast_path.write_text(json.dumps(ast))
    def update(path, change):
        path = Path(path); value=json.loads(path.read_text()); change(value)
        path.write_text(json.dumps(value))
        return {'path':str(path),'resolvedPath':str(path.resolve()),
                'digest':'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()}
    folder = ast_path.parent
    receipt = update(folder/'receipt.json', lambda v: v.update(canonicalAstDigest=
        'sha256:'+hashlib.sha256(ast_path.read_bytes()).hexdigest()))
    context = folder/'contexts.json'
    context.write_text(json.dumps({'functions':[
        {'astPath':[0],'functionContextIdentity':'owner'},
        {'astPath':[1],'functionContextIdentity':'helper'}],
        'asmOwningFunctionContexts':[{'reachableFunctionContexts':['owner','helper']}]}))
    bundle = update(folder/'bundle.json', lambda v: v.update(nativeInputReceiptDigest=receipt['digest'],
        contextsPath=str(context),contextsDigest='sha256:'+hashlib.sha256(context.read_bytes()).hexdigest()))
    prepared = update(folder/'prepared.json', lambda v: v.update(bundle=bundle))
    translation = update(folder/'translation.json', lambda v: v.update(input=prepared))
    run = update(folder/'run.json', lambda v: v.update(input=prepared,translation=translation,bundle=bundle))
    update(root/'preparation/progress.json', lambda v: v['checkpoints'].update(original=run))
    collector.collect(root,output)
    value=json.loads((output/'02-owning-function-asts.json').read_text())
    assert len(value['owners'])==1
    assert [r['functionAstPath'] for r in value['reachableFunctions']]==[[0],[1]]
