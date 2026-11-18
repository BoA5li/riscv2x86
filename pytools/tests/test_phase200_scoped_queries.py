"""Scoped typed witnesses and ownership tests, not GMP execution approval."""
from copy import deepcopy
import os
from pathlib import Path
import pytest
from riscv2x86_py import native_original_applicability as app
from riscv2x86_py import project_native_binding as binding
from riscv2x86_py.verification_session import session, readonly_json
from riscv2x86_py.project_build_records import identity
from .test_original_source_applicability import tree, MODEL, probe_context
from .test_phase199_context_obligations import fixture


def move(node, delta):
    if 'range' in node:
        for endpoint in ('begin', 'end'):
            node['range'][endpoint]['offset'] += delta
    for child in node.get('inner', []): move(child, delta)


def test_queries_outside_asm_guard_are_collected_but_unrelated_functions_are_not():
    ast, records, raw = tree()
    query = deepcopy(ast['inner'][0]['inner'][0]['inner'][0]['inner'][0])
    move(query, len(raw)+1)
    ast['inner'][0]['inner'].append(query)
    ast['inner'].append({'kind':'FunctionDecl','id':'unrelated','inner':[
        {'kind':'CompoundStmt','inner':[deepcopy(query)]}]})
    _, _, queries = app.obligations(ast, records, raw+b';'+raw, MODEL)
    assert [q['astPath'] for q in queries] == [[0, 0, 0, 0], [0, 1]]
    groups, membership = app.query_groups(queries)
    assert len(groups) == 1 and len(set(membership)) == 1
    assert groups[0]['occurrenceAstPaths'] == [q['astPath'] for q in queries]


def test_reachable_helper_queries_follow_declarations_not_names():
    ast, records, raw = tree()
    query = deepcopy(ast['inner'][0]['inner'][0]['inner'][0]['inner'][0])
    query_path = [1, 0, 0]
    ast['inner'][0]['id'] = 'owner'
    ast['inner'][0]['inner'].append({'kind':'CompoundStmt','inner':[
        {'kind':'CallExpr','inner':[{'kind':'ImplicitCastExpr','castKind':'FunctionToPointerDecay','inner':[
            {'kind':'DeclRefExpr','referencedDecl':{'kind':'FunctionDecl','id':'helper','name':'shadowed'}}]}]}]})
    ast['inner'].append({'kind':'FunctionDecl','id':'helper','name':'shadowed','inner':[
        {'kind':'CompoundStmt','inner':[query]}]})
    ast['inner'].append({'kind':'FunctionDecl','id':'different','name':'shadowed','inner':[
        {'kind':'CompoundStmt','inner':[deepcopy(query)]}]})
    _, _, queries = app.obligations(ast, records, raw, MODEL)
    assert query_path in [q['astPath'] for q in queries]
    assert not any(q['astPath'][0] == 2 for q in queries)


def test_different_typed_contracts_or_probe_spelling_never_merge():
    ast, records, raw = tree()
    _, _, queries = app.obligations(ast, records, raw, MODEL)
    a = queries[0]; b = deepcopy(a); b['astPath'] = [9]
    b['contract']['argument']['type']['signed'] = False
    assert len(app.query_groups([a,b])[0]) == 2
    b = deepcopy(a); b['probe'] += '\n'
    assert len(app.query_groups([a,b])[0]) == 2


def test_real_gcc_group_executes_once_per_side_and_check_rebinds_every_occurrence(probe_context, monkeypatch):
    root, specfile, _, ast, _, raw = probe_context
    second = deepcopy(ast['inner'][0]['inner'][0]['inner'][0]['inner'][0]);move(second,len(raw)+1)
    ast['inner'][0]['inner'].append(second)
    old_context=app.context
    monkeypatch.setattr(app,'context',lambda path:(*old_context(path)[:3],raw+b';'+raw,MODEL))
    calls=[]; original=app.project.command
    def command(*args,**kwargs):calls.append(args[0]);return original(*args,**kwargs)
    monkeypatch.setattr(app.project,'command',command)
    result=app.acquire(specfile,root/'grouped')
    assert len(calls)==2 and len(result['queries'])==2 and len(result['queryWitnessGroups'])==1
    assert all(q['sourceAndTargetWitnessVerified'] for q in result['queries'])
    assert app.check(root/'grouped/result.json')==result
    assert len(calls)==2  # check rederives receipts; it is not a compiler rerun.
    forged=deepcopy(result); forged['queries'][1]['witnessGroupIdentity']='other-group'
    app.project.write(root/'grouped/result.json',app.d.seal({k:v for k,v in forged.items()
        if k != 'sourceApplicabilityIdentity'},'sourceApplicabilityIdentity'))
    with pytest.raises(ValueError,match='REDERIVATION_MISMATCH'):app.check(root/'grouped/result.json')
    app.project.write(root/'grouped/result.json',result)
    (root/'grouped/query-000000/query.c').write_text('int unrelated;\n')
    with pytest.raises(ValueError,match='PROBE_CHANGED'):app.check(root/'grouped/result.json')


def test_readonly_context_consumers_share_without_exposing_mutable_public_results():
    ast, records = fixture()
    artifacts={'canonicalAst':readonly_json(ast),'canonicalAstIdentity':identity(ast)}
    with session() as active:
        a=binding._contexts_checked(artifacts,records,'analysis',None,readonly=True)
        b=binding._contexts_checked(artifacts,records,'analysis',None,readonly=True)
        assert a is b
        with pytest.raises(TypeError):a['functions'].clear()
        owned=binding._contexts_checked(artifacts,records,'analysis',None)
        owned['functions'].clear()
        assert a['functions']
        assert 'pure.copy.native-call-contexts.v1' not in active.profile()['timings']
    with session(0):
        a=binding._contexts_checked(artifacts,records,'analysis',None,readonly=True)
        with pytest.raises(TypeError):a['functions'].clear()


def test_file_read_profile_observes_current_bytes_and_failures(tmp_path):
    from riscv2x86_py.project_compile_context import digest
    path=tmp_path/'data';path.write_bytes(b'one')
    with session() as active:
        first=digest(path);before=path.stat();path.write_bytes(b'two')
        os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
        assert digest(path)!=first
        path.unlink()
        with pytest.raises(FileNotFoundError):digest(path)
        row=active.profile()['fileReads']['topPathsBySeconds'][0]
        assert row['path']==str(path) and row['reads']==3 and row['bytes']==6 and row['failedReads']==1
    assert active.profile()['retainedCacheBytes']==0


def test_context_reuses_checked_run_but_rejects_a_changed_run_snapshot(tmp_path, monkeypatch):
    import json
    from riscv2x86_py import native_captured_deployment as d
    def save(name, value):
        path=tmp_path/name;path.write_text(json.dumps(value));return d.snapshot(path)
    inventory=d.seal({'records':[]},'bindingInventoryIdentity')
    bindings=save('bindings.json',inventory)
    prepared=save('prepared.json',{'bindings':bindings})
    receipt=save('receipt.json',{'analysisInput':{'dataModels':{'native':MODEL}}})
    bundle=save('bundle.json',{'nativeInputReceiptPath':receipt['path']})
    manifest=save('manifest.json',{'edits':[]})
    translation=save('translation.json',{'candidateManifest':manifest})
    run=save('run.json',{'input':prepared,'bundle':bundle,'translation':translation})
    monkeypatch.setattr(app.project,'check',lambda path:{'run':run})
    monkeypatch.setattr(app.route,'check_run',lambda path:pytest.fail('redundant original run traversal'))
    monkeypatch.setattr(app,'validated_input',lambda receipt:{'canonicalAst':{},'inputBytes':b''})
    assert app.context(tmp_path/'project.json')[2]==[]
    Path(run['path']).write_text('{}')
    with pytest.raises(ValueError,match='DEPLOYMENT_INPUT_CHANGED'):app.context(tmp_path/'project.json')
