"""Actual native GCC/ar objects, plus malformed/ambiguous evidence rejection."""
from copy import deepcopy
from pathlib import Path
import json
import shutil
import struct
import subprocess
import pytest

from riscv2x86_py.native_dependency_evidence import archive_members, elf_symbols, closure
from riscv2x86_py.native_dependency_inventory import analyze
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py.project_build_capture import _output, create, run, inventory
from riscv2x86_py.project_build_records import identity
from riscv2x86_py import native_backend_inventory as backends


@pytest.fixture
def objects(tmp_path, request):
    cc = shutil.which('gcc'); ar = shutil.which('ar')
    if not cc or not ar:pytest.skip('native GCC and ar required')
    mode = getattr(request, 'param', 'nonpic')
    flags = {'nonpic': ['-fno-pic', '-fno-pie'], 'default': [],
             'pic': ['-fPIC'], 'pie': ['-fPIE']}[mode]
    sources = {
        'root':'extern long leaf(long); long entry(long x){return leaf(x)+1;}',
        'leaf':'extern long last(long); long leaf(long x){return last(x);}',
        'last':'long last(long x){return x*2;}',
        'weak':'__attribute__((weak)) long leaf(long x){return x;}',
        'other':'long leaf(long x){return x+3;}',
    }
    for name, source in sources.items():
        (tmp_path/(name+'.c')).write_text(source)
        subprocess.run([cc,'-c','-O2',*flags,name+'.c','-o',name+'.o'],cwd=tmp_path,check=True)
    archive = tmp_path/'providers.a'
    subprocess.run([ar,'rcs',str(archive),'leaf.o','last.o'],cwd=tmp_path,check=True)
    return tmp_path, cc, ar, archive


def actions(directory, names):
    result = []
    for name in names:
        path = directory/(name+'.o')
        result.append({'kind':'assemble' if name=='last' else 'compile',
            'actionIdentity':name,'directory':str(directory),'arguments':['cc','-c',name+'.c','-o',name+'.o'],
            'observedOutput':{'path':str(path),'resolvedPath':str(path.resolve()),'digest':digest(path)},
            'exitStatusObserved':True,'observedReturnCode':0})
    return result


def test_actual_transitive_dependencies_and_assembly_binding(objects):
    directory,cc,ar,archive = objects
    result = analyze((directory/'root.o').read_bytes(),archive.read_bytes(),actions(directory,['leaf','last']))
    assert len(result['graph']['selectedObjects']) == 3
    assert not result['blockers']
    assert {m['provenanceStatus'] for m in result['members']} == {'content-matches-captured-output'}
    assert not result['graph']['actualLinkSelectionVerified']


def test_external_is_obligation_not_automatic_libc_approval(objects):
    directory,cc,ar,archive = objects
    subprocess.run([ar,'rcs',str(directory/'partial.a'),'leaf.o'],cwd=directory,check=True)
    result = analyze((directory/'root.o').read_bytes(),(directory/'partial.a').read_bytes(),actions(directory,['leaf']))
    assert any(b.get('symbol')=='last' and b['reason']=='external-contract-required' for b in result['blockers'])


def test_same_name_same_bytes_retains_build_variants(objects):
    directory,cc,ar,archive = objects
    variants = actions(directory,['leaf','last']); another = deepcopy(variants[0]);another['actionIdentity']='pic'
    another['arguments'].append('-fPIC');variants.append(another)
    result = analyze((directory/'root.o').read_bytes(),archive.read_bytes(),variants)
    assert any(b['reason']=='SELECTED_MEMBER_MULTIPLE_BUILD_IDENTITIES' for b in result['blockers'])


def test_changed_captured_object_rejected(objects):
    directory,cc,ar,archive = objects
    rows = actions(directory,['leaf','last']);(directory/'leaf.o').write_bytes(b'changed')
    with pytest.raises(ValueError,match='PROVIDER_CONTENT_CHANGED'):
        analyze((directory/'root.o').read_bytes(),archive.read_bytes(),rows)


def test_strong_provider_ambiguity_and_weak_provider_are_not_chosen(objects):
    directory,cc,ar,archive = objects
    for extra in ('other','weak'):
        path = directory/(extra+'.a')
        subprocess.run([ar,'rcs',str(path),'leaf.o',extra+'.o','last.o'],cwd=directory,check=True)
        result = analyze((directory/'root.o').read_bytes(),path.read_bytes(),actions(directory,['leaf',extra,'last']))
        assert any(b['reason']=='ambiguous-or-special-provider' for b in result['blockers'])


def test_weak_reference_requires_contract(objects):
    directory,cc,ar,archive = objects
    root = elf_symbols((directory/'root.o').read_bytes());root['undefined'][0]['binding']=2
    result = closure(root,[])
    assert any(b['reason']=='weak-or-special-reference-contract-required' for b in result['blockers'])


def test_common_definition_requires_contract(objects):
    directory,cc,ar,archive = objects
    root = elf_symbols((directory/'root.o').read_bytes());root['definitions'][0]['sectionIndex']=0xfff2
    assert any(b['reason']=='SPECIAL_DEFINITION_REQUIRES_LINK_CONTRACT' for b in closure(root,[])['blockers'])


def test_gnu_long_names_and_duplicate_members_are_not_collapsed(objects):
    directory,cc,ar,archive = objects
    name='a-very-long-member-name-with-spaces.o';shutil.copy(directory/'leaf.o',directory/name)
    path=directory/'long.a';subprocess.run([ar,'qc',str(path),name,name],cwd=directory,check=True)
    rows=archive_members(path.read_bytes())
    assert [m['name'] for m in rows] == [name,name]
    assert rows[0]['headerOffset'] != rows[1]['headerOffset']


@pytest.mark.parametrize('raw',[b'',b'!<thin>\n',b'!<arch>\nx',b'!<arch>\n'+b' '*60])
def test_malformed_archives_fail(raw):
    with pytest.raises(ValueError):archive_members(raw)


def ar_member(name,data):
    return (name.encode().ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'644'.ljust(8)
            +str(len(data)).encode().ljust(10)+b'`\n'+data+(b'\n' if len(data)&1 else b''))


def test_bsd_names_never_extract_paths(tmp_path):
    name=b'../../outside.o';raw=b'!<arch>\n'+ar_member('#1/'+str(len(name)),name+b'payload')
    assert archive_members(raw)[0]['name']=='../../outside.o'
    assert not (tmp_path/'outside.o').exists()


@pytest.mark.parametrize('edit', ['truncate','machine','symbols'])
def test_elf_corruption_and_architecture_mismatch(objects,edit):
    directory,cc,ar,archive=objects;raw=bytearray((directory/'root.o').read_bytes())
    if edit=='truncate':
        with pytest.raises(ValueError):elf_symbols(bytes(raw[:64]))
    elif edit=='symbols':
        raw[4]=1
        with pytest.raises(ValueError):elf_symbols(bytes(raw))
    else:
        struct.pack_into('<H',raw,18,243)
        result=analyze(bytes(raw),archive.read_bytes(),actions(directory,['leaf','last']))
        assert any(b['reason']=='MEMBER_ARCHITECTURE_OR_FLAGS_DIFFER' for b in result['blockers'])


def test_new_archive_capture_records_real_output_and_keeps_unknown_forms_unresolved(objects):
    directory,cc,ar,archive=objects
    config=directory/'capture/capture.json'
    value=create(config.parent,{'ar':ar})
    _,code=run(config,'archive',[value['wrappers']['ar']['path'],'rcs','captured.a','leaf.o','last.o'],cwd=directory)
    assert code==0
    result=inventory(config,stage='archive');a,=result['actions']
    assert a['observedOutput']['digest']==digest(directory/'captured.a')
    assert a['observedOutput']['elfHeader'] is None
    for option in ('t','x','d','rcT','--plugin','rcs@'):
        assert _output([ar,option,str(archive)],directory) is None
    assert _output([ar,'rcs','missing.a'],directory) is None


def test_missing_and_truncated_backend_are_explicit_no_execution(tmp_path):
    bad=tmp_path/'bad.json';bad.write_text('"-fno-pic", {"schemaVersion":"x"}')
    report=backends.inspect([tmp_path/'missing.json',bad])
    assert [r['status'] for r in report['manifests']]==['missing','malformed']
    assert not report['backendValidationPerformed'] and not report['productionAcceptanceComplete']
    assert backends.replay(report)['staticBackendInventoryReplayComplete']


def test_backend_base_missing_bound_file_and_forged_identity(tmp_path):
    p=tmp_path/'backend.json'
    p.write_text(json.dumps({'schemaVersion':'test','backendIdentity':'sha256:fake',
        'baseBackendPath':str(tmp_path/'base.json'),'baseBackendDigest':'sha256:none',
        'files':{str(tmp_path/'plugin.so'):'sha256:none'}}))
    result=backends.inspect([p])
    assert len(result['blockers'])==3
    changed=deepcopy(result);changed['productionAcceptanceComplete']=True
    changed['inventoryIdentity']=identity({k:v for k,v in changed.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):backends.replay(changed)


def test_backend_replay_detects_bound_file_changes(tmp_path):
    plugin=tmp_path/'plugin';plugin.write_bytes(b'one')
    p=tmp_path/'backend.json';body={'schemaVersion':'test','files':{str(plugin):digest(plugin)}}
    body['backendIdentity']=identity(body);p.write_text(json.dumps(body))
    result=backends.inspect([p]);assert not result['blockers']
    assert not result['programObservationCapabilityVerified']
    plugin.write_bytes(b'two')
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):backends.replay(result)


def test_checked_records_replays_real_capture_and_rejects_analysis_projection(objects):
    from riscv2x86_py.native_dependency_inventory import checked_records
    directory,cc,ar,archive=objects
    config=directory/'record-capture/capture.json';value=create(config.parent,{'cc':cc})
    _,code=run(config,'compile',[value['wrappers']['cc']['path'],'-c','root.c','-o','captured-root.o'],cwd=directory)
    assert code==0
    report=inventory(config,stage='compile');path=directory/'records.json';path.write_text(json.dumps(report))
    assert checked_records(path)['actions']==report['actions']
    path.write_text(json.dumps({'actions':report['actions']}))
    with pytest.raises(ValueError,match='ORIGINAL_BUILD_RECORDS_REQUIRED'):checked_records(path)


def test_dependency_acquire_and_replay_protocol_no_semantic_approval(objects,monkeypatch):
    """Synthetic cross-machine headers exercise receipt plumbing, not cross-ISA execution."""
    from riscv2x86_py import native_dependency_inventory as module
    directory,cc,ar,archive=objects
    def rv(raw):
        data=bytearray(raw);struct.pack_into('<H',data,18,243);return bytes(data)
    (directory/'source.o').write_bytes(rv((directory/'root.o').read_bytes()))
    (directory/'target.o').write_bytes((directory/'root.o').read_bytes())
    (directory/'candidate.i').write_text('protocol fixture, not an execution proof')
    for name in ('leaf','last'):
        (directory/(name+'.o')).write_bytes(rv((directory/(name+'.o')).read_bytes()))
    subprocess.run([ar,'rcs',str(archive),'leaf.o','last.o'],cwd=directory,check=True)
    captured=actions(directory,['leaf','last'])
    records=directory/'records.json';records.write_text('{}')
    config=directory/'legacy-capture.json';config.write_text('{}')
    monkeypatch.setattr(module,'checked_records',lambda p:{'actions':captured,'captureConfig':str(config)})
    body={'schemaVersion':'riscv2x86.native-integer-candidate.v1',
          'candidatePath':str(directory/'candidate.i'),
          'sourceObjectDigest':digest(directory/'source.o'),
          'targetObjectDigest':digest(directory/'target.o'),
          'artifactDigests':{name:digest(directory/name) for name in ('source.o','target.o','candidate.i')},
          'semanticApproval':False,'productionAcceptanceComplete':False}
    body['candidateIdentity']=identity(body)
    candidate=directory/'candidate.json';candidate.write_text(json.dumps(body))
    result=module.acquire(candidate,records,archive)
    assert result['inventoryComplete'] and not result['typedCallContractVerified']
    assert not result['productionAcceptanceComplete']
    assert module.replay(result)['dependencyInventoryReplayComplete']
    forged=deepcopy(result);forged['productionAcceptanceComplete']=True
    forged['inventoryIdentity']=identity({k:v for k,v in forged.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):module.replay(forged)
    (directory/'target.o').write_bytes(b'changed')
    with pytest.raises(ValueError,match='ARTIFACT_CHANGED'):module.replay(result)


def test_cli_failure_has_outer_failed_status_and_no_result(tmp_path):
    import sys
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_native_dependencies.py'
    output=tmp_path/'failed'
    result=subprocess.run([sys.executable,str(script),'inventory','--candidate',str(tmp_path/'missing'),
        '--records',str(tmp_path/'none'),'--archive',str(tmp_path/'none.a'),'--output',str(output)],capture_output=True)
    assert result.returncode==2
    state=json.loads((output/'run-status.json').read_text())
    assert state['status']=='failed' and not state['productionAcceptanceComplete']
    assert not (output/'result.json').exists()


def test_cli_backends_static_inventory_and_replay_preserve_missing(tmp_path):
    import sys
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_native_dependencies.py'
    paths=tmp_path/'paths.txt';paths.write_text(str(tmp_path/'missing.json')+'\n')
    for args in (
        ['backends','--paths-file',str(paths),'--output',str(tmp_path/'first')],
        ['replay-backends','--input',str(tmp_path/'first/result.json'),'--output',str(tmp_path/'replay')],
    ):
        subprocess.run([sys.executable,str(script),*args],check=True,capture_output=True)
    result=json.loads((tmp_path/'first/result.json').read_text())
    assert result['blockers'][0]['reason']=='BACKEND_MANIFEST_MISSING'
    assert not result['backendValidationPerformed']


@pytest.mark.parametrize('objects', ['default', 'pic', 'pie'], indirect=True)
def test_real_compiler_modes_preserve_unresolved_toolchain_symbols(objects):
    """Compiler defaults are inputs, not an assumption of zero external symbols."""
    directory,cc,ar,archive=objects
    result=analyze((directory/'root.o').read_bytes(), archive.read_bytes(), actions(directory,['leaf','last']))
    assert len(result['graph']['selectedObjects'])==3
    assert {edge['symbol'] for edge in result['graph']['edges']} >= {'leaf','last'}
    assert not any(b.get('symbol') in {'leaf','last'} for b in result['blockers'])
    nm=shutil.which('nm')
    if not nm:pytest.skip('native nm required for independent symbol inventory')
    for path in (directory/'root.o', directory/'leaf.o', directory/'last.o'):
        text=subprocess.run([nm,'-u',str(path)],check=True,capture_output=True,text=True).stdout
        extras={line.split()[-1] for line in text.splitlines() if line.split()}-{'leaf','last'}
        reported={b.get('symbol') for b in result['blockers']}
        assert extras <= reported
    assert not result['graph']['actualLinkSelectionVerified']


@pytest.mark.parametrize('symbol', ['_GLOBAL_OFFSET_TABLE_', 'other_toolchain_symbol'])
def test_symbol_names_never_grant_link_permission(symbol):
    # No relocation/use inference exists in this conservative policy. Even an
    # unreferenced declaration stays explicit until a real link contract exists.
    root={'definitions':[], 'undefined':[{'name':symbol,'binding':1}]}
    result=closure(root,[])
    assert result['blockers']==[{'reason':'external-contract-required','object':'root','symbol':symbol}]
    assert not result['actualLinkSelectionVerified']


def test_repeated_missing_base_has_one_observation_and_all_reference_owners(tmp_path):
    paths=[];base=tmp_path/'base.json'
    for name in ('one','two','three'):
        p=tmp_path/(name+'.json');body={'schemaVersion':'test','baseBackendPath':str(base),
            'baseBackendDigest':'sha256:expected','files':{}}
        body['backendIdentity']=identity(body);p.write_text(json.dumps(body));paths.append(p)
    result=backends.inspect(paths)
    assert [b['reason'] for b in result['blockers']]==['BACKEND_MANIFEST_MISSING']
    assert len(result['baseReferences'])==3
    assert len(result['diagnosticSummary']['paths'][0]['owners'])==3
    assert {e['owner'] for e in result['baseReferences']}==set(map(str,paths))
    assert {e['status'] for e in result['baseReferences']}=={'unavailable'}
    replay=backends.replay(result)
    assert replay['replayedBlockerCount']==1 and replay['status']=='blocked'
    assert replay['replayedInventoryIdentity']==result['inventoryIdentity']


def test_base_digest_mismatch_requires_actual_readable_content(tmp_path):
    base=tmp_path/'base.json';base.write_text('{"schemaVersion":"test"}')
    paths=[]
    for name in ('one','two'):
        p=tmp_path/(name+'.json');p.write_text(json.dumps({'schemaVersion':'test',
            'baseBackendPath':str(base),'baseBackendDigest':'sha256:wrong'}));paths.append(p)
    result=backends.inspect(paths)
    assert len(result['baseReferences'])==2
    assert all(b['reason']=='BASE_BACKEND_DIGEST_MISMATCH' for b in result['blockers'])
    assert all(b['actualDigest']==digest(base) for b in result['blockers'])


def test_backend_file_reasons_and_unique_paths_retain_owners(tmp_path):
    present=tmp_path/'present';present.write_bytes(b'changed')
    missing=tmp_path/'missing';directory=tmp_path/'dir';directory.mkdir()
    roots=[]
    for name in ('first','second'):
        p=tmp_path/(name+'.json');p.write_text(json.dumps({'schemaVersion':'test','files':{
            str(present):'sha256:old',str(missing):'sha256:old',str(directory):'sha256:old'}}));roots.append(p)
    result=backends.inspect(roots);summary=result['diagnosticSummary']
    assert summary['blockerCount']==6 and summary['affectedPathCount']==3
    assert summary['reasonCounts']=={'BACKEND_BOUND_FILE_DIGEST_MISMATCH':2,
        'BACKEND_BOUND_FILE_MISSING':2,'BACKEND_BOUND_FILE_NOT_REGULAR':2}
    assert all(len(row['owners'])==2 for row in summary['paths'])
    assert all('observation' in row for row in result['blockers'])


def test_backend_unreadable_is_not_missing_or_digest_mismatch(tmp_path,monkeypatch):
    import errno
    p=tmp_path/'backend.json';blocked=tmp_path/'plugin'
    p.write_text(json.dumps({'schemaVersion':'test','files':{str(blocked):'sha256:expected'}}))
    original=backends._observe
    def observe(name):
        if name==str(blocked):
            return {'status':'unreadable','errorType':'PermissionError','errno':errno.EACCES}
        return original(name)
    monkeypatch.setattr(backends,'_observe',observe)
    result=backends.inspect([p])
    assert result['blockers'][0]['reason']=='BACKEND_BOUND_FILE_UNREADABLE'
    assert result['blockers'][0]['actualDigest'] is None
    assert backends.replay(result)['replayedBlockerCount']==1


def test_newly_available_negative_observation_rejected_at_closing(tmp_path,monkeypatch):
    p=tmp_path/'missing.json';original=backends._observe;calls=0
    def observe(name):
        nonlocal calls
        calls+=1
        if calls==2:p.write_text('{"schemaVersion":"test"}')
        return original(name)
    monkeypatch.setattr(backends,'_observe',observe)
    with pytest.raises(ValueError,match='CLOSING_OBSERVATION_CHANGED'):backends.inspect([p])


def test_legacy_inventory_replay_retains_original_count_and_rejects_forgery(tmp_path):
    from riscv2x86_py.native_backend_inventory_v1 import inspect as old_inspect
    # Legacy duplicated missing/mismatch observations are preserved as history,
    # never rewritten or silently interpreted as an empty current inventory.
    paths=[]
    for name in ('one','two'):
        p=tmp_path/(name+'.json');p.write_text(json.dumps({'schemaVersion':'test',
            'baseBackendPath':str(tmp_path/'missing.json'),'baseBackendDigest':'sha256:old'}));paths.append(p)
    legacy=old_inspect(paths);assert len(legacy['blockers'])==2
    replay=backends.replay(legacy)
    assert replay['replayedBlockerCount']==2
    assert replay['replayedSchemaVersion'].endswith('.v1')
    assert not replay['programObservationCapabilityVerified']
    legacy['blockers']=[];legacy['inventoryIdentity']=identity({k:v for k,v in legacy.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):backends.replay(legacy)


def test_unknown_inventory_schema_cannot_replay(tmp_path):
    report={'schemaVersion':'unknown','roots':[],'blockers':[]};report['inventoryIdentity']=identity(report)
    with pytest.raises(ValueError,match='SCHEMA_UNSUPPORTED'):backends.replay(report)


def test_cli_initial_and_replay_stdout_counts_match(tmp_path):
    import sys
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_native_dependencies.py'
    paths=tmp_path/'paths.txt';paths.write_text(str(tmp_path/'absent.json')+'\n')
    first=subprocess.run([sys.executable,str(script),'backends','--paths-file',str(paths),
        '--output',str(tmp_path/'initial')],check=True,text=True,capture_output=True)
    replay=subprocess.run([sys.executable,str(script),'replay-backends','--input',str(tmp_path/'initial/result.json'),
        '--output',str(tmp_path/'again')],check=True,text=True,capture_output=True)
    left=json.loads(first.stdout);right=json.loads(replay.stdout)
    assert left['blockerCount']==right['blockerCount']==1
    assert left['affectedPathCount']==right['affectedPathCount']==1
    assert left['status']==right['status']=='blocked'
    assert right['replayComplete'] and not right['inventoryComplete']
    assert not right['productionAcceptanceComplete']
    state=json.loads((tmp_path/'again/run-status.json').read_text())
    assert state['status']=='complete' and state['inventoryStatus']=='blocked'


def test_summary_cannot_silently_default_absent_replay_count():
    import importlib.util
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_native_dependencies.py'
    spec=importlib.util.spec_from_file_location('dependency_cli',script)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with pytest.raises(ValueError,match='BLOCKER_COUNT_REQUIRED'):
        module.summarize({'staticBackendInventoryReplayComplete':True})


def test_nonregular_manifest_and_empty_roots_are_explicit(tmp_path):
    report=backends.inspect([tmp_path])
    assert report['blockers'][0]['reason']=='BACKEND_MANIFEST_NOT_REGULAR'
    assert backends.inspect([])['blockers'][0]['reason']=='BACKEND_ROOTS_EMPTY'


def test_unreadable_base_is_not_reported_as_digest_mismatch(tmp_path,monkeypatch):
    base=tmp_path/'base.json';root=tmp_path/'root.json'
    root.write_text(json.dumps({'schemaVersion':'test','baseBackendPath':str(base),
        'baseBackendDigest':'sha256:expected'}))
    original=backends._observe
    def observe(name):
        if name==str(base):return {'status':'unreadable','errorType':'PermissionError','errno':13}
        return original(name)
    monkeypatch.setattr(backends,'_observe',observe)
    report=backends.inspect([root])
    assert [b['reason'] for b in report['blockers']]==['BACKEND_MANIFEST_UNREADABLE']
    assert report['baseReferences'][0]['status']=='unavailable'


def test_readable_base_has_all_matched_references_without_approval(tmp_path):
    base=tmp_path/'base.json';base.write_text('{"schemaVersion":"test"}')
    root=tmp_path/'root.json';root.write_text(json.dumps({'schemaVersion':'test',
        'baseBackendPath':str(base),'baseBackendDigest':digest(base)}))
    report=backends.inspect([root])
    assert not report['blockers']
    assert report['baseReferences'][0]['status']=='digest-matched'
    assert backends.replay(report)['replayedBlockerCount']==0
    assert not report['backendValidationPerformed'] and not report['productionAcceptanceComplete']
