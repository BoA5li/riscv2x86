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
def objects(tmp_path):
    cc = shutil.which('gcc'); ar = shutil.which('ar')
    if not cc or not ar:pytest.skip('native GCC and ar required')
    sources = {
        'root':'extern long leaf(long); long entry(long x){return leaf(x)+1;}',
        'leaf':'extern long last(long); long leaf(long x){return last(x);}',
        'last':'long last(long x){return x*2;}',
        'weak':'__attribute__((weak)) long leaf(long x){return x;}',
        'other':'long leaf(long x){return x+3;}',
    }
    for name, source in sources.items():
        (tmp_path/(name+'.c')).write_text(source)
        subprocess.run([cc,'-c','-O2',name+'.c','-o',name+'.o'],cwd=tmp_path,check=True)
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
    monkeypatch.setattr(module,'checked_records',lambda p:{'actions':captured})
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
