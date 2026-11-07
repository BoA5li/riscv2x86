"""Real GNU ar/ranlib, captured blobs and source selection, including negatives."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest

from riscv2x86_py.project_build_capture import create, run, inventory
from riscv2x86_py.project_archive_provenance import grammar, select, verify, blob
from riscv2x86_py.native_dependency_inventory import analyze
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py.project_build_records import identity


@pytest.fixture
def capture(tmp_path):
    tools={name:shutil.which(name) for name in ('gcc','ar','ranlib')}
    if not all(tools.values()):pytest.skip('native GCC and GNU ar/ranlib required')
    for name in ('ar','ranlib'):
        if not subprocess.check_output([tools[name],'--version'],text=True).startswith('GNU '):
            pytest.skip('GNU binutils required')
    value=create(tmp_path/'capture',{'cc':tools['gcc'],'ar':tools['ar'],'ranlib':tools['ranlib']},
                 archive_tools={'ar':'gnu-ar','ranlib':'gnu-ranlib'})
    config=tmp_path/'capture/capture.json'
    (tmp_path/'leaf.c').write_text('long leaf(long x){return x+1;}')
    (tmp_path/'root.c').write_text('extern long leaf(long); long entry(long x){return leaf(x);}')
    def call(tool,*args):
        _,code=run(config,'build',[value['wrappers'][tool]['path'],*args],cwd=tmp_path)
        assert code==0
    for name in ('root','leaf'):
        call('cc','-c','-fno-pic','-fno-pie',name+'.c','-o',name+'.o')
    # Two real output paths containing the same object bytes, as in the host case.
    call('cc','-c','-fno-pic','-fno-pie','leaf.c','-o','other.o')
    assert (tmp_path/'leaf.o').read_bytes()==(tmp_path/'other.o').read_bytes()
    return tmp_path,value,config,call


def report(capture):
    p,value,config,call=capture
    call('ar','cq','providers.a','leaf.o');call('ranlib','providers.a')
    doc=inventory(config,stage='build');assert doc['importComplete']
    selection=select(doc['actions'],value['directory'],p/'providers.a',digest(p/'providers.a'))
    return doc,selection


def test_real_append_index_selects_actual_input_not_same_bytes(capture):
    p,value,config,call=capture;doc,selection=report(capture)
    assert selection['complete'] and len(selection['operationIdentities'])==2
    legacy=analyze((p/'root.o').read_bytes(),(p/'providers.a').read_bytes(),doc['actions'])
    assert any(b['reason']=='SELECTED_MEMBER_MULTIPLE_BUILD_IDENTITIES' for b in legacy['blockers'])
    result=analyze((p/'root.o').read_bytes(),(p/'providers.a').read_bytes(),doc['actions'],archive_selection=selection)
    assert not result['blockers']
    assert result['members'][0]['selectedBuildActions'][0]['path']==str(p/'leaf.o')
    assert len(result['members'][0]['contentMatchingActions'])==2
    assert not result['graph']['actualLinkSelectionVerified']
    # Independent capture replay reconstructs the identical relation from blobs.
    assert select(inventory(config,stage='build')['actions'],value['directory'],p/'providers.a',digest(p/'providers.a'))==selection


def test_duplicate_member_names_preserve_order_and_input_paths(capture):
    p,value,config,call=capture
    (p/'a').mkdir();(p/'b').mkdir()
    (p/'a/same.o').write_bytes(b'first');(p/'b/same.o').write_bytes(b'second')
    call('ar','cq','dups.a','a/same.o');call('ar','q','dups.a','b/same.o');call('ranlib','dups.a')
    result=select(inventory(config,stage='build')['actions'],value['directory'],p/'dups.a',digest(p/'dups.a'))
    assert result['complete']
    assert [r['path'] for r in result['members']]==[str(p/'a/same.o'),str(p/'b/same.o')]


def test_existing_archive_without_origin_is_chain_gap(capture):
    p,value,config,call=capture
    subprocess.run([value['tools']['ar']['path'],'cq','old.a','leaf.o'],cwd=p,check=True)
    call('ranlib','old.a')
    result=select(inventory(config,stage='build')['actions'],value['directory'],p/'old.a',digest(p/'old.a'))
    assert not result['complete'] and result['reason']=='ARCHIVE_OPERATION_CHAIN_GAP'


def test_blob_tamper_rejects_even_if_input_file_survives(capture):
    p,value,config,call=capture;doc,selection=report(capture)
    evidence=next(a['archiveOperationEvidence'] for a in doc['actions'] if a['kind']=='archive')
    sha=evidence['after']['archive']['digest']
    (Path(value['directory'])/'archive-blobs'/sha[7:]).write_bytes(b'tampered')
    assert not inventory(config,stage='build')['importComplete']


def test_missing_blob_and_final_archive_change_rejected(capture):
    p,value,config,call=capture;doc,selection=report(capture)
    assert select(doc['actions'],value['directory'],p/'providers.a','sha256:changed')['reason']=='ARCHIVE_FINAL_DIGEST_MISMATCH'
    sha=selection['members'][0]['digest']
    (Path(value['directory'])/'archive-blobs'/sha[7:]).unlink()
    with pytest.raises(FileNotFoundError):select(doc['actions'],value['directory'],p/'providers.a',digest(p/'providers.a'))


@pytest.mark.parametrize('profile,args',[
 ('gnu-ar',['rcs','x.a','x.o']),('gnu-ar',['qT','x.a','x.o']),
 ('gnu-ar',['cq','x.a','@inputs']),('gnu-ar',['cq','x.a','-x']),
 ('gnu-ar',['qDU','x.a','x.o']),('gnu-ranlib',['-t','x.a']),
 ('gnu-ranlib',['a.a','b.a']),('gnu-ar',['-M'])])
def test_unsupported_forms_never_gain_append_semantics(profile,args):
    with pytest.raises(ValueError):grammar(profile,args,'/tmp')


def test_unsupported_real_operation_remains_diagnostic(capture):
    p,value,config,call=capture
    call('ar','rcs','unsupported.a','leaf.o')
    doc=inventory(config,stage='build');assert doc['importComplete']
    result=select(doc['actions'],value['directory'],p/'unsupported.a',digest(p/'unsupported.a'))
    assert not result['complete'] and result['reason']=='ARCHIVE_OPERATION_UNSUPPORTED'


def test_changed_input_or_transition_cannot_be_rehashed_into_success(capture):
    p,value,config,call=capture;doc,selection=report(capture)
    action=next(a for a in doc['actions'] if a['kind']=='archive');e=deepcopy(action['archiveOperationEvidence'])
    e['after']['inputs'][0]['resolvedPath']='/different'
    result=verify(value['directory'],e['before'],e['after'],action['arguments'],action['directory'],0)
    assert result['reason']=='ARCHIVE_INPUT_CHANGED'
    e=deepcopy(action['archiveOperationEvidence']);e['before']['inputs']=[]
    with pytest.raises(ValueError,match='INPUT_PATH_MISMATCH'):
        verify(value['directory'],e['before'],e['after'],action['arguments'],action['directory'],0)


def test_reordered_operations_or_missing_tail_not_selected(capture):
    p,value,config,call=capture;doc,selection=report(capture)
    actions=deepcopy(doc['actions'])
    ops=[a for a in actions if 'archiveOperationEvidence' in a]
    first=min(ops,key=lambda a:a['archiveOperationEvidence']['startedMonotonicNs'])
    first['archiveOperationEvidence']['finishedMonotonicNs']=10**30
    assert select(actions,value['directory'],p/'providers.a',digest(p/'providers.a'))['reason']=='ARCHIVE_OPERATION_INTERVAL_INVALID'


def test_failed_tool_does_not_gain_output_proof(capture):
    p,value,config,call=capture
    _,code=run(config,'build',[value['wrappers']['ar']['path'],'q','absent-dir/out.a','leaf.o'],cwd=p)
    assert code!=0
    doc=inventory(config,stage='build')
    assert doc['observedFailureCount']==1
    result=select(doc['actions'],value['directory'],p/'absent-dir/out.a','sha256:none')
    assert result['reason']=='ARCHIVE_TOOL_FAILED'


def test_long_names_and_multiple_inputs(capture):
    p,value,config,call=capture
    name='very-long-member-name-over-sixteen-bytes.o'
    (p/name).write_bytes((p/'leaf.o').read_bytes())
    call('ar','cq','long.a',name,'leaf.o');call('ranlib','-D','long.a')
    result=select(inventory(config,stage='build')['actions'],value['directory'],p/'long.a',digest(p/'long.a'))
    assert result['complete'] and len(result['members'])==2


def test_parallel_cooperating_append_writers_have_serial_chain(capture):
    from concurrent.futures import ThreadPoolExecutor
    p,value,config,call=capture
    commands=[['q','parallel.a',name] for name in ('leaf.o','other.o')]
    with ThreadPoolExecutor(2) as pool:
        results=list(pool.map(lambda args:run(config,'build',[value['wrappers']['ar']['path'],*args],cwd=p),commands))
    assert all(code==0 for token,code in results)
    result=select(inventory(config,stage='build')['actions'],value['directory'],p/'parallel.a',digest(p/'parallel.a'))
    assert result['complete'] and len(result['members'])==2


def test_archive_chain_receipt_and_cli_replay_without_semantic_acceptance(capture):
    import sys
    from riscv2x86_py.project_archive_provenance import acquire_chain,replay_chain
    p,value,config,call=capture;doc,selection=report(capture)
    records=p/'records.json';records.write_text(json.dumps(doc))
    receipt=acquire_chain(records,p/'providers.a')
    assert receipt['archiveActionSelectionVerified'] and not receipt['semanticApproval']
    assert replay_chain(receipt)['replayedBlockerCount']==0
    changed=deepcopy(receipt);changed['productionAcceptanceComplete']=True
    changed['inventoryIdentity']=identity({k:v for k,v in changed.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):replay_chain(changed)
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_native_dependencies.py'
    first=subprocess.run([sys.executable,str(script),'archive-chain','--records',str(records),
        '--archive',str(p/'providers.a'),'--output',str(p/'chain')],capture_output=True,text=True,check=True)
    again=subprocess.run([sys.executable,str(script),'replay-archive','--input',str(p/'chain/result.json'),
        '--output',str(p/'replayed')],capture_output=True,text=True,check=True)
    assert json.loads(first.stdout)['blockerCount']==json.loads(again.stdout)['blockerCount']==0
    assert json.loads(again.stdout)['replayComplete']


def test_legacy_capture_is_not_retroactively_granted_archive_provenance(tmp_path):
    from riscv2x86_py.project_archive_provenance import acquire_chain,replay_chain
    ar=shutil.which('ar')
    if not ar:pytest.skip('ar required')
    value=create(tmp_path/'capture',{'ar':ar});config=tmp_path/'capture/capture.json'
    (tmp_path/'x.o').write_bytes(b'data')
    _,code=run(config,'build',[value['wrappers']['ar']['path'],'cq','old.a','x.o'],cwd=tmp_path)
    assert code==0
    records=tmp_path/'records.json';records.write_text(json.dumps(inventory(config,stage='build')))
    result=acquire_chain(records,tmp_path/'old.a')
    assert result['blockers']==[{'reason':'ARCHIVE_CAPTURE_PROFILE_REQUIRED'}]
    assert replay_chain(result)['replayedBlockerCount']==1


def test_producer_after_archive_cannot_establish_build_origin(capture):
    p,value,config,call=capture;doc,selection=report(capture)
    modified=deepcopy(doc['actions'])
    for action in modified:
        if (action.get('observedOutput') or {}).get('path')==str(p/'leaf.o'):
            action['observedInvocationInterval']={'start':10**29,'finish':10**30}
    result=analyze((p/'root.o').read_bytes(),(p/'providers.a').read_bytes(),modified,archive_selection=selection)
    assert any(b['reason']=='SELECTED_MEMBER_SOURCE_UNBOUND' for b in result['blockers'])


def test_v2_dependency_receipt_protocol_retains_wrong_architecture_blocker(capture):
    # Deliberately altered source ELF header tests the receipt gate only; this is
    # not RISC-V compilation or a translation correctness test.
    import struct
    from riscv2x86_py.native_dependency_inventory import acquire,replay
    p,value,config,call=capture;doc,selection=report(capture)
    root=bytearray((p/'root.o').read_bytes());struct.pack_into('<H',root,18,243)
    (p/'source.o').write_bytes(root);(p/'target.o').write_bytes((p/'root.o').read_bytes())
    (p/'candidate.i').write_text('protocol only')
    records=p/'records.json';records.write_text(json.dumps(doc))
    body={'schemaVersion':'riscv2x86.native-integer-candidate.v1',
        'candidatePath':str(p/'candidate.i'),'sourceObjectDigest':digest(p/'source.o'),
        'targetObjectDigest':digest(p/'target.o'),
        'artifactDigests':{n:digest(p/n) for n in ('source.o','target.o','candidate.i')},
        'semanticApproval':False,'productionAcceptanceComplete':False}
    body['candidateIdentity']=identity(body);candidate=p/'candidate.json';candidate.write_text(json.dumps(body))
    result=acquire(candidate,records,p/'providers.a')
    assert result['schemaVersion'].endswith('.v2')
    assert result['archiveActionSelectionVerified'] and result['archiveMemberBuildSelectionVerified']
    assert any(b['reason']=='MEMBER_ARCHITECTURE_OR_FLAGS_DIFFER' for b in result['blockers'])
    assert not result['semanticApproval'] and not result['targetDependencyCompatibilityVerified']
    assert replay(result)['replayedBlockerCount']==len(result['blockers'])


def test_archive_parser_implementation_is_bound(capture,monkeypatch):
    from riscv2x86_py import project_build_capture as module
    p,value,config,call=capture
    original=module.digest
    parser=value['archiveCapture']['parserPath']
    monkeypatch.setattr(module,'digest',lambda path:'sha256:changed' if str(path)==parser else original(path))
    with pytest.raises(ValueError,match='ARCHIVE_CAPTURE_IMPLEMENTATION_CHANGED'):module.load(config)


def test_new_invocations_cannot_mix_monotonic_clock_domains(capture,monkeypatch):
    from riscv2x86_py import project_archive_provenance as module
    p,value,config,call=capture
    monkeypatch.setattr(module,'clock_domain',lambda:'another-boot')
    with pytest.raises(ValueError,match='CLOCK_DOMAIN_CHANGED'):
        with module.Session(value,'cc',[]):pass
