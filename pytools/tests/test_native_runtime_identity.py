"""Real ELF images with synthetic syscall receipts; plus optional real ptrace.

Synthetic receipts test attribution/integrity boundaries, not capture authenticity.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import platform
import shutil

import pytest

from .test_native_captured_deployment import captured
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_runtime_identity as runtime
from riscv2x86_py.native_process_identity import capture, parse_maps, binding_aliases


@pytest.fixture
def mapping_receipt(captured):
    root, p, _ = captured
    trace=root/'mapping'; trace.mkdir(); (trace/'blobs').mkdir(); (trace/'maps').mkdir()
    image=p/'libprobe.so.1'; raw=image.read_bytes(); st=image.stat()
    blob=trace/'blobs/object.elf';blob.write_bytes(raw)
    row={'start':0x10000,'end':0x15000,'permissions':'r-xp','offset':0,
         'device':[os.major(st.st_dev),os.minor(st.st_dev)],'inode':st.st_ino,'path':str(image)}
    obj={'kind':'backing-file','maps':[row],'path':str(image),'resolvedPath':str(image.resolve()),
         'blob':'blobs/object.elf','digest':d.digest(blob),
         'capturedFileStat':[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]}
    epoch={'index':0,'stopOrdinal':2,'mappingMutation':{'kind':'exec'},'maps':[row],'objects':[obj]}
    ep=trace/'maps/000000.json';ep.write_text(json.dumps(epoch))
    log=f"41: binding file {image} [0] to {image} [0]: normal symbol `value'\n".encode()
    (trace/'stdout.log').write_bytes(b'');(trace/'stderr.log').write_bytes(log)
    process=d.seal({'schemaVersion':'riscv2x86.process-map-capture.v2',
        'backend':'linux-x86_64-ptrace-syscall-single-process.v1','processId':41,
        'syscallPhaseSource':'PTRACE_GET_SYSCALL_INFO',
        'arguments':['/fixture'],'directory':str(root),'environment':{},'timeoutSeconds':10,
        'returnCode':0,'failureReason':None,
        'logLimit':16*1024*1024,'imageLimit':64*1024*1024,'stopLimit':200000,'stopCount':3,
        'epochs':[{'path':'maps/000000.json','digest':d.digest(ep)}],
        'stderrWrites':[{'offset':0,'size':len(log),'epoch':0,'stopOrdinal':3,
            'bindingAliases':[{'label':str(image),'capturedFileStat':obj['capturedFileStat'],
                               'imageDigest':obj['digest']}]}],
        'stdoutDigest':d.digest(trace/'stdout.log'),'stderrDigest':d.digest(trace/'stderr.log'),
        'intervention':'ptrace','untracedRunEquivalenceVerified':False,
        'semanticApproval':False,'productionAcceptanceComplete':False},'processCaptureIdentity')
    return trace,process,epoch


def seal_process(value):return d.seal({k:v for k,v in value.items() if k!='processCaptureIdentity'},'processCaptureIdentity')


def test_event_joins_mapped_inode_and_exact_definition_without_semantic_promotion(mapping_receipt):
    root,process,_=mapping_receipt
    result=runtime.derive(root,process)
    assert result['mappedEndpointOccurrencesVerified']==2
    assert result['metadataCompatibleProviderEvents']==1
    assert not result['untracedRuntimeBindingClosureComplete']
    row=result['events'][0]
    assert not row['actualCallExecutionVerified'] and not row['behaviorContractVerified']
    assert not row['provider']['untracedIdentityVerified']


@pytest.mark.parametrize('change',['pid','namespace','symbol','version'])
def test_wrong_event_identity_or_symbol_version_cannot_be_promoted(mapping_receipt,change):
    root,process,_=mapping_receipt
    raw=(root/'stderr.log').read_bytes()
    if change=='pid': raw=raw.replace(b'41:',b'42:')
    if change=='namespace':raw=raw.replace(b'[0]',b'[2]')
    if change=='symbol':raw=raw.replace(b"`value'",b"`different'")
    if change=='version':raw=raw.rstrip()+b' [WRONG_VERSION]\n'
    (root/'stderr.log').write_bytes(raw)
    process['stderrDigest']=d.digest(root/'stderr.log');process['stderrWrites'][0]['size']=len(raw)
    result=runtime.derive(root,seal_process(process))
    if change in ('pid','namespace'):assert result['mappedEndpointOccurrencesVerified']==0
    else:assert result['metadataCompatibleProviderEvents']==0


@pytest.mark.parametrize('change',['blob','inode','epoch','writes','escape'])
def test_receipt_corruption_is_rejected(mapping_receipt,change):
    root,process,epoch=mapping_receipt
    if change=='blob':(root/'blobs/object.elf').write_bytes(b'changed')
    elif change=='inode':
        epoch['objects'][0]['capturedFileStat'][1]+=1
        (root/'maps/000000.json').write_text(json.dumps(epoch))
        process['epochs'][0]['digest']=d.digest(root/'maps/000000.json')
    elif change=='epoch':(root/'maps/000000.json').write_text('{}')
    elif change=='writes':process['stderrWrites'][0]['size']-=1
    else:process['epochs'][0]['path']='../outside.json'
    with pytest.raises(ValueError):runtime.derive(root,seal_process(process))


def test_partial_line_across_different_mappings_is_not_one_object_identity(mapping_receipt):
    root,process,epoch=mapping_receipt
    second=deepcopy(epoch);second['index']=1;second['stopOrdinal']=4
    second['mappingMutation']={'kind':'syscall','number':25,'arguments':[0x10000,0x5000,0,0,0,0],'returnValue':0x20000}
    second['maps'][0]['start']+=0x10000;second['maps'][0]['end']+=0x10000
    second['objects'][0]['maps']=deepcopy(second['maps'])
    path=root/'maps/000001.json';path.write_text(json.dumps(second))
    process['epochs'].append({'path':'maps/000001.json','digest':d.digest(path)})
    size=process['stderrWrites'][0]['size'];cut=size//2
    process['stderrWrites']=[{'offset':0,'size':cut,'epoch':0,'stopOrdinal':3,'bindingAliases':process['stderrWrites'][0]['bindingAliases']},
        {'offset':cut,'size':size-cut,'epoch':1,'stopOrdinal':5,'bindingAliases':process['stderrWrites'][0]['bindingAliases']}];process['stopCount']=5
    assert runtime.derive(root,seal_process(process))['mappedEndpointOccurrencesVerified']==0


def test_mapped_virtual_object_is_selected_by_elf_identity_not_a_label_whitelist(mapping_receipt):
    root,process,epoch=mapping_receipt
    if platform.system()!='Linux':pytest.skip('Linux virtual ELF required')
    vdso=next(r for r in parse_maps(Path('/proc/self/maps').read_text()) if r['path']=='[vdso]')
    try:
        with Path('/proc/self/mem').open('rb',buffering=0) as f:
            f.seek(vdso['start']);raw=f.read(vdso['end']-vdso['start'])
    except OSError:pytest.skip('own virtual image read unavailable')
    blob=root/'blobs/virtual.elf';blob.write_bytes(raw)
    from riscv2x86_py.native_elf_runtime import parse
    elf=parse(raw);symbol=next(s for s in elf['dynamicSymbols'] if s['defined'] and s['type']==2 and s['name'])
    version=symbol['version']['name'] if symbol['version'] else None
    log=(f"41: binding file {elf['soname']} [0] to {elf['soname']} [0]: normal symbol `{symbol['name']}'"+
         (f' [{version}]' if version else '')+'\n').encode()
    epoch['maps']=[vdso];epoch['objects']=[{'kind':'mapped-virtual-elf','maps':[vdso],
        'blob':'blobs/virtual.elf','digest':d.digest(blob)}]
    path=root/'maps/000000.json';path.write_text(json.dumps(epoch))
    process['epochs'][0]['digest']=d.digest(path)
    (root/'stderr.log').write_bytes(log);process['stderrDigest']=d.digest(root/'stderr.log')
    process['stderrWrites'][0]['size']=len(log)
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==2
    assert result['events'][0]['provider']['objectKind']=='mapped-virtual-elf'


def test_ptrace_collector_preserves_permission_failure_or_real_capture(tmp_path):
    program=shutil.which('true')
    if not program or platform.system()!='Linux' or platform.machine()!='x86_64':
        pytest.skip('Linux x86-64 native executable required')
    root=tmp_path/'trace'
    try:
        process=capture([program],str(tmp_path),dict(os.environ,LD_DEBUG='files,bindings,versions'),root,timeout=20)
    except ValueError as exc:
        if str(exc) in ('PROCESS_IDENTITY_TRACEME_UNAVAILABLE','PROCESS_IDENTITY_SYSCALL_INFO_UNAVAILABLE'):
            saved=d.read(root/'capture.json')
            assert saved['failureReason'] and not saved['semanticApproval']
            pytest.skip('ptrace unavailable; recorded failure, not a verified runtime identity')
        raise
    assert process['returnCode']==0 and process['epochs'] and process['stderrWrites']
    assert process['schemaVersion']=='riscv2x86.process-map-capture.v2'
    assert any(w['bindingAliases'] for w in process['stderrWrites'])
    result=runtime.derive(root,process)
    assert result['mappedEndpointOccurrencesVerified']>0
    assert not result['untracedRuntimeBindingClosureComplete']


def test_copy_destination_is_not_an_ordinary_export_or_initializer_provider(captured):
    root,p,plan=captured
    source=p/'copy.c'
    source.write_text('#include <stdio.h>\nextern int mutable_data;int main(void){return mutable_data+(stderr==0);}\n')
    library=p/'copy-lib.c';library.write_text('int mutable_data=3;\n')
    cc=plan['entry']['compiler']['path']
    import subprocess
    subprocess.run([cc,'-shared','-fPIC',str(library),'-o',str(p/'copy-lib.so')],check=True)
    subprocess.run([cc,'-fno-pic','-no-pie',str(source),str(p/'copy-lib.so'),'-o',str(p/'copy-program')],check=True)
    from riscv2x86_py.native_dynamic_obligations import describe
    metadata=describe(p/'copy-program')
    copies={r['relocation']['symbolIndex'] for r in metadata['relocationObligations'] if r['role']=='copy'}
    symbol=next(s for s in metadata['elf']['dynamicSymbols'] if s['entryIndex'] in copies and s['versionSource']=='requirement')
    event={'symbol':symbol['name'],'version':symbol['version']['name']}
    obj={'elf':metadata['elf'],'copySymbolIndices':copies}
    matches=runtime.definition_candidates(obj,event)
    assert len(matches)==1 and matches[0]['role']=='copy-destination-storage'
    assert matches[0]['specialContractRequired']
    obj['copySymbolIndices']=set()
    assert runtime.definition_candidates(obj,event)==[]


def test_ifunc_metadata_still_requires_resolver_contract(mapping_receipt):
    root,process,epoch=mapping_receipt
    obj=runtime.epoch_objects(root,epoch)[0]
    selected=next(s for s in obj['elf']['dynamicSymbols'] if s['name']=='value')
    selected['type']=10
    matches=runtime.definition_candidates(obj,{'symbol':'value','version':None})
    assert len(matches)==1 and matches[0]['specialContractRequired']


@pytest.mark.parametrize('change',['rehashed-result','capture-scope','write-epoch'])
def test_complete_report_check_rederives_and_rejects_corruption(mapping_receipt,monkeypatch,change):
    import shutil
    trace,process,_=mapping_receipt
    root=trace.parent/'complete-report';root.mkdir()
    shutil.copytree(trace,root/'trace')
    process['directory']=str(root);process=seal_process(process)
    (root/'trace/capture.json').write_text(json.dumps(process))
    image=process['epochs'][0]
    image_digest=d.read(root/'trace'/image['path'])['objects'][0]['digest']
    reference=root.parent/'reference.json';reference.write_text('{}')
    profile={'stage':'diagnostic','arguments':process['arguments'],'environment':process['environment'],
             'returnCode':0,'stdoutDigest':process['stdoutDigest']}
    observed={'observationIdentity':'fixture-observation','deploymentIdentity':'fixture-deployment',
              'deploymentPath':'fixture-deployment.json','commands':[profile],'loader':{'digest':image_digest}}
    monkeypatch.setattr(runtime,'check_observation',lambda _:observed)
    monkeypatch.setattr(d,'check_result',lambda _:{'artifacts':[
        {'stage':'derived-entry','digest':image_digest},{'stage':'derived-library','digest':image_digest}]})
    inputs=d.seal({'schemaVersion':'riscv2x86.runtime-identity-inputs.v1',
        'observation':d.snapshot(reference),'timeoutSeconds':10},'runtimeInputsIdentity')
    (root/'inputs.json').write_text(json.dumps(inputs))
    report=runtime._report(root,observed,process,profile)
    path=root/'result.json';path.write_text(json.dumps(report))
    assert runtime.check(path)==report
    assert report['requiredMappedImagesVerified']
    assert not report['events'][0]['loaderEventAuthenticityVerified']
    if change=='rehashed-result':
        report['semanticApproval']=True
        path.write_text(json.dumps(d.seal({k:v for k,v in report.items() if k!='runtimeIdentityReportIdentity'},'runtimeIdentityReportIdentity')))
    else:
        if change=='capture-scope':process['untracedRunEquivalenceVerified']=True
        else:process['stderrWrites'][0]['epoch']=7
        (root/'trace/capture.json').write_text(json.dumps(seal_process(process)))
    with pytest.raises(ValueError):runtime.check(path)


def write_epoch(root, process, epoch):
    if epoch['index'] and epoch.get('mappingMutation',{}).get('kind')!='syscall':
        epoch['mappingMutation']={'kind':'syscall','number':10,'arguments':[0,0,0,0,0,0],'returnValue':0}
    path=root/'maps'/('%06d.json' % epoch['index'])
    path.write_text(json.dumps(epoch))
    row={'path':str(path.relative_to(root)),'digest':d.digest(path)}
    if epoch['index']==len(process['epochs']):process['epochs'].append(row)
    else:process['epochs'][epoch['index']]=row


def test_alias_is_bound_by_stopped_file_identity_without_reopening_log_paths(mapping_receipt):
    root,process,epoch=mapping_receipt
    original=epoch['objects'][0]['path']
    alias='/does-not-exist-after-process-exit/symlink-name'
    log=(root/'stderr.log').read_bytes().replace(original.encode(),alias.encode())
    (root/'stderr.log').write_bytes(log)
    process['stderrDigest']=d.digest(root/'stderr.log');process['stderrWrites'][0]['size']=len(log)
    process['stderrWrites'][0]['bindingAliases'][0]['label']=alias
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==2
    assert result['diagnosticEndpointMappingComplete']
    assert result['endpointFailureReasonCounts']=={}
    assert not result['events'][0]['loaderEventAuthenticityVerified']


@pytest.mark.parametrize('change',['missing','inode','digest','duplicate','failure'])
def test_alias_spelling_or_current_realpath_does_not_replace_capture_evidence(mapping_receipt,change):
    root,process,_=mapping_receipt
    aliases=process['stderrWrites'][0]['bindingAliases']
    if change=='missing':aliases.clear()
    elif change=='inode':aliases[0]['capturedFileStat'][1]+=1
    elif change=='digest':aliases[0]['imageDigest']='sha256:'+'0'*64
    elif change=='duplicate':aliases.append(deepcopy(aliases[0]))
    else:aliases[0]={'label':aliases[0]['label'],'failureReason':'fixture inaccessible'}
    result=runtime.derive(root,seal_process(process))
    assert result['unverifiedEndpointOccurrenceCount']==2
    assert result['metadataFailureReasonCounts']=={'ENDPOINT_MAPPING_IDENTITY_REQUIRED':1}
    assert not result['diagnosticEndpointMappingComplete']
    assert result['endpointFailureReasonCounts']


def test_stopped_alias_collector_checks_actual_symlink_inode_and_cached_image(mapping_receipt,tmp_path):
    root,process,epoch=mapping_receipt
    obj=epoch['objects'][0];image=Path(obj['path'])
    fakeproc=tmp_path/'proc';processroot=fakeproc/'41/root';processroot.mkdir(parents=True)
    alias=processroot/'arbitrary-link';alias.symlink_to(image)
    raw=b"41: binding file /arbitrary-link [0] to /arbitrary-link [0]: normal symbol `value'\n"
    cache={tuple(obj['capturedFileStat']):{'digest':obj['digest']}}
    rows=binding_aliases(raw,41,cache,proc_root=fakeproc)
    assert rows==[{'label':'/arbitrary-link','capturedFileStat':obj['capturedFileStat'],'imageDigest':obj['digest']}]
    alias.unlink();alias.write_bytes(b'different inode')
    assert 'failureReason' in binding_aliases(raw,41,cache,proc_root=fakeproc)[0]
    assert binding_aliases(raw.rstrip(b'\n'),41,cache,proc_root=fakeproc)==[]
    assert binding_aliases(raw,42,cache,proc_root=fakeproc)==[]


def split_writes(process):
    size=process['stderrWrites'][0]['size'];aliases=process['stderrWrites'][0]['bindingAliases']
    process['stderrWrites']=[{'offset':0,'size':size//2,'epoch':0,'stopOrdinal':3,'bindingAliases':aliases},
        {'offset':size//2,'size':size-size//2,'epoch':1,'stopOrdinal':5,'bindingAliases':aliases}]
    process['stopCount']=5


def test_mprotect_snapshot_change_does_not_create_a_new_load_identity(mapping_receipt):
    root,process,epoch=mapping_receipt
    second=deepcopy(epoch);second.update(index=1,stopOrdinal=4)
    second['maps'][0]['permissions']='r--p'
    second['objects'][0]['maps']=deepcopy(second['maps'])
    write_epoch(root,process,second);split_writes(process)
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==2
    evidence=result['events'][0]['provider']['mappingEvidence']
    assert evidence[0]['mapSnapshotIdentities']!=evidence[1]['mapSnapshotIdentities']
    assert evidence[0]['mappingInstanceIdentities']==evidence[1]['mappingInstanceIdentities']


def test_unload_reload_same_inode_and_address_is_a_different_generation(mapping_receipt):
    root,process,epoch=mapping_receipt
    gap={'index':1,'stopOrdinal':4,'objects':[],'maps':[]};write_epoch(root,process,gap)
    again=deepcopy(epoch);again.update(index=2,stopOrdinal=5);write_epoch(root,process,again)
    split_writes(process);process['stderrWrites'][1].update(epoch=2,stopOrdinal=6);process['stopCount']=6
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==0
    assert result['endpointFailureReasonCounts']['MAPPING_INSTANCE_CHANGED_ACROSS_WRITES']==2


def test_multiple_load_anchors_are_not_merged_by_inode_or_image_digest(mapping_receipt):
    root,process,epoch=mapping_receipt
    extra=deepcopy(epoch['maps'][0]);extra['start']+=0x10000;extra['end']+=0x10000
    epoch['maps'].append(extra);epoch['objects'][0]['maps']=deepcopy(epoch['maps'])
    write_epoch(root,process,epoch)
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==0
    assert result['endpointFailureReasonCounts']=={'MAPPING_LOAD_ANCHOR_AMBIGUOUS_OR_MISSING':2}


def test_stale_epoch_and_legacy_capture_cannot_be_relabelled_as_new_evidence(mapping_receipt):
    root,process,epoch=mapping_receipt
    second=deepcopy(epoch);second.update(index=1,stopOrdinal=3)
    write_epoch(root,process,second)
    with pytest.raises(ValueError,match='STALE_WRITE_EPOCH'):runtime.derive(root,seal_process(process))
    process['schemaVersion']='riscv2x86.process-map-capture.v1'
    with pytest.raises(ValueError):runtime.derive(root,seal_process(process))


def test_unknown_binding_mode_preserves_mapping_but_not_metadata_approval(mapping_receipt):
    root,process,_=mapping_receipt
    raw=(root/'stderr.log').read_bytes().replace(b': normal symbol',b': unknown symbol')
    (root/'stderr.log').write_bytes(raw);process['stderrDigest']=d.digest(root/'stderr.log')
    process['stderrWrites'][0]['size']=len(raw)
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==2
    assert result['metadataCompatibleProviderEvents']==0
    assert result['metadataFailureReasonCounts']=={'BINDING_MODE_UNSUPPORTED':1}


def test_fixed_remap_same_bytes_and_address_is_not_hidden_by_identical_snapshots(mapping_receipt):
    root,process,epoch=mapping_receipt
    second=deepcopy(epoch);second.update(index=1,stopOrdinal=4,
        mappingMutation={'kind':'syscall','number':9,'arguments':[0x10000,0x5000,5,0x12,7,0],
                         'returnValue':0x10000})
    write_epoch(root,process,second);split_writes(process)
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==0
    assert result['endpointFailureReasonCounts']['MAPPING_INSTANCE_CHANGED_ACROSS_WRITES']==2


def test_selectively_omitting_a_second_mapping_cannot_hide_ambiguity(mapping_receipt):
    root,process,epoch=mapping_receipt
    extra=deepcopy(epoch['maps'][0]);extra['start']+=0x10000;extra['end']+=0x10000
    epoch['maps'].append(extra)
    write_epoch(root,process,epoch)
    with pytest.raises(ValueError,match='BACKING_MAP_GROUP_INCOMPLETE'):
        runtime.derive(root,seal_process(process))


def test_empty_binding_log_cannot_vacuously_complete_mapping_coverage(mapping_receipt):
    root,process,_=mapping_receipt
    (root/'stderr.log').write_bytes(b'');process['stderrDigest']=d.digest(root/'stderr.log')
    process['stderrWrites']=[]
    result=runtime.derive(root,seal_process(process))
    assert result['bindingEventCount']==0 and not result['diagnosticEndpointMappingComplete']


def test_legacy_runtime_report_requires_recapture_not_posthoc_realpath(tmp_path):
    path=tmp_path/'result.json'
    path.write_text(json.dumps(d.seal({'schemaVersion':'riscv2x86.diagnostic-map-bindings.v1'},
                                     'runtimeIdentityReportIdentity')))
    with pytest.raises(ValueError,match='STOPPED_ALIAS_EVIDENCE_REQUIRED_RECAPTURE'):runtime.check(path)


def test_mremap_destination_replacement_breaks_continuity_even_when_anchor_survives(mapping_receipt):
    root,process,epoch=mapping_receipt
    anonymous={'start':0x30000,'end':0x31000,'permissions':'rw-p','offset':0,
               'device':[0,0],'inode':0,'path':''}
    epoch['maps'].append(anonymous);write_epoch(root,process,epoch)
    second=deepcopy(epoch);second.update(index=1,stopOrdinal=4,
        mappingMutation={'kind':'syscall','number':25,
                         'arguments':[0x30000,0x1000,0x1000,3,0x14000,0],'returnValue':0x14000})
    second['maps'][0]['end']=0x14000
    second['maps'][1].update(start=0x14000,end=0x15000)
    second['objects'][0]['maps']=[deepcopy(second['maps'][0])]
    write_epoch(root,process,second);split_writes(process)
    result=runtime.derive(root,seal_process(process))
    assert result['mappedEndpointOccurrencesVerified']==0
    assert result['endpointFailureReasonCounts']['MAPPING_INSTANCE_CHANGED_ACROSS_WRITES']==2
