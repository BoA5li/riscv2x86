"""Entry instrumentation is execution evidence, never inline-instance/ABI proof.

Real deployment/ELF fixture, with an explicitly mocked compiler contract boundary.
Synthetic stops exercise replay rejection; optional ptrace exercises collection.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import platform

import pytest

from .test_native_captured_deployment import captured
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_entry_probe as probe
from riscv2x86_py.native_deployment_observation import observe
from riscv2x86_py.native_process_identity import Registers


@pytest.fixture
def entry(captured,monkeypatch):
    root,build,plan=captured
    deployed=d.execute(plan,root/'deployment',diagnostic_only=True)
    observed=observe(root/'deployment/result.json',root/'observation',diagnostic=True)
    report={'contractEvidenceIdentity':'fixture-compiler-contract-boundary',
        'programScope':{'localScopes':{'candidate':{'rootAstPaths':['root']}}},
        'graphs':{'candidate':{'functionDefinitions':[{'astPath':'root','linkerName':'value',
            'signature':{'type':{'qualType':'int (void)'},'parameters':[]},'functionEvidenceIdentity':'fixture-function'}]}}}
    folder=root/'contracts';folder.mkdir();file=folder/'result.json';file.write_text(json.dumps(report))
    (folder/'inputs.json').write_text(json.dumps({'observation':d.snapshot(root/'observation/result.json')}))
    monkeypatch.setattr(probe.contracts,'check',lambda path:report if Path(path).resolve()==file else None)
    return root,file,report,deployed,observed


def synthetic(entry):
    root,file,report,deployed,observed=entry
    out=root/'entry';out.mkdir();trace=out/'trace';trace.mkdir();(trace/'maps').mkdir();(trace/'blobs').mkdir()
    target=probe.targets(report,deployed)[0];image=Path(target['library']['path'])
    blob=trace/'blobs/image.elf';blob.write_bytes(image.read_bytes());st=image.stat()
    mapping={'start':0x10000,'end':0x20000,'permissions':'r-xp','offset':0,
             'device':[os.major(st.st_dev),os.minor(st.st_dev)],'inode':st.st_ino,'path':str(image)}
    obj={'kind':'backing-file','maps':[mapping],'digest':d.digest(blob),'blob':'blobs/image.elf',
         'capturedFileStat':[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]}
    epoch={'index':0,'stopOrdinal':3,'maps':[mapping],'objects':[obj]}
    path=trace/'maps/000000.json';path.write_text(json.dumps(epoch))
    address,byte,_,_=probe.locations(target,epoch,trace)[0]
    registers={n:0 for n,_ in Registers._fields_};registers['rip']=address+1
    hit={'target':target,'address':address,'originalByte':byte,'armedEpoch':0,'armedStopOrdinal':3,
         'mapping':mapping,'mappedImageDigest':obj['digest'],'capturedFileStat':obj['capturedFileStat'],
         'hitEpoch':0,'hitStopOrdinal':4,'registersAtBreakpoint':registers,'scope':'instrumented-function-entry-only'}
    (trace/'stdout.log').write_bytes(b'');(trace/'stderr.log').write_bytes(b'')
    profile=next(c for c in observed['commands'] if c['stage']=='natural')
    process={'backend':'linux-x86_64-ptrace-single-shot-function-entry.v1',
        'arguments':profile['arguments'],'environment':profile['environment'],'directory':str(out),
        'stdoutDigest':d.digest(trace/'stdout.log'),'stderrDigest':d.digest(trace/'stderr.log'),
        'epochs':[{'path':'maps/000000.json','digest':d.digest(path)}],
        'entryProbeEvidence':{'targets':[target],'observations':[hit],'unobservedTargetIdentities':[]},
        'failureReason':None,'stopCount':5,'returnCode':7}
    return trace,process


def save(trace,process):
    process=d.seal({k:v for k,v in process.items() if k!='processCaptureIdentity'},'processCaptureIdentity')
    file=trace/'capture.json';file.write_text(json.dumps(process));return file


def test_entry_replay_does_not_promote_to_fragment_or_abi_coverage(entry):
    trace,process=synthetic(entry);result=probe.derive(entry[1],save(trace,process))
    assert result['candidateFunctionEntriesObserved'] and result['observedFunctionCount']==1
    assert not result['candidateInstructionExecutionCoverageVerified']
    assert not result['nativeAbiClosureVerified'] and not result['legalObjectDomainVerified']
    assert not result['untracedRunCoverageVerified'] and not result['semanticApproval']


@pytest.mark.parametrize('change',['address','original-byte','pc','epoch','stop','duplicate','missing','blob','environment'])
def test_rehashed_entry_receipts_cannot_override_rederived_evidence(entry,change):
    trace,process=synthetic(entry);hit=process['entryProbeEvidence']['observations'][0]
    if change=='address':hit['address']+=1;hit['registersAtBreakpoint']['rip']+=1
    elif change=='original-byte':hit['originalByte']^=1
    elif change=='pc':hit['registersAtBreakpoint']['rip']+=1
    elif change=='epoch':hit['hitEpoch']=-1
    elif change=='stop':hit['hitStopOrdinal']=3
    elif change=='duplicate':process['entryProbeEvidence']['observations'].append(deepcopy(hit))
    elif change=='missing':process['entryProbeEvidence']['unobservedTargetIdentities']=['forged']
    elif change=='blob':(trace/'blobs/image.elf').write_bytes(b'changed')
    else:process['environment']={}
    with pytest.raises(ValueError):probe.derive(entry[1],save(trace,process))


def test_unvisited_target_remains_uncovered(entry):
    trace,process=synthetic(entry)
    process['entryProbeEvidence']['observations']=[]
    process['entryProbeEvidence']['unobservedTargetIdentities']=[process['entryProbeEvidence']['targets'][0]['entryTargetIdentity']]
    result=probe.derive(entry[1],save(trace,process));assert not result['candidateFunctionEntriesObserved']


def test_ambiguous_linker_definition_is_rejected(entry):
    _,_,report,deployed,_=entry
    deployed=deepcopy(deployed);deployed['definitions']*=2
    with pytest.raises(ValueError,match='ATTRIBUTION'):probe.targets(report,deployed)


def test_real_single_shot_entry_or_recorded_ptrace_unavailability(entry):
    if platform.system()!='Linux' or platform.machine()!='x86_64':pytest.skip('Linux x86-64 required')
    root,file,_,_,_=entry;out=root/'real-entry'
    try:result=probe.acquire(file,out,timeout=30)
    except ValueError as exc:
        if str(exc) in ('PROCESS_IDENTITY_TRACEME_UNAVAILABLE','PROCESS_IDENTITY_SYSCALL_INFO_UNAVAILABLE'):
            assert d.read(out/'trace/capture.json')['failureReason']
            pytest.skip('ptrace unavailable; no coverage claim')
        raise
    assert result['candidateFunctionEntriesObserved'] and result['tracedReturnCode']==7
    assert probe.check(out/'result.json')==result


def test_breakpoint_restores_exact_byte_and_rewinds_pc(entry):
    trace,process=synthetic(entry)
    target=process['entryProbeEvidence']['targets'][0]
    epoch=d.read(trace/'maps/000000.json')
    address,byte,_,_=probe.locations(target,epoch,trace)[0]
    shift=8*(address&7);word_address=address&~7
    original=(0x1122334455667788 & ~(255<<shift)) | byte<<shift
    memory={word_address:original};rewound=[]
    def ptrace(request,pid,address=0,data=0):
        if request==2:return memory[address]
        if request==5:memory[address]=data;return 0
        if request==13:rewound.append(data._obj.rip);return 0
        raise AssertionError(request)
    selected=probe.Probe([target]);selected.mapped(17,ptrace,epoch,trace,3)
    assert (memory[word_address]>>shift)&255==0xcc
    regs=Registers();regs.rip=address+1
    assert selected.trapped(17,ptrace,regs,0,4)
    assert memory[word_address]==original and rewound==[address]
    assert not selected.trapped(17,ptrace,regs,0,5)
    assert selected.evidence()['unobservedTargetIdentities']==[]


def test_writable_text_is_never_instrumented(entry):
    trace,process=synthetic(entry);epoch=d.read(trace/'maps/000000.json')
    epoch['maps'][0]['permissions']='rwxp';epoch['objects'][0]['maps']=epoch['maps']
    assert probe.locations(process['entryProbeEvidence']['targets'][0],epoch,trace)==[]
