"""Single-shot candidate function entry observations, not fragment/ABI proof.

Probe locations come only from checked candidate declaration roots and existing
link-time definition attribution. Uses the existing bounded syscall tracer.
A probe hit records pre-instruction registers and mapped image identity. No
untraced-run, whole-function ABI, pointer legality or inline-instance claim.
"""
import ctypes
import json
import os
from pathlib import Path
import struct

from . import native_captured_deployment as d
from . import native_contract_evidence as contracts
from .native_process_identity import capture
from .native_external_providers import checked
from .native_dependency_evidence import bytes_digest
from .project_build_records import identity

SCHEMA='riscv2x86.candidate-function-entry.v1'
MASK=(1<<64)-1


def location_relation(hit,address,byte,obj,mapping,*,armed=False):
    """Compare the code position, not unrelated boundaries of its VMA.

    The arming snapshot itself remains exact. Later snapshots may split or
    merge VMAs only while the address-to-file-offset relation, executable
    private permission and sealed backing identity remain unchanged.
    """
    expected=hit['mapping']
    checks={'address':hit['address']==address,
        'original-byte':hit['originalByte']==byte and byte!=0xcc,
        'image-digest':hit['mappedImageDigest']==obj['digest'],
        'file-stat':hit['capturedFileStat']==obj['capturedFileStat'],
        'mapping-identity':all(expected[k]==mapping[k] for k in ('device','inode','path','permissions')),
        'file-offset':expected['offset']+address-expected['start']==mapping['offset']+address-mapping['start'],
        'executable-private':mapping['permissions']=='r-xp' and mapping['start']<=address<mapping['end']}
    if armed:checks['arming-mapping']=expected==mapping
    failed=[name for name,ok in checks.items() if not ok]
    if failed:raise ValueError('ENTRY_PROBE_CODE_LOCATION_MISMATCH:'+','.join(failed))


def transition_preserves_entry(address,epoch):
    """Reject even same-image replacement or temporary permission changes.

    Bounded Linux x86-64 4KiB-page backend. mmap/mprotect/munmap lengths are
    rounded up, and mremap checks both old and new ranges. Unknown transitions
    never establish continuity. This is traced mapping continuity, not proof
    against arbitrary in-process memory writes or untraced execution.
    """
    change=epoch.get('mappingMutation',{})
    args=change.get('arguments');number=change.get('number');result=change.get('returnValue')
    if (change.get('kind')!='syscall' or number not in (9,10,11,25)
            or not isinstance(args,list) or len(args)!=6
            or any(type(v) is not int or not 0<=v<=MASK for v in args)
            or type(result) is not int or not 0<=result<=MASK):
        raise ValueError('ENTRY_PROBE_MAPPING_TRANSITION_UNSUPPORTED')
    ranges=[(result,args[1])] if number==9 else [(args[0],args[1])]
    if number==25:ranges.append((result,args[2]))
    for start,length in ranges:
        end=start+((length+4095)//4096)*4096
        if not length or start%4096 or end>MASK:
            raise ValueError('ENTRY_PROBE_MAPPING_RANGE_UNSUPPORTED')
        if start<=address<end:raise ValueError('ENTRY_PROBE_ENTRY_MAPPING_MUTATED')


def targets(report,deployed):
    roots=report['programScope']['localScopes']['candidate']['rootAstPaths']
    definitions=report['graphs']['candidate']['functionDefinitions'];rows=[]
    library=next(a for a in deployed['artifacts'] if a['stage']=='derived-library')
    for path in roots:
        matches=[f for f in definitions if f['astPath']==path and f.get('linkerName')]
        if len(matches)!=1:raise ValueError('ENTRY_PROBE_COMPILER_LINKER_DECLARATION_REQUIRED')
        declaration=matches[0]
        linked=[r for r in deployed['definitions'] if r['verified']
                and r['symbol']['name']==declaration['linkerName'] and r['symbol']['type']==2
                and len(r['finalSymbols'])==1 and r['finalSymbols'][0]['size']>0]
        if len(linked)!=1:raise ValueError('ENTRY_PROBE_LINK_ATTRIBUTION_REQUIRED')
        body={'functionEvidenceIdentity':declaration['functionEvidenceIdentity'],
              'candidateAstPath':path,'signature':declaration['signature'],
              'library':{k:library[k] for k in ('path','resolvedPath','digest')},
              'symbol':linked[0]['finalSymbols'][0]}
        rows.append(dict(body,entryTargetIdentity=identity(body)))
    if not rows or len(rows)>64:raise ValueError('ENTRY_PROBE_TARGET_BUDGET_OR_EMPTY')
    return rows


def locations(target,epoch,root):
    """Recompute entry addresses from sealed ELF bytes and the same map epoch."""
    candidates=[]
    for obj in epoch['objects']:
        if obj.get('digest')!=target['library']['digest'] or obj.get('kind')!='backing-file':continue
        path=(root/obj['blob']).resolve(strict=True)
        if not path.is_relative_to(root.resolve()):raise ValueError('ENTRY_PROBE_BLOB_ESCAPE')
        raw=path.read_bytes()
        if bytes_digest(raw)!=obj['digest']:raise ValueError('ENTRY_PROBE_IMAGE_CHANGED')
        if raw[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',raw,18)[0]!=62:
            raise ValueError('ENTRY_PROBE_ELF64_X86_REQUIRED')
        phoff=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
        if size!=56 or phoff+count*size>len(raw):raise ValueError('ENTRY_PROBE_PROGRAM_HEADER_UNSUPPORTED')
        value=target['symbol']['value']
        for i in range(count):
            typ,flags,offset,vaddr,_,filesz,_,_=struct.unpack_from('<IIQQQQQQ',raw,phoff+i*size)
            if typ!=1 or not flags & 1 or not vaddr<=value<vaddr+filesz:continue
            file_offset=offset+value-vaddr
            if file_offset>=len(raw):raise ValueError('ENTRY_PROBE_SEGMENT_BOUNDS_INVALID')
            for mapping in obj['maps']:
                if (mapping in epoch['maps'] and 'x' in mapping['permissions']
                        and mapping['permissions']=='r-xp' and mapping['offset']<=file_offset<
                        mapping['offset']+mapping['end']-mapping['start']):
                    address=mapping['start']+file_offset-mapping['offset']
                    candidates.append((address,raw[file_offset],obj,mapping))
    return candidates


class Probe:
    def __init__(self,targets):
        self.targets=targets;self.armed={};self.observed=[];self.addresses={}

    def mapped(self,pid,ptrace,epoch,root,stop):
        maps=epoch['maps']
        for target in self.targets:
            key=target['entryTargetIdentity']
            candidates=locations(target,epoch,root)
            if not candidates:continue
            if len(candidates)!=1:raise ValueError('ENTRY_PROBE_LOAD_INSTANCE_AMBIGUOUS')
            address,byte,obj,mapping=candidates[0]
            if address in self.armed:
                location_relation(self.armed[address],address,byte,obj,mapping)
                transition_preserves_entry(address,epoch)
            if key in self.addresses:
                if self.addresses[key]!=address:raise ValueError('ENTRY_PROBE_RELOAD_UNSUPPORTED')
                continue
            word_address=address & ~7;shift=8*(address-word_address)
            word=ptrace(2,pid,word_address)&MASK
            if ((word>>shift)&255)!=byte or byte==0xcc:
                raise ValueError('ENTRY_PROBE_ORIGINAL_CODE_BYTE_MISMATCH')
            if address in self.armed:raise ValueError('ENTRY_PROBE_ADDRESS_ALIAS_UNSUPPORTED')
            ptrace(5,pid,word_address,(word & ~(255<<shift)) | (0xcc<<shift))
            self.armed[address]={'target':target,'address':address,'originalByte':byte,
                'armedEpoch':epoch['index'],'armedStopOrdinal':stop,'mapping':mapping,
                'mappedImageDigest':obj['digest'],'capturedFileStat':obj['capturedFileStat']}
            self.addresses[key]=address
        for address,row in self.armed.items():
            if not any(m['start']<=address<m['end'] and m['inode']==row['mapping']['inode']
                       and m['device']==row['mapping']['device'] and 'x' in m['permissions'] for m in maps):
                raise ValueError('ENTRY_PROBE_ARMED_MAPPING_CHANGED')

    def trapped(self,pid,ptrace,regs,epoch,stop):
        address=regs.rip-1
        if address not in self.armed:return False
        row=self.armed.pop(address);word_address=address & ~7;shift=8*(address-word_address)
        word=ptrace(2,pid,word_address)&MASK
        if (word>>shift)&255 != 0xcc:raise ValueError('ENTRY_PROBE_BREAKPOINT_CHANGED')
        ptrace(5,pid,word_address,(word & ~(255<<shift)) | (row['originalByte']<<shift))
        registers={name:int(getattr(regs,name)) for name,_ in regs._fields_}
        regs.rip=address;ptrace(13,pid,0,ctypes.byref(regs))
        self.observed.append({**row,'hitEpoch':epoch,'hitStopOrdinal':stop,
                              'registersAtBreakpoint':registers,'scope':'instrumented-function-entry-only'})
        return True

    def evidence(self):
        return {'targets':self.targets,'observations':self.observed,
                'unobservedTargetIdentities':[t['entryTargetIdentity'] for t in self.targets
                    if t['entryTargetIdentity'] not in {r['target']['entryTargetIdentity'] for r in self.observed}]}


def derive(contracts_path,process_path):
    if d.read(Path(contracts_path).resolve().parent/'inputs.json').get('entryCoverage') is not None:
        raise ValueError('ENTRY_PROBE_BASE_WITHOUT_ENTRY_COVERAGE_REQUIRED')
    report=contracts.check(contracts_path)
    inputs=d.read(Path(contracts_path).resolve().parent/'inputs.json')
    from .native_deployment_observation import check_observation
    observation=check_observation(inputs['observation']['path']);deployed=d.check_result(observation['deploymentPath'])
    expected=targets(report,deployed)
    root=Path(process_path).resolve().parent;process=d.read(process_path);checked(process,'processCaptureIdentity')
    if (process['backend']!='linux-x86_64-ptrace-single-shot-function-entry.v1'
            or process['entryProbeEvidence']['targets']!=expected):
        raise ValueError('ENTRY_PROBE_PROCESS_TARGET_MISMATCH')
    profile=next(c for c in observation['commands'] if c['stage']=='natural')
    if (process['arguments']!=profile['arguments']
            or process['environment']!=profile['environment']
            or process['directory']!=str(root.parent)):
        raise ValueError('ENTRY_PROBE_EXECUTION_PROFILE_MISMATCH')
    for name in ('stdout','stderr'):
        if d.digest(root/(name+'.log'))!=process[name+'Digest']:
            raise ValueError('ENTRY_PROBE_OUTPUT_CHANGED')
    epochs=[]
    for snap in process['epochs']:
        path=(root/snap['path']).resolve()
        if not path.is_relative_to(root) or d.digest(path)!=snap['digest']:
            raise ValueError('ENTRY_PROBE_EPOCH_CHANGED')
        epochs.append(d.read(path))
    seen=set();last_stop=-1
    for index,epoch in enumerate(epochs):
        if epoch['index']!=index or epoch['stopOrdinal']<=last_stop:
            raise ValueError('ENTRY_PROBE_EPOCH_ORDER_INVALID')
        last_stop=epoch['stopOrdinal']
    hits=process['entryProbeEvidence']['observations'];previous=0
    for hit in hits:
        target=hit['target'];key=target['entryTargetIdentity']
        if target not in expected or key in seen:raise ValueError('ENTRY_PROBE_DUPLICATE_OR_UNKNOWN_TARGET')
        seen.add(key)
        armed,hit_index=hit['armedEpoch'],hit['hitEpoch']
        if not (type(armed) is int and type(hit_index) is int and 0<=armed<=hit_index<len(epochs)):
            raise ValueError('ENTRY_PROBE_EPOCH_INDEX_INVALID')
        for index in range(armed,hit_index+1):
            candidates=locations(target,epochs[index],root)
            if len(candidates)!=1:raise ValueError('ENTRY_PROBE_LOAD_INSTANCE_AMBIGUOUS')
            address,byte,obj,mapping=candidates[0]
            location_relation(hit,address,byte,obj,mapping,armed=index==armed)
            if index>armed:transition_preserves_entry(address,epochs[index])
        if (hit['registersAtBreakpoint']['rip']!=hit['address']+1
                or hit['scope']!='instrumented-function-entry-only'
                or hit['armedStopOrdinal']!=epochs[armed]['stopOrdinal']
                or not max(previous,epochs[hit_index]['stopOrdinal'])<hit['hitStopOrdinal']<=process['stopCount']
                or (hit_index+1<len(epochs) and hit['hitStopOrdinal']>=epochs[hit_index+1]['stopOrdinal'])):
            raise ValueError('ENTRY_PROBE_STOP_ORDER_OR_PC_INVALID')
        previous=hit['hitStopOrdinal']
    missing=[t['entryTargetIdentity'] for t in expected if t['entryTargetIdentity'] not in seen]
    if process['entryProbeEvidence']['unobservedTargetIdentities']!=missing:
        raise ValueError('ENTRY_PROBE_UNOBSERVED_LEDGER_INVALID')
    complete=(process['failureReason'] is None and bool(expected) and len(seen)==len(expected))
    return d.seal({'schemaVersion':SCHEMA,'deploymentIdentity':deployed['deploymentIdentity'],
        'contractEvidenceIdentity':report['contractEvidenceIdentity'],'processCaptureIdentity':process['processCaptureIdentity'],
        'candidateFunctionEntriesObserved':complete,'observedFunctionCount':len(seen),
        'expectedFunctionCount':len(expected),'traceFailureReason':process['failureReason'],
        'tracedReturnCode':process['returnCode'],
        'tracedReturnCodeMatchesReference':process['returnCode']==profile['returnCode'],
        'tracedStdoutMatchesReference':process['stdoutDigest']==profile['stdoutDigest'],
        'tracedStderrMatchesReference':process['stderrDigest']==profile['stderrDigest'],
        'workingDirectoryDiffersFromReference':process['directory']!=profile['workingDirectory'],
        'functionEntryObservations':process['entryProbeEvidence']['observations'],
        'candidateInstructionExecutionCoverageVerified':False,'nativeAbiClosureVerified':False,
        'legalObjectDomainVerified':False,'untracedRunCoverageVerified':False,
        'semanticApproval':False,'productionAcceptanceComplete':False},'entryCoverageIdentity')


def acquire(contracts_path,output,*,timeout=300):
    from .native_deployment_prerequisites import output_path
    if os.sysconf('SC_PAGE_SIZE')!=4096:raise ValueError('ENTRY_PROBE_PAGE_SIZE_UNSUPPORTED')
    if d.read(Path(contracts_path).resolve().parent/'inputs.json').get('entryCoverage') is not None:
        raise ValueError('ENTRY_PROBE_BASE_WITHOUT_ENTRY_COVERAGE_REQUIRED')
    report=contracts.check(contracts_path)
    parent=d.read(Path(contracts_path).resolve().parent/'inputs.json')
    from .native_deployment_observation import check_observation
    observation=check_observation(parent['observation']['path']);deployed=d.check_result(observation['deploymentPath'])
    selected=targets(report,deployed)
    profile=next(c for c in observation['commands'] if c['stage']=='natural')
    root=output_path(output);root.mkdir()
    capture(profile['arguments'],root,profile['environment'],
            root/'trace',timeout=timeout,entry_probe=Probe(selected))
    inputs={'schemaVersion':'riscv2x86.candidate-function-entry-inputs.v1',
            'contracts':d.snapshot(contracts_path),'process':d.snapshot(root/'trace/capture.json')}
    value=derive(contracts_path,inputs['process']['path'])
    (root/'inputs.json').write_text(json.dumps(d.seal(inputs,'entryCoverageInputsIdentity'),indent=2)+'\n')
    (root/'result.json').write_text(json.dumps(value,indent=2)+'\n')
    check(root/'result.json');return value


def check(path):
    path=Path(path).resolve(strict=True);value=d.read(path);checked(value,'entryCoverageIdentity')
    inputs=d.read(path.parent/'inputs.json');checked(inputs,'entryCoverageInputsIdentity')
    if inputs.get('schemaVersion')!='riscv2x86.candidate-function-entry-inputs.v1' or set(inputs)!={'schemaVersion','contracts','process','entryCoverageInputsIdentity'}:
        raise ValueError('ENTRY_PROBE_INPUT_SCHEMA_INVALID')
    for key in ('contracts','process'):d.verify_snapshot(inputs[key])
    if derive(inputs['contracts']['path'],inputs['process']['path'])!=value:
        raise ValueError('ENTRY_PROBE_REDERIVATION_MISMATCH')
    return value
