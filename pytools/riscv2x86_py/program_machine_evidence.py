"""ELF-bound structured machine facts and a restricted AMD64 leaf ABI lemma.

No function name patterns, disassembly text, debug line guesses or user-supplied
completeness booleans are consumed. This is not declaration/call-site ABI closure.
"""
import json
import struct
from pathlib import Path
from . import native_captured_deployment as d
from .native_elf_runtime import parse
from .native_verifier_manifest import current,compare
from .project_acquisition import Runner,publish_checked

SCHEMA='riscv2x86.program-machine-evidence.v1'


def derive(raw,symbol):
    import pypcode
    elf=parse(raw)
    if elf['machine']!=62 or elf['elfType'] not in (2,3):raise ValueError('MACHINE_AMD64_LINKED_ELF_REQUIRED')
    matches={(s['value'],s['size'],s['sectionIndex']) for s in elf['staticSymbols']+elf['dynamicSymbols']
             if s['name']==symbol and s['defined'] and s['type']==2 and s['size']>0}
    if len(matches)!=1:raise ValueError('MACHINE_UNIQUE_SIZED_FUNCTION_REQUIRED')
    address,size,section=next(iter(matches))
    if size>65536:raise ValueError('MACHINE_FUNCTION_BUDGET_EXCEEDED')
    shoff=struct.unpack_from('<Q',raw,40)[0];shsize=struct.unpack_from('<H',raw,58)[0]
    fields=struct.unpack_from('<IIQQQQIIQQ',raw,shoff+shsize*section)
    _,kind,flags,vaddr,offset,extent,*_=fields
    start=offset+address-vaddr
    if kind!=1 or not flags&4 or address<vaddr or address+size>vaddr+extent or start+size>len(raw):
        raise ValueError('MACHINE_FUNCTION_EXECUTABLE_RANGE_REQUIRED')
    if any(address<=r['offset']<address+size for r in elf['relocations']):
        raise ValueError('MACHINE_FUNCTION_RELOCATION_EFFECT_REQUIRED')
    code=raw[start:start+size];ctx=pypcode.Context('x86:LE:64:default')
    translation=ctx.translate(code,base_address=address,max_bytes=size)
    def var(v):
        return {'space':v.space.name,'offset':v.offset,'size':v.size,
            'registerName':v.getRegisterName() if v.space.name=='register' else None}
    rows=[];instructions=[]
    for op in translation.ops:
        if len(rows)>100000:raise ValueError('MACHINE_PCODE_BUDGET_EXCEEDED')
        name=op.opcode.name
        if name=='IMARK':
            if len(op.inputs)!=1:raise ValueError('MACHINE_DELAY_SLOT_UNSUPPORTED')
            instructions.append({'address':op.inputs[0].offset,'size':op.inputs[0].size})
        inputs=[]
        for i,v in enumerate(op.inputs):
            if name in ('LOAD','STORE') and i==0:
                # pypcode's address-space constant is a process-local pointer;
                # serialize the backend's space name, never that pointer value.
                inputs.append({'addressSpace':v.getSpaceFromConst().name})
            else:inputs.append(var(v))
        rows.append({'opcode':name,'output':None if op.output is None else var(op.output),'inputs':inputs})
    cursor=address
    for ins in instructions:
        if ins['address']!=cursor or ins['size']<=0:raise ValueError('MACHINE_DECODE_COVERAGE_INCOMPLETE')
        cursor+=ins['size']
    if cursor!=address+size:raise ValueError('MACHINE_DECODE_COVERAGE_INCOMPLETE')
    semantic=[r for r in rows if r['opcode']!='IMARK']
    def reg(v,name):
        r=ctx.registers[name]
        return v==var(r)
    tail=semantic[-3:]
    returned=(len(tail)==3 and tail[0]['opcode']=='LOAD' and tail[0]['inputs'][0]=={'addressSpace':'ram'}
        and reg(tail[0]['inputs'][1],'RSP') and reg(tail[0]['output'],'RIP')
        and tail[1]['opcode']=='INT_ADD' and reg(tail[1]['output'],'RSP')
        and reg(tail[1]['inputs'][0],'RSP') and tail[1]['inputs'][1].get('space')=='const'
        and tail[1]['inputs'][1].get('offset')==8 and tail[1]['inputs'][1].get('size')==8
        and tail[2]['opcode']=='RETURN' and len(tail[2]['inputs'])==1 and reg(tail[2]['inputs'][0],'RIP'))
    body=semantic[:-3] if returned else semantic
    from .runtime_facts import _PROVEN_PURE_INTEGER_OPCODES
    # Faulting division and unmodelled machine state are not admitted by this
    # finite leaf lemma, even when the backend uses a pure integer opcode.
    admitted=_PROVEN_PURE_INTEGER_OPCODES-{'INT_DIV','INT_SDIV','INT_REM','INT_SREM'}
    pure=all(r['opcode'] in admitted for r in body)
    writes=[r['output'] for r in body if r['output'] and r['output']['space']=='register']
    def overlaps(v,name):
        r=ctx.registers[name]
        return v['offset']<r.offset+r.size and r.offset<v['offset']+v['size']
    saved=not any(overlaps(v,n) for v in writes for n in ('RBX','RBP','R12','R13','R14','R15'))
    stack=not any(overlaps(v,'RSP') or overlaps(v,'RIP') for v in writes)
    caller=('RAX','RCX','RDX','RSI','RDI','R8','R9','R10','R11','CF','PF','AF','ZF','SF','OF')
    unknown_writes=[v for v in writes if not any(
        ctx.registers[n].offset<=v['offset'] and v['offset']+v['size']<=ctx.registers[n].offset+ctx.registers[n].size
        for n in caller)]
    restricted=returned and pure and saved and stack and not unknown_writes
    return {'functionSymbol':symbol,'virtualAddress':address,'byteSize':size,'codeDigest':d.identity(code.hex()),
        'instructions':instructions,'structuredPcode':rows,'decodedByteCoverageComplete':True,
        'leafReturnShapeVerified':returned,'bodyPureIntegerDataflowVerified':pure,
        'restrictedLeafPreservationVerified':restricted,
        'calleeSavedNonWriteVerified':restricted,'stackReturnDisciplineVerified':restricted,
        'bodyHasNoMemoryOrCallsVerified':restricted,'unmodeledRegisterWrites':unknown_writes,
        'requiredEntryAssumptions':['sysv-amd64-entry-stack-and-return-continuation-valid'],
        'machineAbiClosureVerified':False,'legalObjectDomainVerified':False,
        'candidateInstructionExecutionCoverageVerified':False,
        'reasonCodes':(['DECLARATION_CALLSITE_AND_BUILD_CONTEXT_JOIN_REQUIRED'] if restricted else
                       ['RESTRICTED_LEAF_SHAPE_OR_PRESERVATION_NOT_PROVEN']),
        'scope':'static-byte-bound-machine-facts-not-runtime-execution-or-full-ABI'}


def decoder():
    import importlib,pypcode
    backend=importlib.import_module(pypcode.Context.__mro__[1].__module__)
    language=pypcode.Context('x86:LE:64:default').language
    return {'version':pypcode.__version__,'extension':d.snapshot(backend.__file__),
            'pythonAdapter':d.snapshot(pypcode.__file__),'sleigh':d.snapshot(language.slafile_path),
            'processorSpec':d.snapshot(language.pspec_path)}


def acquire(elf,symbol,output):
    tool=decoder();raw=Path(elf).read_bytes();facts=derive(raw,symbol)
    runner=Runner(output,'program-machine-evidence')
    try:
        blob=runner.output/'program.elf';blob.write_bytes(raw)
        value=d.seal({'schemaVersion':SCHEMA,'verifier':current(),'original':d.snapshot(elf),
            'blob':d.snapshot(blob),'decoder':tool,'facts':facts,
            'semanticApproval':False,'productionAcceptanceComplete':False},'machineEvidenceIdentity')
        publish_checked(runner.output/'result.json',value,check)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save();return value
    except Exception as exc:runner.failure('machine-facts',exc);raise


def check(path):
    from .native_external_providers import checked
    value=d.read(path);checked(value,'machineEvidenceIdentity');compare(value['verifier'],current())
    for key in ('original','blob'):d.verify_snapshot(value[key])
    if value['schemaVersion']!=SCHEMA or value['decoder']!=decoder():raise ValueError('MACHINE_DECODER_CHANGED')
    if (value['original']['digest']!=value['blob']['digest']
            or value['facts']!=derive(Path(value['blob']['path']).read_bytes(),value['facts']['functionSymbol'])
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('MACHINE_FACT_REDERIVATION_MISMATCH')
    return value
