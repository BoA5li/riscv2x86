"""Typed invocation/unit/native tests; native C is not dual-ISA L3 evidence."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest

from riscv2x86_py.compiler_memory_signature import export, type_fact
from riscv2x86_py.l3_memory_call import bind, store_value
from riscv2x86_py.l3_trace_deployment import store_harness
from riscv2x86_py.l3_qemu_memory_route import parse_objects
from riscv2x86_py.l3_trace_support import identity, Elf
from riscv2x86_py import l3_memory_backend as backend
from tests.test_l3_memory_trace import finding

TYPES={1:'unsigned char',2:'unsigned short',4:'unsigned int',8:'unsigned long long'}


def fixture(width,pointer=0,returns='integer',widen=False):
    f=finding();a=f['approvalArtifact'];facts=a['l2MemoryProofFacts'];authority=a['l2AuthoritySidecar']
    facts.update(accessKind='store',widthBytes=width,byteOffset=width,valueOperandIndex=2)
    authority['sourceEffects'][0]['effectKind']='WriteMemory'
    authority['memoryObjects'][0].update(sizeBytes=4*width,minimumAlignment=width,
        readableRanges=[],writableRanges=[[width,2*width]])
    authority['operands'][0]['parameterIndex']=pointer
    authority['operands'].append({'operandIndex':2,'typeKind':'integer','parameterIndex':1-pointer,'accessMode':'input'})
    f['fragment']['compilerFragmentAuthority']={'fragmentBindingKey':{'beginOffset':12,'endOffset':24}}
    from riscv2x86_py.l3_memory_intent import memory_spec
    spec=memory_spec(f)
    params=['',''];params[pointer]=TYPES[width]+' *';params[1-pointer]='unsigned long long'
    result='void' if returns=='void' else 'unsigned long long' if widen else TYPES[width]
    fn={'functionId':'function','sourceDigest':'digest','arity':2,
        'l2OperandBoundary':{'parameterDeclarationIds':['first','second']}}
    fn['compilerMemoryCallSignature']=export(fn,params,result,lambda t:t)
    scope={'sourceDigest':'digest','functionIdentity':'function','asmBegin':12,'asmEnd':24,
        'scope':'single_asm_void' if returns=='void' else 'single_asm_and_bound_object_return'}
    if returns!='void':scope.update(returnObjectParameterIndex=pointer,returnElementIndex=1)
    fn['compilerStoreFunctionScope']=dict(scope,scopeIdentity=identity(scope))
    return f,fn,spec


@pytest.mark.parametrize('width',[1,2,4,8])
@pytest.mark.parametrize('pointer',[0,1])
@pytest.mark.parametrize('returns',['integer','void'])
@pytest.mark.parametrize('widen',[False,True])
def test_typed_harness_executes_real_native_calls_and_checks_complete_object(tmp_path,width,pointer,returns,widen):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native compiler unavailable; not counted as production')
    f,fn,spec=fixture(width,pointer,returns,widen);call=bind(fn,f,spec)
    scope={'name':'unrelated_probe','callSignature':call}
    text=store_harness(scope,spec,4)
    params=call['compilerSignature']['parameters'];result=call['compilerSignature']['result']['cType']
    names=['',''];names[pointer]='address';names[1-pointer]='input'
    declaration=','.join(p['cType']+' '+n for p,n in zip(params,names))
    body='address[1]=('+TYPES[width]+')input;'+('' if returns=='void' else 'return address[1];')
    source=tmp_path/'program.c';source.write_text(text+'\n'+result+' unrelated_probe('+declaration+'){'+body+'}\n')
    binary=tmp_path/'program'
    subprocess.run([cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],check=True,capture_output=True)
    completed=subprocess.run([str(binary),'a'*64],check=True,capture_output=True,text=True)
    objects=parse_objects(completed.stdout,'a'*64,spec,4,call)
    assert len(objects)==4
    if returns=='void':assert all(o['value'] is None for o in objects)
    else:assert [int(o['value'],16) for o in objects]==[store_value(n,width) for n in range(4)]
    # An adjacent-byte write cannot be hidden behind a matching returned value.
    changed=[json.loads(s) for s in completed.stdout.splitlines()]
    data=bytearray.fromhex(changed[0]['objectHex']);data[-1]^=1;changed[0]['objectHex']=data.hex()
    with pytest.raises(ValueError,match='VALUE_OR_OBJECT'):
        parse_objects('\n'.join(json.dumps(o) for o in changed),'a'*64,spec,4,call)


@pytest.mark.parametrize('mutation',['signed','pointee-width','result-narrow','declaration','offset','region','signature-type'])
def test_call_rejects_rehashed_wrong_typed_bindings(mutation):
    f,fn,spec=fixture(4);signature=fn['compilerMemoryCallSignature'];scope=fn['compilerStoreFunctionScope']
    if mutation=='signed':signature['parameters'][1].update(type_fact('long long'))
    if mutation=='pointee-width':signature['parameters'][0].update(type_fact('unsigned short *'))
    if mutation=='result-narrow':signature['result']=type_fact('unsigned char')
    if mutation=='declaration':signature['parameters'][0]['declarationIdentity']='wrong'
    if mutation=='offset':scope['returnElementIndex']=2
    if mutation=='region':scope['asmEnd']=25
    if mutation=='signature-type':signature['parameters'][1]['signed']=0
    signature['factsIdentity']=identity({k:v for k,v in signature.items() if k!='factsIdentity'})
    scope['scopeIdentity']=identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
    with pytest.raises(ValueError):bind(fn,f,spec)


def test_width_calibration_is_required_without_invalidating_legacy_eight_byte_store():
    for width in (1,2,4):
        with pytest.raises(ValueError,match='WIDTH_CALIBRATION_REQUIRED'):
            backend.require_access({'schemaVersion':'legacy'},{'access':'write','width':width})
    backend.require_access({'schemaVersion':'legacy'},{'access':'write','width':8})


@pytest.mark.parametrize('width',[1,2,4,8])
def test_calibration_probe_native_machine_bytes_and_functional_exit(tmp_path,width):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native compiler unavailable')
    case={'side':'target','width':width};asm=tmp_path/'probe.s';asm.write_text(backend.probe(case));binary=tmp_path/'probe'
    subprocess.run(backend.build_command({'targetCompiler':cc},case,asm,binary),check=True,capture_output=True)
    elf=Elf(binary)
    assert backend.region_code(elf,backend.region(elf))==backend.expected_code(case)
    assert subprocess.run([str(binary)],check=False).returncode==0


def test_backend_requires_the_complete_typed_calibration_matrix(tmp_path,monkeypatch):
    base=tmp_path/'base.json';base.write_text('{}')
    tools={k:[] if k.endswith('Arguments') else '/fixture/'+k for k in backend.TOOLS}
    monkeypatch.setattr(backend.base,'validate_backend',lambda *a,**kw:tools)
    from riscv2x86_py.l3_trace_support import digest
    value={'schemaVersion':backend.SCHEMA,'baseBackendPath':str(base),'baseBackendDigest':digest(base),
        **tools,'files':{p:digest(p) for p in backend.implementation_paths()},
        'calibration':[{'case':c} for c in backend.CASES]}
    calls=[];monkeypatch.setattr(backend,'validate_record',lambda r,b:calls.append(r))
    value['backendIdentity']=identity(value)
    backend.validate_backend(value);assert len(calls)==8
    changed=deepcopy(value);changed['calibration'][-1]=changed['calibration'][0]
    changed['backendIdentity']=identity({k:v for k,v in changed.items() if k!='backendIdentity'})
    with pytest.raises(ValueError,match='COVERAGE_INVALID'):backend.validate_backend(changed)


def test_preparation_failure_keeps_primary_reason_and_no_success_manifest(tmp_path,monkeypatch):
    def refuse(*a,**kw):raise ValueError('original base failure')
    monkeypatch.setattr(backend.base,'validate_backend',refuse)
    with pytest.raises(ValueError,match='original base failure'):backend.prepare(tmp_path/'base.json',tmp_path/'out')
    state=json.loads((tmp_path/'out/build-status.json').read_text())
    assert state['error']=='original base failure' and state['complete'] is False
    assert not (tmp_path/'out/backend.json').exists()


@pytest.mark.parametrize('pointer',[0,1])
def test_compiler_shell_exports_actual_pointer_position_and_return_conversion(pointer):
    from riscv2x86_py.compiler_continuation_sites import memory_store_function_scope
    fn={'inner':[{'kind':'ParmVarDecl','id':'a'},{'kind':'ParmVarDecl','id':'b'},
        {'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt'},
            {'kind':'ReturnStmt','inner':[{'kind':'ImplicitCastExpr','castKind':'IntegralCast','inner':[
                {'kind':'ImplicitCastExpr','castKind':'LValueToRValue','inner':[
                    {'kind':'ArraySubscriptExpr','inner':[
                        {'kind':'DeclRefExpr','referencedDecl':{'id':('a','b')[pointer]}},
                        {'kind':'IntegerLiteral','value':'3'}]}]}]}]}]}]}
    kw={'source_digest':'source','function_identity':'function','source_range':lambda n:(1,8),
        'pointer_parameter_indexes':[pointer]}
    scope=memory_store_function_scope(fn,**kw)
    assert scope['returnObjectParameterIndex']==pointer and scope['returnElementIndex']==3
    kw['pointer_parameter_indexes']=[1-pointer]
    assert memory_store_function_scope(fn,**kw) is None


def test_typed_store_contract_cannot_be_downgraded_to_legacy_schema():
    from tests.test_l3_memory_trace import contract
    from riscv2x86_py.l3_qemu_memory_route import parse_contract,TYPED_STORE_CONTRACT_SCHEMA,STORE_CONTRACT_SCHEMA
    f,fn,spec=fixture(1);call=bind(fn,f,spec)
    value=contract();value.update(schemaVersion=TYPED_STORE_CONTRACT_SCHEMA,spec=spec,
        fragmentId=spec['fragmentId'],programId=spec['programId'],storeCall=call,
        deployment={'spec':spec,'sampleCount':4,'functionScope':{'callSignature':call}})
    value['propertyBindings'][0]['obligationIds']=['memory:approved-write']
    parse_contract(value)
    changed=deepcopy(value);changed['schemaVersion']=STORE_CONTRACT_SCHEMA;del changed['storeCall']
    with pytest.raises(ValueError,match='TYPED_STORE_CONTRACT_VERSION_REQUIRED'):parse_contract(changed)
    changed=deepcopy(value);changed['storeCall']=dict(changed['storeCall'],widthBytes=2)
    with pytest.raises(ValueError,match='STORE_CALL_CHANGED'):parse_contract(changed)


@pytest.mark.parametrize('width',[1,2,4,8])
def test_calibration_rebuild_and_transcript_replay_refuse_changed_outcomes(tmp_path,width):
    """Synthetic callback transcript tests replay logic, not QEMU calibration."""
    from riscv2x86_py.l3_trace_support import run,digest
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native compiler unavailable')
    case={'side':'target','width':width};src=tmp_path/'probe.s';binary=tmp_path/'probe'
    src.write_text(backend.probe(case));tools={'targetCompiler':cc,'targetExecutor':'/fixture/qemu',
        'targetRunnerArguments':[],'plugin':'/fixture/plugin'}
    run(backend.build_command(tools,case,src,binary),tmp_path,'build',120)
    elf=Elf(binary);reg=backend.region(elf);token='b'*64;trace=tmp_path/'guest-trace.log'
    trace.write_text('H 1 '+token+' x86_64 '+format(reg['start'],'x')+' '+format(reg['end'],'x')+'\n'
        +'B 0 '+format(reg['start'],'x')+'\nM 0 0 '+format(reg['start'],'x')+' '
        +format(elf.symbol('data')[0],'x')+' '+str(width)+' W\nE 0 '+format(reg['end'],'x')+'\nF 1 1 1 0\n')
    option=','.join([tools['plugin'],'start='+hex(reg['start']),'end='+hex(reg['end']),
        'limit=4096','output='+str(trace.resolve()),'token='+token])
    cp=tmp_path/'execute.command.json';command={'command':[tools['targetExecutor'],'-plugin',option,str(binary),token],
        'returnCode':0,'timedOut':False,'stdout':'','stderr':''}
    cp.write_text(json.dumps(command))
    record={'case':case,'assembly':str(src),'binary':str(binary),'binaryDigest':digest(binary),
        'buildCommandDigest':digest(tmp_path/'build.command.json'),
        'evidence':{'rawTracePath':str(trace),'rawTraceDigest':digest(trace),'token':token,
                    'commandRecordDigest':digest(cp)}}
    backend.validate_record(record,tools)
    # Rehashing an unsuccessful command cannot make it a successful calibration.
    command['returnCode']=9;cp.write_text(json.dumps(command))
    record['evidence']['commandRecordDigest']=digest(cp)
    with pytest.raises(ValueError,match='EXECUTION_INVALID'):backend.validate_record(record,tools)
    command['returnCode']=False;cp.write_text(json.dumps(command))
    record['evidence']['commandRecordDigest']=digest(cp)
    with pytest.raises(ValueError,match='EXECUTION_INVALID'):backend.validate_record(record,tools)
