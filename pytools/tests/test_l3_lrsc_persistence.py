"""Durable contract boundary tests; fixtures do not claim RISC-V/QEMU execution."""
import json
from pathlib import Path
import pytest

from riscv2x86_py.l3_trace_support import identity
from tests.test_l3_protocol_resolution import lrsc_request
from riscv2x86_py.l3_lrsc_spec import spec,samples


def test_approved_lrsc_spec_survives_json_storage(tmp_path):
    item=lrsc_request(tmp_path)['candidates'][0]
    value=spec(item['finding'],item['compilerFunctions'])
    path=tmp_path/'spec.json';path.write_text(json.dumps(value))
    restored=json.loads(path.read_text())
    assert value==restored
    assert identity(value)==identity(restored)
    assert samples(value)==json.loads(json.dumps(samples(value)))

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from riscv2x86_py.l3_trace_support import require_json_document,require_json_match,digest,save
from tests.test_lrsc_source import ingress,model_for
from tests.test_lrsc_target import finding_case,translated_case
from tests.test_lrsc_sequence_contract import code


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
@pytest.mark.parametrize('bits',range(16))
def test_source_dto_roundtrip_all_ordering_bits(width,operation,bits):
    order=tuple(bool(bits&(1<<i)) for i in range(4))
    fragment,runtime,machine=ingress(width,operation=operation,order=order)
    model=model_for(fragment,runtime,machine).lrsc_sequence
    value=model.to_dict();require_json_document(value)
    assert value==json.loads(json.dumps(value))
    assert type(value['lr_ordering_bits']) is list
    assert value['lr_ordering_bits']==list(order[:2])
    assert value['sc_ordering_bits']==list(order[2:])
    # The wire identity is unchanged from the old tuple-carrying DTO.
    old=dict(value,lr_ordering_bits=model.lr_ordering_bits,sc_ordering_bits=model.sc_ordering_bits)
    assert identity(old)==identity(value)
    assert isinstance(model.lr_ordering_bits,tuple) and isinstance(model.sc_ordering_bits,tuple)


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('slots',[(0,1,2,3,4,5),(3,2,0,1,5,4)])
@pytest.mark.parametrize('registers',[(5,6,9,10,11),(11,12,13,14,15)])
def test_dto_stability_does_not_depend_on_operand_indexes_or_register_names(width,slots,registers):
    fragment,runtime,machine=ingress(width,slot_order=slots,registers=registers)
    value=model_for(fragment,runtime,machine).lrsc_sequence.to_dict()
    require_json_match(value,json.loads(json.dumps(value)),'ROUNDTRIP')


def approved_spec(tmp_path,width,operation):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    finding,functions,_,_=finding_case(width,operation)
    function=functions[0];finding['fragment']['enclosingFunction']='probe'
    function.update(arity=2,parameterTypes=[('unsigned int' if width==32 else 'unsigned long')+' *','unsigned long'],
        pointerParameters=[0],returnType='unsigned long')
    key=finding['fragment']['compilerFragmentAuthority']['fragmentBindingKey']
    scope={'scope':'single_asm_no_other_memory_or_control_effects','functionIdentity':function['functionId'],
        'sourceDigest':function['sourceDigest'],'asmBegin':key['beginOffset'],'asmEnd':key['endOffset']}
    function['compilerAtomicFunctionScope']=dict(scope,scopeIdentity=identity(scope))
    finding.update(translationOutcome='emitted',sourceDigest=function['sourceDigest'])
    frontend=tmp_path/'frontend';frontend.write_text('persistence fixture identity')
    assert materialize_automatic_l2_authority({'findings':[finding]},functions,frontend)==1
    program=identity({'schemaVersion':'riscv2x86.automatic-program.v1','producerDigest':digest(frontend)})
    boundaries,_,_=materialize_fragment_execution_authority([finding],function,program)
    finding['approvalArtifact']['l2FragmentOperandBoundary']=boundaries[finding['fragment']['id']].to_dict()
    return finding,functions,spec(finding,functions)


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
def test_complete_approved_spec_and_real_native_side_are_json_stable(tmp_path,width,operation):
    from riscv2x86_py.l3_lrsc_deployment import build_side
    from riscv2x86_py.l3_control_deployment import flags
    import subprocess
    finding,functions,value=approved_spec(tmp_path,width,operation)
    require_json_match(value,json.loads(json.dumps(value)),'SPEC_ROUNDTRIP')
    _,_,_,_,translation=translated_case(width,operation)
    c=tmp_path/'probe.c';obj=tmp_path/'original.o'
    c.write_text('unsigned long probe('+value['parameterTypes'][0]+'p,unsigned long value){unsigned long old,next,status;'+translation.replacement+'return old;}')
    result=subprocess.run(['gcc',*flags('target'),'-c',str(c),'-o',str(obj)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    artifact=SimpleNamespace(artifact_path=str(obj),artifact_digest=digest(obj),artifact_id='target',build_identity=identity('build'))
    plan=samples(value)
    side=build_side(c,'target',plan,functions[0],{'targetCompiler':'gcc'},artifact,tmp_path/'native-side',value)
    require_json_match(side,json.loads(json.dumps(side)),'SIDE_ROUNDTRIP')
    result=subprocess.run([side['executionArtifact']['artifactPath'],'a'*64],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    from riscv2x86_py.l3_lrsc_spec import parse_samples
    from riscv2x86_py.l3_atomic_semantics import result as outcome
    rows=parse_samples(result.stdout,'a'*64,plan)
    for row in rows:
        assert int(row['after'][0],16)==outcome(operation,int(row['old'],16),int(row['input'],16),width)
        old=int(row['old'],16)
        returned=(old-(1<<32) if width==32 and old&(1<<31) else old)&((1<<64)-1)
        assert int(row['result'],16)==returned
        assert [int(x,16) for x in row['after'][1:]]==[0x31,0x72,0x53]+[0]*(plan['objectCellCount']-4)


@pytest.mark.parametrize('bad',[('tuple',(True,False)),('set',{1}),('bytes',b'x'),('integer-key',{1:'x'}),
    ('nan',float('nan')),('infinity',float('inf'))])
def test_non_json_native_values_are_refused_not_silently_normalized(bad):
    with pytest.raises(ValueError,match='JSON_INVALID'):
        require_json_document({'nested':bad[1]},'JSON_INVALID')


def test_json_guard_rejects_cycles_and_allows_shared_noncyclic_children():
    value=[];value.append(value)
    with pytest.raises(ValueError,match='cyclic'):require_json_document(value)
    shared={'a':[True,1,None]};require_json_document([shared,shared])


@pytest.mark.parametrize('actual',[{'bits':[1,False]},{'bits':[True]},{'bits':[False,False]},
    {'bits':[True,False],'extra':0},{}])
def test_structural_match_preserves_types_lengths_keys_and_values(actual):
    with pytest.raises(ValueError,match='SPEC_MISMATCH') as error:
        require_json_match({'bits':[True,False]},actual,'SPEC_MISMATCH')
    detail=json.loads(str(error.value).split(':',1)[1])
    assert detail['path'].startswith('$') and detail['reason'] in {'type','length','value','keys'}


def persisted_fixture(tmp_path,monkeypatch,width=64,operation='fetch_add'):
    """Exercise real prepare/save/read/validate with compiler/ELF I/O fixtures.

    Full approved specs are rebuilt through the production proof consumers.
    This fixture does not replace or claim host compiler/QEMU calibration.
    """
    import riscv2x86_py.l3_lrsc_deployment as deployment
    from riscv2x86_py.l3_lrsc_machine import source,target
    finding,functions,value=approved_spec(tmp_path,width,operation);function=functions[0]
    source_path=tmp_path/'source.c';source_path.write_text('compiler input fixture')
    target_path=tmp_path/'target.c';target_path.write_text('approved target fixture')
    report_path=tmp_path/'translated_report.json';report_path.write_text(json.dumps({'findings':[finding]}))
    compiler=tmp_path/'compiler';compiler.write_text('compiler fixture')
    source_raw=code(width,operation=operation,registers=(5,6,9,10,11))+bytes.fromhex('1385020067800000')
    # Native target bytes are proved for add here; other operations have real
    # compiler/deployment coverage in the native-side test above.
    assert operation=='fetch_add'
    target_raw=bytes.fromhex('8b074863c04889c24801f2f00fb11775f148c7c100000000c3' if width==32 else '488b074889c24801f2f0480fb11775f348c7c100000000c3')
    raw_by_side={'source':source_raw,'target':target_raw};artifacts={}
    for side,raw in raw_by_side.items():
        path=tmp_path/(side+'.object');path.write_bytes(raw)
        artifacts[side]=SimpleNamespace(artifact_path=str(path),artifact_digest=digest(path),artifact_id=side,build_identity=identity(side))
    calls=[]
    def rebound(*args):
        # Rebuild independently, rather than returning the saved contract DTO.
        fresh=spec(finding,functions)
        return fresh,samples(fresh),function
    def build(path,side,plan,fn,backend,artifact,work,atomic):
        calls.append(side);work.mkdir(parents=True)
        binary=work/'program';binary.write_bytes(raw_by_side[side])
        mechanism=(source if side=='source' else target)(binary.read_bytes(),0x1000,atomic)
        return {'semanticArtifact':{'artifactId':artifact.artifact_id,'artifactPath':str(Path(artifact.artifact_path).resolve()),
            'artifactDigest':artifact.artifact_digest,'buildIdentity':artifact.build_identity},
            'executionArtifact':{'artifactPath':str(binary),'artifactDigest':digest(binary)},
            'region':mechanism['region'],'machineMechanism':mechanism,'files':{str(binary):digest(binary)}}
    class Image:
        def __init__(self,path):self.path=Path(path)
        def execution_image(self):return {'fixtureBytes':self.path.read_bytes().hex()}
        def code(self,name):assert name=='probe';return self.path.read_bytes()
    monkeypatch.setattr(deployment,'bound_inputs',rebound)
    monkeypatch.setattr(deployment,'build_side',build)
    monkeypatch.setattr(deployment,'Elf',Image)
    backend={'backendIdentity':identity('backend')}
    original=deployment.prepare(source_path,target_path,report_path,finding,backend,artifacts['source'],artifacts['target'],tmp_path/'deployment',str(compiler))
    loaded=json.loads((tmp_path/'deployment/deployment.json').read_text())
    return deployment,backend,artifacts,original,loaded,calls


@pytest.mark.parametrize('width',[32,64])
def test_persisted_full_deployment_rebuilds_both_sides(tmp_path,monkeypatch,width):
    deployment,backend,artifacts,original,loaded,calls=persisted_fixture(tmp_path,monkeypatch,width)
    require_json_match(original,loaded,'DEPLOYMENT_ROUNDTRIP')
    assert deployment.validate(loaded,backend,artifacts['source'],artifacts['target'])==loaded
    assert calls==['source','target','source','target']


@pytest.mark.parametrize('change',['lr-bit','sc-bit','bit-type','width','operation','binding','sample','function','input','machine'])
def test_rehashed_persisted_contract_mutations_still_fail_replay(tmp_path,monkeypatch,change):
    deployment,backend,artifacts,_,loaded,_=persisted_fixture(tmp_path,monkeypatch)
    sequence=loaded['spec']['sourceSequence']
    expected='L3_LRSC_SPEC_REPLAY_MISMATCH'
    if change=='lr-bit':sequence['lr_ordering_bits'][0]=not sequence['lr_ordering_bits'][0]
    if change=='sc-bit':sequence['sc_ordering_bits'][1]=not sequence['sc_ordering_bits'][1]
    if change=='bit-type':sequence['lr_ordering_bits'][0]=1
    if change=='width':sequence['memory_width_bits']=32
    if change=='operation':loaded['spec']['operation']['rmw_operation']='fetch_xor'
    if change=='binding':sequence['role_operand_indexes']['address']=sequence['role_operand_indexes']['input']
    if change=='sample':loaded['samplePlan']['inputs'][0]['input']='0000000000000001'
    if change=='function':loaded['functionName']='different'
    if change=='input':
        Path(loaded['inputs']['source']).write_text('changed source')
        expected='L3_LRSC_INPUT_CHANGED'
    if change=='machine':
        loaded['sides']['target']['machineMechanism']['retry']['maximumAttempts']+=1
        expected='L3_LRSC_INDEPENDENT_REBUILD_MISMATCH'
    # Even recomputed nested identities must not substitute for semantic replay.
    sequence['modelIdentity']=identity({k:v for k,v in sequence.items() if k!='modelIdentity'})
    loaded['spec']['specIdentity']=identity({k:v for k,v in loaded['spec'].items() if k!='specIdentity'})
    loaded['samplePlan']['planIdentity']=identity({k:v for k,v in loaded['samplePlan'].items() if k!='planIdentity'})
    loaded['deploymentIdentity']=identity({k:v for k,v in loaded.items() if k!='deploymentIdentity'})
    path=tmp_path/'changed-deployment.json';save(path,loaded);loaded=json.loads(path.read_text())
    with pytest.raises(ValueError,match=expected) as error:
        deployment.validate(loaded,backend,artifacts['source'],artifacts['target'])
    if change=='bit-type':
        assert 'lr_ordering_bits' in str(error.value) and '"reason": "type"' in str(error.value)


def test_contract_file_replay_passes_deployment_gate_before_receipt_audit(tmp_path,monkeypatch):
    from riscv2x86_py import l3_lrsc_route as route,l3_intent_ingress
    from riscv2x86_py.l3_lrsc_spec import LIMITS
    _,backend,artifacts,original,_,calls=persisted_fixture(tmp_path,monkeypatch)
    manifest=tmp_path/'backend.json';save(manifest,backend)
    body={'schemaVersion':route.CONTRACT,'backendPath':str(manifest),'backendDigest':digest(manifest),
        'deployment':original,'atomicPolicy':'executed-lrsc-cas-outcomes-and-approved-contract.v1','limitations':sorted(LIMITS)}
    contract=tmp_path/'contract.json';save(contract,dict(body,contractIdentity=identity(body)))
    detail={'contractPath':str(contract),'contractDigest':digest(contract)}
    monkeypatch.setattr(route,'backend_validate',lambda _:backend)
    def receipt(*args):raise ValueError('fixture: receipt audit reached after deployment replay')
    monkeypatch.setattr(l3_intent_ingress,'validate_receipt',receipt)
    with pytest.raises(ValueError,match='receipt audit reached after deployment replay'):
        route.replay(detail,artifacts['source'],artifacts['target'],None)
    assert calls==['source','target','source','target']


def test_observations_comparison_and_outer_contract_are_json_stable(tmp_path,monkeypatch):
    from tests.test_l3_lrsc_sequence import test_comparison_preserves_control_obligation_and_all_raw_attempts,trace_fixture
    from riscv2x86_py import l3_lrsc_compare as comparison
    original=comparison.report;reports={}
    def capture(side,*args,**kwargs):
        report=original(side,*args,**kwargs)
        reports[side]=deepcopy(report)
        require_json_match(report,json.loads(json.dumps(report)),'OBSERVATION_ROUNDTRIP')
        return report
    monkeypatch.setattr(comparison,'report',capture)
    test_comparison_preserves_control_obligation_and_all_raw_attempts(tmp_path)
    inv=trace_fixture()[0]
    inv['operation'].update(memory_object_identity='object',result_semantics='old_value')
    inv['obligations']={'synchronizationObligations':{'basisComplete':True,'requiredSubproperties':[
        {'propertyId':name} for name in ('sync.compiler-contract','sync.atomic-mechanism','sync.atomic-outcome','sync.ordering-contract')]}}
    result=comparison.comparison(reports,inv)
    require_json_match(result,json.loads(json.dumps(result)),'COMPARISON_ROUNDTRIP')
    contract={'reports':reports,'comparison':result}
    path=tmp_path/'observations.json';save(path,contract)
    require_json_match(contract,json.loads(path.read_text()),'CONTRACT_ROUNDTRIP')


def test_word_arithmetic_source_export_keeps_both_widths(tmp_path):
    fragment,runtime,machine=ingress(32,word_alu=True)
    model=model_for(fragment,runtime,machine).lrsc_sequence
    value=model.to_dict();require_json_match(value,json.loads(json.dumps(value)),'WORD_ROUNDTRIP')
    assert value['memory_width_bits']==32 and value['arithmetic_width_bits']==32
    for field in ('lr_ordering_bits','sc_ordering_bits'):
        with pytest.raises(ValueError,match='ORDERING_BITS_INVALID'):
            replace(model,**{field:(1,False)})


@pytest.mark.parametrize('change',['missing-spec','extra-root','missing-digest','missing-side'])
def test_persisted_deployment_schema_and_input_coverage_are_not_optional(tmp_path,monkeypatch,change):
    deployment,backend,artifacts,_,loaded,_=persisted_fixture(tmp_path,monkeypatch)
    if change=='missing-spec':loaded.pop('spec')
    if change=='extra-root':loaded['unreviewed']=True
    if change=='missing-digest':loaded['inputDigests'].pop(loaded['inputs']['source'])
    if change=='missing-side':loaded['sides'].pop('source')
    loaded['deploymentIdentity']=identity({k:v for k,v in loaded.items() if k!='deploymentIdentity'})
    with pytest.raises(ValueError,match='L3_LRSC_DEPLOYMENT_(INVALID|BINDINGS_INVALID)'):
        deployment.validate(loaded,backend,artifacts['source'],artifacts['target'])


@pytest.mark.parametrize('mutation',[False,True])
def test_read_only_persistence_inspector_checks_saved_contract(tmp_path,monkeypatch,capsys,mutation):
    from tests.test_l3_protocol_resolution import load_script
    from riscv2x86_py.l3_lrsc_route import CONTRACT
    _,_,_,_,loaded,_=persisted_fixture(tmp_path,monkeypatch)
    if mutation:loaded['spec']['sourceSequence']['lr_ordering_bits'][0]=False
    path=tmp_path/'atomic-contract.json';save(path,{'schemaVersion':CONTRACT,'deployment':loaded})
    before=path.read_bytes()
    module=load_script('inspect_lrsc_persistence.py')
    import sys
    monkeypatch.setattr(sys,'argv',['inspect','--root',str(tmp_path)])
    assert module.main()==(2 if mutation else 0)
    summary=json.loads(capsys.readouterr().out.splitlines()[-1])
    assert summary['specReplayComplete'] is (not mutation)
    assert summary['productionAcceptanceComplete'] is False
    assert path.read_bytes()==before
    if mutation:assert 'lr_ordering_bits' in summary['errors'][0]['detail']
