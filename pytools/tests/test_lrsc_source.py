from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from types import SimpleNamespace
import pytest

from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.lrsc_source import (LrScRuntimeEvidence, build_source_sequence,
    source_operands, reference_attempt, reference_prefix)
from riscv2x86_py.lrsc_sequence import SequenceError
from riscv2x86_py.pcode_ir import IRSummary
from riscv2x86_py.runtime_facts import (translation_runtime_facts_to_dict,
    translation_runtime_facts_from_dict)
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.shell_model import SourceShellModel
from riscv2x86_py.source_model import build_source_semantic_model
from riscv2x86_py.source_operand_coverage import snapshot
from riscv2x86_py.route_authority import content_identity
from tests.test_lrsc_compiler_binding import fixture
from tests.test_lrsc_sequence_contract import code


def ingress(bits=64, slot_order=(0,1,2,3,4,5), registers=(5,6,9,10,11), **encoding):
    sequence, authority, context = fixture(bits, slot_order, registers)
    raw = context['frontend_fragment']
    def operand(d, output):
        return AsmOperand(**d, isOutput=output, isEarlyClobber='&' in d['constraint'])
    fragment = AsmFragment(id=authority['fragmentId'], beginOffset=100, endOffset=140,
        outputs=[operand(d, True) for d in raw['outputs']],
        inputs=[operand(d, False) for d in raw['inputs']],
        isVolatile=True, clobbers=['memory'], compilerFragmentAuthority=authority)
    runtime = context['runtime_facts']
    machine = code(bits, registers=registers, **encoding)
    evidence = LrScRuntimeEvidence.produce(fragment, machine, base_address=0,
        xlen_bits=64, runtime_facts=runtime, source_digest=authority['sourceDigest'])
    return fragment, replace(runtime, lrsc_sequence_evidence=evidence), machine


def model_for(fragment, runtime, machine):
    # Unknown control summaries must be closed only for the byte-owned region.
    summary = IRSummary(is_single_block=False, has_branch=True,
        has_call_or_return=False, has_memory_barrier=False, has_atomic=True,
        reads_regs=set(), writes_regs=set(), reads_mem=True, writes_mem=True)
    return build_source_semantic_model(fragment=fragment, blocks=(),
        cfg=CFGResult(ok=True), summary=summary, xlen=64, runtime_facts=runtime,
        machine_code=machine)


@pytest.mark.parametrize('bits', [32,64])
@pytest.mark.parametrize('order', [(0,1,2,3,4,5),(3,2,0,1,5,4)])
@pytest.mark.parametrize('registers',[(5,6,9,10,11),(11,12,13,14,15)])
def test_formal_ingress_closes_all_slots_without_atomic_effect_approval(bits,order,registers):
    fragment, runtime, machine = ingress(bits, order, registers)
    restored = translation_runtime_facts_from_dict(translation_runtime_facts_to_dict(runtime))
    assert restored.lrsc_sequence_evidence == runtime.lrsc_sequence_evidence
    model = model_for(fragment, restored, machine)
    assert model.lrsc_sequence.complete and model.operands.complete
    assert snapshot(fragment.id, model)['unmodeledIndexes'] == []
    by_index = {o.source_operand_index:o for o in model.operands.operands}
    memory = by_index[order.index(3)]
    assert memory.width_bits == bits and memory.access.value == 'read_write'
    assert memory.kind.value == 'memory'
    assert memory.address.memory_object_identity
    assert memory.address.atomic_authority_identity is None
    assert not runtime.atomic_memory_objects and not model.atomic.complete
    assert model.operation.has_return is False
    data = model.lrsc_sequence.to_dict()
    assert data['semanticApproval'] is False and data['sourceStateModelComplete']
    assert data['role_operand_indexes'] == dict(model.lrsc_sequence.role_operand_indexes)
    assert not data['terminationProved'] and not data['orderingRefinementProved']


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('status',[0,1,2,17,(1<<64)-1])
def test_attempt_models_nonzero_failure_codes_and_no_failure_store(bits,status):
    fragment,runtime,machine=ingress(bits)
    model=build_source_sequence(fragment,runtime,xlen_bits=64,machine_code=machine)
    row=reference_attempt(model,loaded_value=0x80000000,input_value=1,sc_status=status)
    assert row['old']==(0xffffffff80000000 if bits==32 else 0x80000000)
    assert row['status']==status and row['successful']==(status==0)
    assert row['storeValue']==(0x80000001 if status==0 else None)
    assert row['evidenceKind']=='reference-calculation-not-observation'


def test_retries_reload_new_values_and_only_final_success_supplies_outputs():
    fragment,runtime,machine=ingress(32)
    model=build_source_sequence(fragment,runtime,xlen_bits=64,machine_code=machine)
    prefix=[{'loadedValue':1,'scStatus':17},{'loadedValue':0x7fffffff,'scStatus':2}]
    pending=reference_prefix(model,prefix,input_value=1)
    assert not pending['executionComplete'] and pending['outputs'] is None
    assert pending['successfulStoreCount']==0
    done=reference_prefix(model,prefix+[{'loadedValue':0xffffffff,'scStatus':0}],input_value=1)
    assert done['outputs']=={'old':(1<<64)-1,'next':0,'status':0}
    assert done['successfulStoreCount']==1 and not done['terminationProved']
    with pytest.raises(SequenceError):
        reference_prefix(model,[{'loadedValue':0,'scStatus':0}]*2,input_value=1)
    assert not reference_prefix(model,[],input_value=0)['executionComplete']


@pytest.mark.parametrize('mutation',['fragment','compiler','map','width','machine','xlen','shell','plain'])
def test_stale_or_substituted_evidence_cannot_close_the_source_model(mutation):
    fragment,runtime,machine=ingress()
    if mutation=='fragment':fragment.id='another'
    if mutation=='compiler':fragment.compilerFragmentAuthority=deepcopy(fragment.compilerFragmentAuthority);fragment.compilerFragmentAuthority['authorityIdentity']='stale'
    if mutation=='map':runtime=replace(runtime,rv_to_operand_index={**runtime.rv_to_operand_index,'t0':1})
    if mutation=='width':runtime=replace(runtime,operand_width_bits={**runtime.operand_width_bits,3:32})
    if mutation=='machine':machine=bytes([machine[0]^1])+machine[1:]
    if mutation=='shell':fragment.isVolatile=False
    if mutation=='plain':
        with pytest.raises(ValueError):replace(runtime,lrsc_sequence_evidence=runtime.lrsc_sequence_evidence.to_dict())
        return
    with pytest.raises(ValueError):
        build_source_sequence(fragment,runtime,xlen_bits=32 if mutation=='xlen' else 64,machine_code=machine)


@pytest.mark.parametrize('field', ['binding','sequence','registerBindings','operandWidths','extra'])
def test_rehashed_serialized_ingress_is_replayed_not_trusted(field):
    fragment,runtime,machine=ingress()
    data=runtime.lrsc_sequence_evidence.to_dict()
    if field=='binding':data[field]['semanticApproval']=True
    if field=='sequence':data[field]['operation']='fetch_xor';data[field]['sequenceIdentity']=content_identity({k:v for k,v in data[field].items() if k!='sequenceIdentity'})
    if field=='registerBindings':data[field]['t0']=1
    if field=='operandWidths':data[field]['3']=32
    if field=='extra':data[field]=True
    data['evidenceIdentity']=content_identity({k:v for k,v in data.items() if k!='evidenceIdentity'})
    with pytest.raises(ValueError):LrScRuntimeEvidence.from_dict(data)


def test_published_source_diagnostic_is_not_an_approval_artifact():
    from riscv2x86_py.translate import _output
    fragment,runtime,machine=ingress()
    source=model_for(fragment,runtime,machine)
    context=SimpleNamespace(decision=source.preservation,xlen=64,instruction_count=4,
        blocks=[],sourceModel=source,fragment=fragment)
    # The diagnostic emitter can be checked independently of backend lifting.
    result=_output(context=context,route='unsupported',kind='unsupported',replacement='')
    record=next(r for r in result.metadata['routeAuthorityDiagnostics'] if r['failureStage']=='lrsc_source_sequence')
    assert not record['accepted'] and record['inputsPayload']['sourceStateModelComplete']
    assert 'SOURCE_OPERAND_COVERAGE_INCOMPLETE' not in result.reasonCodes
    assert not result.metadata.get('approvalArtifact')


@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('operation',['fetch_add','fetch_and','fetch_or','fetch_xor'])
@pytest.mark.parametrize('compressed',[False,True])
@pytest.mark.parametrize('order',[(False,False,False,False),(True,False,False,True),(True,True,True,True)])
def test_source_sequence_domain_retains_operation_and_raw_ordering(bits,operation,compressed,order):
    fragment,runtime,machine=ingress(bits,operation=operation,compressed=compressed,order=order)
    model=build_source_sequence(fragment,runtime,xlen_bits=64,machine_code=machine)
    assert model.operation==operation
    assert model.lr_ordering_bits==order[:2] and model.sc_ordering_bits==order[2:]
    assert model.success_exit==(14 if compressed else 16)
    row=reference_attempt(model,loaded_value=0xffffffff,input_value=1,sc_status=0)
    mask=(1<<bits)-1
    old=(1<<64)-1 if bits==32 else 0xffffffff
    wanted={'fetch_add':old+1,'fetch_and':old&1,'fetch_or':old|1,'fetch_xor':old^1}[operation]
    assert row['next']==wanted&((1<<64)-1) and row['storeValue']==wanted&mask


def test_word_and_full_alu_keep_distinct_next_but_same_store():
    models=[]
    for word in (False,True):
        f,r,m=ingress(32,word_alu=word)
        models.append(build_source_sequence(f,r,xlen_bits=64,machine_code=m))
    rows=[reference_attempt(m,loaded_value=0x7fffffff,input_value=1,sc_status=0) for m in models]
    assert rows[0]['storeValue']==rows[1]['storeValue']==0x80000000
    assert rows[0]['next']==0x80000000 and rows[1]['next']==0xffffffff80000000


def test_reservation_success_is_not_inferred_from_value_equality():
    f,r,m=ingress();model=build_source_sequence(f,r,xlen_bits=64,machine_code=m)
    with pytest.raises(SequenceError,match='RESERVATION_INVALID'):
        reference_attempt(model,loaded_value=1,input_value=0,sc_status=0,reservation_valid=False)
    for valid in (False,True):
        row=reference_attempt(model,loaded_value=1,input_value=0,sc_status=7,reservation_valid=valid)
        assert row['storeValue'] is None and not row['reservationAfterSc']


def test_immutable_snapshot_is_detached_from_caller_maps_and_reloaded_copies():
    fragment,runtime,machine=ingress()
    original=runtime.lrsc_sequence_evidence.evidence_json
    exported=runtime.lrsc_sequence_evidence.to_dict();exported['binding']['semanticApproval']=True
    assert runtime.lrsc_sequence_evidence.evidence_json==original
    with pytest.raises(FrozenInstanceError):runtime.lrsc_sequence_evidence.evidence_json='changed'
    assert build_source_sequence(fragment,runtime,xlen_bits=64,machine_code=machine).complete


def test_normal_translate_entry_keeps_target_gate_closed(monkeypatch):
    import importlib
    t=importlib.import_module('riscv2x86_py.translate')
    f,r,m=ingress()
    summary=IRSummary(is_single_block=False,has_branch=True,has_call_or_return=False,
        has_memory_barrier=False,has_atomic=True,reads_regs=set(),writes_regs=set(),
        reads_mem=True,writes_mem=True)
    context=t.TranslationContext(fragment=f,blocks=[],cfg=CFGResult(ok=True),summary=summary,
        machine_code=m,xlen=64,shell=None,bindings=None,runtimeFacts=r)
    monkeypatch.setattr(t,'_create_context',lambda **kwargs:(context,''))
    result=t.translate(f,None,summary,m,64,blocks=[],cfg=context.cfg,runtime_facts=r,
        target_semantic_catalog=t.TargetSemanticCatalog(frozenset(),frozenset(),'no-lrsc-contract'))
    assert result.kind=='unsupported' and 'lock cmpxchg' not in result.replacement
    assert not result.metadata.get('approvalArtifact')
    assert context.sourceModel.operands.complete and context.sourceModel.lrsc_sequence.complete
    assert not result.metadata.get('approvalArtifact')


def test_incomplete_lift_summary_cannot_erase_machine_atomicity():
    f,r,m=ingress()
    summary=IRSummary(is_single_block=True,has_branch=False,has_call_or_return=False,
        has_memory_barrier=False,has_atomic=False,reads_regs=set(),writes_regs=set(),
        reads_mem=False,writes_mem=False)
    source=build_source_semantic_model(fragment=f,blocks=(),cfg=CFGResult(ok=True),
        summary=summary,xlen=64,runtime_facts=r,machine_code=m)
    assert source.memory.has_atomic and source.memory.reads_memory and source.memory.writes_memory
    assert source.atomic.present and not source.atomic.complete
    assert source.lrsc_sequence.complete


def test_single_amo_effect_authority_cannot_be_reused_for_sequence():
    from riscv2x86_py.runtime_facts import AtomicMemoryObjectRuntimeFact
    f,r,m=ingress()
    fact=AtomicMemoryObjectRuntimeFact('object:unrelated','c.default',8)
    with pytest.raises(SequenceError,match='CONFLICTING_SINGLE_AMO_AUTHORITY'):
        model_for(f,replace(r,atomic_memory_objects={3:fact}),m)


def test_decoder_owned_registers_are_distinct_from_lift_reservation_pseudostate():
    f,r,m=ingress()
    summary=IRSummary(is_single_block=False,has_branch=True,has_call_or_return=False,
        has_memory_barrier=False,has_atomic=True,reads_regs={'opaque_lift_reservation'},
        writes_regs={'opaque_lift_status'},reads_mem=True,writes_mem=True)
    model=build_source_semantic_model(fragment=f,blocks=(),cfg=CFGResult(ok=True),
        summary=summary,xlen=64,runtime_facts=r,machine_code=m)
    assert model.registers.writes_registers==frozenset({'t0','t1','s1'})
    assert not model.completeness.missing_operand_binding_registers
    assert not model.completeness.missing_output_binding_registers
    assert 'opaque_lift_status' in summary.writes_regs  # input ledger unchanged
    assert model.lrsc_sequence.to_dict()['reservationValidity']


def test_bound_xzero_cannot_masquerade_as_arbitrary_c_input():
    with pytest.raises(SequenceError,match='CONSTANT_INPUT_REQUIRES_CONSTANT_SLOT_CONTRACT'):
        ingress(registers=(5,6,9,10,0))


def test_compact_inspector_reads_serialized_stages_and_never_claims_acceptance(tmp_path):
    from pathlib import Path
    import runpy
    f,r,m=ingress(32)
    model=model_for(f,r,m)
    payload=model.lrsc_sequence.to_dict()
    record={'failureStage':'lrsc_source_sequence','inputsPayload':payload,
        'reasonCode':'LRSC_SOURCE_SEQUENCE_MODEL_COMPLETE_TARGET_PROOF_REQUIRED'}
    directory=tmp_path/'case';directory.mkdir()
    report=directory/'translated_report.json'
    report.write_text(json.dumps({'findings':[{'fragment':{'id':f.id},
        'translationOutcome':'unsupported','routeAuthorityDiagnostics':[record],
        'translationRuntimeFacts':translation_runtime_facts_to_dict(r),
        'l2SemanticProfile':{'operandShape':{'complete':True}}}]}))
    script=Path(__file__).resolve().parents[2]/'experiment/inspect_lrsc_source.py'
    collect=runpy.run_path(str(script))['collect']
    data=collect(tmp_path)
    assert not data['errors'] and len(data['records'])==1
    row=data['records'][0]
    assert row['sourceStateModelComplete'] and row['runtimeEvidencePresent']
    assert row['memoryWidthBits']==32 and not row['semanticApproval']
    assert row['translationOutcome']=='unsupported' and not row['approvalArtifactPresent']
    report.write_text('{broken')
    assert collect(tmp_path)['errors']


@pytest.mark.parametrize('field',['hasAsmGoto','hasExternalControlFlow','hasMultipleExits','hasNonLocalControlDependency'])
def test_external_control_requires_a_separate_source_contract(field):
    f,r,m=ingress()
    setattr(f,field,True)
    evidence=LrScRuntimeEvidence.produce(f,m,base_address=0,xlen_bits=64,
        runtime_facts=replace(r,lrsc_sequence_evidence=None),source_digest=f.compilerFragmentAuthority['sourceDigest'])
    with pytest.raises(SequenceError,match='EXTERNAL_CONTROL_UNSUPPORTED'):
        build_source_sequence(f,replace(r,lrsc_sequence_evidence=evidence),xlen_bits=64,machine_code=m)


@pytest.mark.parametrize('values',[{'loaded_value':-1,'input_value':0,'sc_status':0},
    {'loaded_value':1<<32,'input_value':0,'sc_status':0},
    {'loaded_value':0,'input_value':1<<64,'sc_status':0},
    {'loaded_value':0,'input_value':0,'sc_status':True}])
def test_reference_values_cannot_silently_truncate_invalid_observations(values):
    f,r,m=ingress(32);model=build_source_sequence(f,r,xlen_bits=64,machine_code=m)
    with pytest.raises(SequenceError,match='VALUE_DOMAIN_INVALID'):reference_attempt(model,**values)


def test_real_report_roundtrip_and_local_control_surface(tmp_path):
    from riscv2x86_py.schema import Finding, AsmControlFlowSurface, save_report, load_report
    f,r,m=ingress(32)
    f.controlFlow=AsmControlFlowSurface(style='LocalCFG',localLabels=['1'],branchTargets=['1b'])
    evidence=LrScRuntimeEvidence.produce(f,m,base_address=0,xlen_bits=64,
        runtime_facts=replace(r,lrsc_sequence_evidence=None),source_digest=f.compilerFragmentAuthority['sourceDigest'])
    r=replace(r,lrsc_sequence_evidence=evidence)
    path=tmp_path/'report.json'
    save_report([Finding(fragment=f,translationRuntimeFacts=r)],str(path))
    restored=load_report(str(path))[0]
    source=model_for(restored.fragment,restored.translationRuntimeFacts,m)
    assert source.lrsc_sequence.complete and source.operands.complete
    assert source.lrsc_sequence.memory_width_bits==32


def test_nonlocal_control_surface_is_not_a_closed_retry_loop():
    from riscv2x86_py.schema import AsmControlFlowSurface
    f,r,m=ingress();f.controlFlow=AsmControlFlowSurface(style='LocalCFG',hasNonLocalControl=True)
    evidence=LrScRuntimeEvidence.produce(f,m,base_address=0,xlen_bits=64,
        runtime_facts=replace(r,lrsc_sequence_evidence=None),source_digest=f.compilerFragmentAuthority['sourceDigest'])
    with pytest.raises(SequenceError,match='EXTERNAL_CONTROL_UNSUPPORTED'):
        build_source_sequence(f,replace(r,lrsc_sequence_evidence=evidence),xlen_bits=64,machine_code=m)
