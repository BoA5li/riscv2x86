"""Typed semantic/proof tests; no simulated QEMU/concurrency acceptance."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import pytest

from riscv2x86_py.fence_semantics import refinement, describe
from riscv2x86_py.l2_fence_ordering import fence_proof_facts_from_dict, fence_proof_facts_from_source_model
from riscv2x86_py.l3_trace_support import identity
from tests.test_l2_fence_ordering_relations import _facts


@pytest.mark.parametrize('source,target,expected', [
    ((True,True,'rw_rw','system'),(True,True,'rw_rw','system'),'exact'),
    ((False,True,'rw_rw','system'),(True,True,'rw_rw','system'),'strengthened'),
    ((True,True,'rw_rw','system'),(False,True,'rw_rw','system'),None),
    ((True,True,'rw_rw','system'),(True,False,'rw_rw','system'),None),
    ((True,True,'rw_rw','system'),(True,True,'seq_cst','system'),None),
    ((True,True,'seq_cst','system'),(True,True,'rw_rw','system'),None),
    ((True,True,'rw_rw','thread'),(True,True,'rw_rw','system'),None),
    ((True,False,'seq_cst','compiler'),(True,True,'seq_cst','system'),'strengthened'),
    ((True,True,'acquire','system'),(True,True,'release','system'),None),
    ((True,True,'seq_cst','system'),(True,True,'acquire','system'),None),
    ((True,True,'acquire','thread'),(True,True,'seq_cst','system'),None),
    ((1,True,'rw_rw','system'),(True,True,'rw_rw','system'),None),
])
def test_refinement_is_proven_not_inequality(source,target,expected):
    assert refinement(source,target) == expected


def test_source_fence_is_not_c_seq_cst_and_target_is_versioned():
    from tests.test_phase6_full_memory_fence_contract import _model,_environment
    from riscv2x86_py.pcode_ir import FenceSet
    from riscv2x86_py.source_model import SourceFenceOrdering,SourceMemoryOrdering
    from riscv2x86_py.candidate_plans import generate_candidate_plans
    from riscv2x86_py.phase6c_constraints import derive_target_constraints
    model = _model(pred=FenceSet.R|FenceSet.W,succ=FenceSet.R|FenceSet.W)
    assert model.barrier.ordering is SourceFenceOrdering.RW_RW
    assert not isinstance(model.barrier.ordering,SourceMemoryOrdering)
    plan = next(p for p in generate_candidate_plans(model) if p.plan_id == 'x86.barrier.mfence')
    assert plan.metadata['renderer_semantic_contract_id'] == 'x86.gnu-att.mfence.ordinary-rw.v2'
    derived = derive_target_constraints(source_model=model,candidate_plan=plan,target_environment=_environment())
    assert derived.success
    # Changed source domains cannot inherit the reviewed ordinary-RW target.
    weaker = replace(model,barrier=replace(model.barrier,ordering=SourceMemoryOrdering.ACQUIRE))
    assert not derive_target_constraints(source_model=weaker,candidate_plan=plan,target_environment=_environment()).success


def test_native_fence_facts_keep_context_anchors_out_of_dynamic_effects():
    barrier = SimpleNamespace(present=True,complete=True,instruction_serializing=False,
        compiler_barrier=True,hardware_memory_barrier=True,
        ordering=SimpleNamespace(value='rw_rw'),scope=SimpleNamespace(value='system'))
    facts = fence_proof_facts_from_source_model('fragment:renamed',SimpleNamespace(barrier=barrier),
        {'rendererSemanticContractId':'x86.gnu-att.mfence.ordinary-rw.v2',
         'rendererContractId':'registered-mfence','rendererVersion':'2'})
    raw = facts.to_dict()
    assert facts.schema_version.endswith('v3') and facts.relation_kind == 'exact'
    assert raw['effectRoles'] == {'before:read':'proof-context-anchor','after:write':'proof-context-anchor','fence:0':'source-operation'}
    source = raw['sourceOrderingContract']
    assert source['orderedPairs'] == [['R','R'],['R','W'],['W','R'],['W','W']]
    assert source['globalSequentialConsistencyClaimed'] is False
    assert fence_proof_facts_from_dict(raw) == facts


@pytest.mark.parametrize('mutation',['role','pairs','io','schema','target'])
def test_rehashed_facts_cannot_change_semantic_domain(mutation):
    raw = _facts().to_dict()
    if mutation == 'role': raw['effectRoles']['before:read']='source-operation'
    if mutation == 'pairs': raw['sourceOrderingContract']['orderedPairs']=[['W','R']]
    if mutation == 'io': raw['sourceOrderingContract']['memoryDomain']='device-io'
    if mutation == 'schema': raw['schemaVersion']='riscv2x86.l2-fence-proof-facts.v2'
    if mutation == 'target': raw['targetHardwareOrdering']=False
    raw['factsIdentity']=identity({k:v for k,v in raw.items() if k!='factsIdentity'})
    # Serialized domain equality is checked independently of hashes.
    with pytest.raises(ValueError): fence_proof_facts_from_dict(raw)


@pytest.mark.parametrize('changes',[
    {'target_hardware_ordering':False}, {'target_compiler_ordering':False},
    {'target_ordering':'acquire'}, {'target_scope':'compiler'},
    {'relation_kind':'exact'},
])
def test_complete_fence_fact_cannot_authorize_weak_or_mismatched_target(changes):
    with pytest.raises(ValueError): _facts(**changes)


def test_atomic_obligations_replay_dedicated_authority_and_require_real_evidence(tmp_path):
    from tests.test_l3_atomic_eligibility import atomic_fixture
    from riscv2x86_py.l3_property_obligations import analyze,validate
    from riscv2x86_py.l3_execution_plan import build
    f,functions=atomic_fixture(tmp_path)
    ob=analyze(f,functions);sync=ob['synchronizationObligations']
    assert validate(ob)==ob and sync['basisComplete']
    assert sync['mechanismFamily']=='atomic-rmw'
    assert sync['basis']['operation']['width_bits']==64
    props={p['propertyId']:p['evidenceKinds'] for p in sync['requiredSubproperties']}
    assert props['sync.atomic-outcome']==['actual-input-output','object-relative-memory']
    assert 'actual-machine-region' in props['sync.atomic-mechanism']
    assert props['sync.ordering-contract']==['approved-ordering-refinement']
    plan=build([f],functions,{'memory','control','scalar-program','unavailable'})
    assert not plan['complete']
    assert plan['members'][0]['requiredSynchronizationCapabilities']==sorted(props)


@pytest.mark.parametrize('mutation',['drop','evidence','binding','role','limits'])
def test_rehashed_sync_obligations_cannot_weaken_required_evidence(tmp_path,mutation):
    from tests.test_l3_atomic_eligibility import atomic_fixture
    from riscv2x86_py.l3_property_obligations import analyze,validate
    f,functions=atomic_fixture(tmp_path);ob=analyze(f,functions);sync=ob['synchronizationObligations']
    if mutation=='drop':sync['requiredSubproperties']=[p for p in sync['requiredSubproperties'] if p['propertyId']!='sync.atomic-mechanism']
    if mutation=='evidence':sync['requiredSubproperties'][0]['evidenceKinds']=['output-equality']
    if mutation=='binding':sync['proofIdentity']=identity('unrelated-proof')
    if mutation=='role':sync['requiredSubproperties'][0]['required']=False
    if mutation=='limits':sync['declaredLimitations']=[]
    sync['obligationIdentity']=identity({k:v for k,v in sync.items() if k!='obligationIdentity'})
    ob['obligationIdentity']=identity({k:v for k,v in ob.items() if k!='obligationIdentity'})
    with pytest.raises(ValueError):validate(ob)


def test_multi_scalar_dispatch_cannot_erase_synchronization(tmp_path):
    from tests.test_l3_program_regions import fixture
    from riscv2x86_py.l3_execution_plan import build
    _,findings,function=fixture(tmp_path)
    for f in findings:
        profile=f['l2SemanticProfile'];profile['orderingShape']['memoryBarrier']=True
        profile['profileIdentity']=identity({k:v for k,v in profile.items() if k!='profileIdentity'})
        f['approvalArtifact']['l2SemanticProfileIdentity']=profile['profileIdentity']
    plan=build(findings,[function],{'scalar-program'})
    assert not plan['complete']
    for member in plan['members']:
        assert member['mechanism']=='unavailable'
        assert 'synchronization' in {p['dimension'] for p in member['obligations']['requiredProperties']}
        assert member['requiredSynchronizationCapabilities']


def test_pure_scalar_obligation_schema_stays_compatible(tmp_path):
    from tests.test_l3_scalar_trace import finding
    from riscv2x86_py.l3_property_obligations import analyze
    ob=analyze(finding(tmp_path))
    assert ob['schemaVersion']=='riscv2x86.l3-property-obligations.v1'
    assert 'synchronizationObligations' not in ob


def test_normal_translation_catalog_reaches_new_fence_proof_and_renderer():
    from tests.test_phase6_full_memory_fence_contract import _summary,_environment
    from tests.test_phase6_rv64_add_contract import _IngressLift
    from riscv2x86_py.pcode_ir import FenceSet,Block,CanonicalInsn
    from riscv2x86_py.cfg import CFGResult,CFGNode
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.schema import AsmFragment
    from riscv2x86_py.translate import translate
    summary=_summary(pred=FenceSet.R|FenceSet.W,succ=FenceSet.R|FenceSet.W)
    block=Block(addr=0x1000,ops=[],summary=summary,instructions=[
        CanonicalInsn(addr=0x1000,size=4,barrier_info=summary.barrier_info)])
    result=translate(frag=AsmFragment(id='renamed:fence',rawAsmText='fence rw,rw',clobbers=['memory'],isVolatile=True),
        lift=_IngressLift(),summary=summary,machine_code=bytes.fromhex('0f003003'),xlen=64,blocks=(block,),
        cfg=CFGResult(ok=True,entry=0x1000,nodes={0x1000:CFGNode(addr=0x1000,size=4,instr_addrs=[0x1000])}),
        runtime_facts=TranslationRuntimeFacts(),target_environment=_environment())
    assert result.kind=='x86_inline_asm', (result.kind,result.notes,result.reasonCodes)
    approval=result.metadata['approvalArtifact']
    assert approval['rendererSemanticContractId']=='x86.gnu-att.mfence.ordinary-rw.v2'
    facts=fence_proof_facts_from_dict(approval['l2FenceProofFacts'])
    assert facts.source_ordering==facts.target_ordering=='rw_rw'
    assert 'SourceFenceOrdering.RW_RW' in approval['sourceModelId']


def test_complete_isa_fence_cannot_be_recast_as_compiler_or_visibility_barrier():
    from tests.test_phase6_full_memory_fence_contract import _model
    from riscv2x86_py.pcode_ir import FenceSet
    barrier=_model(pred=FenceSet.R|FenceSet.W,succ=FenceSet.R|FenceSet.W).barrier
    for changes in ({'hardware_memory_barrier':False},{'instruction_serializing':True},{'speculation_control':True}):
        with pytest.raises(ValueError):replace(barrier,**changes)


def test_rehashed_atomic_record_cannot_turn_operation_into_context_anchor(tmp_path):
    from tests.test_l3_atomic_eligibility import atomic_fixture
    from riscv2x86_py.l3_property_obligations import analyze,validate
    f,functions=atomic_fixture(tmp_path);ob=analyze(f,functions);sync=ob['synchronizationObligations']
    sync['effectRoles']={k:'proof-context-anchor' for k in sync['effectRoles']}
    sync['obligationIdentity']=identity({k:v for k,v in sync.items() if k!='obligationIdentity'})
    ob['obligationIdentity']=identity({k:v for k,v in ob.items() if k!='obligationIdentity'})
    with pytest.raises(ValueError,match='ROLE_MISMATCH'):validate(ob)
