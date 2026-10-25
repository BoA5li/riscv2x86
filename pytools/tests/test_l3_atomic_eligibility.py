"""Atomic proof/compiler joins classify obligations, never invent an observer."""
import pytest

from riscv2x86_py.l3_property_obligations import analyze
from riscv2x86_py.l3_trace_intent import produce
from riscv2x86_py.l3_trace_support import identity, digest
from tests.test_l3_scalar_trace import request


def atomic_fixture(tmp_path):
    from tests.test_l2_atomic_production import atomic_finding
    from riscv2x86_py.l2_semantic_profile import profile_from_source_model
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    f,functions,model,_=atomic_finding(expression=True)
    f['l2SemanticProfile']=profile_from_source_model(f['fragment']['id'],model).to_dict()
    f['approvalArtifact'].update(architectureSemanticsPreserved=True,shellSemanticsPreserved=True)
    f['translationOutcome']='emitted';f['sourceDigest']=functions[0]['sourceDigest']
    frontend=tmp_path/'frontend';frontend.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},functions,frontend)==1
    program=identity({'schemaVersion':'riscv2x86.automatic-program.v1','producerDigest':digest(frontend)})
    boundaries,_,_=materialize_fragment_execution_authority([f],functions[0],program)
    f['approvalArtifact']['l2FragmentOperandBoundary']=boundaries[f['fragment']['id']].to_dict()
    assert not boundaries[f['fragment']['id']].complete
    return f,functions


def test_atomic_dedicated_authority_not_generic_boundary_is_required(tmp_path):
    f,functions=atomic_fixture(tmp_path);ob=analyze(f,functions)
    assert [p['dimension'] for p in ob['requiredProperties']]==['access_pattern','synchronization']
    req=request(f);req['candidates'][0]['compilerFunctions']=functions
    req['requestIdentity']=identity({k:v for k,v in req.items() if k!='requestIdentity'})
    response=produce(req)
    assert not response['profiles'][0]['complete']
    assert response['profiles'][0]['requiredProperties']==ob['requiredProperties']
    assert response['dispositions'][0]['status']=='unsupported'
    assert response['dispositions'][0]['reasonCodes']==['L3_TRACE_REQUIRED_MECHANISM_UNAVAILABLE:synchronization']
    assert not f['approvalArtifact']['l2FragmentOperandBoundary']['complete']


@pytest.mark.parametrize('mutation',['snapshot','function','source','program','boundary','type','object','proof','persisted-only'])
def test_atomic_independent_replay_rejects_inconsistent_authority(tmp_path,mutation):
    f,functions=atomic_fixture(tmp_path);a=f['approvalArtifact']
    if mutation=='snapshot':functions=[]
    if mutation=='function':functions[0]['functionId']=identity('wrong')
    if mutation=='source':functions[0]['sourceDigest']=identity('wrong')
    if mutation=='program':a['l2FragmentOperandBoundary']['programId']=identity('wrong')
    if mutation=='boundary':a['l2FragmentOperandBoundary']['functionId']=identity('wrong')
    if mutation=='type':f['fragment']['compilerFragmentAuthority']['compilerTypeBindings']['0']['compilerType']['widthBits']=32
    if mutation=='object':a['l2AtomicProofFacts']['atomicOperation']['memory_object_identity']=identity('wrong')
    if mutation=='proof':a['proofIdentity']=identity('wrong')
    if mutation=='persisted-only':
        a['l2MaterializationDecision']['executable']=True
        a['l2AtomicProofFacts']=None
    with pytest.raises((ValueError,KeyError,TypeError)):analyze(f,functions)


def test_atomic_snapshot_is_mandatory_even_with_persisted_l2_pass(tmp_path):
    f,_=atomic_fixture(tmp_path)
    with pytest.raises(ValueError,match='SNAPSHOT_REQUIRED'):analyze(f)
