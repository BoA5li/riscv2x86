"""Bounded real machine facts and conditional object lemmas, never acceptance."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py import program_machine_evidence as machine,program_object_evidence as objects
from riscv2x86_py import program_validation_obligations as plan,native_captured_deployment as d
from .test_native_original_pipeline import adapted,backend_fixture


@pytest.fixture
def binary(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('real host GCC required for linked ELF facts')
    source=tmp_path/'leaf.S'
    source.write_text('.text\n.globl good\n.type good,@function\ngood:\nmov %rdi,%rax\nret\n.size good,.-good\n'
        '.globl bad\n.type bad,@function\nbad:\nmov $1,%rbx\nret\n.size bad,.-bad\n'
        '.globl memory\n.type memory,@function\nmemory:\nmov (%rdi),%rax\nret\n.size memory,.-memory\n'
        '.globl direction\n.type direction,@function\ndirection:\nstd\nret\n.size direction,.-direction\n'
        '.section .note.GNU-stack,"",@progbits\n')
    output=tmp_path/'leaf.so'
    subprocess.run([cc,'-shared','-fPIC',str(source),'-o',str(output)],check=True,capture_output=True)
    return output


def test_actual_machine_leaf_facts_and_independent_rederivation(binary,tmp_path):
    value=machine.acquire(binary,'good',tmp_path/'machine')
    facts=value['facts']
    assert facts['restrictedLeafPreservationVerified']
    assert facts['decodedByteCoverageComplete'] and not facts['machineAbiClosureVerified']
    assert not facts['candidateInstructionExecutionCoverageVerified']
    assert machine.check(tmp_path/'machine/result.json')==value
    value['facts']['machineAbiClosureVerified']=True
    changed=d.seal({k:v for k,v in value.items() if k!='machineEvidenceIdentity'},'machineEvidenceIdentity')
    (tmp_path/'machine/result.json').write_text(json.dumps(changed))
    with pytest.raises(ValueError,match='REDERIVATION'):machine.check(tmp_path/'machine/result.json')


@pytest.mark.parametrize('symbol',['bad','memory','direction'])
def test_register_or_memory_obligations_are_not_silently_ignored(binary,symbol):
    facts=machine.derive(binary.read_bytes(),symbol)
    assert not facts['restrictedLeafPreservationVerified']
    assert not facts['machineAbiClosureVerified']


def model():
    return {'schemaVersion':objects.MODEL,'variables':{},
        'allocations':{'allocation':{'size':32,'alignment':8,'startEpoch':0,'endEpoch':10,'initializedRanges':[]}},
        'views':{'one':{'allocation':'allocation','offset':0,'size':32},
                 'alias':{'allocation':'allocation','offset':0,'size':32}},
        'accesses':[{'sourceEffectId':'write','view':'one','offset':0,'width':8,'alignment':8,'kind':'write','epoch':1},
                    {'sourceEffectId':'read','view':'alias','offset':0,'width':8,'alignment':8,'kind':'read','epoch':2}]}


def test_object_alias_initialization_and_checked_conditional_scope(tmp_path):
    input_path=tmp_path/'model.json';input_path.write_text(json.dumps(model()))
    value=objects.acquire(input_path,tmp_path/'object-evidence')
    assert value['facts']['conditionalObjectRelationsVerified']
    assert not value['facts']['codeAccessBindingVerified'] and not value['facts']['legalObjectDomainVerified']
    assert objects.check(tmp_path/'object-evidence/result.json')==value
    value['facts']['legalObjectDomainVerified']=True
    changed=d.seal({k:v for k,v in value.items() if k!='objectEvidenceIdentity'},'objectEvidenceIdentity')
    (tmp_path/'object-evidence/result.json').write_text(json.dumps(changed))
    with pytest.raises(ValueError,match='REDERIVATION'):objects.check(tmp_path/'object-evidence/result.json')


@pytest.mark.parametrize('change',['uninitialized','bounds','alignment','lifetime'])
def test_bad_object_relation_has_a_counterexample_under_the_model(change):
    value=model();read=value['accesses'][1]
    if change=='uninitialized':read['offset']=8
    elif change=='bounds':read['offset']=32
    elif change=='alignment':read['offset']=1
    elif change=='lifetime':read['epoch']=10
    facts=objects.derive(value)
    assert not facts['conditionalObjectRelationsVerified']
    assert facts['obligations'][-1]['status']=='counterexample-under-model'


def test_affine_bounds_are_universal_over_declared_interval():
    value=model();value['variables']={'n':[0,4]};value['allocations']['allocation']['initializedRanges']=[[0,32]]
    value['accesses']=value['accesses'][1:];value['accesses'][0]['offset']={'constant':0,'terms':{'n':8}}
    facts=objects.derive(value)
    assert not facts['conditionalObjectRelationsVerified']
    assert facts['obligations'][-1]['counterexample']=={'n':'4'}
    value['variables']['n']=[0,3]
    assert objects.derive(value)['conditionalObjectRelationsVerified']


def test_program_plan_freezes_cells_and_separates_execution_preconditions(adapted,monkeypatch):
    from riscv2x86_py import native_original_pipeline as route
    root,prepared,_,raw=adapted;backend_fixture(monkeypatch,prepared,raw)
    route.translate(root/'prepared/result.json',root/'translation')
    contract=root/'declared-contract.json';contract.write_text('{"fixture":"scope-only-not-authority"}')
    scope={'schemaVersion':plan.SCOPE,**{k:str(contract) for k in (
        'entryContract','inputDomainContract','observationContract','trustBoundaryContract')},
        'requiredLevels':['L0','L1','L2'],'buildCells':[{'cellId':'explicit-cell','buildContract':str(contract)}]}
    path=root/'scope.json';path.write_text(json.dumps(scope))
    value=plan.acquire(root/'translation/result.json',path,root/'program-plan')
    assert plan.check(root/'program-plan/result.json')==value
    facts=value['facts'];assert facts['executionPreconditionsSeparatedFromPostconditions']
    assert not facts['programPrerequisitesVerified'] and not facts['canonicalInstructionCoverageVerified']
    assert any(o['phase']=='after-L1' and o['kind']=='actual-output-error-and-termination-relation' for o in facts['obligations'])
    scope['requiredLevels']=['L2']
    with pytest.raises(ValueError,match='LEVEL_ORDER'):plan.derive(root/'translation/result.json',scope)
