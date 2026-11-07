"""External definitions can be present while every behavioral obligation remains."""
from copy import deepcopy
from pathlib import Path
import json
import shutil
import subprocess
import pytest
from riscv2x86_py.native_external_providers import analyze,acquire,replay
from riscv2x86_py.native_elf_runtime import parse
from riscv2x86_py.native_runtime_basis import collect
from riscv2x86_py.project_build_records import identity


@pytest.fixture
def material(tmp_path):
    cc=shutil.which('gcc');readelf=shutil.which('readelf')
    if not cc or not readelf:pytest.skip('native GCC/readelf required')
    (tmp_path/'a.c').write_text('int external_api(int x){return x+1;}')
    subprocess.run([cc,'-shared','-fPIC','a.c','-Wl,-soname,libfixture.so','-o','libfixture.so'],cwd=tmp_path,check=True)
    (tmp_path/'root.c').write_text('extern int external_api(int); int entry(int x){return external_api(x);}')
    subprocess.run([cc,'-fno-pic','-fno-pie','-c','root.c','-o','root.o'],cwd=tmp_path,check=True)
    from riscv2x86_py.native_dependency_evidence import elf_symbols
    obj=elf_symbols((tmp_path/'root.o').read_bytes())
    dep={'rootElf':obj,'members':[],'targetElf':{'machine':243},
        'blockers':[{'reason':'external-contract-required','object':'root','symbol':'external_api'}],
        'inventoryIdentity':'protocol-parent-not-translation'}
    basis=collect([cc],[],[tmp_path/'libfixture.so'],readelf)
    return tmp_path,dep,basis


def test_definition_found_never_closes_contract(material):
    p,dep,basis=material
    from riscv2x86_py.project_compile_context import digest
    provider={'path':str(p/'libfixture.so'),'digest':digest(p/'libfixture.so'),'elf':parse((p/'libfixture.so').read_bytes())}
    result=analyze(dep,[provider]);assert result['candidateDefinitionCoverageComplete']
    item=result['externalObligations'][0]
    assert len(item['definitionCandidates'])==1 and item['targetNameCandidates']==[]
    assert not item['actualLinkBindingVerified'] and not item['typedBehaviorContractVerified']
    assert 'TYPED_BEHAVIOR_CONTRACT_REQUIRED' in item['pendingReasons']
    assert analyze(dep,[])['externalObligations'][0]['pendingReasons'][0]=='PROVIDER_DEFINITION_MISSING'
    assert analyze(dep,[provider,dict(provider,path='duplicate')])['externalObligations'][0]['pendingReasons'][0]=='PROVIDER_DEFINITION_AMBIGUOUS'


def test_inventory_receipt_replay_tamper_and_original_obligations(material,monkeypatch):
    # Parent replay is isolated here: this fixture is native metadata, not a
    # claimed RV64-to-x86 translation. The public path uses actual parent replay.
    import riscv2x86_py.native_external_providers as module
    p,dep,basis=material;monkeypatch.setattr(module,'replay_dependencies',lambda value:None)
    parent=p/'parent.json';parent.write_text(json.dumps(dep));runtime=p/'runtime.json';runtime.write_text(json.dumps(basis))
    out=p/'out';out.mkdir();result=acquire(parent,runtime,out)
    assert result['originalDependencyBlockers']==dep['blockers']
    assert len(result['blockers'])==1 and result['candidateDefinitionCoverageComplete']
    assert not result['semanticApproval'] and not result['actualLinkSelectionVerified']
    again=p/'again';again.mkdir()
    assert replay(result,out,again)['replayedBlockerCount']==1
    forged=deepcopy(result);forged['semanticApproval']=True
    forged['inventoryIdentity']=identity({k:v for k,v in forged.items() if k!='inventoryIdentity'})
    third=p/'third';third.mkdir()
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):replay(forged,out,third)
    blob=out/'elf-blobs'/result['providers'][0]['digest'][7:];blob.write_bytes(b'wrong')
    fourth=p/'fourth';fourth.mkdir()
    with pytest.raises(ValueError,match='ARCHIVED_ELF_CHANGED'):replay(result,out,fourth)


def test_changed_runtime_basis_file_cannot_be_reused(material,monkeypatch):
    import riscv2x86_py.native_external_providers as module
    p,dep,basis=material;monkeypatch.setattr(module,'replay_dependencies',lambda value:None)
    parent=p/'parent.json';parent.write_text(json.dumps(dep));runtime=p/'runtime.json';runtime.write_text(json.dumps(basis))
    (p/'libfixture.so').write_bytes(b'changed');out=p/'out';out.mkdir()
    with pytest.raises(ValueError,match='BOUND_FILE_CHANGED'):acquire(parent,runtime,out)


def test_actual_host_dependency_and_runtime_receipts(tmp_path):
    import os
    parent=os.environ.get('RV2X86_TEST_NATIVE_DEPENDENCIES')
    basis=os.environ.get('RV2X86_TEST_RUNTIME_BASIS')
    if not parent or not basis:
        pytest.skip('real host dependency inventory and runtime basis required')
    first=tmp_path/'first';first.mkdir();value=acquire(parent,basis,first)
    again=tmp_path/'again';again.mkdir();checked=replay(value,first,again)
    external=[b for b in value['originalDependencyBlockers'] if b['reason']=='external-contract-required']
    assert len(value['externalObligations'])==len(external)
    assert checked['replayedBlockerCount']==len(value['blockers'])
    assert not value['actualLinkSelectionVerified'] and not value['semanticApproval']


def test_parent_and_runtime_basis_blockers_are_not_dropped(material,monkeypatch):
    import riscv2x86_py.native_external_providers as module
    p,dep,basis=material;monkeypatch.setattr(module,'replay_dependencies',lambda value:None)
    dep['blockers'].append({'reason':'PARENT_UNRESOLVED'})
    basis['blockers'].append({'reason':'RUNTIME_QUERY_UNRESOLVED'})
    basis['basisIdentity']=identity({k:v for k,v in basis.items() if k!='basisIdentity'})
    parent=p/'parent.json';parent.write_text(json.dumps(dep));runtime=p/'runtime.json';runtime.write_text(json.dumps(basis))
    out=p/'out';out.mkdir();value=acquire(parent,runtime,out)
    assert {b['reason'] for b in value['blockers']}=={'EXTERNAL_CONTRACT_INCOMPLETE','PARENT_DEPENDENCY_BLOCKER','RUNTIME_BASIS_BLOCKER'}
