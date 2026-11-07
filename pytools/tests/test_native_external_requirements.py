from copy import deepcopy
import json
import shutil
import subprocess
import pytest
from riscv2x86_py.native_external_requirements import reference_sites, derive
from riscv2x86_py.native_elf_runtime import parse
from riscv2x86_py.native_dependency_evidence import bytes_digest
from riscv2x86_py.project_build_records import identity


def test_general_function_object_references_and_no_name_authority(tmp_path):
    cc = shutil.which('gcc')
    if not cc:pytest.skip('native compiler required')
    (tmp_path/'root.c').write_text('extern int arbitrary_data; extern int arbitrary_api(int);'
                                 'int owner(void){return arbitrary_api(arbitrary_data);}')
    subprocess.run([cc,'-c',str(tmp_path/'root.c'),'-o',str(tmp_path/'root.o')],check=True)
    raw = (tmp_path/'root.o').read_bytes()
    assert reference_sites(raw,'arbitrary_data')['sites'][0]['containingFunctions'][0]['name']=='owner'
    assert reference_sites(raw,'arbitrary_api')['sites'][0]['containingFunctions'][0]['name']=='owner'
    assert not reference_sites(raw,'absent')['referenceLocationsComplete']
    candidate = tmp_path/'candidate.json';candidate.write_text(json.dumps({'sourceObjectDigest':bytes_digest(raw)}))
    dep = {'inventoryIdentity':'parent','members':[],'candidatePath':str(candidate)}
    obligations = []
    for name, typ in [('arbitrary_api',2),('arbitrary_data',1)]:
        obligations.append({'originalObligation':{'object':'root','symbol':name},
            'obligationIdentity':name,'definitionCandidates':[{'symbol':{'type':typ}}],
            'targetNameCandidates':[]})
    body = {'dependencyInventoryIdentity':'parent','externalObligations':obligations,
            'blockers':[{'reason':'existing-obligation'}]}
    provider = dict(body,inventoryIdentity=identity(body))
    result = derive(provider,dep,raw,b'!<arch>\n')
    assert len(result['requirements'])==2 and result['originalProviderBlockers']==provider['blockers']
    assert 'COMPILER_FUNCTION_TYPE' in result['requirements'][0]['requiredEvidence']
    assert 'COMPILER_OBJECT_TYPE' in result['requirements'][1]['requiredEvidence']
    assert all(r['status']=='blocked' for r in result['requirements'])
    assert not result['externalContractClosureComplete'] and not result['semanticApproval']
    forged = deepcopy(provider);forged['dependencyInventoryIdentity']='other'
    forged['inventoryIdentity']=identity({k:v for k,v in forged.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='PARENT_MISMATCH'):derive(forged,dep,raw,b'!<arch>\n')


def test_requirements_receipt_replays_and_rehashed_claim_rejects(tmp_path, monkeypatch):
    # Isolate provider replay here; actual provider/capture integration is tested
    # separately. These native objects are not claimed as RISC-V translation.
    import riscv2x86_py.native_external_requirements as module
    from riscv2x86_py.project_compile_context import digest
    cc = shutil.which('gcc')
    if not cc:pytest.skip('native compiler required')
    (tmp_path/'root.c').write_text('extern int api(int); int owner(void){return api(1);}')
    subprocess.run([cc,'-c',str(tmp_path/'root.c'),'-o',str(tmp_path/'source.o')],check=True)
    (tmp_path/'candidate.i').write_text('fixture')
    archive = tmp_path/'empty.a';archive.write_bytes(b'!<arch>\n')
    candidate = tmp_path/'candidate.json'
    candidate.write_text(json.dumps({'sourceObjectDigest':digest(tmp_path/'source.o'),
                                    'candidatePath':str(tmp_path/'candidate.i')}))
    dependencies = {'inventoryIdentity':'parent','candidatePath':str(candidate),
                    'archivePath':str(archive),'members':[],
                    'inputDigests':{str(archive):digest(archive),str(candidate):digest(candidate)}}
    dep = tmp_path/'dependencies.json';dep.write_text(json.dumps(dependencies))
    body = {'dependencyInventoryIdentity':'parent','dependencyPath':str(dep),
        'externalObligations':[{'originalObligation':{'object':'root','symbol':'api'},
          'obligationIdentity':'api','definitionCandidates':[{'symbol':{'type':2}}],
          'targetNameCandidates':[]}], 'blockers':[{'reason':'original'}]}
    provider = dict(body,inventoryIdentity=identity(body))
    path = tmp_path/'provider.json';path.write_text(json.dumps(provider))
    monkeypatch.setattr(module,'replay',lambda *a:None)
    out = tmp_path/'out';out.mkdir();value = module.acquire(path,out)
    again = tmp_path/'again';again.mkdir()
    assert module.replay_requirements(value,again)['requirementsReplayComplete']
    forged = deepcopy(value);forged['externalContractClosureComplete']=True
    forged['requirementsIdentity']=identity({k:v for k,v in forged.items() if k!='requirementsIdentity'})
    third = tmp_path/'third';third.mkdir()
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):module.replay_requirements(forged,third)
    archive.write_bytes(b'changed');fourth = tmp_path/'fourth';fourth.mkdir()
    with pytest.raises(ValueError,match='ARCHIVE_CHANGED'):module.acquire(path,fourth)
