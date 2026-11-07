"""Real native link/rebuild evidence does not claim translated execution."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py.native_link_evidence import request,build,audit
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py.project_build_records import identity


@pytest.fixture
def candidate(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC required')
    (tmp_path/'entry.c').write_text('int translated_entry(int x){return x+1;}')
    (tmp_path/'main.c').write_text('extern int translated_entry(int);int main(void){return translated_entry(6);}')
    for src,obj in [('entry.c','target.o'),('main.c','main.o')]:
        subprocess.run([cc,'-c',src,'-o',obj],cwd=tmp_path,check=True)
    (tmp_path/'candidate.i').write_text('native build fixture, no translation proof')
    value={'schemaVersion':'riscv2x86.native-integer-candidate.v1','candidatePath':str(tmp_path/'candidate.i'),
        'targetObjectDigest':digest(tmp_path/'target.o'),'sourceObjectDigest':'not-a-source-proof',
        'artifactDigests':{n:digest(tmp_path/n) for n in ('target.o','candidate.i')},
        'semanticApproval':False,'productionAcceptanceComplete':False}
    value['candidateIdentity']=identity(value);receipt=tmp_path/'candidate.json';receipt.write_text(json.dumps(value))
    return tmp_path,cc,receipt


@pytest.mark.parametrize('directory_name',['out','out,with,commas'])
def test_actual_native_link_and_independent_rebuild(candidate,directory_name):
    p,cc,receipt=candidate;req=request(receipt,'target',cc,[p/'main.o'])
    out=p/directory_name;out.mkdir();value=build(req,out)
    assert value['linkBuildComplete'] and value['candidateObjectExplicitInputVerified']
    assert value['candidateExportsPresent'] and not value['actualLinkSelectionVerified']
    assert not value['typedCallContractVerified'] and not value['translatedInstanceExecutionVerified']
    assert subprocess.run([str(out/'program')]).returncode==7  # local fixture behavior only
    again=p/'again';again.mkdir();checked=audit(value,out,again)
    assert checked['nativeLinkIndependentRebuildComplete'] and not checked['semanticApproval']


def test_duplicate_definition_and_wrong_side_reject(candidate):
    p,cc,receipt=candidate
    out=p/'wrong-side';out.mkdir()
    with pytest.raises((ValueError,FileNotFoundError)):build(request(receipt,'source',cc,[p/'main.o']),out)
    (p/'other.c').write_text('int translated_entry(int x){return x;}')
    subprocess.run([cc,'-c','other.c','-o','other.o'],cwd=p,check=True)
    out=p/'duplicate';out.mkdir()
    with pytest.raises(ValueError,match='COMMAND_FAILED:link'):
        build(request(receipt,'target',cc,[p/'main.o',p/'other.o']),out)
    assert (out/'link.stderr').is_file()


def test_unsupported_options_and_changed_candidate_reject(candidate):
    p,cc,receipt=candidate
    with pytest.raises(ValueError,match='ABI_OPTION_UNSUPPORTED'):
        request(receipt,'target',cc,[p/'main.o'],abi_options=['-Wl,--allow-multiple-definition'])
    with pytest.raises(ValueError,match='DUPLICATE_INPUT'):request(receipt,'target',cc,[p/'main.o',p/'main.o'])
    with pytest.raises(ValueError,match='SHARED_OPTIONS'):request(receipt,'target',cc,[],mode='shared',static=True)
    (p/'target.o').write_bytes(b'changed');out=p/'out';out.mkdir()
    with pytest.raises(ValueError,match='ARTIFACT_CHANGED'):build(request(receipt,'target',cc,[p/'main.o']),out)


def test_audit_rejects_rehashed_false_flags_and_artifact_changes(candidate):
    p,cc,receipt=candidate;out=p/'out';out.mkdir()
    value=build(request(receipt,'target',cc,[p/'main.o']),out)
    forged=deepcopy(value);forged['actualLinkSelectionVerified']=True
    forged['linkBuildIdentity']=identity({k:v for k,v in forged.items() if k!='linkBuildIdentity'})
    again=p/'again';again.mkdir()
    with pytest.raises(ValueError,match='REBUILD_RECEIPT_MISMATCH'):audit(forged,out,again)
    (out/'link.map').write_text('changed');third=p/'third';third.mkdir()
    with pytest.raises(ValueError,match='ARTIFACT_CHANGED'):audit(value,out,third)


def test_wrong_architecture_dependency_rejected_before_link(candidate):
    import struct
    p,cc,receipt=candidate;raw=bytearray((p/'main.o').read_bytes());struct.pack_into('<H',raw,18,243)
    (p/'wrong.o').write_bytes(raw);out=p/'wrong';out.mkdir()
    with pytest.raises(ValueError,match='DEPENDENCY_ARCHITECTURE_INVALID'):
        build(request(receipt,'target',cc,[p/'wrong.o']),out)
    assert not (out/'program').exists()


def test_command_line_link_request_build_and_audit(candidate):
    import sys
    p,cc,receipt=candidate;script=Path(__file__).resolve().parents[2]/'experiment/inspect_native_runtime_contracts.py'
    subprocess.run([sys.executable,str(script),'link-request','--candidate',str(receipt),'--side','target',
        '--compiler',cc,'--input',str(p/'main.o'),'--output',str(p/'request.json')],check=True,capture_output=True)
    subprocess.run([sys.executable,str(script),'link','--request',str(p/'request.json'),
        '--output',str(p/'cli-link')],check=True,capture_output=True)
    result=subprocess.run([sys.executable,str(script),'audit-link','--input',str(p/'cli-link/result.json'),
        '--output',str(p/'cli-audit')],check=True,capture_output=True,text=True)
    assert json.loads(result.stdout)['nativeLinkIndependentRebuildComplete']
    assert not json.loads(result.stdout)['semanticApproval']
    again=subprocess.run([sys.executable,str(script),'link','--request',str(p/'request.json'),
        '--output',str(p/'cli-link')],capture_output=True)
    assert again.returncode==2
