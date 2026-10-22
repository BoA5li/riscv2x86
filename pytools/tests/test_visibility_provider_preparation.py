from dataclasses import asdict
from copy import deepcopy
import json
from pathlib import Path
import sys
import pytest
from tests import test_instruction_visibility_production as fixture
from riscv2x86_py.prepare_instruction_visibility import commands,bind,digest
from riscv2x86_py.semantic_content import semantic_identity
from riscv2x86_py.compiler_instruction_sync_scope import instruction_sync_scope
from riscv2x86_py.automatic_l2_authority import _instruction_stream_authority_checked
from riscv2x86_py.automatic_batch_cli import _explicit_l2_providers


def case(tmp_path,monkeypatch):
    source=tmp_path/'renamed.c';source.write_text('void sync_probe(void){}')
    output=tmp_path/'provider'
    plan=commands(approval_path=output/'approval.json',symbol='sync_probe',source_compiler=sys.executable,
        target_compiler=sys.executable,source_runner=[sys.executable])
    domain=fixture.domain();domain['sourceDigest']=digest(source)
    for side in ('source','target'):domain[side+'Execution']['runnerIdentity']=plan[side+'RunnerIdentity']
    domain['domainIdentity']=semantic_identity({k:v for k,v in domain.items() if k!='domainIdentity'})
    monkeypatch.setattr(fixture,'domain',lambda:domain)
    fragment,approval,text=fixture.approval_fixture();fragment.enclosingFunction='sync_probe'
    fragment.compilerFragmentAuthority={'sourceDigest':digest(source),'functionIdentity':'sha256:'+'4'*64,
        'fragmentBindingKey':{'beginOffset':10,'endOffset':20}}
    ast={'name':'sync_probe','type':{'qualType':'void (void)'},'inner':[{'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt'}]}]}
    approval['l2InstructionSyncFunctionScope']=instruction_sync_scope(ast,source_digest=digest(source),
        function_identity='sha256:'+'4'*64,source_range=lambda n:(10,20))
    finding={'fragment':asdict(fragment),'approvalArtifact':approval,'sourceDigest':digest(source),
        'suggestedReplacement':text,'machineCodeHex':'0f100000'}
    approval['l2AuthoritySidecar']=_instruction_stream_authority_checked(finding,(),digest(source)).to_dict()
    report=tmp_path/'approved.json';report.write_text(json.dumps({'findings':[finding]}))
    return source,output,report,fragment.id


def invoke(source,output,report,fid):
    return bind(source=source,source_root=source.parent,report=report,fragment_id=fid,output=output,
        execution_profile='architectural',source_compiler=sys.executable,target_compiler=sys.executable,
        source_runner=[sys.executable])


def test_prepared_descriptor_is_consumed_by_real_inventory_loader(tmp_path,monkeypatch):
    source,out,report,fid=case(tmp_path,monkeypatch)
    result=invoke(source,out,report,fid)
    assert result['disposition']=='bound_to_existing_approval' and not result['semanticApproval']
    providers,capabilities=_explicit_l2_providers(source,source.parent,out/'providers')
    assert len(providers)==1 and providers[0]['fragmentIds']==['fragment:fence-i']
    assert providers[0]['supportedDimensions']==['memory_effects','shell_semantics']
    assert set(capabilities)=={'instruction_visibility','shell_observation'}
    assert (out/'approval.json').read_bytes()==report.read_bytes()


@pytest.mark.parametrize('mutation',['source','machine','scope','runner','approval'])
def test_provider_preparation_does_not_repair_invalid_or_missing_proof(tmp_path,monkeypatch,mutation):
    source,out,report,fid=case(tmp_path,monkeypatch)
    value=json.loads(report.read_text());f=value['findings'][0]
    if mutation=='source':source.write_text('changed')
    if mutation=='machine':f['machineCodeHex']='13000000'
    if mutation=='scope':f['approvalArtifact']['l2InstructionSyncFunctionScope']['functionSymbol']='wrong'
    if mutation=='runner':out=tmp_path/'other-location' # command identity must change
    if mutation=='approval':f['approvalArtifact'].pop('proofIdentity')
    report.write_text(json.dumps(value))
    with pytest.raises((ValueError,KeyError)):invoke(source,out,report,fid)
    assert not out.exists()


def test_shipped_observer_identity_binds_compiler_and_guest_runner_bytes(tmp_path):
    from riscv2x86_py.l2_instruction_visibility_runner import runner_identity
    compiler=tmp_path/'compiler';compiler.write_bytes(b'compiler-v1')
    runner=tmp_path/'runner';runner.write_bytes(b'runner-v1')
    plan=commands(approval_path=tmp_path/'approval.json',symbol='renameable',source_compiler=str(compiler),
        target_compiler=str(compiler),source_runner=[str(runner)])
    command=plan['sourceCommand'];hd=digest(plan['harnessPath'])
    before=runner_identity(command,hd)
    compiler.write_bytes(b'compiler-v2')
    assert runner_identity(command,hd)!=before
    compiler.write_bytes(b'compiler-v1');runner.write_bytes(b'runner-v2')
    assert runner_identity(command,hd)!=before


def test_observer_command_preserves_selected_virtual_environment_entrypoint(tmp_path):
    python=tmp_path/'venv-python';python.symlink_to(sys.executable)
    plan=commands(approval_path=tmp_path/'approval.json',symbol='probe',python=str(python),
        source_compiler=sys.executable,target_compiler=sys.executable,source_runner=[sys.executable])
    assert plan['sourceCommand'][0]==str(python.absolute())
    assert plan['targetCommand'][0]==str(python.absolute())
