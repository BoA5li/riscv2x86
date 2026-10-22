"""Preparation protocol tests; compiler provenance is simulated explicitly."""
import json
from pathlib import Path
import pytest
from riscv2x86_py.prepare_system_instruction import prepare
from riscv2x86_py.system_instruction_ingress import PROFILE,digest
from tests.test_system_instruction_ingress import environment,authority
from tests.test_system_deployment import execution_file


def inputs(tmp_path,monkeypatch):
    from riscv2x86_py import mechanism_route_checks
    source=tmp_path/'arbitrary.c';source.write_text('/* explicit compiler protocol fixture */')
    finding={'fragment':{'id':'frag','inputs':[],'outputs':[]},'machineCodeHex':'73000000'}
    monkeypatch.setattr(mechanism_route_checks,'compiler_bound_finding',lambda *a:(finding,{}))
    facts=environment();execution=execution_file(tmp_path,facts)
    evidence={'schemaVersion':'riscv2x86.system-mechanism-evidence.v1','profile':PROFILE,
        'semanticBasis':['protocol fixture; does not assert actual implementation correctness'],
        'sourceArtifacts':[],'targetArtifacts':[]}
    for side in ('source','target'):
        for role in ('implementation-source','runner-binary','build-record'):
            p=tmp_path/(side+'-'+role);p.write_bytes((side+role).encode())
            evidence[side+'Artifacts'].append({'role':role,'path':p.name,'digest':digest(p.read_bytes())})
    path=tmp_path/'mechanism.json';path.write_text(json.dumps(evidence))
    transition=authority(bytes.fromhex('73000000'),facts)['bindings'][0]['transition']
    return dict(source=source,report=tmp_path/'unused-protocol-report',fragment_id='frag',
        execution_sidecar=execution,mechanism_evidence=path,transition=transition),finding,evidence


def test_preparation_consumes_artifact_identities_and_does_not_approve_translation(tmp_path,monkeypatch):
    args,finding,evidence=inputs(tmp_path,monkeypatch)
    value=prepare(**args)
    assert 'approved' not in value and 'semanticApproval' not in value
    assert value['bindings'][0]['operation']=='ecall'
    assert value['sourceDigest']==digest(args['source'].read_bytes())


@pytest.mark.parametrize('mutation',['source-artifact','target-artifact','roles','basis','profile','operand','opcode','handler'])
def test_preparation_refuses_missing_basis_wrong_artifacts_and_inapplicable_scope(tmp_path,monkeypatch,mutation):
    args,finding,evidence=inputs(tmp_path,monkeypatch)
    if mutation in ('source-artifact','target-artifact'):
        side=mutation.split('-')[0];(tmp_path/evidence[side+'Artifacts'][0]['path']).write_bytes(b'changed')
    if mutation=='roles':evidence['sourceArtifacts']=evidence['sourceArtifacts'][:1]
    if mutation=='basis':evidence['semanticBasis']=[]
    if mutation=='profile':evidence['profile']='native-linux-syscall'
    if mutation=='operand':finding['fragment']['inputs']=[{'constraint':'r'}]
    if mutation=='opcode':finding['machineCodeHex']='13000000'
    if mutation=='handler':args['transition']['handlerBindingId']='wrong'
    args['mechanism_evidence'].write_text(json.dumps(evidence))
    with pytest.raises(ValueError,match='SYSTEM_'):prepare(**args)
