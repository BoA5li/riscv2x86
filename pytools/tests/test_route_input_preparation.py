import json
from pathlib import Path
import pytest
from riscv2x86_py.prepare_route_environment import prepare
from riscv2x86_py.experiment_environment import load_environment
from riscv2x86_py.csr_architecture_profile import TEMPLATE_SCHEMA
from riscv2x86_py.route_authority import content_identity


def template():
    p={'schemaVersion':TEMPLATE_SCHEMA,'privilegeSpecVersion':'riscv-privileged-1.12',
       'xlenBits':64,'extensions':['zicsr']}
    return {**p,'templateIdentity':content_identity(p)}


def test_explicit_architecture_reaches_sealed_consumer_without_granting_permissions(tmp_path):
    source=tmp_path/'inputs';source.mkdir();(source/'renamed.c').write_text('int renamed(void){return 0;}')
    output=tmp_path/'prepared'
    report=prepare(source=source,output=output,environment_id='declared-environment',directories={},
        architecture=template(),required=['csr_architecture=renamed.c'])
    dirs,snapshot=load_environment(output/'environment.json',source=source)
    assert not report['semanticApproval'] and not snapshot['semanticApproval'] and dirs=={}
    assert snapshot['architectureTemplate']['xlenBits']==64
    assert report['disposition']=='prepared_pending_semantic_validation'
    (source/'renamed.c').write_text('changed')
    with pytest.raises(ValueError,match='SOURCE_SET_OR_IDENTITY'):load_environment(output/'environment.json',source=source)


def test_required_visibility_contract_cannot_be_invented(tmp_path):
    source=tmp_path/'ordinary.c';source.write_text('void f(void){}')
    out=tmp_path/'out'
    result=prepare(source=source,output=out,environment_id='e',directories={},
        required=['instruction_stream_sync=ordinary.c'])
    assert result['disposition']=='missing_inputs'
    assert not (out/'environment.json').exists()
    assert result['requiredInputGaps']==[{'sourceRelativePath':'ordinary.c',
        'family':'instruction_stream_sync','disposition':'not_provided'}]
    with pytest.raises(ValueError,match='OUTPUT_EXISTS'):
        prepare(source=source,output=out,environment_id='e',directories={})


@pytest.mark.parametrize('demand',['wrong=a.c','csr_environment=../a.c','csr_environment=unknown.c'])
def test_invalid_contract_demands_are_rejected_before_output(tmp_path,demand):
    source=tmp_path/'a.c';source.write_text('void f(void){}')
    with pytest.raises(ValueError,match='BINDING_INVALID'):
        prepare(source=source,output=tmp_path/'out',environment_id='e',directories={},required=[demand])
    assert not (tmp_path/'out').exists()


def test_resolved_files_are_not_labelled_semantically_approved(tmp_path):
    source=tmp_path/'a.c';source.write_text('void f(void){}');contracts=tmp_path/'contracts';contracts.mkdir()
    (contracts/'a.c.instruction-stream-sync.json').write_text('{"not":"a valid semantic contract"}')
    result=prepare(source=source,output=tmp_path/'out',environment_id='e',
        directories={'instruction_stream_sync_directory':contracts},required=['instruction_stream_sync=a.c'])
    assert not result['semanticApproval']
    entry=next(x for x in result['resolutions']['a.c']['contracts'] if x['family']=='instruction_stream_sync')
    assert entry['disposition']=='resolved_pending_validation' and not entry['semanticApproval']


def test_template_directory_conflict_does_not_publish_environment(tmp_path):
    source=tmp_path/'a.c';source.write_text('void f(void){}');contracts=tmp_path/'contracts';contracts.mkdir()
    with pytest.raises(ValueError,match='TEMPLATE_DIRECTORY_CONFLICT'):
        prepare(source=source,output=tmp_path/'out',environment_id='e',architecture=template(),
            directories={'csr_architecture_directory':contracts})
    assert not (tmp_path/'out').exists()
