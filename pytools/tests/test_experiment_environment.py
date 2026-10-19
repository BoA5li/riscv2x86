from copy import deepcopy
import json
from pathlib import Path
import pytest
from riscv2x86_py.experiment_environment import seal_environment, load_environment
from riscv2x86_py.route_authority import content_identity


def template():
    value={'schemaVersion':'riscv2x86.csr-architecture-template.v1',
        'privilegeSpecVersion':'riscv-privileged-1.12','xlenBits':64,'extensions':['zicsr']}
    return {**value,'templateIdentity':content_identity(value)}


def sealed(tmp_path):
    source=tmp_path/'inputs';source.mkdir();(source/'renamable.c').write_text('int main(void){return 0;}')
    root=tmp_path/'contracts';root.mkdir();(root/'one.json').write_text('{}')
    value=seal_environment(source=source,directories={'csr_environment_contract_directory':root},
        environment_id='reviewed-environment',architecture_template=template())
    path=tmp_path/'environment.json';path.write_text(json.dumps(value))
    return source,root,path,value


def test_sealed_environment_does_not_grant_semantic_approval(tmp_path):
    source,root,path,value=sealed(tmp_path)
    directories,snapshot=load_environment(path,source=source)
    assert directories['csr_environment_contract_directory']==root
    assert snapshot['semanticApproval'] is False
    assert snapshot['architectureTemplate']==template()


@pytest.mark.parametrize('mutation,reason',[
    ('source','SOURCE_SET_OR_IDENTITY'),('source_added','SOURCE_SET_OR_IDENTITY'),
    ('file','FILE_SET_OR_IDENTITY'),('file_added','FILE_SET_OR_IDENTITY'),
    ('override','OVERRIDE_CONFLICT'),('symlink','SYMLINK_UNSUPPORTED'),
    ('identity','SCHEMA_OR_IDENTITY')])
def test_environment_rejects_stale_or_unsealed_inputs(tmp_path,mutation,reason):
    source,root,path,value=sealed(tmp_path);overrides={}
    if mutation=='source':(source/'renamable.c').write_text('changed')
    if mutation=='source_added':(source/'new.c').write_text('int new_value;')
    if mutation=='file':(root/'one.json').write_text('{"changed":true}')
    if mutation=='file_added':(root/'new.json').write_text('{}')
    if mutation=='override':overrides={'csr_environment_contract_directory':tmp_path/'other'}
    if mutation=='symlink':(root/'link').symlink_to(source/'renamable.c')
    if mutation=='identity':value['environmentId']='mutated';path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match=reason):load_environment(path,source=source,overrides=overrides)


def test_inventory_consumes_template_and_sealed_directory(tmp_path,monkeypatch):
    from riscv2x86_py import automatic_batch_cli as auto
    source,root,path,value=sealed(tmp_path)
    frontend=tmp_path/'frontend';frontend.write_text('fixture only');frontend.chmod(0o755)
    monkeypatch.setattr(auto,'inspect_entry_points',lambda source:(True,()))
    inventory=tmp_path/'inventory'
    result=auto.prepare_automatic_inventory(source,inventory,frontend=frontend,experiment_environment=path)
    assert result['experimentEnvironment']['manifestIdentity']==value['manifestIdentity']
    descriptor=next((inventory/'cases').rglob('riscv2x86-evaluation.json'))
    command=json.loads(descriptor.read_text())['request']['translationCommand']
    assert '--csr-architecture-template' in command
    assert Path(command[command.index('--csr-architecture-template')+1]).is_file()
    resolution=json.loads((descriptor.parent/'contract-resolution.json').read_text())
    arch=next(x for x in resolution['contracts'] if x['family']=='csr_architecture')
    assert arch['disposition']=='template_selected_pending_frontend_binding'
    assert not arch['semanticApproval']


def test_architecture_profile_and_template_cannot_silently_override(tmp_path):
    source,root,path,value=sealed(tmp_path)
    value['contractDirectories']['csr_architecture_directory']={'path':str(root),'files':{'one.json':value['contractDirectories']['csr_environment_contract_directory']['files']['one.json']}}
    value['manifestIdentity']=content_identity({k:v for k,v in value.items() if k!='manifestIdentity'})
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='TEMPLATE_DIRECTORY_CONFLICT'):load_environment(path,source=source)


def test_sealer_cli_records_explicit_isa_without_granting_permissions(tmp_path,monkeypatch):
    import runpy,sys
    source=tmp_path/'input.c';source.write_text('int probe(void){return 0;}')
    output=tmp_path/'environment.json'
    argv=['sealer','--source',str(source),'--output',str(output),'--environment-id','reviewed',
        '--privilege-spec','riscv-privileged-1.12','--xlen','64','--extensions','zicsr']
    monkeypatch.setattr(sys,'argv',argv)
    main=runpy.run_path(str(Path(__file__).resolve().parents[2]/'experiment/prepare_experiment_environment.py'))['main']
    assert main()==0
    _,snapshot=load_environment(output,source=source)
    assert snapshot['architectureTemplate']==template()
    assert snapshot['contractDirectories']=={} and snapshot['semanticApproval'] is False
    assert main()==2 # never overwrite an existing manifest
