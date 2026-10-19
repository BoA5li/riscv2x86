from copy import deepcopy
import json
import pytest
from tests.test_experiment_environment import template
from riscv2x86_py.csr_architecture_profile import materialize_template,profiles_from_payload,load_profile,parse_profile
from riscv2x86_py.route_authority import content_identity


def registry(tmp_path):
    source=tmp_path/'source.c';source.write_text('explicit profile fixture')
    report={'findings':[{'fragment':{'id':'source.c:2:1'}},{'fragment':{'id':'source.c:8:1'}}]}
    return source,materialize_template(template(),report,source=source)


def test_template_binds_all_fragments_with_no_execution_permission(tmp_path):
    source,value=registry(tmp_path);path=tmp_path/'profiles.json';path.write_text(json.dumps(value))
    loaded=load_profile(path,source=source);profiles=profiles_from_payload(loaded,xlen_bits=64)
    assert set(profiles)=={'source.c:2:1','source.c:8:1'}
    assert all(set(x)=={'schemaVersion','sourceDigest','fragmentId','privilegeSpecVersion','xlenBits','extensions','profileIdentity'} for x in profiles.values())
    assert parse_profile(profiles['source.c:2:1']).xlen_bits==64


@pytest.mark.parametrize('mutation,reason',[
    ('duplicate','DUPLICATE_FRAGMENT'),('source','SOURCE_MISMATCH'),
    ('width','XLEN_MISMATCH'),('permission','SCHEMA_INVALID'),('outer','SCHEMA_OR_IDENTITY')])
def test_registry_mutations_rejected(tmp_path,mutation,reason):
    _,value=registry(tmp_path);profile=value['profiles'][0]
    if mutation=='duplicate':value['profiles'].append(deepcopy(profile))
    if mutation=='source':profile['sourceDigest']='sha256:'+'1'*64
    if mutation=='width':profile['xlenBits']=32
    if mutation=='permission':profile['executionAllowed']=True
    profile['profileIdentity']=content_identity({k:v for k,v in profile.items() if k!='profileIdentity'})
    value['registryIdentity']=content_identity({k:v for k,v in value.items() if k!='registryIdentity'})
    if mutation=='outer':value['templateIdentity']='sha256:'+'a'*64
    with pytest.raises(ValueError,match=reason):profiles_from_payload(value,xlen_bits=64)


def test_template_empty_report_is_not_a_fake_fragment(tmp_path):
    source=tmp_path/'source.c';source.write_text('int main(void){return 0;}')
    assert profiles_from_payload(materialize_template(template(),{'findings':[]},source=source))=={}
