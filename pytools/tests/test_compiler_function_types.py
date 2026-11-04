from riscv2x86_py.compiler_function_types import derive, describe


def function(name, returned='double', param='double', storage=None):
    row={'kind':'FunctionDecl','name':name,'type':{'qualType':f'{returned} ({param})'},
         'range':{'begin':{'offset':0},'end':{'offset':40,'tokLen':1}},
         'inner':[{'kind':'ParmVarDecl','type':{'qualType':param}}, {'kind':'CompoundStmt'}]}
    if storage:row['storageClass']=storage
    return row


def test_floating_functions_are_visible_without_becoming_integer_eligible(tmp_path):
    p=tmp_path/'input.c'
    result=derive({'inner':[function('renamed'),function('other','float','float')]},
                  source_path=p,dependency_identity='sha256:first',target='riscv64')
    assert len(result['functions'])==2
    for row in result['functions']:
        assert row['returnType']['kind']=='binary-floating'
        assert row['parameterTypes'][0]['kind']=='binary-floating'
        assert not row['semanticApproval']
        assert row['translationAndEvaluationEligibility']=='not_assessed'
        assert 'PROJECT_FLOAT_TRANSLATION_PROOF_REQUIRED' in row['capabilityPrerequisites']
    assert result['functions'][0]['returnType']['widthBits']==64
    assert result['functions'][1]['returnType']['widthBits']==32


def test_type_facts_include_dependency_identity_and_internal_entries(tmp_path):
    ast={'inner':[function('entry',storage='static')]}
    first=derive(ast,source_path=tmp_path/'x.c',dependency_identity='a',target='riscv64')
    second=derive(ast,source_path=tmp_path/'x.c',dependency_identity='b',target='riscv64')
    assert first['functions'][0]['functionTypeIdentity']!=second['functions'][0]['functionTypeIdentity']
    assert 'PROJECT_INTERNAL_ENTRY_ADAPTER_REQUIRED' in first['functions'][0]['capabilityPrerequisites']


def test_typedef_and_unmodeled_types_remain_typed_not_integer_guesses():
    assert describe({'type':{'qualType':'real_t','desugaredQualType':'double'}})['kind']=='binary-floating'
    assert describe({'type':{'qualType':'long double'}})['kind']=='unclassified'
    assert describe({'type':{'qualType':'struct result'}})['kind']=='unclassified'


def test_header_bodies_are_not_mislabeled_as_primary_file_entries(tmp_path):
    header=function('header'); header['loc']={'file':str(tmp_path/'header.h'),'includedFrom':{'file':str(tmp_path/'x.c')}}
    source=function('entry');source['loc']={'file':str(tmp_path/'x.c')}
    result=derive({'inner':[header,source]},source_path=tmp_path/'x.c',dependency_identity='d',target='x86_64')
    assert [r['name'] for r in result['functions']]==['entry']
