"""Portable typedef replay; no corpus names, offsets or expected results."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from riscv2x86_py.compiler_function_types import derive, stable_type, validate_inventory
from riscv2x86_py.project_build_records import identity, import_log
from riscv2x86_py.project_inspection_replay import require_match, first_difference


def ast(reference='0x123'):
    typ={'qualType':'allocation_size_t','desugaredQualType':'unsigned long',
         'typeAliasDeclId':reference}
    return {'inner':[{'kind':'FunctionDecl','name':'arbitrary_allocator',
        'type':{'qualType':'void *(allocation_size_t)'},
        'range':{'begin':{'offset':0},'end':{'offset':99,'tokLen':1}},
        'inner':[{'kind':'ParmVarDecl','type':typ},{'kind':'CompoundStmt'}]}]}


def inventory(tree):
    return derive(tree,source_path='/tmp/arbitrary-unit.c',
                  dependency_identity='sha256:fixed-dependencies',target='riscv64')


def test_process_local_typedef_reference_is_not_semantic_identity():
    before=ast();saved=deepcopy(before)
    first=inventory(before);second=inventory(ast('0x987'))
    assert first==second
    assert before==saved  # No mutation of raw compiler evidence.
    assert first['schemaVersion']=='riscv2x86.compiler-function-types.v2'
    assert first['typedefDeclarationClosureVerified'] is False
    assert validate_inventory(json.loads(json.dumps(first)))==first
    assert first['functions'][0]['parameterTypes'][0]['compilerType']=={
        'qualType':'allocation_size_t','desugaredQualType':'unsigned long'}
    assert first['functions'][0]['parameterTypes'][0]['proofOrCallContractAvailable'] is False


@pytest.mark.parametrize('field,value',[
    ('qualType','different_alias_t'),('desugaredQualType','signed long'),
    ('qualType','const allocation_size_t'),('qualType','allocation_size_t *'),
    ('futureSemanticField','0x123'),('id','0x123')])
def test_all_other_type_fields_are_preserved_and_compared(field,value):
    original=inventory(ast());other=ast('0x987')
    other['inner'][0]['inner'][0]['type'][field]=value
    changed=inventory(other)
    assert changed!=original
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):
        require_match('functionTypeInventory',{'sourcePath':'unit.c','contextIdentity':'context'},original,changed)


@pytest.mark.parametrize('mutation',['return','variadic','linkage','range','parameter-order'])
def test_real_function_changes_cannot_be_normalized_away(mutation):
    original=ast();changed=deepcopy(original);f=changed['inner'][0]
    if mutation=='return':f['type']['qualType']='int (allocation_size_t)'
    elif mutation=='variadic':f['variadic']=True
    elif mutation=='linkage':f['storageClass']='static'
    elif mutation=='range':f['range']['begin']['offset']=1
    else:
        original['inner'][0]['inner'].insert(1,{'kind':'ParmVarDecl','type':{'qualType':'double'}})
        f['inner'].insert(0,{'kind':'ParmVarDecl','type':{'qualType':'double'}})
    assert inventory(original)!=inventory(changed)


def test_function_level_type_reference_uses_same_projection():
    a=ast();b=ast()
    a['inner'][0]['type']['typeAliasDeclId']='0x111'
    b['inner'][0]['type']['typeAliasDeclId']='0x222'
    assert inventory(a)==inventory(b)


@pytest.mark.parametrize('reference',[None,True,42,{},'not-a-clang-id'])
def test_invalid_alias_reference_is_not_silently_discarded(reference):
    with pytest.raises(ValueError,match='TYPE_ALIAS_REFERENCE_INVALID'):inventory(ast(reference))


def test_projection_is_narrow_not_recursive_hex_or_id_scrubbing():
    facts={'qualType':'int','typeAliasDeclId':'0x123',
           'future':{'typeAliasDeclId':'0xsemantic','id':'0x456'}}
    result=stable_type(facts)
    assert result['future']==facts['future']


def test_old_or_rehashed_inventories_are_not_upgraded():
    value=inventory(ast());value['schemaVersion']='riscv2x86.compiler-function-types.v1'
    value['inventoryIdentity']=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='REACQUISITION_REQUIRED'):validate_inventory(value)
    value=inventory(ast());value['functions'][0]['parameterTypes'][0]['canonicalType']='double'
    value['inventoryIdentity']=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='FUNCTION_TYPE_IDENTITY_INVALID'):validate_inventory(value)


def test_rehashed_transient_reference_is_rejected_in_v2():
    value=inventory(ast());function=value['functions'][0]
    function['parameterTypes'][0]['compilerType']['typeAliasDeclId']='0x123'
    function['functionTypeIdentity']=identity({
        **{k:v for k,v in function.items() if k!='functionTypeIdentity'},
        'dependencyIdentity':value['dependencyIdentity'],'target':value['target']})
    value['inventoryIdentity']=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='PROCESS_LOCAL_REFERENCE'):validate_inventory(value)


def test_dependency_and_target_binding_remain_in_type_identities():
    value=inventory(ast())
    for dependency,target in [('different','riscv64'),('sha256:fixed-dependencies','x86_64')]:
        other=derive(ast(),source_path='/tmp/arbitrary-unit.c',dependency_identity=dependency,target=target)
        assert other['functions'][0]['functionTypeIdentity']!=value['functions'][0]['functionTypeIdentity']


def tool():
    spec=importlib.util.spec_from_file_location('type_replay_cli',
        Path(__file__).parents[2]/'experiment/prepare_real_project_experiment.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def fixture(tmp_path,monkeypatch):
    module=tool();source=tmp_path/'unit.c';source.write_text('int f(void){return 1;}\n')
    log=tmp_path/'build.log';log.write_text('gcc -c unit.c -o unit.o\n')
    control={'reference':'0x123','semantic':'unsigned long'}
    def acquire(context,**kwargs):
        tree=ast(control['reference'])
        tree['inner'][0]['inner'][0]['type']['desugaredQualType']=control['semantic']
        types=derive(tree,source_path=context['sourcePath'],dependency_identity='bound',target='riscv64')
        snapshot={'inventory':{},'functionTypeInventory':types,
            'dependencyManifest':{'compilerCommand':[sys.executable]},
            'compilerCommand':[sys.executable],'compilerDigest':'digest',
            'dependencyClosureVerified':False,'semanticApproval':False}
        result={'functions':[],'contextIdentity':context['contextIdentity'],
            'compilerEquivalenceVerified':False,'semanticApproval':False,
            'productionAcceptanceComplete':False,'contextAcquisitionConsistent':True,'snapshot':snapshot}
        return dict(result,inspectionIdentity=identity(result))
    monkeypatch.setattr(module,'acquire',acquire)
    monkeypatch.setattr(module,'validate_dependencies',lambda value:None)
    report=module.inspect(import_log(log,tmp_path),clang=sys.executable)
    assert report['statusCounts']=={'inspected':1}
    return module,report,control


def test_cli_replay_uses_stable_types_and_reports_real_field_difference(tmp_path,monkeypatch,capsys):
    module,report,control=fixture(tmp_path,monkeypatch)
    control['reference']='0x987'
    assert module.replay(report)['contextReplayComplete'] is True
    control['semantic']='double'
    path=tmp_path/'contexts.json';path.write_text(json.dumps(report))
    assert module.main(['replay','--report',str(path)])==2
    error=json.loads(capsys.readouterr().err)
    assert error['semanticApproval'] is False
    difference=error['replayDifference']
    assert difference['sourcePath']==str(tmp_path/'unit.c')
    assert difference['component']=='functionTypeInventory'
    assert 'Identity' not in difference['difference']['path']


def test_cli_old_inventory_requires_new_inspection(tmp_path,monkeypatch):
    module,report,_=fixture(tmp_path,monkeypatch)
    observation=report['records'][0]['inspection']
    value=observation['snapshot']['functionTypeInventory']
    value['schemaVersion']='riscv2x86.compiler-function-types.v1'
    value['inventoryIdentity']=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
    observation['inspectionIdentity']=identity({k:v for k,v in observation.items() if k!='inspectionIdentity'})
    report['preflightIdentity']=identity({k:v for k,v in report.items() if k!='preflightIdentity'})
    with pytest.raises(ValueError,match='REACQUISITION_REQUIRED'):module.replay(report)


def test_diagnostic_distinguishes_boolean_and_integer_and_absence():
    assert first_difference(True,1)['path']=='$'
    assert first_difference({}, {'a':None})['oldPresent'] is False


def test_real_clang_typedef_inventory_is_stable_across_processes(tmp_path):
    clang=os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    if not clang:pytest.skip('real Clang required for independent AST integration')
    source=tmp_path/'allocator.c'
    source.write_text('typedef unsigned long amount_t;\n'
                      'typedef amount_t alias_t;\n'
                      'alias_t arbitrary(alias_t x, const amount_t *p) { return x + *p; }\n')
    command=[clang,'-fsyntax-only','-Xclang','-ast-dump=json',str(source)]
    def scan():
        result=subprocess.run(command,text=True,capture_output=True,check=True)
        return derive(json.loads(result.stdout),source_path=source,
                      dependency_identity='unchanged-source',target='x86_64')
    first=scan();second=scan()
    assert first==second
    assert first['functions'][0]['parameterTypes'][0]['kind']=='integer'
    validate_inventory(second)
