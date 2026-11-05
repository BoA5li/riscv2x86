from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest

from riscv2x86_py.compiler_asm_activation import derive as scan
from riscv2x86_py.project_activation_batches import make_plan as build_plan,validate_plan,summarize,run_batch
from riscv2x86_py.project_build_records import identity,import_log


def make_plan(path,batch_sources=16):
    # Synthetic planning tests bind an available executable; they do not run it
    # as a compiler. Actual Clang acquisition has a separate integration test.
    return build_plan(path,batch_sources,clang=sys.executable)


def context():
    return {'contextIdentity':'sha256:context','sourcePath':'/tmp/synthetic-unit.c','sourceDigest':'sha256:source'}


def tree():
    return {'kind':'TranslationUnitDecl','inner':[
        {'kind':'FunctionDecl','id':'0x1','name':'header_helper','type':{'qualType':'void ()'},
         'loc':{'file':'/tmp/synthetic-header.h','includedFrom':{'file':'/tmp/synthetic-unit.c'}},
         'inner':[{'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt','id':'0x2',
            'range':{'begin':{'offset':1},'end':{'offset':9,'tokLen':1}}}]}]},
        {'kind':'FunctionDecl','name':'entry','type':{'qualType':'void ()'},
         'inner':[{'kind':'CompoundStmt','inner':[{'kind':'GCCAsmStmt','id':'0x3',
            'range':{'begin':{'spellingLoc':{'file':'/tmp/synthetic-header.h','offset':2},
                              'expansionLoc':{'offset':22}},'end':{'offset':33}}}]}]},
        {'kind':'FileScopeAsmDecl','range':{}}]}


def collect(ast):
    return scan(ast,context=context(),dependency_identity='dep',compiler_digest='compiler',target='riscv64')


def test_header_macro_and_file_scope_asm_are_retained_with_unknown_binding():
    ast=tree();original=deepcopy(ast);value=collect(ast)
    assert ast==original
    assert len(value['instances'])==3
    assert [r['ordinal'] for r in value['instances']]==[0,1,2]
    assert value['instances'][0]['enclosingFunction']['name']=='header_helper'
    assert value['instances'][1]['macroLocationPresent'] is True
    assert value['instances'][2]['enclosingFunction'] is None
    assert all(i['sourceInstanceBinding']=='not_assessed' for i in value['instances'])
    assert not value['sourceInstanceBindingComplete'] and not value['nativeCompilerActivationConfirmed']
    assert not value['asmInstanceInventoryComplete'] and not value['semanticApproval']


def test_asm_ast_ids_change_but_binding_locations_and_occurrence_count_do_not():
    a=tree();b=deepcopy(a);b['inner'][0]['id']='0x987'
    b['inner'][0]['inner'][0]['inner'][0]['id']='0x654'
    assert collect(a)==collect(b)
    b['inner'][1]['inner'][0]['inner'][0]['range']['end']['offset']+=1
    assert collect(a)!=collect(b)
    assert collect({'kind':'TranslationUnitDecl','inner':[]})['instances']==[]


@pytest.mark.parametrize('field',['nativeCompilerActivationConfirmed','sourceInstanceBindingComplete',
                                'asmInstanceInventoryComplete','semanticApproval'])
def test_rehashed_discovery_report_cannot_grant_broader_claims(field):
    from riscv2x86_py.compiler_asm_activation import validate
    value=collect(tree());value[field]=True
    value['inventoryIdentity']=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
    with pytest.raises(ValueError,match='INVENTORY_INVALID'):
        validate(value,context(),'dep','compiler','riscv64')


def records(tmp_path):
    for name in ['a','b','c']:(tmp_path/(name+'.c')).write_text('int '+name+';\n')
    log=tmp_path/'build.log'
    log.write_text('gcc -c c.c -o c.o\ngcc -c a.c -o a.o\ngcc -fPIC -c a.c -o a.lo\n'
                   'gcc -unknown-semantic-option -c b.c -o b.o\n')
    path=tmp_path/'records.json';path.write_text(json.dumps(import_log(log,tmp_path)))
    return path


def test_plan_freezes_every_source_and_variant_including_blocked(tmp_path):
    path=records(tmp_path);plan=make_plan(path,2)
    assert plan['sourceCount']==3 and plan['contextCount']==4
    assert plan['statusCounts']=={'context_ready':3,'blocked':1}
    assert len(plan['batches'])==2
    assert plan['batches'][0]['sourcePaths']==[str(tmp_path/'a.c'),str(tmp_path/'b.c')]
    assert len(plan['batches'][0]['contextIdentities'])==3
    saved=tmp_path/'plan.json';saved.write_text(json.dumps(plan));assert validate_plan(saved)==plan
    plan['batches'][0]['contextIdentities'].pop()
    plan['planIdentity']=identity({k:v for k,v in plan.items() if k!='planIdentity'})
    saved.write_text(json.dumps(plan))
    with pytest.raises(ValueError,match='PLAN_REPLAY_MISMATCH'):validate_plan(saved)


def test_empty_and_duplicate_records_are_explicit_planning_errors(tmp_path):
    path=records(tmp_path);value=json.loads(path.read_text());value['actions']*=2
    value['inventoryIdentity']=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
    path.write_text(json.dumps(value));plan=make_plan(path)
    assert len(plan['planningErrors'])==4
    value['actions']=[];value['inventoryIdentity']=identity({k:v for k,v in value.items() if k!='inventoryIdentity'})
    path.write_text(json.dumps(value));assert make_plan(path)['planningErrors']


def test_inspection_compiler_is_frozen_in_plan(tmp_path):
    executable=tmp_path/'synthetic-compiler';executable.write_text('#!/bin/sh\nexit 0\n');executable.chmod(0o755)
    plan=build_plan(records(tmp_path),clang=str(executable))
    path=tmp_path/'plan.json';path.write_text(json.dumps(plan))
    assert validate_plan(path)==plan
    with pytest.raises(ValueError,match='COMPILER_PLAN_MISMATCH'):
        run_batch(path,0,'tooling',sys.executable,tmp_path/'result')
    executable.write_text('#!/bin/sh\nexit 1\n')
    with pytest.raises(ValueError,match='PLAN_REPLAY_MISMATCH'):validate_plan(path)


def test_pending_failed_and_invalid_batches_never_become_acceptance(tmp_path):
    plan=make_plan(records(tmp_path),1);path=tmp_path/'plan.json';path.write_text(json.dumps(plan))
    root=tmp_path/'results';root.mkdir()
    directory=root/'batch-0000';directory.mkdir()
    state={'status':'failed','primaryFailure':{'stage':'inspect','returnCode':2}}
    state['stateIdentity']=identity(state);(directory/'run-status.json').write_text(json.dumps(state))
    other=root/'batch-0001';other.mkdir();(other/'run-status.json').write_text('{}')
    ledger=summarize(path,root)
    assert ledger['batchStatusCounts']=={'blocked':1,'invalid':1,'not_run':1}
    assert ledger['contextCount']==4 and not ledger['recordedInspectionAstCoverageComplete']
    assert not ledger['freshIndependentReplayPerformed'] and not ledger['productionAcceptanceComplete']


def test_run_uses_same_frozen_batch_and_explicit_asm_mode(tmp_path,monkeypatch):
    path=tmp_path/'plan.json';plan=make_plan(records(tmp_path),2);path.write_text(json.dumps(plan))
    calls=[]
    def execute(*args,**kwargs):calls.append((args,kwargs));return 7
    monkeypatch.setattr('riscv2x86_py.project_activation_batches.execute',execute)
    output=tmp_path/'batch-0000'
    assert run_batch(path,0,'tooling',sys.executable,output)==7
    batch=json.loads(output.with_name(output.name+'.plan.json').read_text())
    assert batch['contextIdentities']==plan['batches'][0]['contextIdentities']
    assert calls[0][1]=={'asm_inventory':True}
    with pytest.raises(FileExistsError):run_batch(path,0,'tooling',sys.executable,output)


def completed_batch(tmp_path):
    from riscv2x86_py.project_compile_context import derive
    from riscv2x86_py.project_compile_context import digest
    from riscv2x86_py.project_inspection_pilot import verify_members
    records_path=records(tmp_path);plan=make_plan(records_path,1)
    plan_path=tmp_path/'plan.json';plan_path.write_text(json.dumps(plan))
    root=tmp_path/'results';root.mkdir();directory=root/'batch-0000';directory.mkdir()
    batch=dict(plan['batches'][0],parentPlanIdentity=plan['planIdentity'],batchIndex=0)
    batch_path=root/'batch-0000.plan.json';batch_path.write_text(json.dumps(batch))
    rows=[]
    for action in json.loads(records_path.read_text())['actions']:
        c=derive(action)
        if c['contextIdentity'] not in batch['contextIdentities']:continue
        v=scan(tree(),context=c,dependency_identity='dep',compiler_digest=plan['inspectionCompilerDigest'],target='riscv64')
        rows.append({'context':c,'status':'inspected','inspection':{'functions':[],
            'contextAcquisitionConsistent':True,'snapshot':{'asmActivationInventory':v,
                'dependencyManifest':{'dependencyIdentity':'dep'},'compilerDigest':plan['inspectionCompilerDigest']}}})
    report={'schemaVersion':'riscv2x86.real-project-context-preflight.v1','records':rows,
        'selection':{'asmInventory':True,'target':'riscv64'},'errors':[],'semanticApproval':False,'productionAcceptanceComplete':False}
    report['preflightIdentity']=identity(report)
    (directory/'contexts.json').write_text(json.dumps(report))
    (directory/'summary.json').write_text(json.dumps(verify_members(report,batch)))
    (directory/'replay.log').write_text(json.dumps({'contextReplayComplete':True,
        'buildVariantCount':len(rows),'semanticApproval':False,'productionAcceptanceComplete':False}))
    state={'status':'complete','compilerInspectionComplete':True,'independentContextReplayComplete':True,
        'acquisitionComplete':True,'semanticApproval':False,'productionAcceptanceComplete':False,
        'inputs':{str(batch_path):digest(batch_path),str(records_path):digest(records_path)},
        'inspectionReportDigest':digest(directory/'contexts.json'),
        'inspectionSummaryDigest':digest(directory/'summary.json'),'replayLogDigest':digest(directory/'replay.log')}
    state['stateIdentity']=identity(state);(directory/'run-status.json').write_text(json.dumps(state))
    return plan_path,root,directory


def test_aggregate_preserves_variants_and_occurrences_without_fresh_audit_claim(tmp_path):
    plan,root,_=completed_batch(tmp_path);ledger=summarize(plan,root)
    assert ledger['batchStatusCounts']=={'recorded_inspection_replayed':1,'not_run':2}
    assert ledger['inspectionAstAsmOccurrenceCount']==6  # Three occurrences in each of two variants.
    assert len({i['contextIdentity'] for i in ledger['occurrences']})==2
    assert not ledger['recordedInspectionAstCoverageComplete']
    assert not ledger['asmInstanceInventoryComplete'] and not ledger['freshIndependentReplayPerformed']


@pytest.mark.parametrize('artifact',['contexts.json','summary.json','replay.log','plan'])
def test_changed_persisted_batch_evidence_is_not_aggregated(tmp_path,artifact):
    plan,root,directory=completed_batch(tmp_path)
    target=(root/'batch-0000.plan.json') if artifact=='plan' else directory/artifact
    target.write_text(target.read_text()+' ')
    assert summarize(plan,root)['batchStatusCounts'].get('invalid')==1


def test_project_acquisition_uses_same_ast_for_optional_inventory(tmp_path,monkeypatch):
    from riscv2x86_py import project_compile_context as project
    c=context();calls=[]
    monkeypatch.setattr(project,'validate',lambda _:None)
    def acquire(source,**kwargs):
        calls.append(kwargs)
        return {'ast':tree(),'inventory':{'functions':[]},'dependencyManifest':{'dependencyIdentity':'dep'},
                'compilerDigest':'compiler','astDigest':'raw-evidence'}
    monkeypatch.setattr('riscv2x86_py.compiler_call_dependencies.acquire',acquire)
    c.update(inspectionReady=True,inspectionArguments=[],workingDirectory=str(tmp_path))
    result=project.acquire(c,clang='clang',include_asm_inventory=True)
    assert calls[0]['include_ast'] is True and calls[0]['native_context']==c
    assert result['schemaVersion']=='riscv2x86.project-context-inspection.v2'
    assert 'ast' not in result['snapshot'] and result['snapshot']['astDigest']=='raw-evidence'
    assert len(result['snapshot']['asmActivationInventory']['instances'])==3


def prepare_tool():
    spec=importlib.util.spec_from_file_location('activation_prepare',Path(__file__).parents[2]/'experiment/prepare_real_project_experiment.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def test_independent_replay_compares_optional_asm_inventory(tmp_path,monkeypatch):
    from riscv2x86_py.compiler_function_types import derive as derive_types
    m=prepare_tool();p=records(tmp_path);control={'changed':False}
    def acquire(c,**kwargs):
        assert kwargs['include_asm_inventory'] is True
        ast=tree()
        if control['changed']:ast['inner'].pop()
        inventory=scan(ast,context=c,dependency_identity='dep',compiler_digest='compiler',target='riscv64')
        snapshot={'inventory':{},'asmActivationInventory':inventory,
            'functionTypeInventory':derive_types({'inner':[]},source_path=c['sourcePath'],dependency_identity='dep',target='riscv64'),
            'dependencyManifest':{'compilerCommand':[sys.executable]},'compilerCommand':[sys.executable],
            'compilerDigest':'compiler','dependencyClosureVerified':False,'semanticApproval':False}
        result={'schemaVersion':'riscv2x86.project-context-inspection.v2','contextIdentity':c['contextIdentity'],
            'snapshot':snapshot,'functions':[],'compilerEquivalenceVerified':False,
            'contextAcquisitionConsistent':True,'semanticApproval':False,'productionAcceptanceComplete':False}
        return dict(result,inspectionIdentity=identity(result))
    monkeypatch.setattr(m,'acquire',acquire);monkeypatch.setattr(m,'validate_dependencies',lambda _:None)
    report=m.inspect(json.loads(p.read_text()),clang=sys.executable,sources=[tmp_path/'a.c'],asm_inventory=True)
    assert m.replay(report)['contextReplayComplete']
    control['changed']=True
    with pytest.raises(ValueError,match='REPLAY_MISMATCH:asmActivationInventory'):m.replay(report)


def test_real_clang_macro_and_header_occurrences_across_compiler_processes(tmp_path):
    clang=os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    if not clang:pytest.skip('real Clang required for whole-AST asm integration')
    header=tmp_path/'body.h';header.write_text('#define OP() __asm__ volatile ("" ::: "memory")\n'
        'static inline void helper(void) { OP(); }\n')
    source=tmp_path/'unit.c';source.write_text('#include "body.h"\nvoid entry(void) { helper(); OP(); }\n')
    def once():
        result=subprocess.run([clang,'-fsyntax-only','-Xclang','-ast-dump=json',str(source)],capture_output=True,text=True,check=True)
        c=dict(context(),sourcePath=str(source))
        return scan(json.loads(result.stdout),context=c,dependency_identity='dep',compiler_digest='compiler',target='x86_64')
    a=once();b=once();assert a==b
    assert len(a['instances'])==2 and all(i['macroLocationPresent'] for i in a['instances'])
