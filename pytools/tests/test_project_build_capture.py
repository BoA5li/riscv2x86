"""Actual nested make/compiler invocations, failures and receipt replay."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from riscv2x86_py.project_build_capture import create,load,run,inventory,read,write
from riscv2x86_py.project_compile_context import derive,validate
from riscv2x86_py.project_build_records import identity


def tools():
    cc=shutil.which('gcc');make=shutil.which('make')
    if not cc or not make:pytest.skip('native GCC and make required')
    return cc,make


def prepare(tmp_path):
    cc,_=tools();config=tmp_path/'config.h';config.write_text('#define VALUE 7\n')
    value=create(tmp_path/'capture',{'cc':cc},inputs=[config])
    source=tmp_path/'source';source.mkdir()
    (source/'x.c').write_text('#include "../config.h"\nint entry(void) {return VALUE;}\n')
    return value,source,tmp_path/'capture/capture.json'


def test_nested_make_preserves_real_cwd_and_objects_and_replay(tmp_path):
    value,source,config=prepare(tmp_path);_,make=tools()
    child=source/'child';child.mkdir();(child/'Makefile').write_text('all:\n\t$(CC) -std=c99 -O2 -c ../x.c -o x.o\n')
    (source/'Makefile').write_text('all:\n\t$(MAKE) -C child CC="$(CC)"\n')
    token,code=run(config,'build',[make,'-j2','CC='+value['wrappers']['cc']['path']],cwd=source)
    assert code==0 and (child/'x.o').is_file()
    doc=inventory(config,stage='build')
    assert doc['importComplete'] and doc['actionCounts']=={'compile':1}
    assert doc['runRecords'][0]['runId']==token
    a=doc['actions'][0]
    assert a['directory']==str(child) and a['arguments'][0]==value['tools']['cc']['path']
    assert a['exitStatusObserved'] and a['observedReturnCode']==0
    assert a['observedOutput']['digest'].startswith('sha256:')
    context=derive(a);assert context['inspectionReady'];validate(context)
    assert not doc['buildSuccessVerified'] and not doc['processTreeCompletenessVerified']
    spec=importlib.util.spec_from_file_location('prepare_capture',Path(__file__).resolve().parents[2]/'experiment/prepare_real_project_experiment.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    report=module.inspect(doc);assert report['buildVariantCount']==1
    assert module.replay(report)['contextReplayComplete']
    (source/'x.c').write_text('int changed;\n')
    assert 'PROJECT_CAPTURE_INPUTS_CHANGED' in derive(a)['blockers']
    with pytest.raises(ValueError):module.replay(report)


def test_configure_probes_are_retained_without_blocking_build_stage(tmp_path):
    value,source,config=prepare(tmp_path)
    wrapper=value['wrappers']['cc']['path']
    _,code=run(config,'configure',[wrapper,'-c','does-not-exist.c','-o','probe.o'],cwd=source)
    assert code!=0
    _,code=run(config,'build',[wrapper,'-std=c99','-c','x.c','-o','x.o'],cwd=source)
    assert code==0
    doc=inventory(config,stage='build')
    assert len(doc['actions'])==1 and len(doc['unselectedActions'])==1 and doc['importComplete']
    assert doc['unselectedActions'][0]['observedReturnCode']!=0
    assert inventory(config)['observedFailureCount']==1
    assert inventory(config,stage='absent')['importComplete'] is False


def test_failed_compile_cannot_become_a_ready_context(tmp_path):
    value,source,config=prepare(tmp_path)
    (source/'x.c').write_text('not valid C at all\n')
    _,code=run(config,'build',[value['wrappers']['cc']['path'],'-c','x.c','-o','bad.o'],cwd=source)
    assert code!=0
    doc=inventory(config,stage='build');assert doc['observedFailureCount']==1
    ctx=derive(doc['actions'][0]);assert not ctx['inspectionReady']
    assert 'PROJECT_NATIVE_ACTION_FAILED' in ctx['blockers']


def test_signals_and_literal_arguments_are_not_shell_evaluated(tmp_path):
    # The caller explicitly selects an executable; arguments remain argv even
    # when their contents look like shell expansion or redirection.
    value=create(tmp_path/'capture',{'python':sys.executable})
    config=tmp_path/'capture/capture.json';output=tmp_path/'args.json'
    command='import json,sys;open(sys.argv[1],"w").write(json.dumps(sys.argv[2:]))'
    _,code=run(config,'build',[value['wrappers']['python']['path'],'-c',command,str(output),'$(touch BAD)','a b','>target'],cwd=tmp_path)
    assert code==0 and not (tmp_path/'BAD').exists()
    assert json.loads(output.read_text())==['$(touch BAD)','a b','>target']
    _,code=run(config,'signal',[value['wrappers']['python']['path'],'-c','import os,signal;os.kill(os.getpid(),signal.SIGTERM)'],cwd=tmp_path)
    assert code==-15
    assert inventory(config,stage='signal')['actions'][0]['observedReturnCode']==-15


def test_parallel_actions_have_unique_receipts(tmp_path):
    value,source,config=prepare(tmp_path);_,make=tools()
    (source/'Makefile').write_text('all: '+ ' '.join('o'+str(i) for i in range(6))+'\n'+
        ''.join(f'o{i}:\n\t$(CC) -c x.c -o o{i}.o\n' for i in range(6)))
    _,code=run(config,'build',[make,'-j6','CC='+value['wrappers']['cc']['path']],cwd=source)
    assert code==0
    d=inventory(config,stage='build');assert len(d['actions'])==6 and d['importComplete']
    assert len({a['provenance']['invocationId'] for a in d['actions']})==6
    assert len({a['observedOutput']['path'] for a in d['actions']})==6


def test_unfinished_and_orphaned_receipts_are_not_success(tmp_path):
    value,source,config=prepare(tmp_path)
    _,code=run(config,'build',[value['wrappers']['cc']['path'],'-c','x.c','-o','x.o'],cwd=source)
    assert code==0
    finished=next((tmp_path/'capture/invocations').glob('*.finish.json'));finished.unlink()
    doc=inventory(config,stage='build')
    assert not doc['importComplete']
    assert any('UNFINISHED_INVOCATION' in r['reasonCode'] for r in doc['unresolved'])


def test_changed_tool_wrapper_or_configuration_rejects(tmp_path):
    value,source,config=prepare(tmp_path)
    (tmp_path/'config.h').write_text('#define VALUE 9\n')
    with pytest.raises(ValueError,match='CONFIGURATION_CHANGED'):load(config)


def test_tampered_return_code_or_pair_is_not_accepted(tmp_path):
    value,source,config=prepare(tmp_path)
    run(config,'build',[value['wrappers']['cc']['path'],'-c','x.c','-o','x.o'],cwd=source)
    path=next((tmp_path/'capture/invocations').glob('*.finish.json'))
    row=json.loads(path.read_text());row['returnCode']=False
    row['recordIdentity']=identity({k:v for k,v in row.items() if k!='recordIdentity'});path.write_text(json.dumps(row))
    assert not inventory(config)['importComplete']


def test_empty_trace_does_not_grant_build_completeness(tmp_path):
    value,source,config=prepare(tmp_path)
    run(config,'build',['/bin/true'],cwd=source)
    doc=inventory(config,stage='build')
    assert not doc['importComplete'] and not doc['buildSuccessVerified']
    assert not doc['productionAcceptanceComplete']


def test_actual_elf_target_is_not_inferred_from_source_path(tmp_path):
    value,source,config=prepare(tmp_path)
    run(config,'build',[value['wrappers']['cc']['path'],'-c','x.c','-o','x.o'],cwd=source)
    doc=inventory(config,stage='build')
    elf=doc['actions'][0]['observedOutput']['elfHeader']
    if elf['machine']!=62 or elf['classBits']!=64:pytest.skip('fixture requires x86_64 native GCC')
    spec=importlib.util.spec_from_file_location('prepare_targets',Path(__file__).resolve().parents[2]/'experiment/prepare_real_project_experiment.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    assert m.inspect(doc,target='riscv64')['records'][0]['status']=='outside_source_target'
    assert m.inspect(doc,target='x86_64')['records'][0]['status']=='context_ready'


def test_failed_parent_command_is_recorded_without_erasing_successful_actions(tmp_path):
    value,source,config=prepare(tmp_path);_,make=tools()
    (source/'Makefile').write_text('all:\n\t$(CC) -c x.c -o x.o\n\tfalse\n')
    _,code=run(config,'build',[make,'CC='+value['wrappers']['cc']['path']],cwd=source)
    assert code!=0
    doc=inventory(config,stage='build')
    assert len(doc['actions'])==1 and doc['actions'][0]['observedReturnCode']==0
    assert doc['selectedRunFailures'] and not doc['buildSuccessVerified']
    assert derive(doc['actions'][0])['inspectionReady']


def test_wrapper_configuration_and_source_changes_are_bound(tmp_path):
    value,source,config=prepare(tmp_path)
    wrapper=Path(value['wrappers']['cc']['path'])
    wrapper.write_text('#!/bin/sh\nexit 0\n')
    with pytest.raises(ValueError,match='TOOL_CHANGED'):load(config)


def test_replay_does_not_accept_new_unreported_invocations(tmp_path):
    value,source,config=prepare(tmp_path)
    wrapper=value['wrappers']['cc']['path']
    run(config,'build',[wrapper,'-c','x.c','-o','x.o'],cwd=source)
    spec=importlib.util.spec_from_file_location('prepare_extra',Path(__file__).resolve().parents[2]/'experiment/prepare_real_project_experiment.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    report=m.inspect(inventory(config,stage='build'))
    run(config,'build',[wrapper,'-c','x.c','-o','other.o'],cwd=source)
    with pytest.raises(ValueError,match='BUILD_RECORD_REPLAY_MISMATCH'):m.replay(report)


def test_per_run_generated_configuration_is_frozen_after_configure(tmp_path):
    value,source,config=prepare(tmp_path)
    generated=tmp_path/'generated.h';generated.write_text('#define FLAG 1\n')
    run(config,'build',[value['wrappers']['cc']['path'],'-c','x.c','-o','x.o'],cwd=source,inputs=[generated])
    doc=inventory(config,stage='build');assert doc['importComplete']
    generated.write_text('#define FLAG 2\n')
    assert not inventory(config,stage='build')['importComplete']


def test_per_run_configuration_change_cannot_be_reported_as_success(tmp_path):
    value,source,config=prepare(tmp_path)
    generated=tmp_path/'generated.h';generated.write_text('original')
    with pytest.raises(ValueError,match='CLOSING_INPUTS_CHANGED'):
        run(config,'change',[sys.executable,'-c','import sys;open(sys.argv[1],"w").write("changed")',str(generated)],
            cwd=source,inputs=[generated])
    finishes=list((tmp_path/'capture/runs').glob('*.finish.json'))
    assert json.loads(finishes[0].read_text())['returnCode']==0


def test_capture_observation_cannot_be_downgraded_to_an_unobserved_log(tmp_path):
    value,source,config=prepare(tmp_path)
    run(config,'build',[value['wrappers']['cc']['path'],'-c','x.c','-o','x.o'],cwd=source)
    a=inventory(config,stage='build')['actions'][0]
    for flag in [False,1]:
        changed=deepcopy(a);changed['exitStatusObserved']=flag
        changed['actionIdentity']=identity({k:v for k,v in changed.items() if k!='actionIdentity'})
        with pytest.raises(ValueError):derive(changed)


def test_explicit_linker_actions_are_retained_with_their_actual_elf(tmp_path):
    cc,_=tools();ld=shutil.which('ld')
    if not ld:pytest.skip('native linker required')
    value=create(tmp_path/'capture',{'cc':cc,'ld':ld});config=tmp_path/'capture/capture.json'
    (tmp_path/'x.c').write_text('int value=7;\n')
    assert run(config,'build',[value['wrappers']['cc']['path'],'-c','x.c','-o','x.o'],cwd=tmp_path)[1]==0
    assert run(config,'build',[value['wrappers']['ld']['path'],'-r','x.o','-o','linked.o'],cwd=tmp_path)[1]==0
    doc=inventory(config,stage='build')
    assert doc['actionCounts']=={'compile':1,'link':1}
    link=next(a for a in doc['actions'] if a['kind']=='link')
    assert link['observedOutput']['elfHeader']['type']==1
    assert not doc['buildSuccessVerified']


def test_parent_run_identifier_cannot_name_an_external_record(tmp_path,monkeypatch):
    from riscv2x86_py.project_build_capture import invoke
    value,source,config=prepare(tmp_path)
    monkeypatch.setenv('RV2X86_PROJECT_CAPTURE_RUN','../../outside')
    with pytest.raises(ValueError,match='RUN_ID_INVALID'):
        invoke(config,'cc',['--version'])
    assert not list((tmp_path/'capture/invocations').iterdir())
    monkeypatch.delenv('RV2X86_PROJECT_CAPTURE_RUN');monkeypatch.chdir(source)
    assert invoke(config,'cc',['-c','x.c','-o','unattributed.o'])==0
    result=inventory(config,stage='build')
    assert any('STAGE_UNATTRIBUTED' in r['reasonCode'] for r in result['unresolved'])
    assert len(inventory(config)['actions'])==1
