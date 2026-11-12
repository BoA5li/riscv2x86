"""Real compiler/archive/link capture; producer scope is not semantic proof."""
from copy import deepcopy
from pathlib import Path
import json
import subprocess

import pytest

from .test_native_captured_deployment import captured
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_link_contexts as contexts
from riscv2x86_py.project_build_capture import inventory,run


def deploy(root,plan):
    return d.execute(plan,root/'context-deployment',diagnostic_only=True)


def test_duplicate_dso_operands_share_producer_facts_but_keep_occurrence_order(captured):
    root,_,plan=captured;deployed=deploy(root,plan)
    report=contexts.derive(plan,deployed)
    assert report['capturedProducerClosureComplete']
    assert len(report['entryOccurrences'])==3
    a,b=report['entryOccurrences'][1:]
    assert a['nodeIdentity']==b['nodeIdentity'] and a['argumentIndex']!=b['argumentIndex']
    assert len(report['compileContexts'])==2
    assert len(report['deployedReplacements'])==2
    assert report['deployedReplacements'][0]['derivedArtifact']['digest']!=plan['library']['originalOutput']['digest']
    assert all(r['replacementVerified'] for r in report['deployedReplacements'])
    assert not report['entryAbiClosureVerified'] and not report['nativeContextAcquisitionComplete']
    assert not report['implicitDriverDependenciesIncluded']


def archive_plan(captured,*,capture_archive=True):
    root,p,old=captured
    records=d.read(old['testRecords']['path']);config=d.read(records['captureConfig'])
    cc=config['wrappers']['cc']['path'];ar=config['wrappers']['ar']['path']
    def invoke(argv):
        _,status=run(records['captureConfig'],'test',argv,cwd=p);assert status==0
    for folder,name,value in [('a','left',2),('b','right',5)]:
        (p/folder).mkdir();(p/folder/'unit.c').write_text(f'int {name}(void){{return {value};}}\n')
        invoke([cc,'-c',folder+'/unit.c','-o',folder+'/same.o'])
    # A byte-identical but unrelated output must not become an ar producer.
    invoke([cc,'-c','a/unit.c','-o','unrelated.o'])
    if capture_archive:invoke([ar,'cqs','support.a','a/same.o','b/same.o'])
    else:subprocess.run([config['tools']['ar']['path'],'rcs','support.a','a/same.o','b/same.o'],cwd=p,check=True)
    (p/'entry.c').write_text('extern int value(void),left(void),right(void);int main(void){return value()+left()+right();}')
    invoke([cc,'-c','entry.c','-o','entry.o'])
    invoke([cc,'-o','archive-program','entry.o','support.a',str(p/'libprobe.so'),'./libprobe.so.1',
            '-Wl,-rpath','-Wl,'+str(p)])
    record=inventory(records['captureConfig'],stage='test')
    path=root/'archive-test-records.json';path.write_text(json.dumps(record))
    entry=next(a for a in record['actions'] if (a.get('observedOutput') or {}).get('path')==str(p/'archive-program'))
    return d.prepare(root/'candidate.json',old['libraryRecords']['path'],path,old['requirements']['path'],
                     entry_action=entry['actionIdentity'],environment=old['environment'])


def test_archive_members_bind_to_recorded_inputs_not_basenames_or_equal_bytes(captured):
    root,_,_=captured;plan=archive_plan(captured);report=contexts.derive(plan,deploy(root,plan))
    assert report['capturedProducerClosureComplete']
    members=[e for e in report['edges'] if e['kind']=='archive-member']
    assert [e['memberName'] for e in members]==['same.o','same.o']
    assert len({e['memberHeaderOffset'] for e in members})==2
    nodes={n['nodeIdentity']:n for n in report['nodes']}
    assert [Path(nodes[e['target']]['file']['path']).parent.name for e in members]==['a','b']
    assert not any(Path(n['file']['path']).name=='unrelated.o' for n in nodes.values())
    assert not report['actualArchiveExtractionSelectionVerified']


def test_archive_without_capture_chain_stays_unbound(captured):
    root,_,_=captured;plan=archive_plan(captured,capture_archive=False)
    report=contexts.derive(plan,deploy(root,plan))
    assert not report['capturedProducerClosureComplete']
    assert any(g['reasonCode']=='ARCHIVE_OPERATION_CHAIN_NOT_UNIQUE_OR_UNAVAILABLE' for g in report['inputGaps'])


def test_consumer_time_not_content_match_selects_producers(captured):
    root,_,plan=captured;deployed=deploy(root,plan)
    changed=deepcopy(plan);changed['entry']['action']['observedInvocationInterval']['start']=0
    report=contexts.derive(changed,deployed)
    assert not report['capturedProducerClosureComplete']
    assert any(g['reasonCode']=='CAPTURED_PRODUCER_NOT_UNIQUE_OR_UNAVAILABLE' for g in report['inputGaps'])


def test_parent_mismatch_changed_input_and_budget_do_not_approve(captured):
    root,p,plan=captured;deployed=deploy(root,plan)
    with pytest.raises(ValueError,match='NODE_BUDGET'):contexts.derive(plan,deployed,node_limit=1)
    wrong=deepcopy(deployed);wrong['deploymentPlanIdentity']='different'
    with pytest.raises(ValueError,match='DEPLOYMENT_MISMATCH'):contexts.derive(plan,wrong)
    (p/'main.o').write_bytes(b'changed')
    with pytest.raises(ValueError):contexts.derive(plan,deployed)


def test_object_alias_binds_same_canonical_producer_without_erasing_lexical_input(captured):
    root,p,old=captured
    record=d.read(old['testRecords']['path']);config=d.read(record['captureConfig'])
    (p/'object-alias.o').symlink_to('main.o')
    _,status=run(record['captureConfig'],'test',[config['wrappers']['cc']['path'],'-o','alias-program',
        'object-alias.o',str(p/'libprobe.so'),'./libprobe.so.1','-Wl,-rpath','-Wl,'+str(p)],cwd=p)
    assert status==0
    new=inventory(record['captureConfig'],stage='test');path=root/'alias-records.json';path.write_text(json.dumps(new))
    entry=next(a for a in new['actions'] if (a.get('observedOutput') or {}).get('path')==str(p/'alias-program'))
    plan=d.prepare(root/'candidate.json',old['libraryRecords']['path'],path,old['requirements']['path'],
                   entry_action=entry['actionIdentity'],environment=old['environment'])
    report=contexts.derive(plan,deploy(root,plan))
    assert report['capturedProducerClosureComplete']
    first=report['entryOccurrences'][0]
    assert first['path']==str(p/'object-alias.o')
    node=next(n for n in report['nodes'] if n['nodeIdentity']==first['nodeIdentity'])
    assert node['file']['resolvedPath']==str(p/'main.o')


def test_archive_diagnostic_retains_underlying_selection_reason(captured):
    root,_,_=captured;plan=archive_plan(captured,capture_archive=False)
    report=contexts.derive(plan,deploy(root,plan))
    gap=next(g for g in report['inputGaps'] if g['reasonCode']=='ARCHIVE_OPERATION_CHAIN_NOT_UNIQUE_OR_UNAVAILABLE')
    assert gap['candidateCount']==0
    assert gap['selectionAttempts']
    assert {a['selection']['reason'] for a in gap['selectionAttempts']}=={'ARCHIVE_OPERATION_EVIDENCE_MISSING'}


def test_assembly_data_object_does_not_receive_function_contract(captured):
    root,p,old=captured
    record=d.read(old['testRecords']['path']);config=d.read(record['captureConfig'])
    wrapper=config['wrappers']['cc']['path']
    (p/'data.S').write_text('.data\n.globl arbitrary_table\n.type arbitrary_table,@object\n'
                           'arbitrary_table:\n.quad 17\n.size arbitrary_table,8\n'
                           '.section .note.GNU-stack,"",@progbits\n')
    for args in [ ['-c','data.S','-o','data.o'],
        ['-o','asm-program','main.o','data.o',str(p/'libprobe.so'),'./libprobe.so.1',
         '-Wl,-rpath','-Wl,'+str(p)]]:
        _,code=run(record['captureConfig'],'test',[wrapper,*args],cwd=p);assert code==0
    new=inventory(record['captureConfig'],stage='test');path=root/'asm-records.json';path.write_text(json.dumps(new))
    entry=next(a for a in new['actions'] if (a.get('observedOutput') or {}).get('path')==str(p/'asm-program'))
    plan=d.prepare(root/'candidate.json',old['libraryRecords']['path'],path,old['requirements']['path'],
                   entry_action=entry['actionIdentity'],environment=old['environment'])
    report=contexts.derive(plan,deploy(root,plan))
    node=next(n for n in report['nodes'] if n['file']['path']==str(p/'data.o'))
    assert node['producerBound']
    symbol=next(s for s in node['assemblyInterface']['definedSymbols'] if s['name']=='arbitrary_table')
    assert symbol['type']==1
    assert not node['assemblyInterface']['nativeAbiContractVerified']
    assert report['capturedProducerClosureComplete']
    assert any(g['reasonCode']=='ASSEMBLY_CONTEXT_CONTRACT_REQUIRED' for g in report['inputGaps'])
