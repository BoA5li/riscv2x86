"""Actual GCC/ar captures across stages with provenance and rejection tests."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from .test_native_captured_deployment import captured
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_link_contexts as contexts
from riscv2x86_py import native_capture_scope as scope
from riscv2x86_py.project_build_capture import inventory,run


def separated(captured, *, stage_exit=0):
    root,p,old=captured
    rec=d.read(old['testRecords']['path']);config=d.read(rec['captureConfig'])
    cc=config['wrappers']['cc']['path'];ar=config['wrappers']['ar']['path']
    (p/'earlier.c').write_text('int earlier(int x){return x+2;}')
    for argv in ([cc,'-c','earlier.c','-o','earlier.o'],[ar,'cq','support.a','earlier.o']):
        token,code=run(rec['captureConfig'],'support-build',argv,cwd=p);assert code==0
        if stage_exit:
            # Explicitly corrupt the parent run's verdict but preserve its
            # own hash: all raw invocation bytes still require replay.
            f=Path(config['directory'])/'runs'/(token+'.finish.json')
            row=d.read(f);row['returnCode']=stage_exit
            f.write_text(json.dumps(d.seal({k:v for k,v in row.items() if k!='recordIdentity'},'recordIdentity')))
    (p/'entry.c').write_text('extern int value(void),earlier(int);int main(void){return value()+earlier(1);}')
    for argv in ([cc,'-c','entry.c','-o','entry.o'],
        [cc,'-o','stage-program','entry.o','support.a',str(p/'libprobe.so'),'./libprobe.so.1','-Wl,-rpath','-Wl,'+str(p)]):
        _,code=run(rec['captureConfig'],'entry-build',argv,cwd=p);assert code==0
    record=inventory(rec['captureConfig'],stage='entry-build')
    path=root/'entry-records.json';path.write_text(json.dumps(record))
    entry=next(a for a in record['actions'] if (a.get('observedOutput') or {}).get('path')==str(p/'stage-program'))
    plan=d.prepare(root/'candidate.json',old['libraryRecords']['path'],path,old['requirements']['path'],
                   entry_action=entry['actionIdentity'],environment=old['environment'])
    return plan,rec['captureConfig']


def test_prior_stage_archive_and_compile_producers_are_replayed(captured):
    root,p,_=captured;plan,_=separated(captured)
    selected=d.read(plan['testRecords']['path'])['actions']
    assert not any(a.get('archiveOperationEvidence') for a in selected)
    deployed=d.execute(plan,root/'deployment',diagnostic_only=True)
    result=contexts.derive(plan,deployed)
    assert result['capturedProducerClosureComplete']
    archive=next(n for n in result['nodes'] if n['kind']=='regular-archive')
    assert archive['archiveProducerStages'][0]['stage']=='support-build'
    member=next(n for n in result['nodes'] if n['file']['path']==str(p/'earlier.o'))
    assert member['producerStage']['stage']=='support-build'
    assert not member['producerStage']['selectedRecordAnchor']
    assert result['crossStageCaptureReplayPerformed']
    assert not result['actualArchiveExtractionSelectionVerified']
    assert contexts.derive(plan,deployed)==result


def test_forged_unselected_json_is_not_used_as_authority(captured):
    root,_,_=captured;plan,_=separated(captured)
    path=Path(plan['testRecords']['path']);value=d.read(path)
    value['unselectedActions']=[{'actionIdentity':'invented','observedReturnCode':0}]
    path.write_text(json.dumps(d.seal({k:v for k,v in value.items() if k!='inventoryIdentity'},'inventoryIdentity')))
    plan['testRecords']=d.snapshot(path)
    # The selected actions are separately replayed; the forged unselected
    # list is never imported. Actual earlier-stage facts come from raw files.
    loaded=scope.load(plan)
    assert 'invented' not in loaded[1]
    assert any(s['stage']=='support-build' for s in loaded[4].values())


def test_raw_replay_corruption_is_rejected(captured):
    _,_,_=captured;plan,config_path=separated(captured)
    config=d.read(config_path)
    file=next((Path(config['directory'])/'invocations').glob('*.finish.json'))
    row=d.read(file);row['returnCode']=123
    file.write_text(json.dumps(row))
    with pytest.raises(ValueError):scope.load(plan)


def test_failed_parent_stage_cannot_close_archive_origin(captured):
    root,_,_=captured;plan,_=separated(captured,stage_exit=1)
    deployed=d.execute(plan,root/'deployment',diagnostic_only=True)
    report=contexts.derive(plan,deployed)
    assert not report['capturedProducerClosureComplete']
    gap=next(g for g in report['inputGaps'] if g['reasonCode']=='ARCHIVE_OPERATION_CHAIN_NOT_UNIQUE_OR_UNAVAILABLE')
    assert any(a['selection'].get('reason')=='ARCHIVE_PRODUCER_STAGE_NOT_ADMITTED' for a in gap['selectionAttempts'])


def test_new_raw_observation_during_derivation_is_detected(captured):
    _,_,plan=captured
    records,actions,origins,configs,stages,summaries,raw=scope.load(plan)
    config=next(iter(configs.values()));folder=Path(config['directory'])/'invocations'
    (folder/('f'*32+'.start.json')).write_text('{}')
    with pytest.raises(ValueError,match='FILE_SET_CHANGED'):scope.close(configs,raw)


def test_checked_map_attributes_unique_archive_member_contribution(captured):
    from riscv2x86_py.native_archive_selection import derive
    root,_,_=captured;plan,_=separated(captured)
    deployed=d.execute(plan,root/'deployment',diagnostic_only=True)
    graph=contexts.derive(plan,deployed)
    value=derive(plan,deployed,graph)
    assert value['observedArchiveMemberCount']==1
    selected=value['archives'][0]['observedMemberSelections']
    assert any(s['memberName']=='earlier.o' and s['observedMemberContributionVerified'] for s in selected)
    assert not value['actualLinkSelectionClosureVerified']
    assert not value['absenceProvesNonExtraction']
    assert all(not s['nativeAbiContractVerified'] for s in selected)
    (root/'deployment/derived-entry/link.map').write_text('changed')
    with pytest.raises(ValueError,match='MAP_CHANGED'):derive(plan,deployed,graph)


def test_independent_archive_audit_rebuilds_bytes_and_member_relations(captured):
    from riscv2x86_py import native_archive_audit as audit
    root,_,_=captured;plan,_=separated(captured)
    d.execute(plan,root/'deployment',diagnostic_only=True)
    value=audit.acquire(root/'deployment/result.json',root/'archive-audit')
    assert value['independentObservedArchiveContributionsVerified']
    assert value['verifiedObservedArchiveMemberCount']==1
    assert audit.check(root/'archive-audit/result.json')==value
    assert not value['actualLinkSelectionClosureVerified']
    path=root/'archive-audit/result.json';value['nativeAbiClosureVerified']=True
    path.write_text(json.dumps(d.seal({k:v for k,v in value.items() if k!='archiveSelectionAuditIdentity'},'archiveSelectionAuditIdentity')))
    with pytest.raises(ValueError,match='REDERIVATION_MISMATCH'):audit.check(path)


def test_duplicate_member_names_do_not_gain_unique_selection(captured):
    from .test_native_link_contexts import archive_plan
    from riscv2x86_py.native_archive_selection import derive
    root,_,_=captured;plan=archive_plan(captured)
    deployed=d.execute(plan,root/'deployment',diagnostic_only=True)
    graph=contexts.derive(plan,deployed)
    value=derive(plan,deployed,graph)
    assert value['observedArchiveMemberCount']==0
    assert any(a['unresolvedContributions'] for a in value['archives'])
    assert not value['actualLinkSelectionClosureVerified']


def test_empty_archive_domain_never_approves_by_vacuity(captured):
    from riscv2x86_py import native_archive_audit as audit
    root,_,plan=captured
    d.execute(plan,root/'deployment',diagnostic_only=True)
    value=audit.acquire(root/'deployment/result.json',root/'empty-audit')
    assert value['artifactBytesReproduced']
    assert value['verifiedObservedArchiveMemberCount']==0
    assert not value['independentObservedArchiveContributionsVerified']


def test_unrelated_ordinary_archive_probe_does_not_poison_target_chain(captured):
    root,p,old=captured
    record=d.read(old['testRecords']['path']);config=d.read(record['captureConfig'])
    ar=config['wrappers']['ar']['path']
    _,code=run(record['captureConfig'],'probe-stage',[ar,'rcs','other.a','main.o'],cwd=p)
    assert code==0
    plan,_=separated(captured)
    deployed=d.execute(plan,root/'deployment',diagnostic_only=True)
    report=contexts.derive(plan,deployed)
    assert report['capturedProducerClosureComplete']
    archive=next(n for n in report['nodes'] if n['kind']=='regular-archive')
    assert any(a['excludedUnrelatedOperationIdentities'] for a in archive['archiveSelectionAttempts'])


def test_unsupported_operation_on_target_is_still_a_blocker(captured):
    root,p,_=captured;plan,config_path=separated(captured)
    config=d.read(config_path)
    # Destination-only identification must not admit a replace operation on
    # the requested archive or turn its observed output into a valid chain.
    from riscv2x86_py.native_capture_scope import unrelated_archive_operation
    _,code=run(config_path,'later-stage',[config['wrappers']['ar']['path'],'rcs','support.a','earlier.o'],cwd=p)
    assert code==0
    actions=inventory(config_path,stage='later-stage')['actions']
    action=next(a for a in actions if a['kind']=='archive')
    assert not unrelated_archive_operation(action,d.snapshot(p/'support.a'))


@pytest.mark.parametrize('profile',['gnu-ar','gnu-ranlib'])
def test_exact_read_only_tool_queries_do_not_become_archive_writes(profile):
    from riscv2x86_py.native_capture_scope import unrelated_archive_operation
    action={'archiveOperationEvidence':{'before':{'supported':False,'profile':profile}},
            'arguments':['/registered/tool','--version']}
    assert unrelated_archive_operation(action,{'resolvedPath':'/archive.a'})
    action['arguments'].append('/archive.a')
    assert not unrelated_archive_operation(action,{'resolvedPath':'/archive.a'})


def test_configuration_change_during_graph_derivation_is_detected(captured):
    _,_,plan=captured
    records,actions,origins,configs,stages,summaries,raw=scope.load(plan)
    path=Path(next(iter(raw.values()))['captureConfig'])
    path.write_text(path.read_text()+'\n')
    with pytest.raises(ValueError,match='CONFIG_CHANGED'):scope.close(configs,raw)
