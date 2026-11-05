import importlib.util
import json
from pathlib import Path
import pytest

from riscv2x86_py.project_activation_batches import summarize
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py import project_instance_eligibility as module


def fixture(tmp_path,bind_locations=False):
    spec=importlib.util.spec_from_file_location('activation_fixture',
        Path(__file__).with_name('test_project_activation_inventory.py'))
    helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
    plan,root,directory=helpers.completed_batch(tmp_path)
    path=directory/'contexts.json';report=json.loads(path.read_text())
    for row in report['records']:
        row['inspection']['snapshot']['dependencyManifest']['dependencies']=[]
    if bind_locations:
        header=tmp_path/'macro.h';header.write_text('synthetic location evidence only\n')
        for row in report['records']:
            snapshot=row['inspection']['snapshot'];c=row['context'];v=snapshot['asmActivationInventory']
            snapshot['dependencyManifest']['dependencies']=[{'resolvedPath':str(p),'digest':digest(p)}
                for p in (header,Path(c['sourcePath']))]
            for instance in v['instances']:
                spelling={'file':str(header),'offset':1,'tokLen':1}
                expansion={'file':c['sourcePath'],'offset':instance['ordinal'],'tokLen':1}
                instance['range']={'begin':{'spellingLoc':spelling,'expansionLoc':expansion},
                    'end':{'spellingLoc':dict(spelling,offset=5),'expansionLoc':expansion}}
                instance['macroLocationPresent']=True
                instance['activationIdentity']=identity({
                    **{k:x for k,x in instance.items() if k!='activationIdentity'},
                    'contextIdentity':c['contextIdentity'],'dependencyIdentity':v['dependencyIdentity'],
                    'compilerDigest':v['compilerDigest'],'target':v['target']})
            v['inventoryIdentity']=identity({k:x for k,x in v.items() if k!='inventoryIdentity'})
    report['preflightIdentity']=identity({k:v for k,v in report.items() if k!='preflightIdentity'})
    path.write_text(json.dumps(report))
    status=directory/'run-status.json';state=json.loads(status.read_text())
    state['inspectionReportDigest']=digest(path)
    from riscv2x86_py.project_inspection_pilot import verify_members
    batch=json.loads((root/'batch-0000.plan.json').read_text())
    (directory/'summary.json').write_text(json.dumps(verify_members(report,batch)))
    state['inspectionSummaryDigest']=digest(directory/'summary.json')
    state['stateIdentity']=identity({k:v for k,v in state.items() if k!='stateIdentity'})
    status.write_text(json.dumps(state))
    ledger_path=tmp_path/'ledger.json';ledger_path.write_text(json.dumps(summarize(plan,root)))
    return plan,root,ledger_path


def test_bound_definition_and_expansion_tokens_are_not_edit_authority(tmp_path):
    plan,root,ledger=fixture(tmp_path,bind_locations=True);value=module.acquire(plan,root,ledger)
    assert value['definitionSliceCount']==1 and value['occurrenceCount']==6
    assert all(r['locationEvidenceComplete'] is True for r in value['records'])
    assert all(r['sourceInstanceBindingComplete'] is False for r in value['records'])
    assert all(r['editAuthorizationComplete'] is False for r in value['records'])
    assert value['firstBlockerCounts']=={'NATIVE_INSPECTION_CPP_COMPARISON_REQUIRED':6}


def test_eligibility_keeps_denominator_variants_and_unknown_macro_locations(tmp_path):
    plan,root,ledger=fixture(tmp_path);value=module.acquire(plan,root,ledger)
    assert value['occurrenceCount']==6
    assert value['contextCount']==4 and value['sourceCount']==3
    assert value['batchStatusCounts']=={'recorded_inspection_replayed':1,'not_run':2}
    assert len({r['contextIdentity'] for r in value['records']})==2
    assert all(r['eligibilityStatus']=='blocked' for r in value['records'])
    assert all(r['locationEvidenceComplete'] is False for r in value['records'])
    assert value['freshCompilerAcquisitionPerformed'] is False
    assert all(r['editAuthorizationComplete'] is False for r in value['records'])
    assert not value['semanticApproval'] and not value['endToEndEligibilityAssessed']
    assert module.validate(json.loads(json.dumps(value)))==value


def test_rehashed_discovery_cannot_omit_occurrences(tmp_path):
    plan,root,path=fixture(tmp_path);ledger=json.loads(path.read_text());ledger['occurrences'].pop()
    ledger['ledgerIdentity']=identity({k:v for k,v in ledger.items() if k!='ledgerIdentity'})
    path.write_text(json.dumps(ledger))
    with pytest.raises(ValueError,match='DISCOVERY_REPLAY_MISMATCH'):module.acquire(plan,root,path)


def test_rehashed_eligibility_cannot_claim_edit_or_semantic_authority(tmp_path):
    plan,root,path=fixture(tmp_path);value=module.acquire(plan,root,path)
    value['records'][0]['editAuthorizationComplete']=True
    value['records'][0]['eligibilityIdentity']=identity({k:v for k,v in value['records'][0].items() if k!='eligibilityIdentity'})
    value['eligibilityInventoryIdentity']=identity({k:v for k,v in value.items() if k!='eligibilityInventoryIdentity'})
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):module.validate(value)
