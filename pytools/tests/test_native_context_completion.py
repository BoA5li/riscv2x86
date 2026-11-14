"""Acquisition scheduling only; compiler/contract boundary uses existing fixtures."""
from pathlib import Path
import json
import sys
import pytest
from .test_native_contract_evidence import fn,prepared,contract_pipeline
from riscv2x86_py import native_context_completion as completion
from riscv2x86_py import native_context_batch as batch
from riscv2x86_py import native_captured_deployment as d


@pytest.fixture
def completion_pipeline(contract_pipeline,monkeypatch):
    # Upstream report verification is covered by the existing contract suite;
    # isolate scheduling from its repeated compiler/relink fixture setup.
    root,report=contract_pipeline;file=(root/'contracts/result.json').resolve()
    def checked_parent(path):
        if Path(path).resolve()!=file:raise ValueError('fixture parent mismatch')
        return report
    monkeypatch.setattr(completion.contracts,'check',checked_parent)
    return root,report


def test_all_eligible_contexts_are_consumed_and_resumed_without_recompile(completion_pipeline,monkeypatch):
    root,_=completion_pipeline;monkeypatch.setattr(batch,'parent_receipts',lambda *a:{})
    first=completion.acquire(root/'contracts/result.json',[],root/'first',clang=sys.executable,max_contexts=1,batch_size=1)
    assert first['acquiredContextCount']==1 and first['remainingEligibleContextIndices']==[1]
    second=completion.acquire(root/'contracts/result.json',first['batchResultPaths'],root/'second',clang=sys.executable,batch_size=1)
    assert second['acquiredContextCount']==2 and second['allCapturedCContextsAcquired']
    assert not second['nativeAbiClosureVerified'] and not second['legalObjectDomainVerified']
    assert completion.check(root/'second/result.json')==second
    monkeypatch.setattr(batch.native,'acquire',lambda *a,**k:pytest.fail('completed context must not recompile'))
    third=completion.acquire(root/'contracts/result.json',second['batchResultPaths'],root/'third',clang=sys.executable)
    assert third['newlySelectedContextIndices']==[]
    assert third['allCapturedCContextsAcquired'] and not third['semanticApproval']
    third['nativeAbiClosureVerified']=True
    p=root/'third/result.json';p.write_text(json.dumps(d.seal({k:v for k,v in third.items() if k!='contextCompletionIdentity'},'contextCompletionIdentity')))
    with pytest.raises(ValueError,match='REDERIVATION_MISMATCH'):completion.check(p)


def test_interrupted_acquisition_reuses_checked_child_batches(completion_pipeline,monkeypatch):
    root,_=completion_pipeline;monkeypatch.setattr(batch,'parent_receipts',lambda *a:{})
    original=batch.acquire;calls=[]
    def interrupted(*a,**k):
        calls.append(k['indices'])
        if len(calls)==2:raise RuntimeError('fixture compiler failed')
        return original(*a,**k)
    monkeypatch.setattr(batch,'acquire',interrupted)
    with pytest.raises(RuntimeError,match='fixture compiler failed'):
        completion.acquire(root/'contracts/result.json',[],root/'interrupted',clang=sys.executable,batch_size=1)
    assert not (root/'interrupted/result.json').exists()
    child=root/'interrupted/batch-000000/result.json';batch.check(child)
    monkeypatch.setattr(batch,'acquire',original)
    result=completion.acquire(root/'contracts/result.json',[child],root/'retry',clang=sys.executable,batch_size=1)
    assert result['newlySelectedContextIndices']==[1] and result['allCapturedCContextsAcquired']


def test_unsupported_contexts_stay_explicit_not_dropped(completion_pipeline,monkeypatch):
    root,_=completion_pipeline;monkeypatch.setattr(batch,'parent_receipts',lambda *a:{})
    monkeypatch.setattr(batch,'blockers',lambda report,context:['FIXTURE_UNSUPPORTED_CONTEXT'])
    result=completion.acquire(root/'contracts/result.json',[],root/'blocked',clang=sys.executable)
    assert len(result['blockedContexts'])==2 and result['acquiredContextCount']==0
    assert not result['allCapturedCContextsAcquired'] and not result['semanticApproval']


def test_duplicate_batches_are_rejected_before_creating_output(completion_pipeline,monkeypatch):
    root,_=completion_pipeline;monkeypatch.setattr(batch,'parent_receipts',lambda *a:{})
    first=completion.acquire(root/'contracts/result.json',[],root/'first',clang=sys.executable,max_contexts=1)
    with pytest.raises(ValueError,match='DUPLICATE_BATCH'):
        completion.acquire(root/'contracts/result.json',first['batchResultPaths']*2,root/'duplicate',clang=sys.executable)
    assert not (root/'duplicate').exists()


@pytest.mark.parametrize('kwargs',[{'max_contexts':0},{'batch_size':65},{'timeout':0}])
def test_invalid_budgets_do_not_read_or_create_inputs(tmp_path,kwargs):
    with pytest.raises(ValueError,match='BUDGET_INVALID'):
        completion.acquire(tmp_path/'absent',[],tmp_path/'output',clang=sys.executable,**kwargs)
    assert not (tmp_path/'output').exists()


def test_different_inspection_compiler_cannot_be_merged_as_missing_input(tmp_path,monkeypatch):
    context={'contextIdentity':'fixture-context'}
    receipt={'context':context,'target':'x86_64','inspectionCompiler':'/fixture/other-clang',
             'nativeInputIdentity':'fixture-identity'}
    file=tmp_path/'receipt.json';file.write_text(json.dumps(receipt))
    monkeypatch.setattr(batch,'validated_input',lambda value:{})
    monkeypatch.setattr(batch,'parent_receipts',lambda *a:{'fixture':d.snapshot(file)})
    report={'producerContextClosure':{'compileContexts':[context]}}
    with pytest.raises(ValueError,match='INSPECTION_COMPILER_MISMATCH'):
        completion.pending(report,tmp_path/'base','/fixture/selected-clang',[])
