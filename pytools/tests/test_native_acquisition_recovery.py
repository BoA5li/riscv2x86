"""Real native CPP/ELF fixture; inspection is explicitly mocked upstream."""
from pathlib import Path
import json
import shutil
import sys
import pytest
from .test_native_context_completion import completion_pipeline
from .test_native_contract_evidence import contract_pipeline,prepared
from riscv2x86_py import native_context_batch as batch
from riscv2x86_py import native_frontend_selection as selection
from riscv2x86_py import native_context_completion as completion
from riscv2x86_py.project_acquisition import Runner,StageFailure


def test_partial_batch_recovers_successful_receipts_without_recompiling(completion_pipeline,monkeypatch):
    root,report=completion_pipeline
    monkeypatch.setattr(batch,'parent_receipts',lambda *a:{})
    native_acquire=batch.native.acquire;calls=[]
    def fail_second(*args,**kwargs):
        calls.append(args[0]['contextIdentity'])
        if len(calls)==2:raise StageFailure('fixture-inspection',7)
        return native_acquire(*args,**kwargs)
    monkeypatch.setattr(batch.native,'acquire',fail_second)
    with pytest.raises(StageFailure):
        batch.acquire(root/'contracts/result.json',root/'partial',clang=sys.executable,count=2)
    progress=json.loads((root/'partial/progress.json').read_text())
    assert progress['state']=='failed' and progress['processedContextIndices']==[0]
    assert progress['acquiredContextIndices']==[0]
    assert not progress['semanticApproval'] and not (root/'partial/result.json').exists()
    monkeypatch.setattr(batch.native,'acquire',lambda *a,**k:pytest.fail('valid receipt must be reused'))
    value=batch.recover(root/'contracts/result.json',root/'partial',root/'recovered',clang=sys.executable)
    assert value['selectedContextIndices']==[0] and value['selectedContextAcquisitionComplete']
    assert not value['nativeAbiClosureVerified']
    acquired,remaining,_=completion.pending(report,root/'contracts/result.json',str(Path(sys.executable).resolve()),
                                          [root/'recovered/result.json'])
    assert len(acquired)==1 and remaining==[1]


def test_recovery_rejects_changed_successful_receipt(completion_pipeline,monkeypatch):
    root,_=completion_pipeline;monkeypatch.setattr(batch,'parent_receipts',lambda *a:{})
    batch.acquire(root/'contracts/result.json',root/'one',clang=sys.executable,count=1)
    file=root/'one/context-000000/native-input.json';file.write_text('{}')
    with pytest.raises((ValueError,KeyError)):
        batch.recover(root/'contracts/result.json',root/'one',root/'never',clang=sys.executable)
    assert not (root/'never').exists()


def test_inspector_selection_preserves_failure_and_checks_exact_success(completion_pipeline,monkeypatch):
    root,report=completion_pipeline
    monkeypatch.setattr(selection.contracts,'check',lambda path:report)
    original=selection.native.acquire;first=str(Path(shutil.which('gcc')).resolve())
    def attempt(context,compiler,output,**kwargs):
        if compiler==first:
            runner=Runner(output,'fixture-language-incompatibility')
            runner.state.update(status='failed',primaryFailure={'stage':'inspection-native-input','returnCode':7})
            runner.save();raise StageFailure('inspection-native-input',7)
        return original(context,compiler,output,**kwargs)
    monkeypatch.setattr(selection.native,'acquire',attempt)
    value=selection.acquire(root/'contracts/result.json',0,[first,sys.executable],root/'selection')
    assert [row['acquired'] for row in value['attempts']]==[False,True]
    assert value['inputAcquired'] and not value['compilerEquivalenceVerified']
    assert selection.check(root/'selection/result.json')==value


def test_all_inspectors_fail_without_fabricating_input(completion_pipeline,monkeypatch):
    root,report=completion_pipeline;monkeypatch.setattr(selection.contracts,'check',lambda path:report)
    def failure(context,compiler,output,**kwargs):
        runner=Runner(output,'fixture-language-incompatibility');runner.state['status']='failed';runner.save()
        raise StageFailure('inspection-native-input',7)
    monkeypatch.setattr(selection.native,'acquire',failure)
    value=selection.acquire(root/'contracts/result.json',0,[sys.executable],root/'selection')
    assert not value['inputAcquired'] and value['selectedReceipt'] is None
    assert not value['semanticApproval'] and selection.check(root/'selection/result.json')==value
