import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('summary',Path(__file__).resolve().parents[2]/'experiment/summarize_route_run.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def result(root,status):
    folder=root/'generated-suite-strict';case=folder/'cases'/'renamable';case.mkdir(parents=True)
    (folder/'batch-evaluation.json').write_text(json.dumps({'caseCount':1,'statusCounts':{status:1}}))
    (case/'evaluation-result.json').write_text(json.dumps({'status':status,'attempts':[{'validation':{'layers':[{
        'detail':json.dumps({'schemaVersion':'riscv2x86.l2-fragment-result.v4','fragmentId':str(root/'p.c')+':3:1',
            'dimensionResults':{'logical_operands':{'status':status,'executionIdentity':'sha256:execution'}},
            'precondition':{'failureStage':'authority_join'}})}]}}]}))
    return root


def test_summary_reads_embedded_dimensions_and_case_regressions(tmp_path):
    old=module.summarize(result(tmp_path/'old','verified'));new=module.summarize(result(tmp_path/'new','needs_route'))
    assert new['artifactErrors']==[] and new['observedStatusCounts']=={'needs_route':1}
    assert new['cases'][0]['l2Dimensions'][0]['precondition']['failureStage']=='authority_join'
    compared=module.compare(new,old)
    assert compared['previouslyVerifiedCaseRegressions']==['renamable']
    assert compared['previouslyVerifiedDimensionRegressions'][0]['dimension']=='logical_operands'


def test_malformed_case_is_reported_and_raw_artifact_is_preserved(tmp_path):
    root=result(tmp_path,'failed');path=root/'generated-suite-strict/cases/renamable/evaluation-result.json'
    path.write_text('broken')
    summary=module.summarize(root)
    assert summary['artifactErrors'][0]['exceptionType']=='JSONDecodeError'
    assert path.read_text()=='broken'


def test_missing_batch_is_a_structured_error(tmp_path):
    assert module.summarize(tmp_path)['artifactErrors'][0]['exceptionType']=='FileNotFoundError'
