"""Actual GCC/process comparison, using same-ISA fixtures without ISA proof."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess

import pytest

from .test_native_captured_deployment import captured
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py import native_program_comparison as comparison


@pytest.fixture
def comparison_plan(captured):
    root,p,plan=captured
    d.execute(plan,root/'deployment',diagnostic_only=True)
    source=p/'source-test.c';source.write_text('int main(void){return 7;}\n')
    subprocess.run([plan['entry']['compiler']['path'],str(source),'-o',str(p/'source-test')],check=True)
    body={'schemaVersion':comparison.SCHEMA,'deployment':d.snapshot(root/'deployment/result.json'),
          'source':{'program':d.snapshot(p/'source-test'),'launcher':None,'launcherArguments':[],
                    'environment':{'PATH':os.environ['PATH'],'LC_ALL':'C'},'directory':str(p)},
          'sourceMachine':62,'arguments':[],'inputDomainIdentity':'fixture-declared-no-arguments',
          'expectedExitCodes':[7],'policy':comparison.POLICY,'timeoutSeconds':10,
          'maxLogBytes':1024*1024,'inputFiles':[]}
    return root,p,body


def write_plan(root,body):
    path=root/'comparison-plan.json';path.write_text(json.dumps(d.seal(body,'processComparisonPlanIdentity')))
    return path


def test_comparison_reuses_l1_function_without_granting_l1_eligibility(comparison_plan):
    root,_,body=comparison_plan
    result=comparison.acquire(write_plan(root,body),root/'comparison')
    assert result['processObservableComparisonStatus']=='verified' and result['mismatches']==[]
    assert not result['l1EligibilityVerified'] and not result['semanticApproval']
    assert not result['candidateExecutionCoverageVerified']
    assert comparison.check(root/'comparison/result.json')==result


@pytest.mark.parametrize('stream',['stdout','stderr'])
def test_non_utf8_and_embedded_nul_are_not_normalized_away(comparison_plan,stream):
    root,p,body=comparison_plan
    code=p/'bytes.c';fd=1 if stream=='stdout' else 2
    code.write_text('#include <unistd.h>\nint main(void){char b[]={-1,0,32,10};write('+str(fd)+',b,4);return 7;}\n')
    subprocess.run([d.read(d.read(body['deployment']['path'])['planPath'])['entry']['compiler']['path'],str(code),'-o',str(p/'bytes')],check=True)
    body['source']['program']=d.snapshot(p/'bytes')
    result=comparison.acquire(write_plan(root,body),root/'comparison')
    assert result['processObservableComparisonStatus']=='failed' and stream in result['mismatches']


def test_target_exit_mismatch_is_failure_not_inconclusive(comparison_plan):
    root,p,body=comparison_plan
    body['source']['program']=d.snapshot(p/'test-program');body['expectedExitCodes']=[3]
    result=comparison.acquire(write_plan(root,body),root/'comparison')
    assert result['sourceReturnCode']==3 and result['targetReturnCode']==7
    assert result['processObservableComparisonStatus']=='failed' and result['mismatches']==['exitCode']


def test_invalid_source_baseline_is_not_a_semantic_counterexample(comparison_plan):
    root,_,body=comparison_plan;body['expectedExitCodes']=[0]
    result=comparison.acquire(write_plan(root,body),root/'comparison')
    assert result['processObservableComparisonStatus']=='inconclusive'
    assert result['sourceExitOutsideDeclaredDomain']


@pytest.mark.parametrize('mutation',['policy','disable-output','machine','launcher'])
def test_unmodeled_policy_or_route_is_rejected(comparison_plan,mutation):
    root,_,body=comparison_plan
    if mutation=='policy':body['policy']='ignore-differences'
    if mutation=='disable-output':body['stdout']=False
    if mutation=='machine':body['sourceMachine']=243
    if mutation=='launcher':body['source']['launcherArguments']=['ignored']
    with pytest.raises(ValueError):comparison.acquire(write_plan(root,body),root/'comparison')
    assert not (root/'comparison').exists()


@pytest.mark.parametrize('mutation',['output','rehashed-result','changed-program'])
def test_bound_evidence_changes_are_rejected(comparison_plan,mutation):
    root,p,body=comparison_plan
    comparison.acquire(write_plan(root,body),root/'comparison')
    if mutation=='output':(root/'comparison/source/stdout.log').write_bytes(b'changed')
    if mutation=='changed-program':(p/'source-test').write_bytes(b'changed')
    if mutation=='rehashed-result':
        result=d.read(root/'comparison/result.json');result['l1EligibilityVerified']=True
        (root/'comparison/result.json').write_text(json.dumps(d.seal(
            {k:v for k,v in result.items() if k!='processComparisonIdentity'},'processComparisonIdentity')))
    with pytest.raises(ValueError):comparison.check(root/'comparison/result.json')


@pytest.mark.parametrize('failure',['timeout','log-budget'])
def test_source_budget_failure_leaves_receipt_and_stops(comparison_plan,failure):
    root,p,body=comparison_plan
    source=p/'budget.c'
    source.write_text('int main(void){for(;;){}return 7;}' if failure=='timeout' else
        '#include <unistd.h>\nint main(void){char b[2048]={0};write(1,b,sizeof b);return 7;}')
    cc=d.read(d.read(body['deployment']['path'])['planPath'])['entry']['compiler']['path']
    subprocess.run([cc,str(source),'-o',str(p/'budget')],check=True)
    body['source']['program']=d.snapshot(p/'budget');body['timeoutSeconds']=1;body['maxLogBytes']=1024
    with pytest.raises(ValueError,match='SOURCE_EXECUTION_BUDGET_FAILED'):
        comparison.acquire(write_plan(root,body),root/'comparison')
    result=d.read(root/'comparison/source/execution.json')
    assert result['failureReason']==('TIMEOUT' if failure=='timeout' else 'LOG_BUDGET_EXCEEDED')
    assert not (root/'comparison/target/execution.json').exists()
    assert not (root/'comparison/result.json').exists()


def test_prepare_pins_explicit_invocation_domain_and_does_not_run(comparison_plan):
    root,p,body=comparison_plan
    domain=root/'invocation-domain.json'
    domain.write_text(json.dumps({'schemaVersion':'riscv2x86.native-process-input-domain.v1',
        'sourceDirectory':str(p),'sourceEnvironment':body['source']['environment'],
        'arguments':[],'expectedExitCodes':[7],'inputFiles':[]}))
    path=root/'prepared-comparison.json'
    plan=comparison.prepare(body['deployment']['path'],body['source']['program']['path'],62,domain,path)
    assert plan['inputDomainIdentity']==d.digest(domain)
    assert not (root/'source/execution.json').exists()
    result=comparison.acquire(path,root/'comparison')
    assert result['processObservableComparisonStatus']=='verified'
    domain.write_text('{}')
    with pytest.raises(ValueError):comparison.check(root/'comparison/result.json')


def test_rehashed_unknown_execution_fields_are_not_ignored(comparison_plan):
    root,_,body=comparison_plan
    comparison.acquire(write_plan(root,body),root/'comparison')
    path=root/'comparison/source/execution.json';value=d.read(path);value['approved']=True
    path.write_text(json.dumps(d.seal({k:v for k,v in value.items() if k!='processExecutionIdentity'},'processExecutionIdentity')))
    with pytest.raises(ValueError,match='EXECUTION_PROFILE_MISMATCH'):
        comparison.check(root/'comparison/result.json')
