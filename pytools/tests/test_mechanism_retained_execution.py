"""Replay actual retained executions; these are not fresh production runs.

Original complete program verdicts remain failed at L0. The records exercise
the real per-layer observer/central-audit path and cannot promote that verdict.
"""
import json
from pathlib import Path
import pytest
from riscv2x86_py.semantic_content import semantic_identity

ROOT=Path(__file__).resolve().parents[2]/'experiment/baselines/phase83'


def retained(route,level):return json.loads((ROOT/(route+'-'+level+'.json')).read_text())


@pytest.mark.parametrize('route',['sync','time'])
def test_retained_actual_layers_pass_their_central_replay(route):
    from riscv2x86_py.controlled_time_environment import audit_case_environment
    from riscv2x86_py.time_trace_runner import validate_persisted_result as time
    from riscv2x86_py.l2_instruction_visibility_runner import validate_persisted_result as sync
    l1=retained(route,'L1');l2=retained(route,'L2')
    detail=json.loads(l2['detail'])
    (sync if route=='sync' else time)(detail)
    assert l2['status']=='verified'
    environment=json.loads(l1['detail'])['environmentId']
    case={'targetEnvironment':{'environmentId':environment},'attempts':[{'validation':{'layers':[l1]}}]}
    audit_case_environment(case)
    case['targetEnvironment']['environmentId']='auto-rv64gc-qemu-x86-native-v1'
    with pytest.raises(ValueError,match='ENVIRONMENT'):audit_case_environment(case)


@pytest.mark.parametrize('mutation',['value','extra-read','order','site','claim','runner'])
def test_rehashed_actual_time_observation_mutations_remain_rejected(mutation):
    from riscv2x86_py.time_trace_runner import validate_persisted_result,DIMENSIONS
    detail=json.loads(retained('time','L2')['detail'])
    target=detail['executions']['target']
    if mutation=='value':
        lines=target['stdout'].splitlines();lines[1]='0 0000000000000008';target['stdout']='\n'.join(lines)+'\n'
    if mutation=='extra-read':target['events']+=target['events'].splitlines()[-1]+'\n'
    if mutation=='order':target['events']='\n'.join(reversed(target['events'].splitlines()))+'\n'
    if mutation=='site':
        source=detail['executions']['source'];lines=source['events'].splitlines()
        fields=lines[0].split();fields[2]='0000000000000000';lines[0]=' '.join(fields);source['events']='\n'.join(lines)+'\n'
    if mutation=='claim':detail['executionEnvironment']['claims']['fullArchitecturalTimeClock']='verified'
    if mutation=='runner':detail['executions']['source']['runnerCommand'].append('-cpu=foreign')
    for d in DIMENSIONS:
        for side in ('source','target'):
            detail['dimensionObservations'][d.value][side+'EvidenceIdentity']=semantic_identity(
                {'dimension':d.value,'side':side,'observation':detail['executions'][side]})
    detail['evidenceIdentity']=semantic_identity({k:v for k,v in detail.items() if k!='evidenceIdentity'})
    with pytest.raises(ValueError):validate_persisted_result(detail)


def test_successful_independent_layers_do_not_promote_failed_programs():
    summary=json.loads((ROOT/'execution-summary.json').read_text())
    assert summary['productionAcceptanceComplete'] is False
    assert all(r['programVerdict']=='failed' for r in summary['routes'].values())
