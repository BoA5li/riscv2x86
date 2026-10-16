from copy import deepcopy
import json

import pytest

from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.effect_relation import ApprovedEffectRelation
from riscv2x86_py.l2_continuation_trace import (
    read_continuation_observations, continuation_observations_match,
    validate_contract, ContinuationTraceError,
)


def contract():
    relation = ApprovedEffectRelation('relation:control', 'control:exit', ('target:control:exit',),
        'exact', ('branch_continuation','target'), (), '', True)
    result = {'schemaVersion':'riscv2x86.continuation-trace-contract.v1',
        'fragmentId':'fragment', 'sourceDigest':'sha256:'+'1'*64, 'targetDigest':'sha256:'+'2'*64,
        'authorityIdentity':'sha256:'+'3'*64, 'proofIdentity':'sha256:'+'4'*64,
        'relation':relation.to_dict(), 'continuations':['fallthrough','taken'],
        'samples':['sample:0','sample:1'], 'sites':{}}
    for side in ('source','target'):
        sites = []
        for cont in ('fallthrough','taken'):
            compiler_site = identity({'compilerASTSite':cont, 'side':side})
            marker = identity({'fragmentId':'fragment','side':side,
                'artifactDigest':result[side+'Digest'], 'compilerSiteIdentity':compiler_site,
                'continuationId':cont})
            sites.append({'continuationId':cont,'compilerSiteIdentity':compiler_site,'markerIdentity':marker})
        result['sites'][side] = sites
    result['contractIdentity'] = identity(result)
    return result


def trace(raw, side, exits=(0,1)):
    return '\n'.join('continuation_trace='+json.dumps({'schemaVersion':'riscv2x86.continuation-trace.v1',
        'sampleId':'sample:'+str(i), 'markerIdentity':raw['sites'][side][exit_]['markerIdentity'],
        'ordinal':0}) for i, exit_ in enumerate(exits))


def observe(raw, side, text=None):
    return read_continuation_observations(trace(raw,side) if text is None else text, raw,
        side=side, execution_identity='sha256:'+'5'*64)


def test_actual_continuation_events_have_side_specific_observation_identity():
    raw = contract()
    left, right = observe(raw,'source'), observe(raw,'target')
    assert continuation_observations_match(left,right)
    assert left['events'] == [{'sampleId':'sample:0','continuationId':'fallthrough','ordinal':0},
                              {'sampleId':'sample:1','continuationId':'taken','ordinal':0}]
    assert left['observationIdentity'] != right['observationIdentity']


def test_equal_return_values_do_not_hide_different_executed_exits():
    raw = contract()
    left = observe(raw,'source',trace(raw,'source')+'\nprobe:return=7')
    right = observe(raw,'target',trace(raw,'target',(1,0))+'\nprobe:return=7')
    assert not continuation_observations_match(left,right)


def test_return_value_alone_never_produces_continuation_observation():
    with pytest.raises(ContinuationTraceError) as failure:
        observe(contract(),'source','probe:return=7')
    assert failure.value.reason_code == 'L2_CONTINUATION_TRACE_ARITY_MISMATCH'


@pytest.mark.parametrize('mutation,reason', [
    ('missing','TRACE_ARITY_MISMATCH'),('duplicate','MULTIPLE_EXITS_OBSERVED'),
    ('unknown','MARKER_UNKNOWN'),('malformed','TRACE_MALFORMED'),('ordinal','TRACE_ORDINAL_INVALID'),
])
def test_trace_rejections_are_precise(mutation, reason):
    raw = contract(); text=trace(raw,'source')
    if mutation=='missing': text=text.splitlines()[0]
    if mutation=='duplicate': text+='\n'+text.splitlines()[0]
    if mutation=='unknown': text=text.replace(raw['sites']['source'][0]['markerIdentity'],'sha256:'+'0'*64)
    if mutation=='malformed': text='continuation_trace={'
    if mutation=='ordinal': text=text.replace('"ordinal": 0','"ordinal": 1')
    with pytest.raises(ContinuationTraceError) as failure:
        observe(raw,'source',text)
    assert failure.value.reason_code == 'L2_CONTINUATION_'+reason


@pytest.mark.parametrize('mutation', ['execution','fragment','relation','content'])
def test_stale_or_cross_execution_observation_is_rejected(mutation):
    raw=contract(); left,right=observe(raw,'source'),observe(raw,'target')
    key={'execution':'executionIdentity','fragment':'fragmentId','relation':'effectRelationIdentity','content':'events'}[mutation]
    right[key] = [] if mutation=='content' else 'other'
    if mutation!='content':
        right['observationIdentity']=identity({k:v for k,v in right.items() if k!='observationIdentity'})
    with pytest.raises(ContinuationTraceError):
        continuation_observations_match(left,right)


def test_rehashed_site_swap_cannot_change_compiler_marker_binding():
    raw=contract(); raw['sites']['target'][0]['continuationId']='taken'
    raw['contractIdentity']=identity({k:v for k,v in raw.items() if k!='contractIdentity'})
    with pytest.raises(ContinuationTraceError): validate_contract(raw)
