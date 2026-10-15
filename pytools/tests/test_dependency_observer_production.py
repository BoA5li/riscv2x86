from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from riscv2x86_py.l2_dependency_observer import (
    DependencyObserverError, build_dependency_plan, compiler_observer_boundary,
    materialize_pair, parse_dependency_trace,
)
from riscv2x86_py.l2_fragment_execution import (
    FragmentOperandBoundary, fragment_boundary_from_dict, identity,
    materialize_operand_observation_authority, fragment_dependency_graph_from_dict,
)
from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
from riscv2x86_py.requirement_staging import (
    write_requirement_failure, read_staged_requirements, RequirementArtifactError,
)
from tests.test_l2_fragment_execution_authority import _function, _findings


def test_explicit_zero_operand_boundary_round_trip_and_missing_arrays_rejected():
    boundary = FragmentOperandBoundary('p', 'f', 'asm', (), (), (), (), True)
    assert fragment_boundary_from_dict(boundary.to_dict()) == boundary
    raw = boundary.to_dict()
    del raw['inputBindings']
    raw['boundaryIdentity'] = identity({k: v for k, v in raw.items() if k != 'boundaryIdentity'})
    with pytest.raises(ValueError, match='bindings are missing'):
        fragment_boundary_from_dict(raw)
    with pytest.raises(ValueError, match='completeness'):
        FragmentOperandBoundary('p', 'f', 'asm', (), (), (), (), True, ('missing-enumeration',))


def prepared(tmp_path):
    findings, function = _findings(), _function()
    frontend = tmp_path / 'frontend'; frontend.write_bytes(b'frontend')
    materialize_automatic_l2_authority({'findings': findings}, [function], frontend)
    statements = []
    for index, finding in enumerate(findings):
        begin, end = (10, 20) if index == 0 else (30, 40)
        finding.update(rewriteBeginOffset=begin, rewriteEndOffset=end + 1,
                       suggestedReplacement="/* approved scalar target statement */")
        statements.append({'candidateIdentity': function['l2OperandBoundary']['fragmentCandidates'][index]['candidateIdentity'],
                           'beforeOffset': begin, 'afterOffset': end + 1})
    payload = {'schemaVersion': 'riscv2x86.compiler-scalar-observer-boundary.v1',
               'sourceDigest': function['sourceDigest'], 'functionIdentity': function['functionId'],
               'statements': statements, 'complete': True, 'reasonCodes': []}
    function['l2OperandBoundary']['scalarObserverBoundary'] = {**payload, 'boundaryIdentity': identity(payload)}
    return findings, function


def test_both_observation_authorities_reference_the_same_canonical_edge(tmp_path):
    findings, _ = prepared(tmp_path)
    authorities = [f['approvalArtifact']['l2OperandObservationAuthority'] for f in findings]
    bindings = [b for a in authorities for b in a['bindings'] if b['closureKind'] in {'producer', 'consumer'}]
    assert len(bindings) == 2
    assert bindings[0]['valueFlowEdgeIdentity'] == bindings[1]['valueFlowEdgeIdentity']


def trace(plan, value=7, *, consumer=None):
    events = []
    for point in plan['points']:
        v = consumer if consumer is not None and point['fragmentId'] == 'fragment:b' and point['phase'] == 'pre' else value
        events.append(f"dependency_trace;{point['pointIdentity']};{v:016x}")
    return '\n'.join(events) + '\noperand_trace=sequence;0000000000000007;0000000000000007\n'


def test_real_edge_events_are_required_and_value_identity_is_static(tmp_path):
    findings, function = prepared(tmp_path)
    plan = build_dependency_plan({'findings': findings}, function)
    values, samples = parse_dependency_trace(trace(plan), plan, 1)
    assert list(values.values()) == [(7,)]
    assert len(samples) == 1
    before = plan['planIdentity']
    assert list(parse_dependency_trace(trace(plan, 9), plan, 1)[0].values()) == [(9,)]
    assert plan['planIdentity'] == before
    with pytest.raises(DependencyObserverError, match='direct value flow'):
        parse_dependency_trace(trace(plan, consumer=8), plan, 1)
    with pytest.raises(DependencyObserverError, match='every authorized point'):
        parse_dependency_trace('operand_trace=sequence;0;0\n', plan, 1)
    with pytest.raises(DependencyObserverError, match='unknown/duplicate'):
        parse_dependency_trace(trace(plan).splitlines()[0] + '\n' + trace(plan), plan, 1)
    with pytest.raises(DependencyObserverError, match='sample'):
        parse_dependency_trace(trace(plan), plan, 2)


def test_observer_domain_rejects_control_flow_and_missing_ast():
    function = {'kind': 'FunctionDecl', 'inner': [{'kind': 'CompoundStmt', 'inner': [{'kind': 'IfStmt'}]}]}
    def walk(node):
        yield node
        for child in node.get('inner', []):
            yield from walk(child)
    result = compiler_observer_boundary(function, [], source=b'', source_digest='s',
        function_identity='f', candidate_ids={}, source_range=lambda n: None, walk=walk)
    assert not result['complete']


def test_requirement_failure_preserves_original_exception_and_rejects_stale(tmp_path):
    report = tmp_path / 'report.json'; report.write_text('{"findings": []}')
    write_requirement_failure(report, ValueError('boundary at fragment x is invalid'), 'requirement_classification')
    with pytest.raises(RequirementArtifactError) as captured:
        read_staged_requirements(report)
    assert captured.value.detail['failureStage'] == 'requirement_classification'
    assert captured.value.detail['exceptionType'] == 'ValueError'
    report.write_text('{"findings": [1]}')
    with pytest.raises(RequirementArtifactError, match='stale'):
        read_staged_requirements(report)


def test_compiler_boundary_program_plan_reaches_real_host_execution(tmp_path):
    # Actual compilation/execution validates insertion and event protocol;
    # the cross-ISA production test separately uses the real frontend.
    if not shutil.which('gcc'):
        pytest.skip('gcc unavailable')
    source = b'unsigned long sequence(unsigned long x){ unsigned long a,b; a=x+1; b=a+2; return b; }'
    first = (source.index(b'a=x'), source.index(b'; b=') + 1)
    second = (source.index(b'b=a'), source.index(b'; return') + 1)
    points = []
    for fragment, node, phase, name, offset in [('a', 'n1', 'post', 'a', first[1]), ('b', 'n2', 'pre', 'a', second[0])]:
        point = {'fragmentId': fragment, 'valueNodeIdentity': node, 'phase': phase,
                 'declarationName': name, 'widthBits': 64, 'offset': offset}
        points.append({**point, 'pointIdentity': identity(point)})
    from hashlib import sha256
    edge = {'producerFragmentId': 'a', 'consumerFragmentId': 'b', 'valueNodeIdentity': 'n1', 'consumerValueNodeIdentity': 'n2'}
    payload = {'sourceDigest': 'sha256:' + sha256(source).hexdigest(), 'points': points, 'edges': [edge]}
    plan = {**payload, 'planIdentity': identity(payload)}
    left = tmp_path / 's.c'; right = tmp_path / 't.c'
    left.write_bytes(source); right.write_bytes(source)
    instrumented, _ = materialize_pair(left, right, {'findings': []}, plan, tmp_path)
    harness = tmp_path / 'h.c'
    harness.write_text('#include <stdio.h>\nunsigned long sequence(unsigned long);\nvoid __r2x_l2_dependency(const char*p,unsigned long long v){printf("dependency_trace;%s;%016llx\\n",p,v);}\nint main(void){unsigned long v=sequence(4);printf("operand_trace=sequence;4;%lx\\n",v);}\n')
    exe = tmp_path / 'run'
    subprocess.run(['gcc', '-O2', str(harness), str(instrumented), '-o', str(exe)], check=True)
    result = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
    assert parse_dependency_trace(result.stdout, plan, 1)[0][identity(edge)] == (5,)


@pytest.mark.parametrize('mutation,reason', [
    ('boundary', 'L2_DEPENDENCY_OBSERVER_BOUNDARY_STALE'),
    ('placement', 'L2_DEPENDENCY_OBSERVER_RANGE_MISMATCH'),
    ('shell', 'L2_OBSERVER_MEMORY_CLOBBER_UNSUPPORTED'),
    ('constraint', 'L2_DEPENDENCY_OBSERVER_CONSTRAINT_UNSUPPORTED'),
    ('proof', 'L2_DEPENDENCY_OBSERVER_PROOF_UNAPPROVED'),
])
def test_plan_mutations_fail_before_harness(tmp_path, mutation, reason):
    findings, function = prepared(tmp_path)
    if mutation == 'boundary':
        function['l2OperandBoundary']['scalarObserverBoundary']['sourceDigest'] = 'wrong'
    elif mutation == 'placement':
        findings[0]['rewriteEndOffset'] += 1
    elif mutation == 'shell':
        findings[0]['fragment']['clobbers'] = ['memory']
    elif mutation == 'constraint':
        findings[0]['fragment']['outputs'][0]['constraint'] = '=a'
    elif mutation == 'proof':
        findings[0]['approvalArtifact']['proofStatus'] = 'unapproved'
    with pytest.raises(DependencyObserverError) as captured:
        build_dependency_plan({'findings': findings}, function)
    assert captured.value.reason_code == reason


def test_event_reordering_is_rejected(tmp_path):
    findings, function = prepared(tmp_path)
    plan = build_dependency_plan({'findings': findings}, function)
    lines = trace(plan).splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    with pytest.raises(DependencyObserverError) as captured:
        parse_dependency_trace('\n'.join(lines), plan, 1)
    assert captured.value.reason_code == 'L2_DEPENDENCY_TRACE_EVENT_ORDER_INVALID'


def test_runtime_execution_record_and_program_plan_are_rehashed_by_closer():
    from tests.test_l2_evidence_closure import artifact, dimensions, H
    from riscv2x86_py.l2_dimensions import L2Dimension
    from riscv2x86_py.l2_evidence_closure import provider_evidence_fields, validated_provider_evidence
    record = {'source': {'stdout': 'actual observation'}, 'target': {'stdout': 'actual observation'}}
    observer_plan = {'schemaVersion': 'test', 'points': ['typed point']}
    observer_plan['planIdentity'] = identity(observer_plan)
    payload = {'schemaVersion': 'riscv2x86.l2-program-execution.v3',
               'programId': H, 'functionId': H, 'fragmentIds': ['fragment:a'],
               'dependencyGraphIdentity': H, 'executionMode': 'composite',
               'executionAuthorityIdentity': H, 'executionRecordIdentity': identity(record),
               'observationPlanIdentity': observer_plan['planIdentity']}
    detail = provider_evidence_fields(artifact(), provider_id='provider', harness_identity=H,
        execution_nonce={}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
        dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS),
        authorized_execution_identity=identity(payload), execution_payload=payload)
    detail.update(executionRecord=record, dependencyObservationPlan=observer_plan)
    assert validated_provider_evidence(detail, artifact(), dimension='logical_operands', provider_id='provider')[1] == ()
    changed = deepcopy(detail)
    changed['executionRecord']['source']['stdout'] = 'forged observation'
    reasons = validated_provider_evidence(changed, artifact(), dimension='logical_operands', provider_id='provider')[1]
    assert 'l2.provider-evidence.execution-record-identity-invalid' in reasons
    changed = deepcopy(detail)
    changed['dependencyObservationPlan']['points'] = ['different point']
    reasons = validated_provider_evidence(changed, artifact(), dimension='logical_operands', provider_id='provider')[1]
    assert 'l2.provider-evidence.observation-plan-identity-invalid' in reasons
