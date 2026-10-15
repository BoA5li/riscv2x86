from copy import deepcopy
import json
import shutil
import subprocess

import pytest

from riscv2x86_py.l2_dependency_observer import (
    DependencyObserverError, build_dependency_plan, materialize_pair,
    parse_dependency_trace, validate_plan_compatibility,
)
from riscv2x86_py.l2_observer_shell import validate_observer_shell_decision
from riscv2x86_py.l2_fragment_execution import identity
from tests.test_dependency_observer_production import prepared, trace


def rehash(value, field):
    value[field] = identity({k: v for k, v in value.items() if k != field})


@pytest.mark.parametrize('members', [(), (0,), (1,), (0, 1)])
def test_program_plans_support_proof_closed_cc_members(tmp_path, members):
    findings, function = prepared(tmp_path)
    for index in members:
        findings[index]['fragment']['clobbers'] = ['cc']
    plan = build_dependency_plan({'findings': findings}, function)
    assert plan['schemaVersion'] == 'riscv2x86.scalar-program-observation-plan.v2'
    assert len(plan['shellCompatibilityDecisions']) == 2
    for decision in plan['shellCompatibilityDecisions']:
        validate_observer_shell_decision(decision)
        assert decision['disposition'] == 'supported'
    assert sum(d['clobberClasses'] == ['condition_code'] for d in plan['shellCompatibilityDecisions']) == len(members)
    assert list(parse_dependency_trace(trace(plan), plan, 1)[0].values()) == [(7,)]


@pytest.mark.parametrize('clobber,reason', [
    ('memory', 'L2_OBSERVER_MEMORY_CLOBBER_UNSUPPORTED'),
    ('rax', 'L2_OBSERVER_REGISTER_OR_STATE_CLOBBER_UNSUPPORTED'),
    ('unmodelled-state', 'L2_OBSERVER_REGISTER_OR_STATE_CLOBBER_UNSUPPORTED'),
])
def test_clobber_classes_not_covered_by_cc_rule_reject(tmp_path, clobber, reason):
    findings, function = prepared(tmp_path)
    findings[0]['fragment']['clobbers'] = [clobber]
    with pytest.raises(DependencyObserverError) as caught:
        build_dependency_plan({'findings': findings}, function)
    assert reason in caught.value.compatibility_decision['reasonCodes']
    assert caught.value.compatibility_decision['disposition'] == 'precondition_rejected'


@pytest.mark.parametrize('field,reason', [
    ('ccClobberPreserved', 'L2_OBSERVER_CC_RELATION_UNAPPROVED'),
    ('volatilePlacementPreserved', 'L2_OBSERVER_VOLATILE_PLACEMENT_UNAPPROVED'),
    ('continuationPreserved', 'L2_OBSERVER_CONTINUATION_UNAPPROVED'),
    ('compilerVisibilityPreserved', 'L2_OBSERVER_COMPILER_VISIBILITY_UNAPPROVED'),
])
def test_approved_boolean_cannot_replace_missing_shell_obligation(tmp_path, field, reason):
    findings, function = prepared(tmp_path)
    finding = findings[0]
    finding['fragment']['clobbers'] = ['cc']
    proof = finding['approvalArtifact']['l2EffectProofFacts']
    proof['shellRelation'][field] = False
    rehash(proof, 'factsIdentity')
    with pytest.raises(DependencyObserverError) as caught:
        build_dependency_plan({'findings': findings}, function)
    assert reason in caught.value.compatibility_decision['reasonCodes']


@pytest.mark.parametrize('mutation', ['proof', 'renderer', 'effect', 'fixed_register', 'facts_identity'])
def test_structured_proof_and_authority_mutations_reject(tmp_path, mutation):
    findings, function = prepared(tmp_path)
    finding = findings[0]; finding['fragment']['clobbers'] = ['cc']
    approval = finding['approvalArtifact']
    proof = approval['l2EffectProofFacts']
    if mutation == 'proof':
        approval['proofIdentity'] = 'sha256:' + 'a' * 64
    elif mutation == 'renderer':
        approval['rendererContractIdentity'] = 'sha256:' + 'a' * 64
    elif mutation == 'effect':
        proof['sourceEffects'][0]['effectKind'] = 'ReadMemory'
        rehash(proof, 'factsIdentity')
    elif mutation == 'fixed_register':
        sidecar = approval['l2AuthoritySidecar']
        sidecar['operands'][0]['fixedRegisterContract'] = 'physical-register-contract'
        rehash(sidecar, 'authorityIdentity')
    else:
        proof['factsIdentity'] = 'sha256:' + 'a' * 64
    with pytest.raises(DependencyObserverError) as caught:
        build_dependency_plan({'findings': findings}, function)
    assert caught.value.compatibility_decision['reasonCodes']


@pytest.mark.parametrize('mutation', ['clobber', 'replacement', 'extent', 'renderer'])
def test_replay_recomputes_compatibility_from_current_report(tmp_path, mutation):
    findings, function = prepared(tmp_path)
    findings[0]['fragment']['clobbers'] = ['cc']
    report = {'findings': findings}
    plan = build_dependency_plan(report, function)
    if mutation == 'clobber':
        findings[0]['fragment']['clobbers'] = ['memory']
    elif mutation == 'replacement':
        findings[0]['suggestedReplacement'] += ' /* changed */'
    elif mutation == 'extent':
        findings[0]['rewriteEndOffset'] += 1
    else:
        findings[0]['approvalArtifact']['rendererContractIdentity'] = 'sha256:' + 'b' * 64
    with pytest.raises(DependencyObserverError, match='current report/proof'):
        validate_plan_compatibility(plan, report)


def test_new_cc_contract_changes_plan_identity_and_stale_points_reject(tmp_path):
    findings, function = prepared(tmp_path)
    original = build_dependency_plan({'findings': findings}, function)
    findings[0]['fragment']['clobbers'] = ['cc']
    changed = build_dependency_plan({'findings': findings}, function)
    assert original['planIdentity'] != changed['planIdentity']
    broken = deepcopy(changed)
    broken['points'][0]['offset'] += 1
    rehash(broken['points'][0], 'pointIdentity'); rehash(broken, 'planIdentity')
    with pytest.raises(DependencyObserverError, match='point binding'):
        validate_plan_compatibility(broken)
    decision = deepcopy(changed['shellCompatibilityDecisions'][0])
    decision['unknown'] = True; rehash(decision, 'decisionIdentity')
    with pytest.raises(ValueError, match='fields'):
        validate_observer_shell_decision(decision)


def test_original_cc_inline_asm_survives_host_instrumentation(tmp_path):
    if not shutil.which('gcc'):
        pytest.skip('gcc unavailable')
    source = (b'unsigned long sequence(unsigned long x){ unsigned long a,b; '
              b'__asm__ volatile("leaq 1(%1),%0" : "=r"(a) : "r"(x) : "cc"); '
              b'__asm__ volatile("movq %1,%0\\n\\txorq $7,%0" : "=r"(b) : "r"(a) : "cc"); return b; }')
    first = source.index(b'__asm__'); first_end = source.index(b');', first) + 2
    second = source.index(b'__asm__', first_end)
    points = []
    for fragment, node, phase, offset in [('producer', 'p', 'post', first_end), ('consumer', 'c', 'pre', second)]:
        point = {'fragmentId': fragment, 'valueNodeIdentity': node, 'phase': phase,
                 'declarationName': 'a', 'widthBits': 64, 'offset': offset}
        points.append({**point, 'pointIdentity': identity(point)})
    from hashlib import sha256
    edge = {'producerFragmentId': 'producer', 'consumerFragmentId': 'consumer',
            'valueNodeIdentity': 'p', 'consumerValueNodeIdentity': 'c'}
    payload = {'sourceDigest': 'sha256:' + sha256(source).hexdigest(), 'points': points, 'edges': [edge]}
    plan = {**payload, 'planIdentity': identity(payload)}
    left = tmp_path / 's.c'; right = tmp_path / 't.c'
    left.write_bytes(source); right.write_bytes(source)
    instrumented, _ = materialize_pair(left, right, {'findings': []}, plan, tmp_path)
    assert instrumented.read_bytes().count(b': "cc"') == 2
    harness = tmp_path / 'h.c'
    harness.write_text('#include <stdio.h>\nunsigned long sequence(unsigned long);\nvoid __r2x_l2_dependency(const char*p,unsigned long long v){printf("dependency_trace;%s;%016llx\\n",p,v);}\nint main(void){unsigned long v=sequence(4);printf("operand_trace=sequence;4;%lx\\n",v); return v!=2;}\n')
    exe = tmp_path / 'run'
    subprocess.run(['gcc', '-O2', '-Wall', '-Wextra', '-Werror', str(harness), str(instrumented), '-o', str(exe)], check=True)
    run = subprocess.run([str(exe)], check=True, capture_output=True, text=True)
    assert parse_dependency_trace(run.stdout, plan, 1)[0][identity(edge)] == (5,)


def test_closer_requires_compatibility_bound_to_current_fragment_evidence(tmp_path):
    from tests.test_l2_evidence_closure import artifact, dimensions, H
    from riscv2x86_py.l2_dimensions import L2Dimension
    from riscv2x86_py.l2_evidence_closure import provider_evidence_fields, validated_provider_evidence
    findings, function = prepared(tmp_path)
    findings[0]['fragment']['clobbers'] = ['cc']
    plan = build_dependency_plan({'findings': findings}, function)
    decision = next(x for x in plan['shellCompatibilityDecisions'] if x['fragmentId'] == 'fragment:a')
    current = artifact()
    current.proof_identity = decision['proofIdentity']
    current.l2_authority_identity = decision['authorityIdentity']
    current.effect_relation_set_identity = decision['effectRelationSetIdentity']
    record = {'source': {'stdout': 'observed'}, 'target': {'stdout': 'observed'}}

    def evidence(observer_plan):
        payload = {'schemaVersion': 'riscv2x86.l2-program-execution.v3',
                   'programId': H, 'functionId': H, 'fragmentIds': ['fragment:a', 'fragment:b'],
                   'dependencyGraphIdentity': observer_plan['graphIdentity'], 'executionMode': 'composite',
                   'executionAuthorityIdentity': H, 'executionRecordIdentity': identity(record),
                   'observationPlanIdentity': observer_plan['planIdentity']}
        value = provider_evidence_fields(current, provider_id='provider', harness_identity=H,
            execution_nonce={}, dimensions=(L2Dimension.LOGICAL_OPERANDS,),
            dimension_evidence=dimensions(L2Dimension.LOGICAL_OPERANDS),
            authorized_execution_identity=identity(payload), execution_payload=payload)
        value.update(executionRecord=record, dependencyObservationPlan=observer_plan)
        return value

    assert validated_provider_evidence(evidence(plan), current,
        dimension='logical_operands', provider_id='provider')[1] == ()
    broken = deepcopy(plan)
    broken['points'][0]['boundaryIdentity'] = H
    rehash(broken['points'][0], 'pointIdentity'); rehash(broken, 'planIdentity')
    assert 'l2.provider-evidence.observer-shell-compatibility-invalid' in validated_provider_evidence(
        evidence(broken), current, dimension='logical_operands', provider_id='provider')[1]


def test_rejected_shell_contract_remains_not_produced_with_typed_diagnostic(tmp_path):
    from riscv2x86_py.automatic_l2_operand import _failure_result, L2OperandFailureStage
    from riscv2x86_py.l2_evidence_closure import L2ProviderExecutionDisposition
    findings, function = prepared(tmp_path)
    findings[0]['fragment']['clobbers'] = ['memory']
    with pytest.raises(DependencyObserverError) as caught:
        build_dependency_plan({'findings': findings}, function)
    result = _failure_result(L2OperandFailureStage.AUTHORITY_JOIN, caught.value,
        artifact_path=tmp_path / 'report.json',
        disposition=L2ProviderExecutionDisposition.PRECONDITION_REJECTED,
        reason_code=caught.value.reason_code)
    detail = json.loads(result.detail)
    assert detail['executionDisposition'] == 'precondition_rejected'
    assert detail['evidenceProductionDisposition'] == 'not_produced'
    assert detail['failureStage'] == 'authority_join'
    assert detail['observerShellCompatibility']['reasonCodes'] == ['L2_OBSERVER_MEMORY_CLOBBER_UNSUPPORTED']
