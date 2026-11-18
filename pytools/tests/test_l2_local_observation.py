"""Original observer integration with fixture-owned compiler/proof ingress.

Host execution tests instrumentation and event binding, not RISC-V equivalence.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py import l2_local_observation as local
from riscv2x86_py.l2_fragment_execution import (FragmentOperandBoundary, OperandBinding,
    ObservationSinkBinding, FragmentDependencyGraph, identity, fragment_boundary_from_dict)
from riscv2x86_py.canonical_l2_operand import bind_canonical_l2_operands
from riscv2x86_py.l2_internal_value import L2InternalValueProofFacts, L2InternalValueProofPoint, L2CanonicalType
from riscv2x86_py.l2_operand_observation_plan import bind_operand_observation_plan
from riscv2x86_py.automatic_l2_operand import _sample_observations
from .test_l2_internal_value_instrumentation import _proof
from .l2_profile_fixtures import profile_dict
from .l2_effect_proof_fixtures import attach_effect_proof

H = lambda n: 'sha256:' + str(n) * 64


def setup(tmp_path):
    source = b'unsigned long value(unsigned long x){unsigned long t=0,u=x+1,v=2;for(unsigned i=0;i<2;i++){t=u+v;}return t;}'
    begin = source.index(b't=u+v;'); end = begin + len(b't=u+v;')
    source_path = tmp_path / 'input.i'; target_path = tmp_path / 'target.i'
    source_path.write_bytes(source); target_path.write_bytes(source)
    sink = (ObservationSinkBinding(H(4), H(1), 'branch_condition', True),
            ObservationSinkBinding(H(5), H(1), 'branch_condition', True))
    boundary = FragmentOperandBoundary('program', 'function', 'fragment',
        (OperandBinding(1, 'u-id', H(2), 'input', 64, True, 'unsigned'),
         OperandBinding(2, 'v-id', H(3), 'input', 64, True, 'unsigned')),
        (OperandBinding(0, 't-id', H(1), 'output', 64, True, 'unsigned'),),
        (H(2), H(3)), (H(1),), True, observation_sinks=sink)
    graph = FragmentDependencyGraph('program', 'function', ('fragment',), (), 'shared_independent', True)
    a = {'proofStatus': 'approved', 'architectureSemanticsPreserved': True,
        'shellSemanticsPreserved': True, 'sourceModelId': 'model', 'preservationDecisionId': 'decision',
        'planId': 'plan', 'constraintsId': 'constraints', 'targetEnvironmentId': 'env', 'targetCatalogVersion': 'catalog',
        'l2FragmentOperandBoundary': boundary.to_dict(), 'l2FragmentDependencyGraph': graph.to_dict()}
    attach_effect_proof(a, 'fragment')
    a['l2InternalValueProofFacts'] = L2InternalValueProofFacts('fragment',
        (L2InternalValueProofPoint('value:operand:0', 0, 0, L2CanonicalType('integer', 64, 'unsigned')),), _proof(), True).to_dict()
    typ = {'canonicalType': 'unsigned long', 'widthBits': 64, 'isInteger': True,
           'isPointer': False, 'isSigned': False, 'sideEffectFree': True, 'expressionRepeatable': True, 'modifiableLvalue': True}
    finding = {'fragment': {'id': 'fragment', 'enclosingFunction': 'value', 'clobbers': [],
        'outputs': [{'constraint': '=r', 'compilerType': dict(typ)}],
        'inputs': [{'constraint': 'r', 'compilerType': dict(typ)}, {'constraint': 'r', 'compilerType': dict(typ)}]},
        'approvalArtifact': a, 'l2SemanticProfile': profile_dict('fragment'),
        'rewriteBeginOffset': begin, 'rewriteEndOffset': end, 'suggestedReplacement': 't=u+v;', 'fileName': str(source_path)}
    # The fixture's source statement simulates the already approved region;
    # no source text parser or fake frontend is used to grant production proof.
    asm = {'kind': 'GCCAsmStmt', 'inner': [
        {'kind': 'DeclRefExpr', 'referencedDecl': {'id': name + '-id'}} for name in ('t', 'u', 'v')]}
    ast = {'kind': 'FunctionDecl', 'inner': [{'kind': 'ForStmt', 'inner': [{'kind': 'CompoundStmt', 'inner': [asm]}]}]}
    def walk(node):
        yield node
        for child in node.get('inner', []): yield from walk(child)
    fn = {'functionId': 'function', 'name': 'value', 'arity': 1,
        'sourceDigest': 'sha256:' + sha256(source).hexdigest(), 'l2OperandBoundary': {
            'parameterDeclarationIds': ['x-id'], 'returnDeclarationId': 't-id',
            'declarations': {name + '-id': {'name': name, 'type': 'project_alias', 'canonicalType': 'unsigned long'} for name in ('t', 'u', 'v')}}}
    fn['l2OperandBoundary']['localObserverBoundary'] = local.compiler_boundary(ast, [asm], source=source,
        source_digest=fn['sourceDigest'], function_identity='function', candidate_ids={id(asm): H(6)},
        source_range=lambda n: (begin, end-1), walk=walk)
    canonical = bind_canonical_l2_operands(finding['fragment'], a['l2FragmentOperandBoundary'], fn['l2OperandBoundary'], a['l2EffectProofFacts'])
    return finding, fn, canonical, source_path, target_path, boundary, graph


def test_local_pre_post_capture_handles_nested_visits_and_preserves_all_sinks(tmp_path):
    f, fn, operands, source, target, boundary, graph = setup(tmp_path)
    plan = local.plan(f, fn, operands)
    assert len(plan['observationSinks']) == 2
    assert [p['phase'] for p in plan['points']] == ['post', 'pre', 'pre']
    authority = local.authority(boundary, operands, plan, proof_identity=f['approvalArtifact']['proofIdentity'], graph_identity=graph.graph_identity)
    sample_plan = bind_operand_observation_plan(operands, authority, (0,1,2))
    if not shutil.which('gcc'): pytest.skip('native GCC required')
    left, right = local.materialize(source, target, {'findings': [f]}, f, plan, tmp_path)
    header = tmp_path / 'h.c'
    header.write_text('#include <stdio.h>\n#include <stdarg.h>\nunsigned long value(unsigned long);\n'
        'void __r2x_l2_observe(unsigned n,...){va_list a;va_start(a,n);printf("internal_trace");'
        'for(unsigned i=0;i<n;i++)printf(";%016llx",va_arg(a,unsigned long long));puts("");va_end(a);}\n'
        'int main(void){unsigned long y=value(5);printf("operand_trace=value;0000000000000005;%016lx\\n",y);}\n')
    results = []
    for i, body in enumerate((left, right)):
        exe = tmp_path / ('exe' + str(i))
        subprocess.run(['gcc','-std=gnu11','-Werror',str(body),str(header),'-o',str(exe)],check=True,capture_output=True)
        result = subprocess.run([str(exe)],check=True,capture_output=True,text=True)
        rows, values, visits = local.parse_visits(result.stdout,'value',1,3,1)
        assert visits == ((0,0),(0,1)) and values == ((8,6,2),(8,6,2))
        samples = _sample_observations(rows, sample_plan, values, trace_arity=1, expected_sample_count=2)
        assert samples[0]['logicalOperands'][1]['valueBefore'] == '0x0000000000000006'
        results.append(result.stdout)
    assert results[0] == results[1]
    before = left.read_bytes()
    assert local.materialize(source,target,{'findings':[f]},f,plan,tmp_path,readback=True) == (left,right)
    assert left.read_bytes() == before


@pytest.mark.parametrize('mutation', ['proof', 'identity', 'volatile', 'expression', 'role'])
def test_local_observer_rejects_missing_authority_and_unsafe_capture(tmp_path, mutation):
    f, fn, operands, *_ = setup(tmp_path)
    if mutation == 'proof': f['approvalArtifact'].pop('l2InternalValueProofFacts')
    if mutation == 'identity': fn['sourceDigest'] = H(9)
    if mutation == 'volatile': fn['l2OperandBoundary']['declarations']['u-id']['canonicalType'] = 'volatile unsigned long'
    if mutation == 'expression': f['fragment']['inputs'][0]['compilerType']['sideEffectFree'] = False
    if mutation == 'role': f['fragment']['inputs'][0]['constraint'] = 'm'
    with pytest.raises(ValueError): local.plan(f,fn,operands)


def test_dynamic_protocol_rejects_empty_missing_extra_and_unbound_visits():
    boundary = 'operand_trace=value;0000000000000001;0000000000000001\n'
    trace = 'internal_trace;0000000000000001\n'
    for text,count in ((boundary,1),(trace+boundary,2),(trace+boundary+trace,1),(trace+boundary+boundary,1)):
        with pytest.raises(ValueError): local.parse_visits(text,'value',1,1,count)
    assert local.parse_visits(trace+boundary+trace+trace+boundary,'value',1,1,2)[2] == ((0,0),(1,0),(1,1))


def test_original_authority_producer_and_consumer_rederive_same_local_plan(tmp_path, monkeypatch):
    from dataclasses import replace
    from riscv2x86_py.automatic_l2_authority import _scalar_authority
    from riscv2x86_py.automatic_l2_operand import _authority
    from riscv2x86_py.l2_fragment_execution import ProgramExecutionAuthority
    from .test_automatic_l2_operand import _artifact
    f, fn, operands, source, target, boundary, graph = setup(tmp_path)
    fn.update(returnType='unsigned long', parameterTypes=['unsigned long'])
    fn['l2OperandBoundary'].update(complete=True, fragmentCandidates=[{'fixture': 'compiler candidate'}],
                                    declarationReferenceCounts={})
    a = f['approvalArtifact']
    a['l2ProgramExecutionAuthority'] = ProgramExecutionAuthority('program', 'function', ('fragment',),
        graph.graph_identity, 'shared_independent', True).to_dict()
    sidecar = _scalar_authority(f,[fn],H(7))
    assert sidecar is not None
    a['l2AuthoritySidecar'] = sidecar.to_dict()
    a['l2OperandObservationAuthority'] = sidecar.operand_observation_authority.to_dict()
    artifact = replace(_artifact(), shell_facts_identity=sidecar.shell_fact_identity,
        proof_identity=a['proofIdentity'], l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity, l2_authority_complete=True)
    auth, reason = _authority(f,[fn],artifact)
    assert auth is not None, reason
    assert auth['localObservationPlan'] == a['l2LocalOperandObservationPlan']
    from riscv2x86_py import automatic_l2_operand as runner
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    import json
    if not shutil.which('gcc'): pytest.skip('native GCC required')
    report = tmp_path / 'report.json'; report.write_text(json.dumps({'findings': [f], 'functions': [fn]}))
    config = {'schemaVersion': runner.AUTO_L2_OPERAND_SCHEMA, 'sourcePath': str(source),
        'targetPath': str(target), 'sourceDigest': fn['sourceDigest'], 'targetDigest': fn['sourceDigest'],
        'translatedReport': str(report), 'functions': [fn], 'workDirectory': str(tmp_path / 'work'),
        'replayDirectory': str(tmp_path / 'replay'), 'timeoutSeconds': 10, 'seed': 1, 'qemuBinary': '/usr/bin/env'}
    original_run = runner._run
    def host_run(argv, cwd, timeout):
        # Cross-ISA compiler ingress is fixture-owned; the original wrapper,
        # observer, execution, parser and evidence producer run unchanged.
        if argv[0] == 'riscv64-linux-gnu-gcc':
            argv = ['gcc', *(a for a in argv[1:] if not a.startswith(('-march=', '-mabi=')))]
        return original_run(argv, cwd, timeout)
    monkeypatch.setattr(runner, '_run', host_run)
    result = runner.build_auto_l2_operand_validator(config)(level=ValidationLevel.L2,
        comparison_policy=ARCHITECTURAL_COMPARISON_POLICY, translation_artifact=artifact, l2_provider_id='host-fixture')
    assert result.status.value == 'verified', result.detail
    from riscv2x86_py.l2_evidence_closure import validated_provider_evidence
    closure, reasons = validated_provider_evidence(json.loads(result.detail), artifact,
        dimension='logical_operands', provider_id='host-fixture')
    assert closure is not None and reasons == ()
    observation = json.loads((tmp_path / 'replay/operand-observation.json').read_text())
    assert observation['sampleCount'] == 16 and observation['entryCaseCount'] == 8
    assert len(observation['sourceTracePayload']['visits']) == 16
    changed = deepcopy(f); changed['approvalArtifact']['l2LocalOperandObservationPlan']['points'][1]['declarationName'] = 'wrong'
    assert _authority(changed,[fn],artifact)[1] == 'L2_LOCAL_OBSERVER_PLAN_REDERIVATION_MISMATCH'


def test_canonical_alias_metadata_must_agree_with_operand_compiler_type(tmp_path):
    f, fn, operands, *_ = setup(tmp_path)
    assert [(o.type_kind,o.width_bits,o.signedness) for o in operands] == [('integer',64,'unsigned')] * 3
    for mutation in ('missing', 'signed', 'width'):
        finding, function = deepcopy(f), deepcopy(fn)
        if mutation == 'missing': function['l2OperandBoundary']['declarations']['u-id'].pop('canonicalType')
        if mutation == 'signed': finding['fragment']['inputs'][0]['compilerType']['isSigned'] = True
        if mutation == 'width': finding['fragment']['inputs'][0]['compilerType']['widthBits'] = 32
        with pytest.raises(ValueError):
            bind_canonical_l2_operands(finding['fragment'], finding['approvalArtifact']['l2FragmentOperandBoundary'],
                function['l2OperandBoundary'], finding['approvalArtifact']['l2EffectProofFacts'])


def test_producer_records_observation_failure_without_mislabeling_missing_effects(tmp_path):
    from riscv2x86_py.automatic_l2_authority import _scalar_authority
    f, fn, *_ = setup(tmp_path)
    fn['l2OperandBoundary'].update(complete=True, fragmentCandidates=[{}])
    f['approvalArtifact'].pop('l2InternalValueProofFacts')
    f['fragment']['clobbers'] = ['memory']
    failures = []
    assert _scalar_authority(f,[fn],H(8),failure_details=failures) is None
    assert failures[0]['failureStage'] == 'operand_observation_authority'
    assert 'SHELL_PROOF_REJECTED' in failures[0]['detail']


def test_scalar_local_observer_uses_original_proof_bound_shell_rule(tmp_path):
    from riscv2x86_py.automatic_l2_authority import _scalar_authority
    f, fn, *_ = setup(tmp_path)
    fn['l2OperandBoundary'].update(complete=True, fragmentCandidates=[{}])
    f['approvalArtifact'].pop('l2InternalValueProofFacts')
    sidecar = _scalar_authority(f,[fn],H(8))
    assert sidecar is not None
    decision = f['approvalArtifact']['l2LocalOperandObservationPlan']['shellCompatibilityDecision']
    assert decision['disposition'] == 'supported'
    assert decision['ruleIdentity'] == 'scalar-register-whole-statement-normal-call-v2'
