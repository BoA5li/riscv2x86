from dataclasses import replace
from types import SimpleNamespace as NS
import json
import pytest
from riscv2x86_py.contract_resolution import resolve_contract_files
from riscv2x86_py.csr_runtime_implementation import validate_implementation, implementation_manifest
from riscv2x86_py.csr_structured_renderer import CsrRuntimeRecipe
from riscv2x86_py.csr_state_dataflow import analyze_csr_state_dataflow, CsrControlDisposition
from riscv2x86_py.semantic_content import semantic_identity


def test_discovery_does_not_approve_unparsed_contracts(tmp_path):
    source = tmp_path / 'probe.c'; source.write_text('void probe(void) {}')
    root = tmp_path / 'contracts'; root.mkdir()
    path = root / 'probe.c.csr-environment.json'; path.write_text('not valid JSON')
    result = resolve_contract_files(source, 'probe.c', (
        ('missing_directory', None, '.json'), ('missing_file', root, '.absent'),
        ('environment', root, '.csr-environment.json')))
    rows = result['contracts']
    assert [x['disposition'] for x in rows] == ['not_provided', 'not_found', 'resolved_pending_validation']
    assert all(x['semanticApproval'] is False for x in rows)
    assert rows[2]['artifactDigest'].startswith('sha256:')
    old = result['resolutionIdentity']; path.write_text('{}')
    assert resolve_contract_files(source, 'probe.c', (('environment', root, '.csr-environment.json'),))['resolutionIdentity'] != old


def test_missing_cfg_is_unknown_not_proven_whole_function():
    result = analyze_csr_state_dataflow(blocks=(), cfg=NS(entry=None))
    assert not result.complete and not result.requires_whole_function
    assert result.control_disposition is CsrControlDisposition.UNKNOWN
    assert result.reason_codes == ('csr-dataflow.cfg-entry-missing',)


def recipe(symbol='rv2x86_read_counter_checked_v1', token='RV2X86_COUNTER_MONOTONIC_NS'):
    return CsrRuntimeRecipe('recipe', symbol, token, 'ctx', None, 'out',
        'riscv2x86_csr_runtime.h', 'libriscv2x86_runtime', 'v1', 'no-trap-observation', True)


def counter(relation='functional-monotonic-observation'):
    effect = NS(operation=NS(value='read'), csr_class=NS(value='user_counter_observation'),
        affected_fields=(NS(field_id='counter.all'),), xlen_bits=64)
    constraint = NS(field_mappings=('counter.all',), counter_relation_kind=relation, counter_contract_payload={
        'target_observation_mechanism': 'clock_gettime:CLOCK_MONOTONIC:ns', 'wraparound_bits': 64,
        'availability_policy':'runtime-checked-fail-closed','trap_policy':'execution-failure-not-a-counter-value'})
    return (effect,), (constraint,)


def test_shipped_clock_manifest_is_content_addressed_and_functional_only():
    payload, identity = validate_implementation(recipe(), *counter())
    assert identity == semantic_identity(payload)
    assert payload['implementation'].supported_relations == ('functional-monotonic-observation',)
    with pytest.raises(ValueError, match='COUNTER_DOMAIN_UNSUPPORTED'):
        validate_implementation(recipe(), *counter('architectural-equivalence'))


@pytest.mark.parametrize('mutation, reason', [
    ('token', 'COUNTER_ID_UNSUPPORTED'), ('helper', 'COUNTER_DOMAIN_UNSUPPORTED'),
    ('header', 'ABI_MISMATCH'), ('operation', 'OPERATION_MISMATCH'),
    ('mechanism', 'COUNTER_MECHANISM_MISMATCH')])
def test_runtime_implementation_rejects_semantic_or_abi_mutation(mutation, reason):
    r = recipe(); effects, constraints = counter()
    if mutation == 'token': r = replace(r, csr_token='RV2X86_COUNTER_INSTRET')
    if mutation == 'helper': r = recipe('rv2x86_csr_read', '1')
    if mutation == 'header': r = replace(r, required_header='riscv2x86/csr_runtime.h')
    if mutation == 'operation': effects[0].operation.value = 'write'
    if mutation == 'mechanism': constraints[0].counter_contract_payload['target_observation_mechanism'] = 'rdtsc'
    with pytest.raises(ValueError, match=reason): validate_implementation(r, effects, constraints)


def test_runtime_shell_is_independent_of_pure_c_eligibility():
    from riscv2x86_py.csr_runtime_shell import prove_runtime_shell, render_runtime_shell, AUTOMATIC_RUNTIME_BUILD_CONTRACT
    source = {'id': 'frag', 'isVolatile': True, 'clobbers': ['memory', 'cc'],
              'outputs': [{'constraint': '=r', 'isEarlyClobber': False}], 'inputs': []}
    proof = prove_runtime_shell(source, 'sha256:' + '1'*64, AUTOMATIC_RUNTIME_BUILD_CONTRACT)
    rendered = render_runtime_shell('result = helper(ctx);', proof)
    assert rendered.count('result = helper(ctx);') == 1
    assert rendered.count('__asm__ __volatile__("" ::: "memory", "cc");') == 2
    assert proof['volatile'] is True
    with pytest.raises(ValueError, match='BUILD_CONTRACT_REQUIRED'):
        prove_runtime_shell(source, 'sha256:' + '1'*64, None)
    with pytest.raises(ValueError, match='CLOBBER_UNSUPPORTED'):
        prove_runtime_shell({**source, 'clobbers': ['rax']}, 'sha256:' + '1'*64, AUTOMATIC_RUNTIME_BUILD_CONTRACT)


def test_runtime_shell_target_abi_executes_with_separate_translation_units(tmp_path):
    """Target ABI smoke test only; this is not source/target clock equivalence."""
    import shutil, subprocess
    from pathlib import Path
    from riscv2x86_py.csr_runtime_shell import prove_runtime_shell, render_runtime_shell, AUTOMATIC_RUNTIME_BUILD_CONTRACT
    gcc = shutil.which('gcc')
    if gcc is None: pytest.skip('gcc is required')
    root = Path(__file__).resolve().parents[2]
    proof = prove_runtime_shell({'id':'f','isVolatile':True,'clobbers':['memory'],
        'outputs':[{'constraint':'=r'}],'inputs':[]}, 'sha256:'+'1'*64, AUTOMATIC_RUNTIME_BUILD_CONTRACT)
    statement = render_runtime_shell('out = rv2x86_read_counter_checked_v1(&ctx, RV2X86_COUNTER_MONOTONIC_NS);', proof)
    main = tmp_path/'main.c'
    main.write_text('#include "riscv2x86_csr_runtime.h"\n'
        'int main(void) { struct rv2x86_counter_context ctx = {0}; ctx.version = 1; uint64_t out = 0;\n'
        + statement + '\nreturn out == 0; }\n')
    obj = tmp_path/'runtime.o'; binary = tmp_path/'probe'
    include = '-I'+str(root/'runtime/include')
    for command in ([gcc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fno-lto',include,'-c',str(root/'runtime/riscv2x86_csr_runtime.c'),'-o',str(obj)],
                    [gcc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fno-lto',include,str(main),str(obj),'-o',str(binary)]):
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def approved_csr_runtime_fixture():
    """Real decoder/analysis/6D/render chain; not a frontend or QEMU test."""
    from tests.test_csr_semantic_closure import read_inputs
    from tests.test_privileged_state_analysis import _facts
    from tests.test_csr_translation_pipeline import _counter_contract
    from riscv2x86_py.privileged_state_analysis import _typed_csr_effect
    from riscv2x86_py.csr_value_flow import SourceCsrOperandBinding
    from riscv2x86_py.source_csr_semantic_model import adapt_source_csr_semantic_model
    from riscv2x86_py.csr_effect_constraints import CsrTargetMapping
    from riscv2x86_py.csr_translation_pipeline import CsrRuntimeRegistry, CsrRendererRegistry, CsrTranslationFallbackPolicy, run_csr_translation_pipeline
    from riscv2x86_py.schema import AsmFragment, AsmOperand
    from riscv2x86_py.csr_runtime_shell import AUTOMATIC_RUNTIME_BUILD_CONTRACT
    from riscv2x86_py.csr_runtime_approval import build_csr_runtime_approval
    block,cfg,op=read_inputs(); facts=_facts(readable=('riscv.csr.time',), writable=())
    effect=_typed_csr_effect(block.addr,0,op,facts,isolated_counter_access=True)
    binding=SourceCsrOperandBinding('e:time',0,None,None,64,'unsigned',True)
    flow=analyze_csr_state_dataflow(blocks=(block,),cfg=cfg,access_effects=(effect,))
    observability=NS(complete=True,unignored_privileged_state_ids=(),fallback_eligible=True,
        ignored_states=(NS(state_id='riscv.csr.time.architectural_counter_value',complete=True),))
    model=adapt_source_csr_semantic_model(NS(csr_effects=(effect,),csr_operand_bindings=(binding,),csr_state_dataflow=flow),observability=observability)
    counter_contract=replace(_counter_contract('functional-monotonic-observation'),
        target_observation_mechanism='clock_gettime:CLOCK_MONOTONIC:ns',
        availability_policy='runtime-checked-fail-closed',trap_policy='execution-failure-not-a-counter-value')
    profile=facts.source_execution_profile.value
    mapping=CsrTargetMapping('e:time','riscv.csr.time','counter-context','read-counter','v1',profile,'per-execution',
        read_result_mapping='return',field_mappings=('riscv.csr.time.value',),old_new_state_relation_id='clock-observation',
        access_policy_mapping_id='counter-policy',ordering_relation_id='call-order',
        counter_contract_identity=counter_contract.contract_id,counter_relation_kind=counter_contract.relation_kind,counter_contract=counter_contract)
    fragment=AsmFragment(id='frag',isVolatile=True,clobbers=['memory'],
        outputs=[AsmOperand(constraint='=r',isOutput=True,exprText='out')])
    runtime=CsrRuntimeRegistry('registry','v1',profile,(mapping,),True,True,fragment_id='frag')
    renderer=CsrRendererRegistry('renderer',{'read-counter':recipe()}, {'recipe':'v1'})
    result=run_csr_translation_pipeline(model,None,NS(execution_profile=profile),runtime,renderer,
        CsrTranslationFallbackPolicy(allow_functional_fallbacks=True,shell_preserved=False),
        operand_expressions={0:'out'},fragment_id='frag',source_fragment=fragment,
        target_build_contract=AUTOMATIC_RUNTIME_BUILD_CONTRACT)
    assert result.status=='approved', result.reason_codes
    approval=build_csr_runtime_approval(fragment,result,machine_code=bytes.fromhex('732510c0'),
        decoder_profile={'privilege_spec_version':'1.12','xlen_bits':64,'extensions':['zicsr']},
        target_environment_id='test-environment',functional_observability=observability)
    return fragment,result,approval


def test_csr_approval_replays_real_field_proof_renderer_and_shell():
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    fragment,result,approval=approved_csr_runtime_fixture()
    facts=validate_csr_runtime_approval(approval,fragment,result.suggested_replacement)
    assert facts==approval['l2EffectProofFacts']
    assert approval['architectureSemanticsPreserved'] is False
    assert approval['preservationMode']=='functional_equivalence_only'
    from riscv2x86_py.helper_runtime_manifest import get_runtime_helper_contract
    assert get_runtime_helper_contract(approval['runtimeContractId']) is not None


@pytest.mark.parametrize('mutation',['value','implementation','scope','machine','replacement','shell','relation'])
def test_csr_runtime_approval_rejects_mutation(mutation):
    from copy import deepcopy
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval
    fragment,result,approval=approved_csr_runtime_fixture(); approval=deepcopy(approval)
    if mutation=='value': approval['proofPayload']['fieldProof']['sourceModel']['effects'][0]['csr_id']='riscv.csr.cycle'
    if mutation=='implementation': approval['proofPayload']['implementationIdentity']='sha256:'+'f'*64
    if mutation=='scope': approval['architectureSemanticsPreserved']=True
    if mutation=='machine': approval['proofPayload']['machineCodeHex']='13000000'
    if mutation=='replacement': approval['replacementDigest']='sha256:'+'a'*64
    if mutation=='shell': approval['proofPayload']['shellProof']['clobbers']=[]
    if mutation=='relation': approval['l2EffectProofFacts']['relations'][0]['preservedProperties']=['architectural_counter_value']
    # Rehashing the outer envelope must not conceal an inconsistent proof,
    # implementation, decoder relation or shell payload.
    approval['proofIdentity']=semantic_identity(approval['proofPayload'])
    with pytest.raises((ValueError,KeyError,TypeError,IndexError)):
        validate_csr_runtime_approval(approval,fragment,result.suggested_replacement)


def test_privileged_state_runner_cannot_claim_unobserved_shell():
    from riscv2x86_py.l2_privileged_runner import run_l2_privileged_differential
    from riscv2x86_py.l2_dimensions import L2Dimension
    result=run_l2_privileged_differential(object(),l2_provider_dimensions=(L2Dimension.SHELL_SEMANTICS,),
        privileged_command_runner=lambda *args: pytest.fail('must reject before execution'))
    data=json.loads(result.detail)
    assert data['reasonCode']=='l2.privileged.provider-dimension-unsupported'
    assert data['executionDisposition']=='precondition_rejected'
    assert data['evidenceProductionDisposition']=='not_produced'


@pytest.mark.parametrize("unknown_call, successors, reason", [
    (True, (), "csr-dataflow.unknown-call-or-return"),
    (False, (2,), "csr-dataflow.external-successor"),
])
def test_unknown_control_does_not_prove_whole_function(unknown_call, successors, reason):
    block = NS(addr=1, successors=successors, instructions=(
        NS(addr=1, has_unknown_call=unknown_call, privileged_operations=()),))
    result = analyze_csr_state_dataflow(blocks=(block,), cfg=NS(entry=1))
    assert not result.complete and not result.requires_whole_function
    assert result.control_disposition is CsrControlDisposition.UNKNOWN
    assert reason in result.reason_codes
