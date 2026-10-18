"""Native execution checks are not substitutes for the real RISC-V chain."""
from types import SimpleNamespace
from pathlib import Path
import shutil,subprocess
import pytest
from tests.test_l2_atomic_production import atomic_finding
from riscv2x86_py.automatic_l2_atomic import atomic_wrapper,atomic_events
from riscv2x86_py.l2_atomic_authority import materialize_atomic_authority
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import TargetEnvironment
from riscv2x86_py.phase6d_common import run_semantic_proof_gate,TargetSemanticCatalog,CompilerCapabilityModel
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan,SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import Phase6FRenderRequest,RendererContext,render_approved_target_lowering,RenderedReplacementKind


def rendered_atomic(model,constraints):
    plan=next(p for p in generate_candidate_plans(model) if p.plan_id=='c-builtin.atomic-fetch-add')
    environment=TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features={'compiler:atomic-builtin'},
        builtin_capabilities={'c_builtin:atomic','c_builtin:compiler_barrier'})
    proof=run_semantic_proof_gate(source_model=model,preservation_decision=model.preservation,
        candidate_plan=plan,constraints=constraints,target_environment=environment,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}),frozenset({plan.metadata['renderer_semantic_contract_id']}),'atomic-test'),
        compiler_capabilities=CompilerCapabilityModel(True,True,frozenset({'c_builtin:atomic','c_builtin:compiler_barrier'})),
        fragment_id='source.c:7:3')
    assert proof.approved
    approved=ApprovedTargetLoweringPlan(plan,constraints,proof,proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id,proof.evidence.target_environment_id,'unit','1',SelectionTier.PUBLIC_PORTABLE)
    recipe=GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    assert recipe is not None
    result=render_approved_target_lowering(Phase6FRenderRequest(approved,environment,
        RendererContext({plan.plan_id:recipe},{0:'value',1:'*ptr' if model.atomic.address_projection else 'ptr'})))
    assert result.kind is RenderedReplacementKind.C_BUILTIN,result
    return result


def execute(tmp_path,body,harness,tag):
    if shutil.which('gcc') is None:pytest.skip('native compiler unavailable')
    source=tmp_path/(tag+'.c');driver=tmp_path/(tag+'-driver.c');exe=tmp_path/tag
    source.write_text(body);driver.write_text(harness)
    built=subprocess.run(['gcc','-std=gnu11','-O2','-fstrict-aliasing','-Wall','-Wextra','-Werror',str(source),str(driver),'-o',str(exe)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    completed=subprocess.run([str(exe)],capture_output=True,text=True)
    assert completed.returncode==0 and completed.stderr==''
    return completed.stdout


@pytest.mark.parametrize('width',[32,64])
def test_renderer_matches_independent_xadd_oracle_including_word_extension(tmp_path,width):
    raw,functions,model,constraints=atomic_finding(memory_width=width)
    sidecar=materialize_atomic_authority(raw,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    atom=raw['approvalArtifact']['l2AtomicProofFacts']['atomicOperation']
    result=rendered_atomic(model,constraints)
    assert result.emitted_text.count('__atomic_signal_fence')==2
    function=functions[0];harness=atomic_wrapper(function,atom,sidecar)
    pointer=function['parameterTypes'][0]
    declaration=f'unsigned long probe({pointer} ptr,unsigned long value)'
    operation=('lock xaddq %0,(%1)' if width==64 else 'lock xaddl %k0,(%1); movslq %k0,%0')
    oracle=declaration+'{ __asm__ volatile("'+operation+'" : "+r"(value) : "r"(ptr) : "memory","cc"); return value; }'
    target=declaration+'{ '+result.emitted_text+' return value; }'
    expected=atomic_events(execute(tmp_path,oracle,harness,'oracle'),atom)
    actual=atomic_events(execute(tmp_path,target,harness,'target'),atom)
    assert expected==actual
    if width==32:
        broken=declaration+'{ '+result.emitted_text.replace('(__INT64_TYPE__)(__INT32_TYPE__)','')+' return value; }'
        wrong=atomic_events(execute(tmp_path,broken,harness,'bad-extension'),atom)
        assert wrong!=expected


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('operation,builtin',[('fetch_add','__atomic_fetch_add'),('fetch_and','__atomic_fetch_and'),
    ('fetch_or','__atomic_fetch_or'),('fetch_xor','__atomic_fetch_xor'),('exchange','__atomic_exchange_n')])
def test_actual_rmw_values_do_not_depend_on_detecting_a_changed_memory_word(tmp_path,width,operation,builtin):
    pointer='unsigned int *' if width==32 else 'unsigned long *'
    function={'name':'probe','arity':2,'parameterTypes':[pointer,'unsigned long'],'returnType':'unsigned long','pointerParameters':[0]}
    atom={'width_bits':width,'rmw_operation':operation,'result_semantics':'old_value',
        'memory_object_identity':'object','address_operand_index':1,'value_operand_index':0}
    sidecar=SimpleNamespace(operands=[SimpleNamespace(operand_index=0,parameter_index=1,width_bits=64),
        SimpleNamespace(operand_index=1,parameter_index=0,width_bits=64)])
    call=f'{builtin}(ptr,(__typeof__(*ptr))value,__ATOMIC_ACQ_REL)'
    if width==32:call='(__INT64_TYPE__)(__INT32_TYPE__)('+call+')'
    body=f'unsigned long probe({pointer} ptr,unsigned long value){{ return {call}; }}'
    observed=atomic_events(execute(tmp_path,body,atomic_wrapper(function,atom,sidecar),'rmw'),atom)
    assert len(observed)==8
    assert all(x['effectKind']=='AtomicReadModifyWrite' for x in observed)


@pytest.mark.parametrize('broken',[False,True])
def test_native_atomic_provider_preserves_four_dimension_execution_evidence(tmp_path,monkeypatch,broken):
    """Provider/harness contract test with injected compiler fixtures, not RV proof."""
    import json
    import riscv2x86_py.automatic_l2_effect as effect
    import riscv2x86_py.automatic_batch_cli as batch
    from riscv2x86_py.automatic_l2_atomic import build_atomic_validator
    from riscv2x86_py.compiler_value_flow import identity
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus,PreservationMode
    from riscv2x86_py.l2_evidence_closure import validated_provider_evidence
    finding,functions,_,_=atomic_finding()
    approval=finding['approvalArtifact'];function=functions[0]
    compiler=finding['fragment']['compilerFragmentAuthority']
    payload={'sourceDigest':compiler['sourceDigest'],'asmBegin':100,'asmEnd':140}
    function['compilerAtomicFunctionScope']={**payload,'scopeIdentity':identity(payload)}
    sidecar=materialize_atomic_authority(finding,functions,'sha256:'+'f'*64)
    approval['l2AuthoritySidecar']=sidecar.to_dict()
    source=tmp_path/'source.c';target=tmp_path/'target.c'
    source.write_text('unsigned long probe(unsigned long *ptr,unsigned long value){ __asm__ volatile("lock xaddq %0,(%1)" : "+r"(value) : "r"(ptr) : "memory","cc"); return value;}')
    target.write_text('unsigned long probe(unsigned long *ptr,unsigned long value){ __atomic_signal_fence(__ATOMIC_SEQ_CST); unsigned long old=__atomic_fetch_add(ptr,value,__ATOMIC_ACQ_REL); __atomic_signal_fence(__ATOMIC_SEQ_CST); return old;}')
    if broken:target.write_text(target.read_text().replace('ptr,value,__ATOMIC_ACQ_REL','ptr,value+1,__ATOMIC_ACQ_REL'))
    report=tmp_path/'report.json';report.write_text(json.dumps({'findings':[finding]}))
    real_digest=effect._digest
    monkeypatch.setattr(effect,'_digest',lambda path:compiler['sourceDigest'] if Path(path)==source else real_digest(path))
    monkeypatch.setattr(batch,'inspect_entry_points',lambda path,**kwargs:(False,functions))
    def native_run(argv,cwd,timeout):
        argv=list(argv)
        if argv[0]=='riscv64-linux-gnu-gcc':
            argv=['gcc',*(x for x in argv[1:] if not x.startswith(('-march=','-mabi=')) and x!='-static')]
        if argv[0]=='unit-native-source-runner':argv=argv[1:]
        return subprocess.run(argv,cwd=cwd,timeout=timeout,capture_output=True,text=True)
    monkeypatch.setattr(effect,'_run',native_run)
    artifact=SimpleNamespace(fragment_id=finding['fragment']['id'],proof_identity=approval['proofIdentity'],
        shell_facts_identity=sidecar.shell_fact_identity,l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity,l2_authority_complete=True,
        preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,target_route='c_builtin',
        renderer_semantic_contract_id=approval['rendererSemanticContractId'],runtime_contract_id='',runtime_contract_version='')
    config={'sourcePath':str(source),'targetPath':str(target),'sourceDigest':compiler['sourceDigest'],
        'targetDigest':real_digest(target),'translatedReport':str(report),'functions':functions,
        'workDirectory':str(tmp_path/'work'),'replayDirectory':str(tmp_path/'replay'),
        'timeoutSeconds':30,'qemuBinary':'unit-native-source-runner'}
    result=build_atomic_validator(config)(level=ValidationLevel.L2,comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        translation_artifact=artifact,l2_provider_id='atomic-provider')
    assert result.status is (ValidationStatus.FAILED if broken else ValidationStatus.VERIFIED),result.detail
    detail=json.loads(result.detail)
    assert detail['executionDisposition']==('executed_failed' if broken else 'executed_verified')
    if broken:assert detail['reasonCode']=='L2_ATOMIC_RMW_VALUE_RELATION_FAILED'
    assert (tmp_path/'replay/atomic-execution.json').is_file()
    for dimension in ('logical_operands','memory_effects','atomic_memory_order','shell_semantics'):
        evidence,reasons=validated_provider_evidence(detail,artifact,dimension=dimension,provider_id='atomic-provider')
        assert evidence is not None and not reasons,reasons


def test_memory_only_renderer_evaluates_address_not_memory_contents(tmp_path):
    finding,functions,model,constraints=atomic_finding(memory_only=True)
    sidecar=materialize_atomic_authority(finding,functions,'sha256:'+'f'*64)
    assert sidecar is not None
    atom=finding['approvalArtifact']['l2AtomicProofFacts']['atomicOperation']
    rendered=rendered_atomic(model,constraints)
    assert '&(*ptr)' in rendered.emitted_text
    harness=atomic_wrapper(functions[0],atom,sidecar)
    declaration='unsigned long probe(unsigned long *ptr,unsigned long value)'
    oracle=declaration+'{ __asm__ volatile("lock xaddq %0,(%1)" : "+r"(value) : "r"(ptr) : "memory","cc"); return value; }'
    target=declaration+'{ '+rendered.emitted_text+' return value; }'
    assert atomic_events(execute(tmp_path,oracle,harness,'address-oracle'),atom)==atomic_events(execute(tmp_path,target,harness,'address-target'),atom)
