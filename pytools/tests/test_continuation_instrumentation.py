import pytest
from riscv2x86_py.automatic_l2_continuation import instrument_continuations,actual_events,VALUES
from riscv2x86_py.compiler_value_flow import identity
from hashlib import sha256
from types import SimpleNamespace


def sites(data):
    payload={'schemaVersion':'riscv2x86.compiler-continuation-sites.v1',
        'sourceDigest':'sha256:'+sha256(data).hexdigest(),'functionIdentity':'sha256:'+'1'*64,
        'asmBegin':2,'fallthroughBegin':8,'inputParameterIndex':0,'inputIdentifier':'x',
        'labels':[{'label':'done','statementBegin':15}],
        'scope':'single_parameter_single_asm_direct_compound'}
    return {**payload,'siteFactsIdentity':identity(payload)}


def test_edits_use_compiler_offsets_and_retain_instrumentation_map():
    data=b' ' * 20
    patched,mapping=instrument_continuations(data,sites(data),label='done',prefix='r2x_0123456789abcdef')
    assert b'_in((unsigned long long)(x));' in patched
    assert b'_out(0);' in patched and b'_out(1);' in patched
    assert [x['offset'] for x in mapping['edits']]==[2,8,15]
    assert mapping['scope']=='architectural_predicate_observation_only'


def test_return_value_is_not_used_to_predict_exit():
    control=SimpleNamespace(source_continuation='fallthrough',target_continuation='taken')
    def stream(exit_id):return '\n'.join(f'goto_trace;{i};0000000000000000;1;1;{exit_id}' for i in range(len(VALUES)))
    assert actual_events(stream(0),control,64)!=actual_events(stream(1),control,64)


@pytest.mark.parametrize('suffix', [';0;1;0',';1;0;0',';1;2;0',';1;1;3'])
def test_missing_or_duplicate_actual_hooks_fail(suffix):
    control=SimpleNamespace(source_continuation='fallthrough',target_continuation='taken')
    with pytest.raises(ValueError,match='ARITY'):
        actual_events('goto_trace;0;0000000000000000'+suffix,control,64)


def test_stale_sites_and_colliding_namespace_are_rejected():
    data=b' ' * 20;raw=sites(data)
    with pytest.raises(ValueError): instrument_continuations(data+b' ',raw,label='done',prefix='r2x_0123456789abcdef')
    data=b'r2x_0123456789abcdef' + b' '*20
    with pytest.raises(ValueError): instrument_continuations(data,sites(data),label='done',prefix='r2x_0123456789abcdef')


def test_validator_uses_registry_keyword_call_contract():
    from riscv2x86_py.automatic_l2_continuation import build_continuation_validator
    from riscv2x86_py.translation_validation import ValidationLevel
    import json
    result=build_continuation_validator({})(level=ValidationLevel.L2,translation_artifact=None)
    assert json.loads(result.detail)['reasonCode']=='L2_ASM_GOTO_COMPARISON_POLICY_MISMATCH'


def test_native_execution_distinguishes_exits_with_identical_returns(tmp_path):
    import shutil,subprocess
    from riscv2x86_py.automatic_l2_continuation import wrapper
    if shutil.which('gcc') is None: pytest.skip('native compiler unavailable')
    data=(b'unsigned long probe(unsigned long x){\n'
          b'__asm__ volatile goto("testq %0,%0; je %l[taken]" : : "r"(x) : "cc" : taken);\n'
          b'return 7; taken: return 7; }\n')
    raw=sites(data)
    raw.update(asmBegin=data.index(b'__asm__'),fallthroughBegin=data.index(b'return 7'),
        labels=[{'label':'taken','statementBegin':data.rindex(b'return 7')}])
    raw['siteFactsIdentity']=identity({k:v for k,v in raw.items() if k!='siteFactsIdentity'})
    prefix='r2x_0123456789abcdef'
    patched,_=instrument_continuations(data,raw,label='taken',prefix=prefix)
    source=tmp_path/'instrumented.c';source.write_bytes(patched)
    driver=tmp_path/'driver.c';driver.write_text(wrapper({'name':'probe','arity':1,
        'parameterTypes':['unsigned long'],'returnType':'unsigned long'},prefix))
    exe=tmp_path/'observe'
    built=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(source),str(driver),'-o',str(exe)],capture_output=True,text=True)
    assert built.returncode==0,built.stderr
    executed=subprocess.run([str(exe)],capture_output=True,text=True)
    assert executed.returncode==0 and executed.stderr==''
    events=actual_events(executed.stdout,SimpleNamespace(source_continuation='fallthrough',target_continuation='taken'),64)
    assert events[0]['continuationId']=='taken'
    assert events[1]['continuationId']=='fallthrough'
    assert len({e['continuationId'] for e in events})==2


def test_provider_native_execution_closes_three_dimension_evidence(tmp_path,monkeypatch):
    """Native provider integration only; this is not a RISC-V production proof."""
    import json,shutil,subprocess
    from tests.test_l2_asm_goto_authority import finding
    from riscv2x86_py.automatic_l2_authority import _asm_goto_authority
    from riscv2x86_py.automatic_l2_continuation import build_continuation_validator
    from riscv2x86_py.l2_evidence_closure import validated_provider_evidence
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    from riscv2x86_py.translation_validation import ValidationLevel
    from riscv2x86_py.validation_status import PreservationMode,ValidationStatus
    import riscv2x86_py.automatic_batch_cli as batch
    import riscv2x86_py.automatic_l2_effect as effect
    if shutil.which('gcc') is None:pytest.skip('native compiler unavailable')
    data=(b'unsigned long probe(unsigned long x){\n'
          b'__asm__ volatile goto("testq %0,%0; je %l[taken]" : : "r"(x) : "cc" : taken);\n'
          b'return 7; taken: return 7; }\n')
    site=sites(data)
    site.update(asmBegin=data.index(b'__asm__'),fallthroughBegin=data.index(b'return 7'),
        labels=[{'label':'taken','statementBegin':data.rindex(b'return 7')}])
    site['siteFactsIdentity']=identity({k:v for k,v in site.items() if k!='siteFactsIdentity'})
    raw,functions=finding();approval=raw['approvalArtifact']
    sidecar=_asm_goto_authority(raw,functions,'sha256:'+'5'*64)
    approval['l2AuthoritySidecar']=sidecar.to_dict()
    raw['fragment']['compilerFragmentAuthority']={'functionIdentity':site['functionIdentity'],
        'fragmentBindingKey':{'beginOffset':site['asmBegin']}}
    source=tmp_path/'source.c';target=tmp_path/'target.c'
    source.write_bytes(data);target.write_bytes(data)
    report=tmp_path/'report.json';report.write_text(json.dumps({'findings':[raw]}))
    function={'name':'probe','arity':1,'parameterTypes':['unsigned long'],'returnType':'unsigned long',
        'compilerContinuationSites':site}
    monkeypatch.setattr(batch,'inspect_entry_points',lambda path,**kwargs:(False,(function,)))
    def native_run(argv,cwd,timeout):
        argv=list(argv)
        if argv[0]=='riscv64-linux-gnu-gcc':
            argv=['gcc',*(x for x in argv[1:] if not x.startswith(('-march=','-mabi=')) and x!='-static')]
        if argv[0]=='unit-native-source-runner':argv=argv[1:]
        return subprocess.run(argv,cwd=cwd,timeout=timeout,capture_output=True,text=True)
    monkeypatch.setattr(effect,'_run',native_run)
    artifact=SimpleNamespace(fragment_id=raw['fragment']['id'],proof_identity=approval['proofIdentity'],
        shell_facts_identity=sidecar.shell_fact_identity,l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity,l2_authority_complete=True,
        preservation_mode=PreservationMode.ARCHITECTURE_EQUIVALENT,target_route='asm-goto',
        renderer_semantic_contract_id='unit-contract',runtime_contract_id='',runtime_contract_version='')
    config={'sourcePath':str(source),'targetPath':str(target),'sourceDigest':site['sourceDigest'],
        'targetDigest':site['sourceDigest'],'translatedReport':str(report),'functions':[function],
        'workDirectory':str(tmp_path/'work'),'replayDirectory':str(tmp_path/'replay'),
        'timeoutSeconds':30,'qemuBinary':'unit-native-source-runner'}
    result=build_continuation_validator(config)(level=ValidationLevel.L2,comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
        translation_artifact=artifact,l2_provider_id='provider')
    assert result.status is ValidationStatus.VERIFIED,result.detail
    detail=json.loads(result.detail)
    assert detail['executionDisposition']=='executed_verified'
    for dimension in ('logical_operands','control_flow','shell_semantics'):
        evidence,reasons=validated_provider_evidence(detail,artifact,dimension=dimension,provider_id='provider')
        assert not reasons and evidence is not None
