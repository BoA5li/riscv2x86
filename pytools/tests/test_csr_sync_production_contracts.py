from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace
import pytest

from riscv2x86_py.csr_architecture_profile import parse_profile, SCHEMA
from riscv2x86_py.csr_metadata_ingress import decode_csr_instruction, canonical_csr_operations_from_decoded
from riscv2x86_py.route_authority import content_identity
from riscv2x86_py.privileged_execution_sidecar import default_user_process_execution_facts


def profile(**changes):
    p={'schemaVersion':SCHEMA,'sourceDigest':'sha256:'+'1'*64,
       'fragmentId':'f','privilegeSpecVersion':'riscv-privileged-1.12',
       'xlenBits':64,'extensions':['zicsr']}
    p.update(changes);p['profileIdentity']=content_identity(p)
    return p


def test_architecture_profile_does_not_grant_access_or_complete_environment():
    explicit=parse_profile(profile(),source_digest='sha256:'+'1'*64,fragment_id='f',xlen_bits=64)
    # Exact CSRRS encoding, independent of any disassembly spelling.
    code=((0xc01<<20)|(2<<12)|(10<<7)|0x73).to_bytes(4,'little')
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=decode_csr_instruction(code),xlen_bits=64,profile=explicit)[0]
    assert op.csr_id=='riscv.csr.time' and op.state_complete
    assert op.may_trap is True and op.access_gate_evaluation_complete is False
    assert default_user_process_execution_facts('f').complete is False


@pytest.mark.parametrize('args,reason',[
    ({'source_digest':'sha256:'+'2'*64},'SOURCE_MISMATCH'),
    ({'fragment_id':'other'},'FRAGMENT_MISMATCH'),
    ({'xlen_bits':32},'XLEN_MISMATCH')])
def test_profile_content_binding(args,reason):
    with pytest.raises(ValueError,match=reason):parse_profile(profile(),**args)


@pytest.mark.parametrize('changes',[
    {'xlenBits':True},{'extensions':['zicsr','zicsr']},
    {'extensions':['Zicsr']},{'privilegeSpecVersion':'latest'},
    {'executionAllowed':True}])
def test_profile_rejects_permission_shortcuts_and_unknown_fields(changes):
    with pytest.raises(ValueError):parse_profile(profile(**changes))


def test_profile_identity_mutation():
    p=profile();p['extensions']=[]
    with pytest.raises(ValueError,match='IDENTITY'):parse_profile(p)


def compiler_fragment(constraint="=r", *, source_digest=None):
    from tests.test_production_route_authority import _compiler_authority
    from riscv2x86_py.schema import AsmFragment, AsmOperand
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
    a=_compiler_authority(source_digest=source_digest);c=deepcopy(a['candidate'])
    # Independently close an output-only compiler candidate; no join helper
    # constructs the expected decoder role or expected value node.
    c.pop('closureIdentity');c.pop('closureProvenance')
    c['schemaVersion']=c.pop('sourceCandidateSchemaVersion')
    c['operandCarriers']=c['operandCarriers'][:1]
    for key in ('operandBindings','valueNodes'):
        if key in c:c[key]=c[key][:1]
    from tests.test_compiler_expression_contracts import ctype
    typ=ctype()
    f=AsmFragment(id=a['fragmentId'],beginOffset=100,endOffset=140,
        rawAsmText='deliberately not parsed',isVolatile=True,
        outputs=[AsmOperand(constraint=constraint,isOutput=True,compilerType=typ)])
    a['candidate']=close_compiler_fragment_candidate(c,asdict(f),
        source_digest=a['sourceDigest'],function_identity=a['functionIdentity'])
    a['compilerTypeBindings']={'0':{'operandIndex':0,'valueNodeIdentity':a['candidate']['operandBindings'][0]['valueNodeIdentity'],'compilerType':typ}}
    a['authorityIdentity']=content_identity({k:v for k,v in a.items() if k!='authorityIdentity'})
    f.compilerFragmentAuthority=a
    return f


def one_insn():
    code=((0xc01<<20)|(2<<12)|(10<<7)|0x73).to_bytes(4,'little')
    d=decode_csr_instruction(code)
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=d,xlen_bits=64,profile=parse_profile(profile()))[0]
    return SimpleNamespace(addr=0x10000,decoded_csr_instruction=d,privileged_operations=(op,))


def test_static_csr_join_uses_compiler_value_node_and_assembler_binding():
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    from riscv2x86_py.csr_value_flow import join_csr_operand_bindings
    f=compiler_fragment();runtime=TranslationRuntimeFacts(rv_to_operand_index={'a0':0},operand_width_bits={0:64})
    authority,witness=bind_csr_compiler_operands(f,runtime,[one_insn()],source_digest=f.compilerFragmentAuthority['sourceDigest'],architecture_profile=parse_profile(profile()))
    assert authority.value_node_to_operand_index=={'decoder-csr:0x10000:rd:x10':0}
    assert witness['operandRoles'][0]['compilerValueNodeIdentity']==f.compilerFragmentAuthority['candidate']['operandBindings'][0]['valueNodeIdentity']
    assert join_csr_operand_bindings(lifted_insns=[one_insn()],authority=authority)[0].complete
    assert one_insn().privileged_operations[0].may_trap is True


@pytest.mark.parametrize('mutation,reason',[
    ('register','BINDING_MISSING'),('width','WIDTH_MISMATCH'),
    ('constraint','CONSTRAINT_UNSUPPORTED'),('identity','IDENTITY'),
    ('mixed','REGION_CLOSURE_REQUIRED')])
def test_csr_join_rejects_mutation(mutation,reason):
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    f=compiler_fragment();runtime=TranslationRuntimeFacts(rv_to_operand_index={'a0':0},operand_width_bits={0:64});ins=[one_insn()]
    if mutation=='register':runtime=TranslationRuntimeFacts(rv_to_operand_index={'a1':0},operand_width_bits={0:64})
    if mutation=='width':runtime=TranslationRuntimeFacts(rv_to_operand_index={'a0':0},operand_width_bits={0:32})
    if mutation=='constraint':f.outputs[0].constraint='=m'
    if mutation=='identity':f.compilerFragmentAuthority['authorityIdentity']='sha256:'+'9'*64
    if mutation=='mixed':ins*=2
    with pytest.raises(ValueError,match=reason):bind_csr_compiler_operands(f,runtime,ins,source_digest=f.compilerFragmentAuthority['sourceDigest'],architecture_profile=parse_profile(profile()))


def test_route_rejection_keeps_specific_proof_reason(monkeypatch):
    from riscv2x86_py import translate as module
    from riscv2x86_py.route_authority import validate_route_decision
    monkeypatch.setattr(module,'_output',lambda **kwargs:kwargs)
    context=SimpleNamespace(fragment=SimpleNamespace(id='f'),decision=None)
    result=module._needs_route(context,route='instruction_stream_synchronization_adapter',
        reason='No registered contract',reason_code='TR_INSTRUCTION_STREAM_SYNC_RUNTIME_CONTRACT_REQUIRED',
        metadata={'phase6dReasonCode':'ISS_RUNTIME_CONTRACT_MISSING'})
    d=result['metadata']['routeAuthorityDiagnostics'][0]
    validate_route_decision(d)
    assert d['reasonCode']=='ISS_RUNTIME_CONTRACT_MISSING'
    assert d['inputsPayload']['executionDisposition']=='precondition_rejected'
    assert d['inputsPayload']['evidenceProductionDisposition']=='not_produced'


def test_instruction_fence_only_closes_control_absence():
    from riscv2x86_py.pcode_ir import CanonicalInsn, BarrierInfo, BarrierKind, Op, _summarize_instructions
    ins=CanonicalInsn(0x10000,4,ops=[Op(0x10000,'CALLOTHER',None,[])],
        barrier_info=BarrierInfo(BarrierKind.INSTRUCTION_FENCE))
    summary=_summarize_instructions([ins],is_single_block=True)
    assert summary.has_instruction_barrier
    assert summary.has_return is False and summary.has_indirect_control_flow is False
    # No target or microarchitectural proof is fabricated by the summary.
    assert summary.has_speculation_control is None and summary.has_cache_operation is None
    ins.ops.append(Op(0x10000,'STORE',None,[]))
    assert _summarize_instructions([ins],is_single_block=True).has_return is None


def test_decoder_role_corruption_is_rejected():
    from dataclasses import replace
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    ins=one_insn()
    ins.privileged_operations=(replace(ins.privileged_operations[0],write_value_node_id='invented'),)
    with pytest.raises(ValueError,match='DECODER_EFFECT_MISMATCH'):
        bind_csr_compiler_operands(compiler_fragment(),TranslationRuntimeFacts(
            rv_to_operand_index={'a0':0},operand_width_bits={0:64}),[ins],source_digest=compiler_fragment().compilerFragmentAuthority['sourceDigest'],architecture_profile=parse_profile(profile()))


@pytest.mark.parametrize('family',['instruction_sync','csr_read'])
def test_real_missing_environment_remains_auditable_needs_route(tmp_path,family):
    import json,subprocess,sys
    from tests.test_l2_real_production_chain import _tools, _assert_frontend_accepts
    frontend=_tools()
    inputs=tmp_path/'inputs';inputs.mkdir()
    source=inputs/'probe.c'
    source.write_text('void probe(void){__asm__ volatile("fence.i" ::: "memory");}\n'
        if family=='instruction_sync' else
        '#include <stdint.h>\nuint64_t probe(void){uint64_t value;__asm__ volatile("rdtime %0":"=r"(value));return value;}\n')
    _assert_frontend_accepts(frontend,source,tmp_path)
    command=[sys.executable,'-m','riscv2x86_py.automatic_batch_cli','--input',str(inputs),
        '--frontend',frontend,'--output-directory',str(tmp_path/'results'),'--jobs','1','--timeout-seconds','120']
    if family=='csr_read':
        from hashlib import sha256
        frontend_report=json.loads((tmp_path/'syntax-report.json').read_text())
        fragment=frontend_report['findings'][0]['fragment']
        profiles=tmp_path/'profiles';profiles.mkdir()
        p=profile(sourceDigest='sha256:'+sha256(source.read_bytes()).hexdigest(),
            fragmentId=fragment.get('fragmentId') or fragment['id'])
        (profiles/'probe.c.csr-architecture.json').write_text(json.dumps(p))
        command+=['--csr-architecture-directory',str(profiles)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=300,check=False)
    evaluation=json.loads((tmp_path/'results/cases/probe/evaluation-result.json').read_text())
    assert result.returncode==1 and evaluation['status']=='needs_route',evaluation
    decisions=[d for a in evaluation['attempts'] for d in a.get('routeAuthorityDiagnostics',[])]
    assert decisions,evaluation
    if family=='csr_read':
        assert any(d['reasonCode']=='CSR_COMPILER_JOIN_COMPLETE' and d['accepted'] for d in decisions),decisions
    else:
        assert any(d['reasonCode']=='ISS_RUNTIME_CONTRACT_MISSING' for d in decisions),decisions


def test_read_write_csr_keeps_single_gnu_carrier_and_two_decoder_nodes():
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.csr_value_flow import join_csr_operand_bindings
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    # CSRRW x10, mstatus, x10: old result and incoming write share a +r.
    code=((0x300<<20)|(10<<15)|(1<<12)|(10<<7)|0x73).to_bytes(4,'little')
    decoded=decode_csr_instruction(code);p=parse_profile(profile())
    op=canonical_csr_operations_from_decoded(addr=0x10000,decoded=decoded,xlen_bits=64,profile=p)[0]
    ins=SimpleNamespace(addr=0x10000,decoded_csr_instruction=decoded,privileged_operations=(op,))
    f=compiler_fragment('+r')
    authority,_=bind_csr_compiler_operands(f,TranslationRuntimeFacts(rv_to_operand_index={'a0':0},operand_width_bits={0:64}),
        [ins],source_digest=f.compilerFragmentAuthority['sourceDigest'],architecture_profile=p)
    assert set(authority.value_node_to_operand_index.values())=={0}
    assert len(authority.value_node_to_operand_index)==2
    assert authority.tied_operand_pairs==((0,0),)
    joined=join_csr_operand_bindings(lifted_insns=[ins],authority=authority)[0]
    assert joined.complete and joined.read_result_operand_index==joined.write_value_operand_index==0


def test_static_csr_join_rejects_cross_source_even_with_valid_envelope():
    from riscv2x86_py.csr_production_binding import bind_csr_compiler_operands
    from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
    with pytest.raises(ValueError,match='SOURCE_DIGEST_MISMATCH'):
        bind_csr_compiler_operands(compiler_fragment(),TranslationRuntimeFacts(),[one_insn()],
            source_digest='sha256:'+'9'*64,architecture_profile=parse_profile(profile()))
