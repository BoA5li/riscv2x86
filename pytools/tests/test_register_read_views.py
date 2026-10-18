from types import SimpleNamespace as NS
from dataclasses import replace
import pytest
from riscv2x86_py.register_views import database_read_view, RegisterReadView
from riscv2x86_py.ghidra_pythonrun_bridge import PythonRunRegisterNameResolver
from riscv2x86_py.lift import adapt_raw_pcode_op
from riscv2x86_py.pcode_ir import _to_var


def record(name='database_register',offset=12345,size=8):
    return {'name':name,'offset':offset,'size':size,'bitLength':size*8,
        'isProcessorContext':False,'baseName':name,'baseOffset':offset,'baseSize':size}


def resolver(records=None):
    return PythonRunRegisterNameResolver({('register',12345,8):'database_register'},
        tuple(records or [record()]),'test-language:LE',False)


def raw(size=4,offset=12345):return NS(space='register',offset=offset,size=size)


def test_read_view_preserves_width_and_database_identity_in_canonical_ir():
    r=resolver()
    op=adapt_raw_pcode_op(NS(opcode='COPY',inputs=[raw()],output=None),register_name_resolver=r)
    v=op.inputs[0]
    assert v.name=='database_register' and v.size==4
    assert v.register_read_view.parent_size==8
    assert v.register_read_view.offset==12345
    canonical=_to_var(v)
    assert canonical.size==4 and canonical.register_read_view==v.register_read_view
    assert canonical.register_read_view.view_identity.startswith('sha256:')


def test_write_does_not_inherit_read_view_or_invent_extension_semantics():
    r=resolver()
    op=adapt_raw_pcode_op(NS(opcode='COPY',inputs=[],output=raw()),register_name_resolver=r)
    assert op.output.name=='' and op.output.register_read_view is None


@pytest.mark.parametrize('offset,size,endian',[(12346,4,False),(12345,9,False),(12345,0,False),(12345,4,True),(12345,4,None)])
def test_unproven_slice_rejected(offset,size,endian):
    assert database_read_view([record()],space='register',offset=offset,size=size,
        language_id='test',big_endian=endian) is None


def test_ambiguous_or_context_registers_are_not_guessed():
    assert resolver([record(),record('other')]).register_read_view_for_varnode(space='register',offset=12345,size=4) is None
    assert resolver([{**record(),'isProcessorContext':True}]).register_read_view_for_varnode(space='register',offset=12345,size=4) is None
    assert PythonRunRegisterNameResolver({('register',12345,8):'x'}).register_read_view_for_varnode(space='register',offset=12345,size=4) is None


def test_low_view_does_not_depend_on_riscv_offset_table():
    view=database_read_view([record('backend_word',913,16)],space='register',offset=913,size=3,
        language_id='different-language',big_endian=False)
    assert view.parent_name=='backend_word' and view.size==3 and view.parent_size==16


def test_memory_only_profile_consumes_address_without_relabelling_access():
    from tests.test_l2_atomic_production import atomic_finding
    from riscv2x86_py.l2_semantic_profile import profile_from_source_model
    finding,_,model,_=atomic_finding(memory_only=True)
    profile=profile_from_source_model(finding['fragment']['id'],model)
    assert model.operands.operands[1].access.value=='read_write'
    assert profile.memory_shape.object_relative and profile.memory_shape.complete
    assert profile.complete
    address=model.operands.operands[1]
    for wrong in (replace(address,address=None),
                  replace(address,address=replace(address.address,address_projection=None)),
                  replace(address,address=replace(address.address,memory_object_identity='other')),
                  replace(address,source_operand_index=99)):
        changed=replace(model,operands=replace(model.operands,operands=(model.operands.operands[0],wrong)))
        assert not profile_from_source_model(finding['fragment']['id'],changed).memory_shape.complete


def test_precandidate_failure_reaches_terminal_archive_with_stage():
    from riscv2x86_py.pipeline import _complete_non_candidate_evaluation_states
    from riscv2x86_py.schema import Finding,AsmFragment
    finding=Finding(category='Unsupported',fragment=AsmFragment(id='source:1:1'),
        verificationStatus='unsupported',ruleName='phase5.authoritative_register_name_unavailable',
        verificationDetail='backend rejected register view')
    _complete_non_candidate_evaluation_states([finding])
    assert finding.translationReasonCodes==['phase5.authoritative_register_name_unavailable']
    assert finding.routeAuthorityDiagnostics[0]['failureStage']=='phase5'
    assert finding.routeAuthorityDiagnostics[0]['inputsPayload']['evidenceProductionDisposition']=='not_produced'
    assert finding.translationOutcome=='unsupported'


def test_actual_word_amo_pcode_uses_narrow_read_and_full_width_result():
    import pypcode
    from riscv2x86_py.lift import lift
    ctx=pypcode.Context('RISCV:LE:64:default')
    # Test backend database supplies names/locations; no numeric register map.
    registers=[];names={}
    for name in ('a0','a1','a2','a3'):
        vn=ctx.registers[name]
        registers.append(record(name,vn.offset,vn.size))
        names[('register',vn.offset,vn.size)]=name
    r=PythonRunRegisterNameResolver(names,tuple(registers),'RISCV:LE:64:default',False)
    result=lift(bytes.fromhex('2fa5c506'),register_name_resolver=r,
        require_authoritative_register_names=True)
    assert result.ok,result.error
    reads=[v for ins in result.insns for op in ins.raw_ops for v in op.inputs if v.register_read_view]
    assert reads and all(v.size==4 and v.register_read_view.parent_size==8 for v in reads)
    outputs=[op.output for ins in result.insns for op in ins.raw_ops if op.output and op.output.space=='register']
    assert outputs and all(v.size==8 and v.register_read_view is None for v in outputs)


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('memory_only',[False,True])
def test_profile_then_atomic_materializer_matrix(width,memory_only):
    from tests.test_l2_atomic_production import atomic_finding
    from riscv2x86_py.l2_semantic_profile import profile_from_source_model
    from riscv2x86_py.l2_atomic_authority import materialize_atomic_authority
    finding,functions,model,_=atomic_finding(memory_width=width,memory_only=memory_only)
    profile=profile_from_source_model(finding['fragment']['id'],model)
    assert profile.complete
    assert materialize_atomic_authority(finding,functions,'sha256:'+'f'*64) is not None


def test_direct_ghidra_api_read_view_uses_database_base_register():
    from riscv2x86_py.lift import GhidraLanguageRegisterResolver
    reg=NS(getAddress=lambda:NS(getOffset=lambda:913,getAddressSpace=lambda:NS(getName=lambda:'register')),
        getBaseRegister=lambda:None,getMinimumByteSize=lambda:8,getBitLength=lambda:64,
        isProcessorContext=lambda:False,getName=lambda:'backend_name')
    language=NS(getRegisters=lambda:[reg],getLanguageID=lambda:'db-language',isBigEndian=lambda:False)
    r=GhidraLanguageRegisterResolver(language)
    v=r.register_read_view_for_varnode(space='register',offset=913,size=4)
    assert v.parent_name=='backend_name' and v.parent_offset==913


def test_canonical_view_cannot_disagree_with_parent_name_or_width():
    r=resolver()
    op=adapt_raw_pcode_op(NS(opcode='COPY',inputs=[raw()],output=None),register_name_resolver=r)
    with pytest.raises(ValueError,match='CANONICAL_REGISTER_READ_VIEW_MISMATCH'):
        _to_var(replace(op.inputs[0],name='wrong'))
    with pytest.raises(ValueError,match='CANONICAL_REGISTER_READ_VIEW_MISMATCH'):
        _to_var(replace(op.inputs[0],size=8))
