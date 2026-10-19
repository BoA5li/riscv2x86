from copy import deepcopy
from dataclasses import replace
import pytest
from riscv2x86_py.pcode_ir import Var,VarKind,Op,CanonicalInsn,_summarize_instructions
from riscv2x86_py.csr_metadata_ingress import CsrDecoderProfile,decode_csr_privileged_operations
from riscv2x86_py.csr_pcode_normalization import normalize,replay,architectural_state_reads
from riscv2x86_py.semantic_content import semantic_identity


def region():
    addr=0x10000
    meta=decode_csr_privileged_operations(addr=addr,machine_bytes=bytes.fromhex('732510c0'),
        xlen_bits=64,profile=CsrDecoderProfile('1.12',64,('zicsr',)))
    zero=Var(VarKind.CONST,'const',0,8);temporary=Var(VarKind.UNIQUE,'unique',128,8)
    condition=Var(VarKind.UNIQUE,'unique',256,1)
    state=Var(VarKind.REG,'register',9000,8,'time');result=Var(VarKind.REG,'register',8272,8,'a0')
    ops=[Op(addr,'COPY',temporary,[zero]),Op(addr,'COPY',result,[state]),
        Op(addr,'INT_EQUAL',condition,[zero,zero]),
        Op(addr,'CBRANCH',None,[Var(VarKind.MEM,'ram',addr+4,8),condition]),
        Op(addr,'INT_OR',state,[state,temporary])]
    return ops,meta


def test_rdtime_constant_control_and_unreachable_state_write_are_replayable():
    ops,meta=region();normalized,proof=normalize(ops,addr=0x10000,size=4,privileged_operations=meta)
    assert len(normalized)==3 and len(ops)==5
    assert proof['removedOperationIndexes']==[3,4]
    assert replay(proof,privileged_operations=meta)==normalized
    assert architectural_state_reads(normalized,meta)==(ops[1].inputs[0],)
    ins=CanonicalInsn(0x10000,4,ops=normalized,privileged_operations=meta,csr_normalization_facts=proof)
    summary=_summarize_instructions([ins],is_single_block=True)
    assert summary.reads_regs==set() and summary.writes_regs=={'a0'} and not summary.has_branch
    assert meta[0].may_trap is True # normalization never grants access


@pytest.mark.parametrize('mutation',['condition','target','unknown_userop','width','metadata','overlap'])
def test_unsupported_control_retains_original_operations(mutation):
    ops,meta=region()
    if mutation=='condition':ops[2].inputs[0]=ops[1].inputs[0]
    if mutation=='target':ops[3].inputs[0]=replace(ops[3].inputs[0],offset=0x20000)
    if mutation=='unknown_userop':ops.insert(3,Op(0x10000,'CALLOTHER',None,[]))
    if mutation=='width':ops[2].output=replace(ops[2].output,size=8)
    if mutation=='metadata':meta=()
    if mutation=='overlap':ops.insert(3,Op(0x10000,'COPY',replace(ops[2].output,size=2),[Var(VarKind.REG,'register',42,2,'opaque')]))
    normalized,proof=normalize(ops,addr=0x10000,size=4,privileged_operations=meta)
    assert normalized==ops and proof is None


@pytest.mark.parametrize('mutation',['output','removed','condition','decoder'])
def test_rehashed_normalization_mutations_are_rejected(mutation):
    ops,meta=region();_,proof=normalize(ops,addr=0x10000,size=4,privileged_operations=meta)
    changed=deepcopy(proof)
    if mutation=='output':changed['normalizedOperations']=[]
    if mutation=='removed':changed['removedOperationIndexes']=[3]
    if mutation=='condition':changed['branchDecisions'][0]['conditionValue']=0
    if mutation=='decoder':changed['privilegedOperations'][0]['csr_numeric_address']=0xc00
    changed['normalizationIdentity']=semantic_identity({k:v for k,v in changed.items() if k!='normalizationIdentity'})
    with pytest.raises(ValueError):replay(changed,privileged_operations=meta)


def test_state_namespace_does_not_hide_foreign_gpr_or_incomplete_permissions():
    ops,meta=region();normalized,_=normalize(ops,addr=0x10000,size=4,privileged_operations=meta)
    normalized[1]=replace(normalized[1],inputs=[replace(normalized[1].inputs[0],name='a1')])
    assert architectural_state_reads(normalized,meta)==()


def test_real_pypcode_rdtime_has_no_phantom_csr_write_or_program_branch():
    from riscv2x86_py.lift import lift
    from riscv2x86_py.pcode_ir import from_lifted
    result=lift(bytes.fromhex('732510c0'),base_addr=0x10000,xlen=64,
        csr_decoder_profile=CsrDecoderProfile('1.12',64,('zicsr',)))
    assert result.ok,result.error
    blocks,summary=from_lifted(result.insns)
    assert not summary.has_branch and 'time' not in summary.writes_regs and 'time' not in summary.reads_regs
    # SLEIGH versions may already suppress the unreachable write.
    proof=blocks[0].instructions[0].csr_normalization_facts
    if proof is not None:
        replay(proof,privileged_operations=blocks[0].instructions[0].privileged_operations)


def test_approval_replays_normalization_against_decoded_machine_instruction(tmp_path):
    from tests.test_csr_family_environment import pipeline_fixture
    from riscv2x86_py.csr_runtime_approval import build_csr_runtime_approval,validate_csr_runtime_approval
    fragment,result,legacy=pipeline_fixture(tmp_path,1)
    payload=legacy['proofPayload'];code=bytes.fromhex(payload['machineCodeHex'])
    addr=payload['fieldProof']['sourceModel']['effects'][0]['block_address']
    metadata=decode_csr_privileged_operations(addr=addr,machine_bytes=code,xlen_bits=64,
        profile=CsrDecoderProfile('1.12',64,('zicsr',)))
    condition=Var(VarKind.UNIQUE,'unique',256,1)
    ops=[Op(addr,'COPY',condition,[Var(VarKind.CONST,'const',0,1)]),
         Op(addr,'CBRANCH',None,[Var(VarKind.MEM,'ram',addr+4,8),condition])]
    _,proof=normalize(ops,addr=addr,size=4,privileged_operations=metadata)
    approval=build_csr_runtime_approval(fragment,result,machine_code=code,
        decoder_profile=payload['decoderProfile'],target_environment_id=payload['targetEnvironmentId'],
        normalization_facts=(proof,))
    assert approval['proofPayload']['schemaVersion']=='riscv2x86.csr-runtime-proof.v3'
    validate_csr_runtime_approval(approval,fragment,result.suggested_replacement)


def test_old_sleigh_region_is_normalized_before_cfg_and_operand_summary():
    from riscv2x86_py.lift import LiftedInsn
    from riscv2x86_py.pcode_ir import from_lifted
    ops,metadata=region()
    instruction=LiftedInsn(0x10000,4,'','',[],raw_ops=ops,privileged_operations=metadata)
    blocks,summary=from_lifted([instruction])
    canonical=blocks[0].instructions[0]
    assert canonical.csr_normalization_facts['removedOperationIndexes']==[3,4]
    assert not summary.has_branch
    assert summary.reads_regs==set() and summary.writes_regs=={'a0'}
