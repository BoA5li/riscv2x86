"""Instruction-owned CSR coverage, including older SLEIGH temporary prefixes.

Structured reproductions are not reported as full QEMU production acceptance.
"""
from dataclasses import replace
import pytest
from riscv2x86_py.pcode_ir import Var, VarKind, Op, CanonicalInsn, Block
from riscv2x86_py.csr_metadata_ingress import CsrDecoderProfile, decode_csr_privileged_operations
from riscv2x86_py.privileged_state_analysis import analyze_privileged_state


def region(prefix_count=1, rd=10, register='a0'):
    address = 0x10000
    word = (0xc01 << 20) | (2 << 12) | (rd << 7) | 0x73
    metadata = decode_csr_privileged_operations(addr=address,
        machine_bytes=word.to_bytes(4, 'little'), xlen_bits=64,
        profile=CsrDecoderProfile('1.12', 64, ('i', 'zicsr')))
    state = Var(VarKind.REG, 'register', 9000, 8, 'time')
    result = Var(VarKind.REG, 'register', 8272, 8, register)
    ops = [Op(address, 'COPY', Var(VarKind.UNIQUE, 'unique', 128 + i*8, 8),
              [Var(VarKind.CONST, 'const', 0, 8)]) for i in range(prefix_count)]
    ops.append(Op(address, 'COPY', result, [state]))
    return ops, metadata


def model(ops, metadata, *, facts=None):
    from tests.test_controlled_time import trace_contract
    from tests.test_privileged_state_analysis import _cfg
    facts = facts or trace_contract()[1]
    ins = CanonicalInsn(0x10000, 4, ops=ops, privileged_operations=metadata)
    block = Block(0x10000, ops=ops, instructions=[ins])
    return analyze_privileged_state(fragment_id=facts.fragment_id, blocks=[block],
        cfg=_cfg(block), execution_facts=facts)


@pytest.mark.parametrize('prefix', [0, 1, 3])
@pytest.mark.parametrize('rd,register', [(10, 'a0'), (11, 'a1'), (7, 't2')])
def test_pure_prefix_does_not_duplicate_one_decoded_read(prefix, rd, register):
    ops, metadata = region(prefix, rd, register)
    state = model(ops, metadata)
    assert state.complete, state.missing_fact_codes
    assert len(state.csr_effects) == 1
    assert state.csr_effects[0].operation_index == 0
    assert state.csr_effects[0].access_allowed is True


@pytest.mark.parametrize('prefix', [0, 1])
@pytest.mark.parametrize('mutation', ['write', 'write-before', 'extra-read', 'foreign-csr',
    'result', 'width', 'unknown-effect', 'control', 'metadata'])
def test_typed_read_never_hides_uncovered_or_contradictory_operations(prefix, mutation):
    ops, metadata = region(prefix)
    read = ops[-1]
    if mutation in {'write', 'write-before'}:
        write = Op(read.addr, 'COPY', read.inputs[0], [Var(VarKind.CONST, 'const', 0, 8)])
        ops.insert(0 if mutation == 'write-before' else len(ops), write)
    if mutation == 'extra-read': ops.append(replace(read))
    if mutation == 'foreign-csr':
        ops.append(replace(read, inputs=[replace(read.inputs[0], name='riscv.csr.cycle')]))
    if mutation == 'result': ops[-1] = replace(read, output=replace(read.output, name='a1'))
    if mutation == 'width': ops[-1] = replace(read, inputs=[replace(read.inputs[0], size=4)])
    if mutation == 'unknown-effect': ops.append(Op(read.addr, 'CALLOTHER', None, []))
    if mutation == 'control': ops.append(Op(read.addr, 'RETURN', None, []))
    if mutation == 'metadata': metadata = (replace(metadata[0], state_complete=False),)
    state = model(ops, metadata)
    assert not state.complete
    assert state.missing_fact_codes


def test_read_coverage_does_not_grant_missing_access_permission():
    from tests.test_controlled_time import trace_contract
    ops, metadata = region()
    facts = trace_contract()[1]
    # Use the existing unconfigured user facts, never manufacture system facts.
    from riscv2x86_py.privileged_execution_sidecar import default_user_process_execution_facts
    state = model(ops, metadata, facts=default_user_process_execution_facts(facts.fragment_id))
    assert not state.complete and not state.access_permissions_complete


def test_real_lifter_read_passes_complete_privileged_analysis():
    from riscv2x86_py.lift import lift
    from riscv2x86_py.pcode_ir import from_lifted
    from riscv2x86_py.cfg import build_cfg_from_blocks
    from tests.test_controlled_time import trace_contract
    lifted = lift(bytes.fromhex('732510c0'), base_addr=0x10000, xlen=64,
        csr_decoder_profile=CsrDecoderProfile('1.12', 64, ('i', 'zicsr')))
    assert lifted.ok, lifted.error
    blocks, _ = from_lifted(lifted.insns)
    facts = trace_contract()[1]
    state = analyze_privileged_state(fragment_id=facts.fragment_id, blocks=blocks,
        cfg=build_cfg_from_blocks(blocks), execution_facts=facts)
    assert state.complete, state.missing_fact_codes
    assert len(state.csr_effects) == 1


def test_normalized_old_sleigh_region_reaches_proof_replay_and_contract_consumption(tmp_path):
    from tests.test_csr_pcode_normalization import region as old_region
    from riscv2x86_py.csr_pcode_normalization import normalize
    from tests.test_controlled_time import pipeline_fixture
    from riscv2x86_py.csr_runtime_approval import validate_csr_runtime_approval, build_csr_runtime_approval
    from riscv2x86_py.contract_consumption import consumption_receipt
    from riscv2x86_py.time_trace_harness import digest
    from types import SimpleNamespace
    from dataclasses import asdict
    ops, metadata = old_region()
    ops, proof = normalize(ops, addr=0x10000, size=4, privileged_operations=metadata)
    source = tmp_path / 'renamed.c'
    source.write_text('uint64_t renamed(void);\n')
    fragment, result, original, registry, renderer = pipeline_fixture(
        source_digest=digest(source), canonical_ops=ops)
    payload = original['proofPayload']
    approval = build_csr_runtime_approval(fragment, result,
        machine_code=bytes.fromhex(payload['machineCodeHex']), decoder_profile=payload['decoderProfile'],
        target_environment_id=payload['targetEnvironmentId'], normalization_facts=(proof,))
    validate_csr_runtime_approval(approval, fragment, result.suggested_replacement)
    receipt = consumption_receipt(source, {'findings': [{
        'sourceDigest': digest(source), 'fragment': asdict(fragment),
        'approvalArtifact': approval, 'suggestedReplacement': result.suggested_replacement}]},
        csr=SimpleNamespace(fragment_id=fragment.id, runtime_registry=registry, renderer_registry=renderer))
    assert receipt['records'][0]['disposition'] == 'consumed'
