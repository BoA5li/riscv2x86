from types import SimpleNamespace

from riscv2x86_py.csr_metadata_ingress import (
    CsrDecoderProfile,
    DecodedCsrOpcodeKind,
    decode_csr_instruction,
    decode_csr_privileged_operations,
)
from riscv2x86_py.pcode_ir import CanonicalCsrOperationKind, canonicalize_lifted_instruction


P64 = CsrDecoderProfile("1.12", 64, ("f", "zicsr"))
P32 = CsrDecoderProfile("1.12", 32, ("zicsr",))


def _encoded(funct3, csr, rd=10, source=0):
    return ((csr << 20) | (source << 15) | (funct3 << 12) | (rd << 7) | 0x73).to_bytes(4, "little")


def _one(funct3, csr, rd=10, source=0, xlen=64, profile=P64):
    return decode_csr_privileged_operations(
        addr=0x1000, machine_bytes=_encoded(funct3, csr, rd, source),
        xlen_bits=xlen, profile=profile,
    )[0]


def test_decoded_fields_drive_all_csr_forms_and_suppression():
    decoded = decode_csr_instruction(_encoded(0b001, 0x300, rd=0, source=10))
    assert decoded is not None
    assert decoded.opcode_kind is DecodedCsrOpcodeKind.CSRRW
    assert decoded.csr_numeric_address == 0x300
    assert decoded.rd_register_id == "x0" and decoded.rs1_register_id == "x10"
    assert _one(0b001, 0x300, rd=0, source=10).csr_operation is CanonicalCsrOperationKind.WRITE
    assert _one(0b010, 0x300, rd=10, source=0).csr_operation is CanonicalCsrOperationKind.READ
    assert _one(0b011, 0x300, rd=10, source=11).csr_operation is CanonicalCsrOperationKind.CLEAR_BITS
    assert _one(0b101, 0x300, rd=10, source=31).immediate_mask == 31
    assert _one(0b110, 0x300, rd=10, source=0).csr_operation is CanonicalCsrOperationKind.READ
    assert _one(0b111, 0x300, rd=10, source=3).csr_operation is CanonicalCsrOperationKind.CLEAR_BITS


def test_counter_pseudos_are_normalized_from_encoding_and_rv32_high_halves():
    assert _one(0b010, 0xC00, source=0).csr_id == "riscv.csr.cycle"
    assert not _one(0b010, 0xC80, source=0).state_complete
    high = _one(0b010, 0xC80, source=0, xlen=32, profile=P32)
    assert high.csr_id == "riscv.csr.cycleh" and high.state_complete


def test_illegal_address_and_profile_mismatch_stay_typed_and_incomplete():
    illegal = _one(0b010, 0xFFF, source=0)
    assert illegal.csr_numeric_address == 0xFFF and not illegal.state_complete
    no_f = CsrDecoderProfile("1.12", 64, ("zicsr",))
    mismatch = _one(0b010, 0x003, source=0, profile=no_f)
    assert mismatch.csr_semantic_class == "unknown" and not mismatch.state_complete
    no_zicsr = CsrDecoderProfile("1.12", 64, ())
    assert not _one(0b010, 0x300, source=0, profile=no_zicsr).state_complete


def test_lift_and_canonicalization_receive_byte_decoded_metadata(monkeypatch):
    from riscv2x86_py import lift as lift_module

    class Context:
        def __init__(self, _language_id): pass
        def translate(self, *_args, **_kwargs):
            return SimpleNamespace(ops=[SimpleNamespace(opcode="IMARK", inputs=[], output=None)], length=4)
        def disassemble(self, *_args, **_kwargs):
            # Deliberately misleading text: semantic metadata must still be
            # decoded from the actual bytes below.
            return SimpleNamespace(instructions=[SimpleNamespace(mnem="addi", body="a0, a0, 1", length=4)])

    monkeypatch.setattr(lift_module.pypcode, "Context", Context)
    result = lift_module.lift(_encoded(0b010, 0x300, rd=10, source=0), xlen=64, csr_decoder_profile=P64)
    assert result.ok
    insn = result.insns[0]
    assert insn.decoded_csr_instruction is not None
    assert insn.privileged_operations[0].csr_id == "riscv.csr.mstatus"
    canonical = canonicalize_lifted_instruction(insn)
    assert canonical.privileged_operations[0].csr_operation is CanonicalCsrOperationKind.READ


def test_unsupported_csr_encoding_is_never_an_integer_instruction():
    # funct3=100 is reserved in SYSTEM/CSR space.  It remains an explicit,
    # incomplete typed CSR operation rather than returning an empty result.
    op = _one(0b100, 0x300, source=0)
    assert op.csr_operation is CanonicalCsrOperationKind.UNKNOWN
    assert not op.state_complete
