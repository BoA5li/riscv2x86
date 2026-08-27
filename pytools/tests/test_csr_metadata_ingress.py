from riscv2x86_py.csr_metadata_ingress import CsrDecoderProfile, decode_csr_privileged_operations
from riscv2x86_py.pcode_ir import CanonicalCsrOperationKind

P = CsrDecoderProfile("1.12", 64, ("f", "zicsr"))

def _one(mnem, body, xlen=64):
    return decode_csr_privileged_operations(addr=0x1000, decoder_mnemonic=mnem, decoder_operands=body, xlen_bits=xlen, profile=P)[0]

def test_csr_forms_and_zero_suppression_are_normalized():
    assert _one("csrrw", "x0, mstatus, a0").csr_operation is CanonicalCsrOperationKind.WRITE
    assert _one("csrrs", "a0, mstatus, x0").csr_operation is CanonicalCsrOperationKind.READ
    assert _one("csrrci", "a0, mstatus, 3").csr_operation is CanonicalCsrOperationKind.CLEAR_BITS
    assert _one("csrrsi", "a0, mstatus, 0").csr_operation is CanonicalCsrOperationKind.READ

def test_counter_pseudos_and_profile_fail_closed():
    assert _one("rdcycle", "a0").csr_id == "riscv.csr.cycle"
    assert not _one("rdcycleh", "a0", 64).state_complete
    rv32 = CsrDecoderProfile("1.12", 32, ("zicsr",))
    assert decode_csr_privileged_operations(addr=1, decoder_mnemonic="rdcycleh", decoder_operands="a0", xlen_bits=32, profile=rv32)[0].state_complete
    assert not _one("csrrwi", "a0, 0xfff, 32").state_complete

def test_unknown_address_and_extension_mismatch_remain_typed_incomplete():
    assert not _one("csrrs", "a0, 0xfff, x0").state_complete
    no_f = CsrDecoderProfile("1.12", 64, ("zicsr",))
    op = decode_csr_privileged_operations(addr=1, decoder_mnemonic="csrrs", decoder_operands="a0, fcsr, x0", xlen_bits=64, profile=no_f)[0]
    assert not op.state_complete and op.csr_id == ""

def test_lift_attaches_decoder_metadata_before_canonicalization(monkeypatch):
    from types import SimpleNamespace
    from riscv2x86_py import lift as lift_module

    class Context:
        def __init__(self, _language_id): pass
        def translate(self, *_args, **_kwargs):
            return SimpleNamespace(ops=[SimpleNamespace(opcode="IMARK", inputs=[], output=None)], length=4)
        def disassemble(self, *_args, **_kwargs):
            return SimpleNamespace(instructions=[SimpleNamespace(mnem="csrrs", body="a0, mstatus, x0", length=4)])

    monkeypatch.setattr(lift_module.pypcode, "Context", Context)
    result = lift_module.lift(b"\\x73\\x25\\x00\\x30", xlen=64, csr_decoder_profile=P)
    assert result.ok
    op = result.insns[0].privileged_operations[0]
    assert op.csr_id == "riscv.csr.mstatus"
    assert op.csr_operation is CanonicalCsrOperationKind.READ
