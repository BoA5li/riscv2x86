from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble, _normalize_riscv_assembler_aliases

def make_amoadd():
    return AsmFragment(
        rawAsmText="amoadd.w %0, %2, %1",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True),
                 AsmOperand(constraint="+A", exprText="*p", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="v")],
        clobbers=["memory"], isVolatile=True)

def test_assemble_amoadd():
    r = assemble(make_amoadd())
    assert r.ok, r.error
    assert len(r.machine_code) == 4   # RV64 amoadd.w 是单条 32-bit
    assert any("amoadd.w" in line[2] for line in r.insn_listing)

def test_assemble_fence():
    f = AsmFragment(rawAsmText="fence rw,rw")
    r = assemble(f)
    assert r.ok
    assert len(r.machine_code) == 4

def test_assemble_invalid():
    f = AsmFragment(rawAsmText="this_is_not_an_insn x0,x0")
    r = assemble(f)
    assert not r.ok


def test_riscv_mov_alias_is_normalized_in_any_labeled_asm_body():
    """Phase 4 accepts GCC's register-copy spelling without changing CFG facts."""
    source = (
        "beq x11, x12, branch_taken\n\t"
        "mov x10, x14\n\t"
        "j branch_exit\n\t"
        "branch_taken:\n\t"
        "mov x10, x13\n\t"
        "branch_exit:\n"
    )
    normalized = _normalize_riscv_assembler_aliases(source)
    assert "mv x10, x14" in normalized
    assert "mv x10, x13" in normalized
    assert "beq x11, x12, branch_taken" in normalized
    assert "branch_taken:" in normalized
    assert "branch_exit:" in normalized


def test_riscv_alias_normalization_rejects_noncanonical_mov_forms():
    """Only the two-register pseudoinstruction is canonicalized."""
    source = "mov x10, x11, x12\n"
    assert _normalize_riscv_assembler_aliases(source) == source
