from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble

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