from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate

def _pipeline_for(frag):
    a = assemble(frag); assert a.ok, a.error
    l = lift(a.machine_code); assert l.ok
    _, summary = from_lifted(l.insns)
    return translate(frag, l, summary)

def test_translate_amoadd():
    frag = AsmFragment(
        rawAsmText="amoadd.w %0, %2, %1",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True),
                 AsmOperand(constraint="+A", exprText="*p", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="v")])
    out = _pipeline_for(frag)
    assert out.kind == "pure_c"
    assert "__atomic_fetch_add" in out.replacement
    assert "&(*p)" in out.replacement
    assert "v" in out.replacement
    assert "__ATOMIC_RELAXED" in out.replacement

def test_translate_amoadd_aq():
    frag = AsmFragment(
        rawAsmText="amoadd.w.aq %0, %2, %1",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True),
                 AsmOperand(constraint="+A", exprText="*p", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="v")])
    out = _pipeline_for(frag)
    assert out.kind == "pure_c"
    assert "__atomic_fetch_add" in out.replacement
    assert "__ATOMIC_ACQUIRE" in out.replacement

def test_translate_amoadd_rl():
    frag = AsmFragment(
        rawAsmText="amoadd.w.rl %0, %2, %1",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True),
                 AsmOperand(constraint="+A", exprText="*p", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="v")])
    out = _pipeline_for(frag)
    assert out.kind == "pure_c"
    assert "__atomic_fetch_add" in out.replacement
    assert "__ATOMIC_RELEASE" in out.replacement

def test_translate_amoadd_aqrl():
    frag = AsmFragment(
        rawAsmText="amoadd.w.aqrl %0, %2, %1",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True),
                 AsmOperand(constraint="+A", exprText="*p", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="v")])
    out = _pipeline_for(frag)
    assert out.kind == "pure_c"
    assert "__atomic_fetch_add" in out.replacement
    assert "__ATOMIC_SEQ_CST" in out.replacement

def test_translate_fence():
    frag = AsmFragment(rawAsmText="fence rw,rw")
    out = _pipeline_for(frag)
    assert out.kind == "pure_c"
    assert "__atomic_thread_fence" in out.replacement

def test_translate_unsupported_branch():
    frag = AsmFragment(rawAsmText="beq a0, a1, 1f\n nop\n 1:")
    out = _pipeline_for(frag)
    assert out.kind == "unsupported"