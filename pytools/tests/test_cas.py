from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate
from riscv2x86_py.verify import verify

def _frag(text, outs, ins):
    return AsmFragment(rawAsmText=text, outputs=outs, inputs=ins,
                       clobbers=["memory"], isVolatile=True)

def _all(frag):
    a = assemble(frag); assert a.ok, a.error
    l = lift(a.machine_code); assert l.ok
    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)
    return tr, verify(frag, l, s, tr)

def test_cas_retry_w():
    frag = _frag(
        text=("1: lr.w %0, %1\n"
              "   bne  %0, %3, 2f\n"
              "   sc.w %2, %4, %1\n"
              "   bnez %2, 1b\n"
              "2:"),
        outs=[AsmOperand(constraint="=&r", exprText="old", isOutput=True),
              AsmOperand(constraint="+A",  exprText="*p",  isOutput=True),
              AsmOperand(constraint="=&r", exprText="sc",  isOutput=True)],
        ins =[AsmOperand(constraint="r", exprText="expected"),
              AsmOperand(constraint="r", exprText="desired")])
    tr, vr = _all(frag)
    assert tr.kind == "pure_c"
    assert "__atomic_compare_exchange_n" in tr.replacement
    assert "weak=0" not in tr.replacement.replace(" ", "")  # 实参写的是 /*weak=*/0
    assert ", 0," in tr.replacement.replace("/*weak=*/", "")
    assert vr.status == "verified", vr.detail

def test_cas_oneshot_w():
    frag = _frag(
        text=("lr.w %0, %1\n"
              "bne  %0, %3, 2f\n"
              "sc.w %2, %4, %1\n"
              "2:"),
        outs=[AsmOperand(constraint="=&r", exprText="old", isOutput=True),
              AsmOperand(constraint="+A",  exprText="*p",  isOutput=True),
              AsmOperand(constraint="=&r", exprText="sc",  isOutput=True)],
        ins =[AsmOperand(constraint="r", exprText="expected"),
              AsmOperand(constraint="r", exprText="desired")])
    tr, vr = _all(frag)
    assert tr.kind == "pure_c"
    assert "__atomic_compare_exchange_n" in tr.replacement
    # weak=1（一次性）
    assert ", 1," in tr.replacement.replace("/*weak=*/", "")
    assert vr.status == "verified", vr.detail

def test_cas_aqrl_d():
    frag = _frag(
        text=("1: lr.d.aq %0, %1\n"
              "   bne     %0, %3, 2f\n"
              "   sc.d.rl %2, %4, %1\n"
              "   bnez    %2, 1b\n"
              "2:"),
        outs=[AsmOperand(constraint="=&r", exprText="old", isOutput=True),
              AsmOperand(constraint="+A",  exprText="*p",  isOutput=True),
              AsmOperand(constraint="=&r", exprText="sc",  isOutput=True)],
        ins =[AsmOperand(constraint="r", exprText="expected"),
              AsmOperand(constraint="r", exprText="desired")])
    tr, vr = _all(frag)
    assert "__ATOMIC_SEQ_CST" in tr.replacement
    assert vr.status == "verified", vr.detail

def test_non_cas_branchy_falls_through_to_unsupported():
    # 三条指令但不构成 LR/SC：应当被认为 unsupported（旧策略也无法匹配）
    frag = _frag(
        text="beq a0, a1, 1f\n nop\n 1: nop",
        outs=[], ins=[])
    tr, _ = _all(frag)
    assert tr.kind == "unsupported"