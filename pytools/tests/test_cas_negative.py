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


def test_no_match_when_addr_regs_differ():
    frag = _frag(
        text=("1: lr.w %0, %1\n"
              "   bne  %0, %3, 2f\n"
              "   sc.w %2, %4, %5\n"   # 注意：sc 的地址用了不同寄存器
              "   bnez %2, 1b\n"
              "2:"),
        outs=[AsmOperand(constraint="=&r", exprText="old", isOutput=True),
              AsmOperand(constraint="+A",  exprText="*p",  isOutput=True),
              AsmOperand(constraint="=&r", exprText="sc",  isOutput=True)],
        ins =[AsmOperand(constraint="r", exprText="expected"),
              AsmOperand(constraint="r", exprText="desired"),
              AsmOperand(constraint="r", exprText="other")])
    tr, _ = _all(frag)
    assert tr.kind == "unsupported"

def test_no_match_when_bne_compares_wrong_reg():
    frag = _frag(
        text=("1: lr.w %0, %1\n"
              "   bne  %3, %4, 2f\n"   # bne 不涉及 lr 的输出
              "   sc.w %2, %4, %1\n"
              "   bnez %2, 1b\n"
              "2:"),
        outs=[AsmOperand(constraint="=&r", exprText="old", isOutput=True),
              AsmOperand(constraint="+A",  exprText="*p",  isOutput=True),
              AsmOperand(constraint="=&r", exprText="sc",  isOutput=True)],
        ins =[AsmOperand(constraint="r", exprText="expected"),
              AsmOperand(constraint="r", exprText="desired")])
    tr, _ = _all(frag)
    assert tr.kind == "unsupported"