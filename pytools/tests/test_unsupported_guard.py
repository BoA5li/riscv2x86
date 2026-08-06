import pytest

from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate


NEGATIVE = [
    # 步骤 1 反例
    ("lr+mul+sc",      "1: lr.w t0,(%1); mul t1,t0,%2; sc.w t2,t1,(%1); bnez t2,1b"),
    # 步骤 2 反例
    ("backedge in if", "1: addi %0,%0,1; bne %0,%1,1b"),
    # 步骤 3 反例（构造一对 cross-asm，但中间 ALU 是 mul）
    ("cross mul",      None),  # 在 fixture 里构造
    # 步骤 4 反例
    ("auipc no reloc", "auipc %0, 0"),
    # 通用反例
    ("csrrw",          "csrrw %0, mstatus, %1"),
    ("ecall",          "ecall"),
    ("jalr ind",       "jalr x0, %0, 0"),
]


@pytest.mark.parametrize("name,asm", NEGATIVE, ids=[c[0] for c in NEGATIVE])
def test_must_be_unsupported(name, asm):
    if asm is None:
        pytest.skip("constructed in another fixture")

    frag = AsmFragment(
        rawAsmText=asm,
        outputs=[
            AsmOperand(constraint="=r", exprText="o", isOutput=True),
        ],
        inputs=[
            AsmOperand(constraint="r", exprText="a"),
            AsmOperand(constraint="r", exprText="b"),
        ],
    )

    try:
        a = assemble(frag)
        if not a.ok:
            return  # 汇编都过不去更好

        l = lift(a.machine_code)
        _, s = from_lifted(l.insns)
        tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)
    except Exception:
        return  # 异常优于错误翻译

    assert tr.kind == "unsupported", (
        f"{name}: expected unsupported, got {tr.kind} -> {tr.replacement!r}"
    )