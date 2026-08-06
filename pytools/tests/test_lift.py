from riscv2x86_py.lift import lift

def test_lift_amoadd_w_bytes():
    # 直接给出已知 amoadd.w 编码（占位寄存器编码）
    # 你可以用 llvm-mc 跑一次取真实字节代入
    from riscv2x86_py.schema import AsmFragment, AsmOperand
    from riscv2x86_py.assemble import assemble
    frag = AsmFragment(rawAsmText="amoadd.w a0,a1,(a2)",
                       outputs=[], inputs=[])
    a = assemble(frag)
    assert a.ok, a.error
    r = lift(a.machine_code, xlen=64)
    assert r.ok
    assert r.insns and r.insns[0].asm_mnem.lower().startswith("amoadd")