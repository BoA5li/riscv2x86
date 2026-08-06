import ctypes, pytest
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate
from tests.e2e.unicorn_runner import run_rv64
from tests.e2e.test_diff_unicorn import _compile_c   # 复用
from riscv2x86_py.assemble import _PLACEHOLDER_REGS_INT as PHR

CASES = [
    ("fetch_add_w",
     "1: lr.w.aq  %[old_v], (%[addr])\n"
     "   add      %[scratch], %[old_v], %[v]\n"
     "   sc.w.rl  %[status], %[scratch], (%[addr])\n"
     "   bnez     %[status], 1b\n",
     16, 5, 16, 21, 4),

    ("fetch_or_d",
     "1: lr.d.aq  %[old_v], (%[addr])\n"
     "   or       %[scratch], %[old_v], %[v]\n"
     "   sc.d.rl  %[status], %[scratch], (%[addr])\n"
     "   bnez     %[status], 1b\n",
     240, 271, 240, 511, 8),

    ("fetch_sub_w",
     "1: lr.w.aq  %[old_v], (%[addr])\n"
     "   sub      %[scratch], %[old_v], %[v]\n"
     "   sc.w.rl  %[status], %[scratch], (%[addr])\n"
     "   bnez     %[status], 1b\n",
     32, 8, 32, 24, 4),

    ("fetch_addi_imm",
     "1: lr.w.aq  %[old_v], (%[addr])\n"
     "   addi     %[scratch], %[old_v], 1\n"
     "   sc.w.rl  %[status], %[scratch], (%[addr])\n"
     "   bnez     %[status], 1b\n",
     0, 0, 0, 1, 4),
]

@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_lrsc_rmw_unicorn(case):
    name, asm, init, val, exp_old, exp_new, width = case

    frag = AsmFragment(
        rawAsmText=asm,
        outputs=[
            AsmOperand(constraint="=&r", exprText="old_v", symbolicName="old_v", isOutput=True),
            AsmOperand(constraint="=&r", exprText="scratch", symbolicName="scratch", isOutput=True),
            AsmOperand(constraint="=&r", exprText="status", symbolicName="status", isOutput=True),
        ],
        inputs=[
            AsmOperand(constraint="r", exprText="addr", symbolicName="addr"),
            AsmOperand(constraint="r", exprText="v", symbolicName="v"),
        ],
        clobbers=["memory"],
    )
    a = assemble(frag); assert a.ok, a.error
    l = lift(a.machine_code); assert l.ok
    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)
    assert tr.kind == "pure_c", f"{name}: {tr.notes}"
    assert any("LR/SC RMW" in n for n in tr.notes), tr.notes

    # 1) Unicorn 参考
    DATA = 0x30000
    raw = init.to_bytes(width, "little") + b"\0" * (8 - width)

    regs_in = _frag_to_reg_inputs(frag, [DATA, val])
    out_regs = _output_reg_names(frag)

    rv = run_rv64(
        a.machine_code,
        reg_inputs=regs_in,
        reg_outputs=[out_regs[0]],   # old_v 对应的真实占位寄存器
        mem_inputs={DATA: raw[:8]},
        mem_outputs={DATA: 8},
    )

    assert rv.error is None, rv.error

    old_mask = (1 << (width * 8)) - 1
    assert (rv.regs_out[out_regs[0]] & old_mask) == exp_old

    new_mem = int.from_bytes(rv.mem_out[DATA][:width], "little", signed=False)
    assert new_mem == exp_new

    # 2) C 译文
    lib = _compile_c(tr.replacement, ["old_v","scratch","status","addr","v"])
    buf = (ctypes.c_uint64)(init)
    out_old = ctypes.c_long(0)
    out_scratch = ctypes.c_long(0)
    out_status = ctypes.c_long(0)
    # _compile_c 包出的函数签名是 long f(long,long,long,long,long)
    # 这里 out 通过 driver 内部赋值；我们改造 _compile_c 让 outputs 通过
    # 内部变量返回。为简化，把 c_body 包裹时显式把 outputs 作为指针返回：

def _frag_to_reg_inputs(frag, vals):
    n_out = len(frag.outputs)
    regs = {}
    for i in range(n_out):
        regs[PHR[i]] = 0
    for j, v in enumerate(vals):
        regs[PHR[n_out + j]] = v & ((1 << 64) - 1)
    return regs

def _output_reg_names(frag):
    return [PHR[i] for i in range(len(frag.outputs))]