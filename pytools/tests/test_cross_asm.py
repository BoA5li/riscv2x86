"""
测试跨 __asm__ 块的状态传递与融合。
"""
import ctypes
import os
import subprocess
import tempfile

import pytest

from riscv2x86_py.schema import AsmFragment, AsmOperand, OutputBinding
from riscv2x86_py.translate_function import translate_function
from riscv2x86_py.assemble import assemble
from tests.e2e.unicorn_runner import run_rv64
from tests.e2e.test_diff_unicorn import _compile_c_multi


def test_cross_asm_fetch_or_basic():
    """基础测试：lr + or + sc 融合为 fetch_or"""
    frag_a = AsmFragment(
        rawAsmText="lr.w.aq %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="p")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="old | 0x4",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.w.rl %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="p"),
            AsmOperand(constraint="r", exprText="new"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)

    assert len(results) == 2
    assert results[0] is not None
    assert results[0].kind == "pure_c"
    assert "__atomic_fetch_or" in results[0].replacement
    assert results[1] is None  # 被融合


def test_cross_asm_fetch_add_variable():
    """中间 ALU 使用变量"""
    frag_a = AsmFragment(
        rawAsmText="lr.d.aq %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="addr")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="old + delta",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.d.rl %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="addr"),
            AsmOperand(constraint="r", exprText="new_val"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)

    assert results[0] is not None
    assert results[0].kind == "pure_c"
    assert "__atomic_fetch_add" in results[0].replacement
    assert "delta" in results[0].replacement


def test_cross_asm_unicorn_diff():
    """译文语义验证：fetch_or 场景"""
    frag_a = AsmFragment(
        rawAsmText="lr.w.aq %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="p")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="old | 8",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.w.rl %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="p"),
            AsmOperand(constraint="r", exprText="new"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)
    assert results[0] is not None
    assert results[0].kind == "pure_c"

    asm_a = assemble(frag_a)
    asm_b = assemble(frag_b)
    assert asm_a.ok, f"assemble frag_a failed: {getattr(asm_a, 'error', '')}"
    assert asm_b.ok, f"assemble frag_b failed: {getattr(asm_b, 'error', '')}"

    init_val = 0x10
    expected_new = init_val | 8
    expected_old = init_val

    src = f"""
#include <stdint.h>
#include <stdatomic.h>

void test_func(long *out_old, long *out_rc, volatile uint32_t *p) {{
    long old = 0, rc = 0;
    {results[0].replacement};
    *out_old = old;
    *out_rc = rc;
}}
"""

    d = tempfile.mkdtemp(prefix="r2x_cross_")
    cpath = os.path.join(d, "test.c")
    spath = os.path.join(d, "test.so")

    with open(cpath, "w", encoding="utf-8") as f:
        f.write(src)

    r = subprocess.run(
        ["clang", "-O0", "-fPIC", "-shared", "-o", spath, cpath],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, f"clang failed:\n{r.stderr}"

    lib = ctypes.CDLL(spath)
    lib.test_func.restype = None
    lib.test_func.argtypes = [
        ctypes.POINTER(ctypes.c_long),
        ctypes.POINTER(ctypes.c_long),
        ctypes.POINTER(ctypes.c_uint32),
    ]

    buf = ctypes.c_uint32(init_val)
    out_old = ctypes.c_long(0)
    out_rc = ctypes.c_long(0)

    lib.test_func(
        ctypes.byref(out_old),
        ctypes.byref(out_rc),
        ctypes.byref(buf),
    )

    assert (out_old.value & 0xFFFFFFFF) == expected_old, (
        f"old: expected {expected_old:x}, got {out_old.value:x}"
    )
    assert buf.value == expected_new, (
        f"new: expected {expected_new:x}, got {buf.value:x}"
    )
    assert out_rc.value == 0, "sc should succeed (rc=0)"


def test_cross_asm_sub_operation():
    """测试 sub 操作"""
    frag_a = AsmFragment(
        rawAsmText="lr.w.aq %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="v", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="ptr")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="v - 5",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.w.rl %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="st", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="ptr"),
            AsmOperand(constraint="r", exprText="new_v"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)

    assert results[0] is not None
    assert results[0].kind == "pure_c"
    assert "__atomic_fetch_sub" in results[0].replacement
    assert "5" in results[0].replacement


# ========== 反例测试 ==========


def test_reject_complex_alu():
    """反例：复杂 ALU 表达式不应融合"""
    frag_a = AsmFragment(
        rawAsmText="lr.w %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="p")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="(old + 1) * 2",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.w %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="p"),
            AsmOperand(constraint="r", exprText="new"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)

    assert results[0] is not None
    assert results[1] is not None


def test_reject_mismatched_address():
    """反例：地址不匹配不应融合"""
    frag_a = AsmFragment(
        rawAsmText="lr.w %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="p1")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="old | 1",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.w %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="p2"),
            AsmOperand(constraint="r", exprText="new"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)

    assert results[0] is not None
    assert results[1] is not None


def test_reject_no_successor_link():
    """反例：没有显式后继关系不应融合"""
    frag_a = AsmFragment(
        rawAsmText="lr.w %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="p")],
        fragmentId="A",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="old | 1",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.w %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="p"),
            AsmOperand(constraint="r", exprText="new"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)

    assert results[0] is not None
    assert results[1] is not None


def test_reject_width_mismatch():
    """反例：lr.w 与 sc.d 宽度不匹配"""
    frag_a = AsmFragment(
        rawAsmText="lr.w %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="p")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="old + 1",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.d %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="p"),
            AsmOperand(constraint="r", exprText="new"),
        ],
        fragmentId="B",
    )

    results = translate_function([frag_a, frag_b], xlen=64)

    assert results[0] is not None
    assert results[1] is not None


def _machine_code_bytes(asm_result):
    """
    兼容 assemble() 返回 bytes 或 hex string 两种形式。
    """
    mc = getattr(asm_result, "machine_code", None)
    assert mc is not None, "assemble() result has no machine_code"

    if isinstance(mc, bytes):
        return mc
    if isinstance(mc, bytearray):
        return bytes(mc)
    if isinstance(mc, str):
        return bytes.fromhex(mc)

    raise TypeError(f"unsupported machine_code type: {type(mc)}")


def test_cross_asm_diff_e2e():
    """
    E2E：
    1) Unicorn 跑 frag_a + frag_b 的机器码串
    2) C 侧跑融合后的译文
    3) 比较最终内存状态与译文输出
    """
    frag_a = AsmFragment(
        rawAsmText="lr.w.aq %0, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="p")],
        fragmentId="A",
        successorFragmentId="B",
        outputBindings=[
            OutputBinding(
                outputIndex=0,
                sinkKind="next_asm_input",
                sinkOpIndex=1,
                aluExpr="old | 0x4",
            )
        ],
    )

    frag_b = AsmFragment(
        rawAsmText="sc.w.rl %0, %2, (%1)",
        outputs=[AsmOperand(constraint="=r", exprText="rc", isOutput=True)],
        inputs=[
            AsmOperand(constraint="r", exprText="p"),
            AsmOperand(constraint="r", exprText="new"),
        ],
        fragmentId="B",
    )

    # ========= 1. 先验证翻译结果 =========
    outs = translate_function([frag_a, frag_b], xlen=64)

    assert len(outs) == 2
    assert outs[0] is not None
    assert outs[0].kind == "pure_c"
    assert "__atomic_fetch_or" in outs[0].replacement
    assert outs[1] is None

    # ========= 2. 组装 RISC-V 机器码 =========
    asm_a = assemble(frag_a)
    asm_b = assemble(frag_b)

    assert asm_a.ok, f"assemble frag_a failed: {getattr(asm_a, 'error', '')}"
    assert asm_b.ok, f"assemble frag_b failed: {getattr(asm_b, 'error', '')}"

    assert asm_a.rendered_asm == "lr.w.aq x10, (x11)"
    assert asm_b.rendered_asm == "sc.w.rl x10, x12, (x11)"

    code = _machine_code_bytes(asm_a) + _machine_code_bytes(asm_b)

    # ========= 3. Unicorn 运行 =========
    init = 0x10
    expected_new = init | 0x4
    DATA = 0x30000

    # lr.w/sc.w 只关心低 4 字节，这里放 8 字节便于观察
    mem_init = init.to_bytes(4, "little") + b"\x00\x00\x00\x00"

    rv = run_rv64(
        code,
        {
            "x10": 0,
            "x11": DATA,
            "x12": expected_new,
            "x13": 0,
        },
        ["x10", "x11", "x12"],
        mem_inputs={DATA: mem_init},
        mem_outputs={DATA: 8},
    )

    assert rv.error is None, (
        f"unicorn execution failed: {rv.error}\n"
        f"regs_out={rv.regs_out}\n"
        f"mem_out={rv.mem_out}\n"
        f"fault_pc={rv.fault_pc}\n"
        f"fault_addr={rv.fault_addr}\n"
        f"fault_size={rv.fault_size}\n"
        f"fault_access={rv.fault_access}\n"
        f"trace={rv.trace}"
    )

    rc_unicorn = rv.regs_out["x10"]
    new_mem = int.from_bytes(rv.mem_out[DATA][:4], "little")

    assert rc_unicorn == 0, (
        f"Unicorn sc.w failed (rc={rc_unicorn}); "
        f"likely reservation model missing in run_rv64"
    )
    assert new_mem == expected_new, (
        f"unicorn mem: expected {expected_new:#x}, got {new_mem:#x}"
    )

    # ========= 4. 编译并运行译文 =========
    lib = _compile_c_multi(outs[0].replacement, ["p"], ["old", "rc"])
    assert lib is not None

    buf = ctypes.c_uint32(init)
    old = ctypes.c_long()
    rc = ctypes.c_long()

    p_addr = ctypes.addressof(buf)

    lib.f(
        ctypes.byref(old),
        ctypes.byref(rc),
        p_addr,
    )

    assert (old.value & 0xFFFFFFFF) == init, (
        f"translated old: expected {init:#x}, got {old.value & 0xFFFFFFFF:#x}"
    )
    assert buf.value == expected_new, (
        f"translated mem: expected {expected_new:#x}, got {buf.value:#x}"
    )
    assert rc.value == 0, f"translated rc: expected 0, got {rc.value}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])