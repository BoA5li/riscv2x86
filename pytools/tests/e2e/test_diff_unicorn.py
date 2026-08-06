"""
对每条样例：
  1. assemble() 得到 machine_code
  2. translate() 得到 C 替换体
  3. 选一组输入：
       - Unicorn 跑机器码 -> 参考输出
       - 把 C 替换体编译成进程内 .so，ctypes 调用 -> 实测输出
  4. 断言两边一致
"""
import ctypes, os, subprocess, tempfile
from typing import Dict, List
import pytest

from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble, _PLACEHOLDER_REGS_INT as PHR
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate
from tests.e2e.unicorn_runner import run_rv64

CLANG = os.environ.get("R2X_CC", "clang")

def _compile_c(c_body: str, args: List[str], ret="long") -> ctypes.CDLL:
    """
    把 c_body 包成函数：
      long f(long arg0, long arg1, ...) { long out; { c_body; } return out; }
    然后编成 .so 加载。
    """
    arglist = ", ".join(f"long {a}" for a in args)
    src = (
        "#include <stdint.h>\n"
        "#include <stdatomic.h>\n"
        f"{ret} f({arglist}) {{\n"
        f"    long out = 0; (void)out;\n"
        f"    {c_body};\n"
        f"    return ({ret})out;\n"
        f"}}\n"
    )
    d = tempfile.mkdtemp(prefix="r2x_e2e_")
    cpath = os.path.join(d, "f.c"); spath = os.path.join(d, "f.so")
    with open(cpath, "w") as f: f.write(src)
    r = subprocess.run(
        [CLANG, "-O0", "-fPIC", "-shared", "-o", spath, cpath],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"clang failed:\n{r.stderr}\n--- src ---\n{src}")
    lib = ctypes.CDLL(spath)
    lib.f.restype = ctypes.c_long
    lib.f.argtypes = [ctypes.c_long] * len(args)
    return lib

def _compile_c_multi(c_body: str, in_args: list[str], out_args: list[str]) -> ctypes.CDLL:
    """
    生成函数：
      void f(long* out0, long* out1, ..., long in0, long in1, ...) {
          long <out>;   // for each output, exprText 名字
          long <in>;    // 同上，并初始化为参数值
          { c_body; }
          *out0 = <出参 1>; ...
      }
    """
    decls = []
    for n in out_args:
        decls.append(f"    long {n} = 0;")

    sig_in = ", ".join(f"long _in_{n}" for n in in_args)
    init_in = "\n".join(f"    long {n} = _in_{n};" for n in in_args)

    sig_out = ", ".join(f"long *_out_{n}" for n in out_args)
    writebacks = "\n".join(f"    *_out_{n} = {n};" for n in out_args)

    sig = ", ".join(filter(None, [sig_out, sig_in]))

    src = (
        "#include <stdint.h>\n"
        "#include <stdatomic.h>\n"
        f"void f({sig}) {{\n"
        + "\n".join(decls) + "\n"
        + (init_in + "\n" if init_in else "")
        + f"    {{ {c_body}; }}\n"
        + (writebacks + "\n" if writebacks else "")
        + "}\n"
    )

    d = tempfile.mkdtemp(prefix="r2x_e2e_")
    cpath = os.path.join(d, "f.c")
    spath = os.path.join(d, "f.so")

    with open(cpath, "w", encoding="utf-8") as f:
        f.write(src)

    r = subprocess.run(
        [CLANG, "-O0", "-fPIC", "-shared", "-o", spath, cpath],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"clang failed:\n{r.stderr}\n--- src ---\n{src}")

    lib = ctypes.CDLL(spath)

    # 关键修复：显式绑定 ABI，避免 ctypes 默认把 Python int 当 c_int 传入
    lib.f.restype = None
    lib.f.argtypes = [ctypes.POINTER(ctypes.c_long)] * len(out_args) + [ctypes.c_long] * len(in_args)

    return lib

def _frag_to_reg_inputs(frag: AsmFragment, vals: List[int]) -> Dict[str,int]:
    """outputs 在前、inputs 在后，按占位寄存器顺序铺。"""
    n_out = len(frag.outputs)
    regs = {}
    # 输出寄存器先给 0（CAS/AMO 类有 "+r" 输入语义时再覆盖）
    for i in range(n_out):
        regs[PHR[i]] = 0
    for j, v in enumerate(vals):
        regs[PHR[n_out + j]] = v & ((1<<64)-1)
    return regs

def _output_reg_names(frag: AsmFragment) -> List[str]:
    return [PHR[i] for i in range(len(frag.outputs))]

# ---------- 用例 ----------

CASES = [
    # (name, asm, out_exprs, in_exprs, c_args, value_sets)
    ("add",
     "add %0, %1, %2",
     ["out"], ["a", "b"],
     ["a", "b"],
     [(1, 2), (0xffff_ffff, 1), (-1 & ((1<<64)-1), 1)]),
    ("addw_sx",
     "addw %0, %1, %2",
     ["out"], ["a", "b"],
     ["a", "b"],
     [(0x7fff_ffff, 1), (0x8000_0000, 0xffff_ffff), (1, 2)]),
    ("sllw_mask",
     "sllw %0, %1, %2",
     ["out"], ["x", "n"],
     ["x", "n"],
     [(1, 1), (1, 33), (0x8000_0000, 1)]),
    ("andi_imm",
     "andi %0, %1, 0xff",
     ["out"], ["a"],
     ["a"],
     [(0x1234_5678, ), (0xff, ), (0,)]),
    ("srai_imm",
     "srai %0, %1, 4",
     ["out"], ["a"],
     ["a"],
     [(0x8000_0000_0000_0000 & ((1<<64)-1),), (16,), (-1 & ((1<<64)-1),)]),
]

@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_unicorn_diff(case):
    name, asm, outs, ins, c_args, value_sets = case
    frag = AsmFragment(
        rawAsmText=asm,
        outputs=[AsmOperand(constraint="=r", exprText=o, isOutput=True) for o in outs],
        inputs=[AsmOperand(constraint="r", exprText=i) for i in ins])
    a = assemble(frag); assert a.ok, a.error
    l = lift(a.machine_code); assert l.ok
    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)
    assert tr.kind == "pure_c", f"{name}: unsupported"

    lib = _compile_c(tr.replacement, c_args)
    out_regs = _output_reg_names(frag)

    for values in value_sets:
        # 1) Unicorn 参考
        regs_in = _frag_to_reg_inputs(frag, list(values))
        rv = run_rv64(a.machine_code, regs_in, out_regs)
        assert rv.error is None, f"{name}: {rv.error}"
        # outputs[0] 在 x10 (PHR[0]) 上
        ref = rv.regs_out[out_regs[0]]
        ref_signed = ref if ref < (1<<63) else ref - (1<<64)

        # 2) C 译文
        got = lib.f(*[ctypes.c_long(v).value for v in values])

        assert got == ref_signed, (
            f"{name}{values}: ref=0x{ref:016x}({ref_signed}) "
            f"got=0x{got & ((1<<64)-1):016x}({got})")