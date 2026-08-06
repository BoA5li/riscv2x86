import ctypes
import os
import subprocess
import tempfile
from typing import List, Sequence

from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble, _PLACEHOLDER_REGS_INT as PHR
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate
from tests.e2e.unicorn_runner import run_rv64

CLANG = os.environ.get("R2X_CC", "clang")


def _compile_c_multi(c_body: str, in_args: list[str], out_args: list[str]):
    """
    生成函数：
      void f(long* out0, long* out1, ..., long in0, long in1, ...) {
          long <out>;
          long <in>;
          { c_body; }
          *out0 = <out0>; ...
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
        + init_in + "\n"
        + f"    {{ {c_body}; }}\n"
        + writebacks + "\n"
        + "}\n"
    )

    d = tempfile.mkdtemp(prefix="r2x_e2e_")
    cpath = os.path.join(d, "f.c")
    spath = os.path.join(d, "f.so")
    with open(cpath, "w") as f:
        f.write(src)

    r = subprocess.run(
        [CLANG, "-O0", "-fPIC", "-shared", "-o", spath, cpath],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"clang failed:\n{r.stderr}\n--- src ---\n{src}")

    lib = ctypes.CDLL(spath)
    return lib


def _frag_to_reg_inputs(outs: Sequence[str], values: Sequence[int]) -> dict[str, int]:
    """
    按 placeholder 寄存器约定铺输入：
      outputs 在前先置 0
      inputs 紧随其后
    """
    regs = {}
    for i in range(len(outs)):
        regs[PHR[i]] = 0
    for j, v in enumerate(values):
        regs[PHR[len(outs) + j]] = v & ((1 << 64) - 1)
    return regs


def build_and_diff(asm, outs, ins, cases, out_index):
    frag = AsmFragment(
        rawAsmText=asm,
        outputs=[
            AsmOperand(constraint="=r", exprText=o, isOutput=True)
            for o in outs
        ],
        inputs=[
            AsmOperand(constraint="r", exprText=i)
            for i in ins
        ],
    )

    a = assemble(frag)
    assert a.ok, a.error

    l = lift(a.machine_code, xlen=64, relocations=a.relocations)
    assert l.ok, l.error if hasattr(l, "error") else "lift failed"

    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)
    assert tr.kind == "pure_c", getattr(tr, "notes", None)

    lib = _compile_c_multi(tr.replacement, ins, outs)
    lib.f.restype = None
    lib.f.argtypes = [ctypes.POINTER(ctypes.c_long)] * len(outs) + [ctypes.c_long] * len(ins)

    out_reg = PHR[out_index]

    for values in cases:
        regs = _frag_to_reg_inputs(outs, values)

        rv = run_rv64(
            a.machine_code,
            reg_inputs=regs,
            reg_outputs=[out_reg],
        )
        assert rv.error is None, rv.error
        ref = rv.regs_out[out_reg] & ((1 << 64) - 1)

        out_buf = [ctypes.c_long(0) for _ in outs]
        lib.f(
            *[ctypes.byref(b) for b in out_buf],
            *[ctypes.c_long(v).value for v in values],
        )
        got = out_buf[out_index].value & ((1 << 64) - 1)

        assert got == ref, f"{values}: ref=0x{ref:x} got=0x{got:x}"

def run_pipeline_report(tmp_path, findings, *, xlen=64):
    """
    将 Finding 列表写入临时 report，执行真实 pipeline.run()，
    再读取输出 report。

    返回：
        (stats, output_findings)

    使用示例：
        stats, out = run_pipeline_report(tmp_path, [finding])
        result = out[0]
        assert result.verificationStatus == "failed"
    """
    from riscv2x86_py.pipeline import run
    from riscv2x86_py.schema import load_report, save_report

    in_json = tmp_path / "pipeline-input.json"
    out_json = tmp_path / "pipeline-output.json"

    save_report(findings, str(in_json))
    stats = run(str(in_json), str(out_json), xlen=xlen)
    output_findings = load_report(str(out_json))

    return stats, output_findings


def run_single_pipeline_finding(tmp_path, finding, *, xlen=64):
    """
    run_pipeline_report() 的单 Finding 便利包装。
    """
    stats, findings = run_pipeline_report(tmp_path, [finding], xlen=xlen)
    assert len(findings) == 1
    return stats, findings[0]