import ctypes
import os
import subprocess
import tempfile
import pytest

from riscv2x86_py.schema import AsmFragment, AsmOperand, AsmSymbolRef
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate

CLANG = os.environ.get("R2X_CC", "clang")


def _compile_raw(src: str) -> ctypes.CDLL:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        cpath = f.name
    sopath = cpath + ".so"
    try:
        subprocess.run(
            [CLANG, "-O0", "-fPIC", "-shared", cpath, "-o", sopath],
            check=True,
            capture_output=True,
            text=True,
        )
        return ctypes.CDLL(sopath)
    finally:
        try:
            os.unlink(cpath)
        except OSError:
            pass


def test_pic_pcrel_pair_basic():
    """
    auipc %0, %pcrel_hi(g_pic_sym)
    addi  %0, %0, %pcrel_lo(1b)
    => p = ((uint64_t)(uintptr_t)&(g_pic_sym));
    """
    frag = AsmFragment(
        rawAsmText=(
            "1: auipc %0, %pcrel_hi(g_pic_sym)\n"
            "   addi  %0, %0, %pcrel_lo(1b)\n"
        ),
        outputs=[AsmOperand(constraint="=r", exprText="p", isOutput=True)],
        inputs=[],
        symbols=[AsmSymbolRef(asmName="g_pic_sym", cName="g_pic_sym")],
    )

    a = assemble(frag)
    assert a.ok, a.error
    assert hasattr(a, "relocations"), "assemble result missing relocations field"
    assert len(a.relocations) >= 2, f"expected >=2 relocs, got {a.relocations}"

    l = lift(a.machine_code, relocations=a.relocations)
    assert l.ok
    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)

    assert tr.kind == "pure_c", getattr(tr, "notes", None)
    assert "&(g_pic_sym)" in tr.replacement
    assert "p =" in tr.replacement


def test_pic_native_dereference():
    """
    译文挂上真的全局变量，确认指针指向预期地址。
    """
    frag = AsmFragment(
        rawAsmText=(
            "1: auipc %0, %pcrel_hi(g_pic_sym)\n"
            "   addi  %0, %0, %pcrel_lo(1b)\n"
        ),
        outputs=[AsmOperand(constraint="=r", exprText="p", isOutput=True)],
        inputs=[],
        symbols=[AsmSymbolRef(asmName="g_pic_sym", cName="g_pic_sym")],
    )

    a = assemble(frag)
    assert a.ok, a.error
    assert hasattr(a, "relocations"), "assemble result missing relocations field"

    l = lift(a.machine_code, relocations=a.relocations)
    assert l.ok
    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)
    assert tr.kind == "pure_c", getattr(tr, "notes", None)

    src = (
        "#include <stdint.h>\n"
        "long g_pic_sym = 0x123;\n"
        "void f(long *out_p) {\n"
        "  long p = 0;\n"
        f"  {tr.replacement}\n"
        "  *out_p = p;\n"
        "}\n"
    )
    lib = _compile_raw(src)
    lib.f.restype = None
    lib.f.argtypes = [ctypes.POINTER(ctypes.c_long)]

    p_out = ctypes.c_long(0)
    lib.f(ctypes.byref(p_out))

    deref = ctypes.cast(p_out.value, ctypes.POINTER(ctypes.c_long))[0]
    assert deref == 0x123


def test_pic_missing_cname_raises():
    """
    schema.symbols 中没有 cName -> translator 应明确报错。
    """
    frag = AsmFragment(
        rawAsmText=(
            "1: auipc %0, %pcrel_hi(g_pic_sym)\n"
            "   addi  %0, %0, %pcrel_lo(1b)\n"
        ),
        outputs=[AsmOperand(constraint="=r", exprText="p", isOutput=True)],
        inputs=[],
        symbols=[AsmSymbolRef(asmName="g_pic_sym", cName="")],
    )

    a = assemble(frag)
    assert a.ok, a.error
    assert hasattr(a, "relocations"), "assemble result missing relocations field"

    l = lift(a.machine_code, relocations=a.relocations)
    assert l.ok
    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)

    assert tr.kind == "unsupported"
    joined = " ".join(getattr(tr, "notes", []))
    assert "PIC" in joined and "cName" in joined


def test_pic_mismatched_dest_regs_rejected():
    """
    auipc 与 addi 目的寄存器不同 -> 不识别。
    """
    frag = AsmFragment(
        rawAsmText=(
            "1: auipc %0, %pcrel_hi(g_pic_sym)\n"
            "   addi  %1, %0, %pcrel_lo(1b)\n"
        ),
        outputs=[
            AsmOperand(constraint="=r", exprText="p0", isOutput=True),
            AsmOperand(constraint="=r", exprText="p1", isOutput=True),
        ],
        inputs=[],
        symbols=[AsmSymbolRef(asmName="g_pic_sym", cName="g_pic_sym")],
    )

    a = assemble(frag)
    if not a.ok:
        pytest.skip(f"assemble rejected; reason: {a.error}")

    assert hasattr(a, "relocations"), "assemble result missing relocations field"

    l = lift(a.machine_code, relocations=a.relocations)
    assert l.ok
    _, s = from_lifted(l.insns)
    tr = translate(frag, l, s, machine_code=a.machine_code, xlen=64)

    assert "&(g_pic_sym)" not in getattr(tr, "replacement", "")