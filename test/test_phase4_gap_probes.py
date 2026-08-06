import os
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import importlib
import importlib.util
import pathlib
import sys

import pytest

from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.lift import LiftResult, LiftedInsn
from riscv2x86_py.translate import translate
from riscv2x86_py.assemble import _PLACEHOLDER_REGS_INT as PHR


def _tool_supports_riscv(exe: str) -> bool:
    if not exe or not os.path.exists(exe):
        return False
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True)
    except OSError:
        return False
    txt = (p.stdout or "") + "\n" + (p.stderr or "")
    return "riscv" in txt.lower()


def _pick_llvm_mc() -> str | None:
    candidates = [
        os.environ.get("R2X_LLVM_MC"),
        shutil.which("llvm-mc-10"),
        shutil.which("llvm-mc"),
        shutil.which("llvm-mc-11"),
        shutil.which("llvm-mc-12"),
        shutil.which("llvm-mc-13"),
        shutil.which("llvm-mc-14"),
    ]
    seen = set()
    for c in candidates:
        if not c or c in seen:
            continue
        seen.add(c)
        if _tool_supports_riscv(c):
            return c
    return None


def _pick_readelf() -> str | None:
    return (
        os.environ.get("R2X_READELF")
        or shutil.which("readelf")
        or shutil.which("llvm-readelf-10")
        or shutil.which("llvm-readelf")
    )


def _load_helpers_module():
    errs = []

    helper_path = pathlib.Path(
        os.environ.get(
            "R2X_HELPERS_PY",
            "/root/src/poc_trans/path_b/riscv2x86/pytools/tests/helpers.py",
        )
    ).resolve()

    # 补齐运行 helpers.py 需要的两个根路径
    # project_root = .../riscv2x86
    # pytools_root = .../riscv2x86/pytools
    project_root = str(helper_path.parents[2])
    pytools_root = str(helper_path.parents[1])

    for p in (project_root, pytools_root):
        if p not in sys.path:
            sys.path.insert(0, p)

    for name in (
        "pytools.tests.helpers",
        "tests.helpers",
        "helpers",
    ):
        try:
            return importlib.import_module(name)
        except Exception as e:
            errs.append(f"{name}: {e}")

    if helper_path.exists():
        try:
            spec = importlib.util.spec_from_file_location(
                "phase4_helpers_probe_mod", str(helper_path)
            )
            mod = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(mod)
            return mod
        except Exception as e:
            errs.append(f"exec {helper_path}: {e}")

    raise ImportError(" ; ".join(errs))

def _summary():
    return SimpleNamespace(
        is_single_block=True,
        has_atomic=False,
        has_memory_barrier=False,
        has_branch=False,
        has_call_or_return=False,
        writes_mem=False,
    )


def _pic_frag():
    return AsmFragment(
        rawAsmText="auipc %0, %pcrel_hi(sym)\naddi %0, %0, %pcrel_lo(sym)",
        outputs=[AsmOperand(constraint="=r", exprText="out", isOutput=True)],
        inputs=[],
        clobbers=[],
        isVolatile=False,
        symbols=[SimpleNamespace(asmName="sym", cName="sym")],
    )


def _pic_lift(with_relocs: bool) -> LiftResult:
    rd = PHR[0]
    hi_ref = (0, "PCREL_HI20") if with_relocs else None
    lo_ref = (0, "PCREL_LO12_I") if with_relocs else None
    insns = [
        LiftedInsn(
            addr=0x10000,
            length=4,
            asm_mnem="auipc",
            asm_body=f"{rd}, %pcrel_hi(sym)",
            pcode_ops=[],
            raw_ops=[],
            sym_ref=hi_ref,
        ),
        LiftedInsn(
            addr=0x10004,
            length=4,
            asm_mnem="addi",
            asm_body=f"{rd}, {rd}, %pcrel_lo(.Lpcrel_hi0)",
            pcode_ops=[],
            raw_ops=[],
            sym_ref=lo_ref,
        ),
    ]
    return LiftResult(True, insns)


def test_probe_pic_translation_becomes_unsupported_if_relocations_are_not_forwarded():
    frag = _pic_frag()
    lift_no_reloc = _pic_lift(with_relocs=False)

    tr = translate(frag, lift_no_reloc, _summary(), machine_code=b"", xlen=64)

    assert tr.kind == "unsupported"
    assert any("PIC syntax detected" in n for n in tr.notes)


def test_probe_pic_translation_recovers_once_relocations_reach_lift():
    frag = _pic_frag()
    lift_with_reloc = _pic_lift(with_relocs=True)

    tr = translate(frag, lift_with_reloc, _summary(), machine_code=b"", xlen=64)

    assert tr.kind == "pure_c"
    assert "&(sym)" in tr.replacement
    assert "uint64_t" in tr.replacement


def test_probe_translate_output_changes_with_xlen_for_same_pic_pair():
    frag = _pic_frag()
    lift_with_reloc = _pic_lift(with_relocs=True)

    tr32 = translate(frag, lift_with_reloc, _summary(), machine_code=b"", xlen=32)
    tr64 = translate(frag, lift_with_reloc, _summary(), machine_code=b"", xlen=64)

    assert tr32.kind == "pure_c"
    assert tr64.kind == "pure_c"
    assert "uint32_t" in tr32.replacement
    assert "uint64_t" in tr64.replacement
    assert tr32.replacement != tr64.replacement


def test_probe_helper_pipeline_currently_drops_relocations_and_hardcodes_xlen64(monkeypatch):
    try:
        helpers = _load_helpers_module()
    except ImportError as e:
        pytest.skip(f"could not import helpers module: {e}")

    calls = {}

    class DummyAssembleResult:
        ok = True
        machine_code = b"\x13\x05\x00\x00\x13\x05\x05\x00"
        relocations = [object()]
        error = ""

    class DummyLiftResult:
        ok = True
        insns = []
        error = ""

    class DummyTranslation:
        kind = "pure_c"
        replacement = "out = 0"
        notes = []

    class DummyRunRv64Result:
        error = None
        regs_out = {}

    def fake_assemble(frag):
        calls["assemble_called"] = True
        return DummyAssembleResult()

    def fake_lift(machine_code, *args, **kwargs):
        calls["lift_args"] = args
        calls["lift_kwargs"] = kwargs
        return DummyLiftResult()

    def fake_from_lifted(insns):
        calls["from_lifted_called"] = True
        return None, object()

    def fake_translate(frag, l, s, machine_code=None, xlen=None):
        calls["translate_machine_code"] = machine_code
        calls["translate_xlen"] = xlen
        return DummyTranslation()

    def fake_compile_c_multi(c_body, in_args, out_args):
        class DummyLib:
            pass

        def _f(*args):
            return None

        lib = DummyLib()
        lib.f = _f
        lib.f.restype = None
        lib.f.argtypes = []
        return lib

    def fake_run_rv64(machine_code, reg_inputs=None, reg_outputs=None):
        rr = DummyRunRv64Result()
        rr.regs_out = {reg_outputs[0]: 0}
        return rr

    monkeypatch.setattr(helpers, "assemble", fake_assemble)
    monkeypatch.setattr(helpers, "lift", fake_lift)
    monkeypatch.setattr(helpers, "from_lifted", fake_from_lifted)
    monkeypatch.setattr(helpers, "translate", fake_translate)
    monkeypatch.setattr(helpers, "_compile_c_multi", fake_compile_c_multi)
    monkeypatch.setattr(helpers, "run_rv64", fake_run_rv64)

    helpers.build_and_diff(
        asm="addi a0, a0, 0",
        outs=["out"],
        ins=["inp"],
        cases=[(123,)],
        out_index=0,
    )

    assert calls["assemble_called"] is True
    assert calls["from_lifted_called"] is True

    assert calls["lift_kwargs"].get("relocations") == DummyAssembleResult.relocations
    assert calls["lift_kwargs"].get("xlen") == 64

    assert calls["translate_machine_code"] == DummyAssembleResult.machine_code
    assert calls["translate_xlen"] == 64


@pytest.mark.skipif(
    not shutil.which("llvm-mc") or not shutil.which("llvm-objdump"),
    reason="needs llvm-mc and llvm-objdump",
)
def test_probe_actual_pic_la_lowering_shape_against_current_translator_coverage():
    llvm_mc = _pick_llvm_mc()
    if not llvm_mc:
        pytest.skip("no RISC-V capable llvm-mc found; set R2X_LLVM_MC=/usr/bin/llvm-mc-10")

    readelf = _pick_readelf()
    if not readelf:
        pytest.skip("no readelf found")

    src = """\
.text
.globl _start
_start:
  la a0, sym
"""

    with tempfile.TemporaryDirectory(prefix="phase4_la_probe_") as td:
        spath = os.path.join(td, "t.s")
        opath = os.path.join(td, "t.o")

        with open(spath, "w", encoding="utf-8") as f:
            f.write(src)

        proc_show = subprocess.run(
            [
                llvm_mc,
                "--triple=riscv64-unknown-elf",
                "--assemble",
                "--position-independent",
                "--show-encoding",
                spath,
            ],
            capture_output=True,
            text=True,
        )
        assert proc_show.returncode == 0, proc_show.stderr

        show_txt = (proc_show.stdout or "").lower()
        assert "auipc" in show_txt, show_txt
        assert "%got_pcrel_hi(sym)" in show_txt, show_txt
        assert re.search(r"\b(ld|lw)\b", show_txt), show_txt

        proc_obj = subprocess.run(
            [
                llvm_mc,
                "--triple=riscv64-unknown-elf",
                "--assemble",
                "--position-independent",
                "--filetype=obj",
                spath,
                "-o",
                opath,
            ],
            capture_output=True,
            text=True,
        )
        assert proc_obj.returncode == 0, proc_obj.stderr

        proc_rel = subprocess.run(
            [readelf, "-rW", opath],
            capture_output=True,
            text=True,
        )
        assert proc_rel.returncode == 0, proc_rel.stderr

        rel_txt = proc_rel.stdout or ""
        assert "R_RISCV_GOT_HI20" in rel_txt, rel_txt
        assert "R_RISCV_PCREL_LO12_I" in rel_txt, rel_txt