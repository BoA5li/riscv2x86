
import os
import re
import importlib
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import List, Optional

import pytest


# ---------------------------------------------------------------------------
# Flexible import helpers
# ---------------------------------------------------------------------------

def _import_first(candidates):
    last = None
    for name in candidates:
        try:
            return importlib.import_module(name)
        except Exception as e:  # pragma: no cover - best effort import scan
            last = e
    raise AssertionError(f"cannot import any of {candidates!r}; last error={last!r}")


def _load_structurize_module():
    env = os.getenv("R2X_STRUCTURIZE_MODULE")
    candidates = [env] if env else []
    # 新增真实路径 riscv2x86_py.patterns.structurize，删除错误 riscv_to_x86
    candidates += [
        "structurize",
        "patterns.structurize",
        "riscv2x86_py.patterns.structurize",
    ]
    return _import_first([x for x in candidates if x])


def _load_translate_module():
    env = os.getenv("R2X_TRANSLATE_MODULE")
    candidates = [env] if env else []
    candidates += [
        "translate_2",
        "translate",
        "riscv2x86_py.translate",
    ]
    return _import_first([x for x in candidates if x])


def _load_intblock_module():
    env = os.getenv("R2X_INTBLOCK_MODULE")
    candidates = [env] if env else []
    candidates += [
        "intblock",
        "patterns.intblock",
        "riscv2x86_py.patterns.intblock",
    ]
    return _import_first([x for x in candidates if x])


# ---------------------------------------------------------------------------
# Minimal duck-typed fixtures for translate/structurize contract tests
# ---------------------------------------------------------------------------

@dataclass
class FakeOperand:
    exprText: str
    constraint: str = ""
    symbolicName: str = ""


@dataclass
class FakeSymbol:
    cName: str
    asmName: str = ""


@dataclass
class FakeInsn:
    addr: int
    asm_mnem: str
    asm_body: str = ""
    sym_ref: Optional[tuple] = None


@dataclass
class FakeFrag:
    outputs: List[FakeOperand] = field(default_factory=list)
    inputs: List[FakeOperand] = field(default_factory=list)
    clobbers: List[str] = field(default_factory=list)
    symbols: List[FakeSymbol] = field(default_factory=list)
    isVolatile: bool = False


@dataclass
class FakeLift:
    insns: List[FakeInsn] = field(default_factory=list)


@dataclass
class FakeSummary:
    is_single_block: bool = True
    has_atomic: bool = False
    has_memory_barrier: bool = False
    has_branch: bool = False
    has_call_or_return: bool = False
    writes_mem: bool = False


@dataclass
class FakeIBResult:
    body: str
    notes: List[str]


def _translation_output_fields(out):
    return getattr(out, "kind"), getattr(out, "replacement"), list(getattr(out, "notes"))


def _contains_any(text: str, patterns):
    return any(re.search(p, text, re.I | re.S) for p in patterns)


# ---------------------------------------------------------------------------
# Patch 4: structurize.py contract tests
# ---------------------------------------------------------------------------

def test_structurize_single_forward_if():
    smod = _load_structurize_module()
    Line = smod.Line
    lines = [
        Line("br", is_branch=True, cond="x > 0", target_pos=30),
        Line("y = 1;"),
        Line("z = 2;"),
    ]
    ins_pos = [10, 20, 30]
    out = smod.structurize(lines, ins_pos, {}, 100)
    assert out is not None
    assert out == [
        "if (!(x > 0)) {",
        "  y = 1;",
        "}",
        "z = 2;",
    ]


def test_structurize_if_else():
    smod = _load_structurize_module()
    Line = smod.Line
    lines = [
        Line("br", is_branch=True, cond="cond", target_pos=40),  # if (cond) goto else
        Line("then_stmt();"),
        Line("jmp", is_jump=True, target_pos=60),                # skip else
        Line("else_stmt();"),
        Line("tail();"),
    ]
    ins_pos = [10, 20, 30, 40, 60]
    out = smod.structurize(lines, ins_pos, {}, 100)
    assert out is not None
    assert out == [
        "if (!(cond)) {",
        "  then_stmt();",
        "} else {",
        "  else_stmt();",
        "}",
        "tail();",
    ]


def test_structurize_tail_jump_to_region_end_is_ignored():
    smod = _load_structurize_module()
    Line = smod.Line
    lines = [
        Line("a = 1;"),
        Line("jmp", is_jump=True, target_pos=50),
    ]
    ins_pos = [10, 20]
    out = smod.structurize(lines, ins_pos, {}, 50)
    assert out == ["a = 1;"]


def test_structurize_backward_branch_returns_none():
    smod = _load_structurize_module()
    Line = smod.Line
    lines = [
        Line("br", is_branch=True, cond="flag", target_pos=5),
        Line("x = 1;"),
    ]
    ins_pos = [10, 20]
    assert smod.structurize(lines, ins_pos, {}, 100) is None


def test_structurize_allows_empty_if_block():
    smod = _load_structurize_module()
    Line = smod.Line
    lines = [
        Line("br", is_branch=True, cond="c", target_pos=20),
        Line("after();"),
    ]
    ins_pos = [10, 20]
    out = smod.structurize(lines, ins_pos, {}, 100)
    assert out == [
        "if (!(c)) {",
        "}",
        "after();",
    ]


# ---------------------------------------------------------------------------
# Patch 5: translate_2.py policy / PIC bridging tests
# ---------------------------------------------------------------------------

def test_simple_pic_pair_fallback_addi():
    tmod = _load_translate_module()
    frag = FakeFrag(
        outputs=[FakeOperand("dst", "=r")],
        symbols=[FakeSymbol("global_sym", "global_sym")],
    )
    lift = FakeLift(
        [
            FakeInsn(0x1000, "auipc", "a0, %pcrel_hi(global_sym)", sym_ref=(0, "PCREL_HI20")),
            FakeInsn(0x1004, "addi", "a0, a0, %pcrel_lo(.L0)", sym_ref=(0, "PCREL_LO12_I")),
        ]
    )
    out = tmod._simple_pic_pair_fallback(frag, lift, xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "pure_c"
    assert "dst" in repl
    assert "&(global_sym)" in repl
    assert any("PIC fallback matched auipc+addi" in n for n in notes)


def test_simple_pic_pair_fallback_mv():
    tmod = _load_translate_module()
    frag = FakeFrag(
        outputs=[FakeOperand("dst", "=r")],
        symbols=[FakeSymbol("global_sym", "global_sym")],
    )
    lift = FakeLift(
        [
            FakeInsn(0x1000, "auipc", "a0, %pcrel_hi(global_sym)", sym_ref=(0, "PCREL_HI20")),
            FakeInsn(0x1004, "mv", "a0, a0", sym_ref=(0, "PCREL_LO12_I")),
        ]
    )
    out = tmod._simple_pic_pair_fallback(frag, lift, xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "pure_c"
    assert "&(global_sym)" in repl
    assert any("auipc+mv" in n for n in notes)


def test_simple_pic_pair_fallback_register_mismatch_is_unsupported():
    tmod = _load_translate_module()
    frag = FakeFrag(
        outputs=[FakeOperand("dst", "=r")],
        symbols=[FakeSymbol("global_sym", "global_sym")],
    )
    lift = FakeLift(
        [
            FakeInsn(0x1000, "auipc", "a0, %pcrel_hi(global_sym)", sym_ref=(0, "PCREL_HI20")),
            FakeInsn(0x1004, "addi", "a1, a0, %pcrel_lo(.L0)", sym_ref=(0, "PCREL_LO12_I")),
        ]
    )
    out = tmod._simple_pic_pair_fallback(frag, lift, xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "unsupported"
    assert repl == ""
    assert any("dest/source registers do not match" in n for n in notes)


def test_try_pic_non_pure_block_returns_none(monkeypatch):
    tmod = _load_translate_module()
    frag = FakeFrag(
        outputs=[FakeOperand("dst", "=r")],
        symbols=[FakeSymbol("sym0", "sym0")],
    )
    lift = FakeLift(
        [
            FakeInsn(0x1000, "auipc", "a0, %pcrel_hi(sym0)", sym_ref=(0, "PCREL_HI20")),
            FakeInsn(0x1004, "addi", "a0, a0, %pcrel_lo(.L0)", sym_ref=(0, "PCREL_LO12_I")),
            FakeInsn(0x1008, "lw", "a1, 0(a0)"),
        ]
    )
    summary = FakeSummary()
    monkeypatch.setattr(tmod, "fragment_uses_pic_syntax", lambda frag: True)
    monkeypatch.setattr(tmod, "has_any_pcrel_reloc", lambda insns: True)

    binding = SimpleNamespace(
        reg="a0",
        sym_index=0,
        c_expr="((uint64_t)(uintptr_t)&(sym0))",
        consumed_insn_addrs={0x1000, 0x1004},
    )
    monkeypatch.setattr(tmod, "detect_pic_pairs", lambda insns, frag, xlen=64: [binding])

    out = tmod._try_pic(frag, lift, summary, xlen=64)
    assert out is None, "PIC + extra integer ops should fall through to intblock path"


def test_pic_bindings_for_intblock_swallow_nonfatal_valueerror(monkeypatch):
    tmod = _load_translate_module()
    frag = FakeFrag()
    lift = FakeLift([FakeInsn(0x1000, "auipc", "a0, %pcrel_hi(sym0)")])

    monkeypatch.setattr(tmod, "has_any_pcrel_reloc", lambda insns: True)

    def boom(insns, frag, xlen=64):
        raise ValueError("invalid pcrel pair")
    monkeypatch.setattr(tmod, "detect_pic_pairs", boom)

    assert tmod._pic_bindings_for_intblock(frag, lift, xlen=64) == []


def test_translate_with_generic_intblock_enabled_returns_pure_c(monkeypatch):
    tmod = _load_translate_module()
    frag = FakeFrag(outputs=[FakeOperand("out0", "=r")], symbols=[FakeSymbol("sym0", "sym0")])
    lift = FakeLift([FakeInsn(0x1000, "add", "a0, a1, a2")])
    summary = FakeSummary()

    monkeypatch.setattr(tmod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(tmod, "_classify_preservation",
                        lambda *a, **k: SimpleNamespace(level="A", route="canonical_pure_c_or_semantic_x86", reasons=["A"]))
    monkeypatch.setattr(tmod, "_decision_notes", lambda d: ["preservation_level=A", "preservation_route=canonical_pure_c_or_semantic_x86"])
    monkeypatch.setattr(tmod, "_try_lrsc_cas", lambda *a, **k: None)
    monkeypatch.setattr(tmod, "_try_lrsc_rmw", lambda *a, **k: None)
    monkeypatch.setattr(tmod, "_CANONICAL_PURE_C_STRATEGIES", [])
    monkeypatch.setattr(tmod, "_pic_bindings_for_intblock", lambda *a, **k: [
        SimpleNamespace(reg="a0", sym_index=0, c_expr="((uint64_t)(uintptr_t)&(sym0))")
    ])
    monkeypatch.setattr(tmod, "_ALLOW_GENERIC_INTBLOCK_PURE_C", True)
    monkeypatch.setattr(
        tmod,
        "try_integer_block",
        lambda *a, **k: FakeIBResult("out0 = in1 + in2;", ["ib matched"])
    )

    out = tmod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "pure_c"
    assert repl == "out0 = in1 + in2;"
    assert any("ib matched" in n for n in notes)
    assert any("PIC binding injected into intblock:" in n for n in notes)


def test_translate_with_generic_intblock_disabled_routes_to_semantic_x86(monkeypatch):
    tmod = _load_translate_module()
    frag = FakeFrag(outputs=[FakeOperand("out0", "=r")], symbols=[FakeSymbol("sym0", "sym0")])
    lift = FakeLift([FakeInsn(0x1000, "add", "a0, a1, a2")])
    summary = FakeSummary()

    monkeypatch.setattr(tmod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(tmod, "_classify_preservation",
                        lambda *a, **k: SimpleNamespace(level="A", route="canonical_pure_c_or_semantic_x86", reasons=["A"]))
    monkeypatch.setattr(tmod, "_decision_notes", lambda d: ["preservation_level=A", "preservation_route=canonical_pure_c_or_semantic_x86"])
    monkeypatch.setattr(tmod, "_try_lrsc_cas", lambda *a, **k: None)
    monkeypatch.setattr(tmod, "_try_lrsc_rmw", lambda *a, **k: None)
    monkeypatch.setattr(tmod, "_CANONICAL_PURE_C_STRATEGIES", [])
    monkeypatch.setattr(tmod, "_pic_bindings_for_intblock", lambda *a, **k: [
        SimpleNamespace(reg="a0", sym_index=0, c_expr="((uint64_t)(uintptr_t)&(sym0))")
    ])
    monkeypatch.setattr(tmod, "_ALLOW_GENERIC_INTBLOCK_PURE_C", False)
    monkeypatch.setattr(
        tmod,
        "try_integer_block",
        lambda *a, **k: FakeIBResult("out0 = in1 + in2;", ["ib matched"])
    )

    out = tmod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "needs_semantic_x86_lowering"
    assert repl == ""
    assert any("generic integer-block pure_c lowering is disabled by policy" in n for n in notes)
    assert any("PIC binding available for later lowering:" in n for n in notes)


def test_translate_sp_ra_sensitive_fragment_does_not_enter_generic_intblock(monkeypatch):
    tmod = _load_translate_module()
    frag = FakeFrag(outputs=[FakeOperand("out0", "=r")])
    lift = FakeLift([FakeInsn(0x1000, "addi", "sp, sp, -16")])
    summary = FakeSummary()

    monkeypatch.setattr(tmod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(
        tmod,
        "_classify_preservation",
        lambda *a, **k: SimpleNamespace(level="B", route="needs_stack_aware_lowering", reasons=["touches sp/x2"])
    )

    called = {"ib": False}
    def fake_ib(*a, **k):
        called["ib"] = True
        return FakeIBResult("never used;", ["unexpected"])
    monkeypatch.setattr(tmod, "try_integer_block", fake_ib)

    out = tmod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "needs_stack_aware_lowering"
    assert repl == ""
    assert called["ib"] is False
    assert any("touches sp/x2" in n for n in notes)


def test_translate_call_ret_like_fragment_does_not_enter_level_a(monkeypatch):
    tmod = _load_translate_module()
    frag = FakeFrag(outputs=[FakeOperand("out0", "=r")])
    lift = FakeLift([FakeInsn(0x1000, "ret", "")])
    summary = FakeSummary(has_call_or_return=True)

    monkeypatch.setattr(tmod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(
        tmod,
        "_classify_preservation",
        lambda *a, **k: SimpleNamespace(level="C", route="needs_control_preserving_lowering", reasons=["call/ret-like control transfer detected"])
    )

    called = {"cas": False, "rmw": False, "ib": False}
    monkeypatch.setattr(tmod, "_try_lrsc_cas", lambda *a, **k: called.__setitem__("cas", True))
    monkeypatch.setattr(tmod, "_try_lrsc_rmw", lambda *a, **k: called.__setitem__("rmw", True))
    monkeypatch.setattr(tmod, "try_integer_block", lambda *a, **k: called.__setitem__("ib", True))

    out = tmod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "needs_control_preserving_lowering"
    assert repl == ""
    assert called == {"cas": False, "rmw": False, "ib": False}
    assert any("call/ret-like control transfer detected" in n for n in notes)


def test_translate_pic_true_error_becomes_unsupported(monkeypatch):
    tmod = _load_translate_module()
    frag = FakeFrag()
    lift = FakeLift()
    summary = FakeSummary()

    def boom(*a, **k):
        raise ValueError("invalid pcrel pair")
    monkeypatch.setattr(tmod, "_try_pic", boom)

    out = tmod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    kind, repl, notes = _translation_output_fields(out)
    assert kind == "unsupported"
    assert repl == ""
    assert any("PIC translation error: invalid pcrel pair" in n for n in notes)


# ---------------------------------------------------------------------------
# Patch 6: executable integration matrix for intblock
# ---------------------------------------------------------------------------

def _resolve_try_integer_block():
    imod = _load_intblock_module()
    tib = getattr(imod, "try_integer_block", None)
    if tib is None:
        pytest.skip("try_integer_block not found in resolved intblock module")
    return imod, tib


def _mk_asm_case(
    mnem,
    body,
    *,
    outputs=None,
    inputs=None,
    symbols=None,
    xlen=64,
    pic_bindings=None,
):
    frag = FakeFrag(
        outputs=outputs or [FakeOperand("out0", "=r")],
        inputs=inputs or [FakeOperand("in1", "r"), FakeOperand("in2", "r")],
        symbols=symbols or [],
    )
    lift = FakeLift([FakeInsn(0x1000, mnem, body)])
    return frag, lift, xlen, (pic_bindings or [])


def _run_intblock_case(case):
    _, try_integer_block = _resolve_try_integer_block()
    frag, lift, xlen, pic_bindings = case
    try:
        return try_integer_block(frag, lift, pic_bindings=pic_bindings, xlen=xlen)
    except TypeError:
        # older signature without pic_bindings
        return try_integer_block(frag, lift, xlen=xlen)


@pytest.mark.integration
@pytest.mark.parametrize(
    "mnem,body,expect_any",
    [
        ("add",  "a0, a1, a2",  [r"\+", r"out0"]),
        ("sub",  "a0, a1, a2",  [r"-", r"out0"]),
        ("and",  "a0, a1, a2",  [r"&", r"out0"]),
        ("or",   "a0, a1, a2",  [r"\|", r"out0"]),
        ("xor",  "a0, a1, a2",  [r"\^", r"out0"]),
        ("addi", "a0, a1, 7",   [r"\+", r"7"]),
        ("andi", "a0, a1, 7",   [r"&", r"7"]),
        ("mul",  "a0, a1, a2",  [r"\*", r"out0"]),
        ("div",  "a0, a1, a2",  [r"/", r"==\s*0|!=\s*0|div"]),
        ("rem",  "a0, a1, a2",  [r"%", r"==\s*0|!=\s*0|rem"]),
        ("addw", "a0, a1, a2",  [r"32|int32|uint32|sign"]),
        ("subw", "a0, a1, a2",  [r"32|int32|uint32|sign"]),
        ("mulw", "a0, a1, a2",  [r"32|int32|uint32|sign"]),
    ],
)
def test_matrix_pure_integer_no_branch(mnem, body, expect_any):
    case = _mk_asm_case(mnem, body)
    out = _run_intblock_case(case)
    assert out is not None, f"{mnem} should be handled by integer block lowering"
    body_text = getattr(out, "body", "")
    assert _contains_any(body_text, expect_any), body_text


@pytest.mark.integration
@pytest.mark.parametrize(
    "mnem,body,xlen,expect_any",
    [
        ("lw",  "a0, 0(a1)",   64, [r"\*", r"int32|uint32|load"]),
        ("sw",  "a0, 0(a1)",   64, [r"\*", r"store|="]),
        ("ld",  "a0, 0(a1)",   64, [r"\*", r"int64|uint64|load"]),
        ("sd",  "a0, 0(a1)",   64, [r"\*", r"store|="]),
        ("lb",  "a0, 0(a1)",   64, [r"int8|uint8|char"]),
        ("lbu", "a0, 0(a1)",   64, [r"uint8|unsigned"]),
        ("lh",  "a0, 0(a1)",   64, [r"int16|uint16"]),
        ("lhu", "a0, 0(a1)",   64, [r"uint16|unsigned"]),
        ("lwu", "a0, 0(a1)",   64, [r"uint32|unsigned"]),
    ],
)
def test_matrix_load_store(mnem, body, xlen, expect_any):
    outs = [FakeOperand("out0", "=r")] if mnem.startswith("l") else []
    ins = [FakeOperand("base", "r"), FakeOperand("src", "r")]
    case = _mk_asm_case(mnem, body, outputs=outs, inputs=ins, xlen=xlen)
    out = _run_intblock_case(case)
    assert out is not None, f"{mnem} should be handled by integer block lowering"
    body_text = getattr(out, "body", "")
    assert _contains_any(body_text, expect_any), body_text


@pytest.mark.integration
def test_matrix_pic_plus_intblock_lw():
    pic = [SimpleNamespace(reg="a0", sym_index=0, c_expr="((uint64_t)(uintptr_t)&(sym0))")]
    frag = FakeFrag(
        outputs=[FakeOperand("out0", "=r")],
        inputs=[],
        symbols=[FakeSymbol("sym0", "sym0")],
    )
    lift = FakeLift([FakeInsn(0x1008, "lw", "a1, 0(a0)")])
    _, try_integer_block = _resolve_try_integer_block()
    try:
        out = try_integer_block(frag, lift, pic_bindings=pic, xlen=64)
    except TypeError:
        pytest.skip("current try_integer_block signature has no pic_bindings; patch 3+ not applied")
    assert out is not None
    assert _contains_any(getattr(out, "body", ""), [r"sym0", r"&\(sym0\)", r"uintptr_t"])


@pytest.mark.integration
def test_matrix_pic_plus_intblock_sw():
    pic = [SimpleNamespace(reg="a0", sym_index=0, c_expr="((uint64_t)(uintptr_t)&(sym0))")]
    frag = FakeFrag(
        outputs=[],
        inputs=[FakeOperand("src", "r")],
        symbols=[FakeSymbol("sym0", "sym0")],
    )
    lift = FakeLift([FakeInsn(0x1008, "sw", "a1, 0(a0)")])
    _, try_integer_block = _resolve_try_integer_block()
    try:
        out = try_integer_block(frag, lift, pic_bindings=pic, xlen=64)
    except TypeError:
        pytest.skip("current try_integer_block signature has no pic_bindings; patch 3+ not applied")
    assert out is not None
    assert _contains_any(getattr(out, "body", ""), [r"sym0", r"&\(sym0\)", r"store|="])


@pytest.mark.integration
def test_matrix_semantic_boundaries_div_rem_shift_and_rv32_rv64():
    cases = [
        ("div",  "a0, a1, a2", 64, [r"==\s*0|!=\s*0", r"INT(?:32|64)_MIN|-1"]),
        ("rem",  "a0, a1, a2", 64, [r"==\s*0|!=\s*0", r"INT(?:32|64)_MIN|-1"]),
        ("sll",  "a0, a1, a2", 64, [r"0x3f|63|&\s*63"]),
        ("srl",  "a0, a1, a2", 64, [r"0x3f|63|&\s*63"]),
        ("sra",  "a0, a1, a2", 64, [r"0x3f|63|&\s*63"]),
        ("sllw", "a0, a1, a2", 64, [r"0x1f|31|&\s*31"]),
        ("srlw", "a0, a1, a2", 64, [r"0x1f|31|&\s*31"]),
        ("sraw", "a0, a1, a2", 64, [r"0x1f|31|&\s*31"]),
        ("add",  "a0, a1, a2", 32, [r"32|int32|uint32"]),
        ("add",  "a0, a1, a2", 64, [r"64|int64|uint64|out0"]),
    ]
    for mnem, body, xlen, pats in cases:
        case = _mk_asm_case(mnem, body, xlen=xlen)
        out = _run_intblock_case(case)
        assert out is not None, f"{mnem}/{xlen} should lower"
        body_text = getattr(out, "body", "")
        assert _contains_any(body_text, pats), f"{mnem}/{xlen}: {body_text}"


# ---------------------------------------------------------------------------
# Optional smoke helper
# ---------------------------------------------------------------------------

def test_matrix_import_smoke():
    # This gives a fast failure with actionable names if module wiring is wrong.
    _load_structurize_module()
    _load_translate_module()
