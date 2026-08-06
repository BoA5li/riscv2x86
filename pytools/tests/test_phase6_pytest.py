from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


# 兼容不同运行目录：
# - 若测试位于 repo_root/pytools/tests 下，则：
#   parents[1] == repo_root/pytools
#   parents[2] == repo_root
_THIS = Path(__file__).resolve()
_CANDIDATE_ROOTS = []
for idx in (1, 2, 3):
    try:
        _CANDIDATE_ROOTS.append(_THIS.parents[idx])
    except IndexError:
        pass

for p in _CANDIDATE_ROOTS:
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)


def _mod_candidates(env_name: str, *defaults: str) -> list[str]:
    env = os.getenv(env_name, "").strip()
    out: list[str] = []
    if env:
        out.append(env)
    out.extend(defaults)
    return [x for x in out if x]


def _import_any(*modnames: str):
    last_exc = None
    for modname in modnames:
        try:
            return importlib.import_module(modname)
        except ModuleNotFoundError as e:
            last_exc = e
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("no import candidate provided")


cfg_mod = _import_any(*_mod_candidates(
    "PHASE6_CFG_MOD",
    "riscv2x86_py.cfg",
    "pytools.riscv2x86_py.cfg",
    "pytools.cfg",
))

translate_mod = _import_any(*_mod_candidates(
    "PHASE6_TRANSLATE_MOD",
    "riscv2x86_py.translate",
    "pytools.riscv2x86_py.translate",
    # 兼容少数旧目录布局/文件名
    "translate",
    "translate_2",
    "pytools.translate",
    "pytools.translate_2",
))

lrsc_mod = _import_any(*_mod_candidates(
    "PHASE6_LRSC_MOD",
    "riscv2x86_py.patterns.lrsc",
    "pytools.riscv2x86_py.patterns.lrsc",
    "pytools.patterns.lrsc",
))


@dataclass
class FakeInsn:
    addr: int
    asm_mnem: str
    asm_body: str = ""
    asm: str = ""
    bytes_: bytes = b"\x13\x00\x00\x00"
    size: int = 4
    sym_ref: object = None
    asm_operands: list = field(default_factory=list)

    def __post_init__(self):
        if not self.asm:
            body = f" {self.asm_body}" if self.asm_body else ""
            self.asm = f"{self.asm_mnem}{body}"


@dataclass
class FakeOperand:
    exprText: str
    constraint: str
    symbolicName: str = ""


@dataclass
class FakeSymbol:
    cName: str
    asmName: str = ""


@dataclass
class FakeFrag:
    outputs: list = field(default_factory=list)
    inputs: list = field(default_factory=list)
    clobbers: list = field(default_factory=list)
    isVolatile: bool = False
    symbols: list = field(default_factory=list)


@dataclass
class FakeLift:
    insns: list = field(default_factory=list)


@dataclass
class FakeSummary:
    is_single_block: bool = False
    has_atomic: bool = False
    has_memory_barrier: bool = False
    has_branch: bool = False
    has_call_or_return: bool = False
    writes_mem: bool = False


def _node(addr, insn_addrs, succs):
    return cfg_mod.CFGNode(
        addr=addr,
        size=4 * len(insn_addrs),
        instr_addrs=list(insn_addrs),
        successors=list(succs),
    )


def _cfg(nodes_dict):
    entry = min(nodes_dict.keys()) if nodes_dict else 0
    return cfg_mod.CFGResult(ok=True, nodes=nodes_dict, entry=entry)


def test_build_cfg_any_uses_lifted_cfg_without_machine_code():
    insns = [
        FakeInsn(0x1000, "addi", "a0, a0, 1"),
        FakeInsn(0x1004, "bnez", "a0, -4", asm="bnez a0, -4"),
        FakeInsn(0x1008, "addi", "a1, a1, 1"),
    ]
    res = cfg_mod.build_cfg_any(b"", insns=insns, xlen=64, base_addr=0x1000)
    assert res.ok is True
    assert 0x1000 in res.nodes
    assert 0x1008 in res.nodes
    assert set(res.nodes[0x1000].successors) == {0x1000, 0x1008}


def test_cfg_from_lifted_cond_branch_has_target_and_fallthrough():
    insns = [
        FakeInsn(0x2000, "addi", "a0, a0, 1"),
        FakeInsn(0x2004, "bne", "a0, a1, -4", asm="bne a0, a1, -4"),
        FakeInsn(0x2008, "addi", "a2, a2, 1"),
    ]
    res = cfg_mod._build_cfg_from_lifted(insns, base_addr=0x2000)
    assert res.ok is True
    assert set(res.nodes[0x2000].successors) == {0x2000, 0x2008}


def test_detect_cas_retry_loop_merges_aq_rl_to_acq_rel_and_indices_are_stable():
    insns = [
        FakeInsn(0x3000, "lr.w.aq", "a0, (a2)"),
        FakeInsn(0x3004, "bne", "a0, a1, 8"),
        FakeInsn(0x3008, "sc.w.rl", "a3, a4, (a2)"),
        FakeInsn(0x300C, "bnez", "a3, -12"),
    ]

    cfg = _cfg({
        0x3000: _node(0x3000, [0x3000, 0x3004], [0x3008]),
        0x3008: _node(0x3008, [0x3008, 0x300C], [0x3000]),
    })

    operand_index_map = {
        "a0": 0,
        "x10": 0,
        "a3": 1,
        "x13": 1,
        "a2": 2,
        "x12": 2,
        "a1": 3,
        "x11": 3,
        "a4": 4,
        "x14": 4,
    }

    cas = lrsc_mod.detect_cas(
        insns,
        cfg,
        operand_index_map,
        output_count=2,
    )
    assert cas is not None
    assert cas.width == 32
    assert cas.is_weak is False
    assert cas.addr_operand_idx == 2
    assert cas.expected_operand_idx == 3
    assert cas.desired_operand_idx == 4
    assert cas.old_output_idx == 0
    assert cas.sc_status_output_idx == 1
    # 当前实现按 lr/sc 的 aq/rl 位并集映射，不再把 retry loop 一律当成 SEQ_CST。
    assert cas.success_order == "__ATOMIC_ACQ_REL"
    assert cas.failure_order == "__ATOMIC_ACQUIRE"


def test_detect_cas_one_shot_stays_weak_and_relaxed():
    insns = [
        FakeInsn(0x4000, "lr.w", "a0, (a2)"),
        FakeInsn(0x4004, "bne", "a0, a1, 8"),
        FakeInsn(0x4008, "sc.w", "a3, a4, (a2)"),
    ]
    cfg = _cfg({
        0x4000: _node(0x4000, [0x4000, 0x4004], [0x4008]),
        0x4008: _node(0x4008, [0x4008], []),
    })
    operand_index_map = {
        "a0": 0,
        "x10": 0,
        "a3": 1,
        "x13": 1,
        "a2": 2,
        "x12": 2,
        "a1": 3,
        "x11": 3,
        "a4": 4,
        "x14": 4,
    }
    cas = lrsc_mod.detect_cas(
        insns,
        cfg,
        operand_index_map,
        output_count=2,
    )
    assert cas is not None
    assert cas.is_weak is True
    assert cas.success_order == "__ATOMIC_RELAXED"
    assert cas.failure_order == "__ATOMIC_RELAXED"


def test_translate_lrsc_cas_does_not_require_machine_code(monkeypatch):
    frag = FakeFrag(
        outputs=[
            FakeOperand("old_out", "=r"),
            FakeOperand("sc_status", "=r"),
        ],
        inputs=[
            FakeOperand("mem", "A"),
            FakeOperand("expected", "r"),
            FakeOperand("desired", "r"),
        ],
    )
    lift = FakeLift(insns=[FakeInsn(0x5000, "lr.w", "a0, (a2)")])
    summary = FakeSummary(has_atomic=True)

    cfg = _cfg({0x5000: _node(0x5000, [0x5000], [])})

    monkeypatch.setattr(translate_mod, "build_cfg_any", lambda *a, **k: cfg)

    fake_cas = lrsc_mod.MatchedCAS(
        width=32,
        is_weak=True,
        success_order="__ATOMIC_ACQUIRE",
        failure_order="__ATOMIC_RELAXED",
        addr_operand_idx=2,
        expected_operand_idx=3,
        desired_operand_idx=4,
        old_output_idx=0,
        sc_status_output_idx=1,
        explain="test cas",
    )
    monkeypatch.setattr(translate_mod, "detect_cas", lambda *a, **k: fake_cas)
    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_STRATEGIES", [])
    monkeypatch.setattr(translate_mod, "try_integer_block", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "detect_rmw", lambda *a, **k: None)

    out = translate_mod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    assert out.kind == "pure_c"
    assert "__atomic_compare_exchange_n" in out.replacement
    assert "&(mem)" in out.replacement
    assert "old_out = __r2x_old_32;" in out.replacement


def test_translate_lrsc_rmw_does_not_require_machine_code(monkeypatch):
    frag = FakeFrag(
        outputs=[FakeOperand("oldv", "=r")],
        inputs=[FakeOperand("mem", "A"), FakeOperand("rhs", "r")],
    )
    lift = FakeLift(insns=[FakeInsn(0x6000, "lr.w", "a0, (a1)")])
    summary = FakeSummary(has_atomic=True)

    class FakeRmw:
        addr_reg = "a1"
        val_kind = "reg"
        val_reg = "a2"

    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "build_cfg_any", lambda *a, **k: _cfg({}))
    monkeypatch.setattr(translate_mod, "detect_cas", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "detect_rmw", lambda *a, **k: FakeRmw())
    monkeypatch.setattr(translate_mod, "_STRATEGIES", [])
    monkeypatch.setattr(translate_mod, "try_integer_block", lambda *a, **k: None)
    monkeypatch.setattr(
        translate_mod,
        "emit_rmw_c",
        lambda frag, m: (
            "oldv = __atomic_fetch_add(&(mem), rhs, __ATOMIC_SEQ_CST);",
            ["rmw"],
        ),
    )

    out = translate_mod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    assert out.kind == "pure_c"
    assert "__atomic_fetch_add" in out.replacement


def test_translate_pic_then_intblock_bridge(monkeypatch):
    frag = FakeFrag(
        outputs=[FakeOperand("dst", "=r")],
        inputs=[],
        symbols=[FakeSymbol(cName="global_obj", asmName="global_obj")],
    )
    lift = FakeLift(insns=[FakeInsn(0x7000, "auipc", "a0, %pcrel_hi(global_obj)")])
    summary = FakeSummary()

    monkeypatch.setattr(translate_mod, "_try_pic", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "detect_cas", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "detect_rmw", lambda *a, **k: None)
    monkeypatch.setattr(translate_mod, "_STRATEGIES", [])

    class FakeIB:
        body = "dst = *(int *)&global_obj;"
        notes = ["intblock"]

    class FakeBinding:
        reg = "a0"
        sym_index = 0
        c_expr = "((uint64_t)(uintptr_t)&(global_obj))"
        consumed_insn_addrs = [0x7000]

    monkeypatch.setattr(
        translate_mod,
        "_pic_bindings_for_intblock",
        lambda *a, **k: [FakeBinding()],
    )
    monkeypatch.setattr(
        translate_mod,
        "try_integer_block",
        lambda frag, lift, pic_bindings, xlen: FakeIB() if pic_bindings else None,
    )

    out = translate_mod.translate(frag, lift, summary, machine_code=b"", xlen=64)
    assert out.kind == "pure_c"
    assert "global_obj" in out.replacement
    assert any("PIC binding injected into intblock" in note for note in out.notes)
