"""
translate 阶段正确性验证测试。

运行方式：

    export TRANSLATOR_MODULE=your_package.translate
    pytest -q tests/test_translate_correctness.py

如果项目的 translate 模块路径固定，也可以将下方 MODULE_NAME 的默认值
直接改成实际模块路径。
"""

from __future__ import annotations

import importlib
import os
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
import pytest
import re

import json

from riscv2x86_py.pipeline import run
import inspect

from riscv2x86_py.translate_backup import _iter_canonical_pure_c_strategies
from riscv2x86_py.assemble import assemble
from riscv2x86_py.schema import load_report
import riscv2x86_py.translate_backup as translate_mod
import riscv2x86_py.pipeline as pipeline_mod
# ---------------------------------------------------------------------------
# 被测模块加载
# ---------------------------------------------------------------------------

MODULE_NAME = os.environ.get(
    "TRANSLATOR_MODULE",
    "riscv2x86_py.translate",  # 修改为项目真实路径，或通过环境变量覆盖
)

try:
    tr = importlib.import_module(MODULE_NAME)
except ModuleNotFoundError as exc:
    raise RuntimeError(
        f"无法导入 translate 模块: {MODULE_NAME!r}\n"
        "请设置环境变量，例如：\n"
        "  TRANSLATOR_MODULE=riscv2x86_py.translate pytest -q\n"
    ) from exc


# ---------------------------------------------------------------------------
# 通用构造器
# ---------------------------------------------------------------------------

def make_output(
    *,
    kind: str = "pure_c",
    replacement: str = "x = 1;",
    notes: List[str] | None = None,
):
    return tr.TranslationOutput(
        kind=kind,
        replacement=replacement,
        notes=list(notes or []),
    )


def make_decision(
    *,
    level: str = "A",
    route: str = "canonical_pure_c_or_semantic_x86",
    reasons: List[str] | None = None,
):
    """
    translate() 对 PreservationDecision 使用 getattr，因此此处使用
    SimpleNamespace 可避免测试依赖 PreservationDecision 的构造函数细节。
    """
    return SimpleNamespace(
        level=level,
        route=route,
        reasons=list(reasons or []),
    )


def make_frag(**kwargs):
    """
    使用最小 duck-typed fragment。

    _classify_preservation / translate 目前只通过 getattr 读取属性，
    因而不必强依赖 AsmFragment 的全部构造参数。
    """
    defaults: Dict[str, Any] = {
        "rawAsmText": "",
        "isVolatile": False,
        "microarchSensitive": False,
        "microArch": SimpleNamespace(
            level="A",
            preserveExperiment=False,
            preserveControlFlowShape=False,
            preserveBranchPredictorShape=False,
            preserveCacheFootprint=False,
            preserveAtomicRetryShape=False,
            preserveFenceShape=False,
            preserveTimingSource=False,
            tags=[],
            explain="",
        ),
        "inputs": [],
        "outputs": [],
        "clobbers": [],
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def make_lift(**kwargs):
    defaults: Dict[str, Any] = {
        "ok": True,
        "insns": [],
        "summary": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def make_summary(**kwargs):
    defaults: Dict[str, Any] = {
        "is_single_block": True,
        "has_branch": False,
        "has_call_or_return": False,
        "has_memory_barrier": False,
        "has_atomic": False,
        "reads_regs": set(),
        "writes_regs": set(),
        "reads_mem": False,
        "writes_mem": False,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# TranslationOutput / contract 基础测试
# ---------------------------------------------------------------------------

def test_translation_output_normalization_defaults():
    out = tr.TranslationOutput(
        kind="",
        replacement="",
        notes=[],
        preservationLevel="invalid-level",
        preservationRoute="",
        buildFamily="",
    )

    assert out.normalized_level() == "A"
    assert out.normalized_route() == "canonical_public_c"
    assert out.normalized_build_family() == "unsupported"


@pytest.mark.parametrize(
    ("kind", "replacement", "expected_family"),
    [
        ("pure_c", "x = 1;", "pure_c"),
        ("x86_inline_asm", '__asm__ volatile("nop");', "x86_inline_asm"),
        ("x86_asm_goto", '__asm__ goto("jmp %l0" : : : : target);', "x86_asm_goto"),
        ("unsupported", "", "unsupported"),
        ("unknown-kind", "x = 1;", "pure_c"),
        ("unknown-kind", '__asm__ volatile("nop");', "x86_inline_asm"),
        (
            "unknown-kind",
            '__asm__ goto("jmp %l0" : : : : target);',
            "x86_asm_goto",
        ),
    ],
)
def test_translation_output_build_family_inference(
    kind,
    replacement,
    expected_family,
):
    out = tr.TranslationOutput(
        kind=kind,
        replacement=replacement,
        notes=[],
    )

    assert out.normalized_build_family() == expected_family


def test_attach_contract_merges_metadata_and_deduplicates_reason_codes():
    out = make_output(kind="pure_c", replacement="x = 1;")
    out.metadata = {"already_present": True}

    attached = tr._attach_contract(
        out,
        level="A",
        route="canonical_public_c",
        reason_codes=["first", "first", "second"],
        metadata={"new_key": 123},
    )

    assert attached is out
    assert out.preservationLevel == "A"
    assert out.preservationRoute == "canonical_public_c"
    assert out.buildFamily == "pure_c"

    assert out.metadata["already_present"] is True
    assert out.metadata["new_key"] == 123

    assert out.reasonCodes == ["first", "second"]

    assert "preservation.level=A" in out.notes
    assert "preservation.route=canonical_public_c" in out.notes
    assert "build.family=pure_c" in out.notes

    # pure_c 必须要求 block proof。
    assert out.requiresBlockProof is True
    assert out.requiresPathValidation is False


def test_needs_route_returns_controlled_unsupported_result():
    decision = make_decision(
        level="B",
        route="needs_stack_aware_lowering",
        reasons=["touches sp/x2"],
    )

    out = tr._needs_route(
        route="needs_stack_aware_lowering",
        decision=decision,
        reasons=["additional reason"],
    )

    assert out.kind == "unsupported"
    assert out.replacement == ""
    assert out.preservationLevel == "B"
    assert out.preservationRoute == "needs_stack_aware_lowering"
    assert out.buildFamily == "unsupported"

    assert "needs_manual_lowering" in out.reasonCodes
    assert out.metadata["decision_reasons"] == ["touches sp/x2"]

    # stack-aware route 被定义为需要 block/path 验证。
    assert out.requiresBlockProof is True
    assert out.requiresPathValidation is True


# ---------------------------------------------------------------------------
# _classify_preservation 分类测试
# ---------------------------------------------------------------------------

def test_classify_preservation_returns_d_for_explicit_preserve_experiment(
    monkeypatch,
):
    monkeypatch.setattr(
        tr,
        "_has_microarch_experiment_markers",
        lambda frag, lift: False,
    )

    frag = make_frag(
        microArch=SimpleNamespace(
            level="A",
            preserveExperiment=True,
        ),
    )
    lift = make_lift()
    summary = make_summary()

    decision = tr._classify_preservation(frag, lift, summary)

    assert decision.level == "D"
    assert decision.route == "needs_experiment_preserving_lowering"
    assert "fragment requests preserveExperiment" in decision.reasons


def test_classify_preservation_returns_d_for_microarch_sensitive_flag(
    monkeypatch,
):
    monkeypatch.setattr(
        tr,
        "_has_microarch_experiment_markers",
        lambda frag, lift: False,
    )

    frag = make_frag(microarchSensitive=True)
    lift = make_lift()
    summary = make_summary()

    decision = tr._classify_preservation(frag, lift, summary)

    assert decision.level == "D"
    assert "fragment marked microarchSensitive" in decision.reasons


def test_classify_preservation_returns_b_for_barrier(monkeypatch):
    monkeypatch.setattr(
        tr,
        "_has_microarch_experiment_markers",
        lambda frag, lift: False,
    )
    monkeypatch.setattr(
        tr,
        "_barrier_requires_semantic_lowering",
        lambda summary: True,
    )
    monkeypatch.setattr(
        tr,
        "_describe_barriers",
        lambda summary: ["memory fence pred=rw succ=rw"],
    )

    frag = make_frag()
    lift = make_lift()
    summary = make_summary(has_memory_barrier=True)

    decision = tr._classify_preservation(frag, lift, summary)

    assert decision.level == "B"
    assert decision.route == "needs_memory_ordering_lowering"

    assert any(
        "generic pure-C lowering is forbidden" in reason
        for reason in decision.reasons
    )


def test_classify_preservation_returns_c_for_call_return(monkeypatch):
    monkeypatch.setattr(
        tr,
        "_has_microarch_experiment_markers",
        lambda frag, lift: False,
    )
    monkeypatch.setattr(
        tr,
        "_barrier_requires_semantic_lowering",
        lambda summary: False,
    )
    monkeypatch.setattr(
        tr,
        "_touches_reg",
        lambda lift, reg: False,
    )

    frag = make_frag()
    lift = make_lift()
    summary = make_summary(has_call_or_return=True)

    decision = tr._classify_preservation(frag, lift, summary)

    assert decision.level == "C"
    assert decision.route == "needs_control_preserving_lowering"
    assert any("call/ret-like control transfer" in r for r in decision.reasons)


def test_classify_preservation_returns_b_when_touching_sp(monkeypatch):
    monkeypatch.setattr(
        tr,
        "_has_microarch_experiment_markers",
        lambda frag, lift: False,
    )
    monkeypatch.setattr(
        tr,
        "_barrier_requires_semantic_lowering",
        lambda summary: False,
    )
    monkeypatch.setattr(
        tr,
        "_touches_reg",
        lambda lift, reg: reg == "x2",
    )

    frag = make_frag()
    lift = make_lift()
    summary = make_summary()

    decision = tr._classify_preservation(frag, lift, summary)

    assert decision.level == "B"
    assert decision.route == "needs_stack_aware_lowering"
    assert any("touches sp/x2" in r for r in decision.reasons)


def test_classify_preservation_returns_a_for_plain_fragment(monkeypatch):
    monkeypatch.setattr(
        tr,
        "_has_microarch_experiment_markers",
        lambda frag, lift: False,
    )
    monkeypatch.setattr(
        tr,
        "_barrier_requires_semantic_lowering",
        lambda summary: False,
    )
    monkeypatch.setattr(
        tr,
        "_touches_reg",
        lambda lift, reg: False,
    )
    monkeypatch.setattr(
        tr,
        "_is_call_like",
        lambda ins: False,
    )
    monkeypatch.setattr(
        tr,
        "_is_ret_like",
        lambda ins: False,
    )

    frag = make_frag()
    lift = make_lift(insns=[])
    summary = make_summary()

    decision = tr._classify_preservation(frag, lift, summary)

    assert decision.level == "A"
    assert decision.route == "canonical_pure_c_or_semantic_x86"
    assert "no stack/call/return/microarchitectural markers detected" in decision.reasons


# ---------------------------------------------------------------------------
# translate() 顶层路由测试
# ---------------------------------------------------------------------------

def test_translate_pic_fast_path_short_circuits_everything(monkeypatch):
    frag = make_frag(rawAsmText="auipc a0, %pcrel_hi(symbol)")
    lift = make_lift()
    summary = make_summary()

    pic_out = make_output(
        kind="pure_c",
        replacement="a0 = (uintptr_t)&symbol;",
        notes=["PIC lowered"],
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: pic_out)

    def fail_classifier(*args, **kwargs):
        pytest.fail("PIC 快速路径命中后不应继续调用 _classify_preservation")

    monkeypatch.setattr(tr, "_classify_preservation", fail_classifier)

    seen = {}

    def fake_append(out, *, level, route):
        seen["out"] = out
        seen["level"] = level
        seen["route"] = route
        return out

    monkeypatch.setattr(tr, "_append_preservation_notes", fake_append)

    out = tr.translate(frag, lift, summary)

    assert out is pic_out
    assert seen["out"] is pic_out
    assert seen["level"] == "A"
    assert seen["route"] == "canonical_pic_pure_c"


def test_translate_d_uses_experiment_preserving_result(monkeypatch):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()

    decision = make_decision(
        level="D",
        route="needs_experiment_preserving_lowering",
        reasons=["preserve experiment"],
    )
    expected = make_output(
        kind="x86_inline_asm",
        replacement='__asm__ volatile("mfence");',
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(
        tr,
        "_try_experiment_preserving_x86",
        lambda **kwargs: expected,
    )

    def fail_fallback(**kwargs):
        pytest.fail("D 专门路径成功时不应进入 fallback")

    monkeypatch.setattr(tr, "_close_to_x86_inline_asm_or_route", fail_fallback)

    out = tr.translate(frag, lift, summary)

    assert out is expected


def test_translate_d_falls_back_with_preserve_experiment_true(monkeypatch):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()

    decision = make_decision(
        level="D",
        route="needs_experiment_preserving_lowering",
        reasons=["timing source"],
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(
        tr,
        "_try_experiment_preserving_x86",
        lambda **kwargs: None,
    )

    captured = {}

    def fake_close(**kwargs):
        captured.update(kwargs)
        return make_output(
            kind="x86_inline_asm",
            replacement='__asm__ volatile("lfence");',
        )

    monkeypatch.setattr(tr, "_close_to_x86_inline_asm_or_route", fake_close)

    out = tr.translate(frag, lift, summary)

    assert out.kind == "x86_inline_asm"
    assert captured["route"] == "needs_experiment_preserving_lowering"
    assert captured["preserve_experiment"] is True
    assert captured["decision"] is decision
    assert "timing source" in captured["reasons"]
    assert "experiment-sensitive" in captured["reasons"]


def test_translate_c_uses_control_preserving_result(monkeypatch):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()

    decision = make_decision(
        level="C",
        route="needs_control_preserving_lowering",
        reasons=["call-like"],
    )
    expected = make_output(
        kind="phase6.lower_to_x86_inline_asm",
        replacement='__asm__ volatile("call target");',
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(
        tr,
        "_try_control_preserving_x86",
        lambda **kwargs: expected,
    )

    def fail_needs_route(**kwargs):
        pytest.fail("C 专门 lowering 成功时不应进入 needs_route")

    monkeypatch.setattr(tr, "_needs_route", fail_needs_route)

    out = tr.translate(frag, lift, summary)

    assert out is expected


def test_translate_c_returns_needs_route_when_no_control_lowering(monkeypatch):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()

    decision = make_decision(
        level="C",
        route="needs_control_preserving_lowering",
        reasons=["return-like"],
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(
        tr,
        "_try_control_preserving_x86",
        lambda **kwargs: None,
    )

    captured = {}

    def fake_needs_route(**kwargs):
        captured.update(kwargs)
        return make_output(kind="unsupported", replacement="")

    monkeypatch.setattr(tr, "_needs_route", fake_needs_route)

    out = tr.translate(frag, lift, summary)

    assert out.kind == "unsupported"
    assert captured["route"] == "needs_control_preserving_lowering"
    assert captured["decision"] is decision
    assert "return-like" in captured["reasons"]
    assert "call/ret-sensitive" in captured["reasons"]


def test_translate_b_never_attempts_pure_c_or_lrsc(monkeypatch):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary(has_memory_barrier=True)

    decision = make_decision(
        level="B",
        route="needs_memory_ordering_lowering",
        reasons=["barrier detected"],
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)

    def fail_lrsc(*args, **kwargs):
        pytest.fail("B 级 fragment 不应进入 LR/SC 或 pure-C 路径")

    monkeypatch.setattr(tr, "_try_lrsc_cas", fail_lrsc)
    monkeypatch.setattr(tr, "_try_lrsc_rmw", fail_lrsc)

    captured = {}

    def fake_needs_route(**kwargs):
        captured.update(kwargs)
        return make_output(kind="unsupported", replacement="")

    monkeypatch.setattr(tr, "_needs_route", fake_needs_route)

    out = tr.translate(frag, lift, summary)

    assert out.kind == "unsupported"
    assert captured["route"] == "needs_memory_ordering_lowering"
    assert "barrier detected" in captured["reasons"]
    assert "stack/ra-sensitive" in captured["reasons"]


def test_translate_a_lrsc_cas_has_priority_over_rmw_and_pure_c(monkeypatch):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary(has_atomic=True)

    decision = make_decision(level="A")
    cas_out = make_output(
        kind="x86_inline_asm",
        replacement='__asm__ volatile("lock cmpxchgq ...");',
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(tr, "_try_lrsc_cas", lambda **kwargs: cas_out)

    def fail_after_cas(*args, **kwargs):
        pytest.fail("CAS 成功后不应尝试后续 RMW/pure-C 路径")

    monkeypatch.setattr(tr, "_try_lrsc_rmw", fail_after_cas)
    monkeypatch.setattr(
        tr,
        "_call_collect_generic_pure_c_proof_failures",
        fail_after_cas,
    )

    out = tr.translate(frag, lift, summary)

    assert out is cas_out


def test_translate_a_proof_gate_rejects_pure_c_and_enters_semantic_x86(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()

    decision = make_decision(
        level="A",
        reasons=["normal A fragment"],
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(tr, "_try_lrsc_cas", lambda **kwargs: None)
    monkeypatch.setattr(tr, "_try_lrsc_rmw", lambda **kwargs: None)
    monkeypatch.setattr(
        tr,
        "_call_collect_generic_pure_c_proof_failures",
        lambda **kwargs: [
            "writes memory but memory equivalence proof is unavailable",
        ],
    )

    captured = {}

    def fake_fallback(**kwargs):
        captured.update(kwargs)
        return make_output(
            kind="x86_inline_asm",
            replacement='__asm__ volatile("nop");',
        )

    monkeypatch.setattr(tr, "_fallback_after_pure_c_reject", fake_fallback)

    out = tr.translate(frag, lift, summary)

    assert out.kind == "x86_inline_asm"
    assert captured["route"] == "needs_semantic_x86_lowering"
    assert captured["decision"] is decision

    assert "normal A fragment" in captured["reasons"]
    assert "explicit semantics-preservation proof not satisfied" in captured["reasons"]
    assert (
        "writes memory but memory equivalence proof is unavailable"
        in captured["reasons"]
    )


def test_translate_a_uses_first_accepted_canonical_pure_c_strategy(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()
    decision = make_decision(level="A")

    expected = make_output(
        kind="pure_c",
        replacement="result = input + 1;",
        notes=["canonical strategy accepted"],
    )

    calls = []

    def first_strategy(**kwargs):
        calls.append("first")
        return None

    def second_strategy(**kwargs):
        calls.append("second")
        return expected

    def third_strategy(**kwargs):
        pytest.fail("第二个 strategy 成功后不应调用第三个 strategy")

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(tr, "_try_lrsc_cas", lambda **kwargs: None)
    monkeypatch.setattr(tr, "_try_lrsc_rmw", lambda **kwargs: None)
    monkeypatch.setattr(
        tr,
        "_call_collect_generic_pure_c_proof_failures",
        lambda **kwargs: [],
    )
    monkeypatch.setattr(
        tr,
        "_iter_canonical_pure_c_strategies",
        lambda: [first_strategy, second_strategy, third_strategy],
    )

    out = tr.translate(frag, lift, summary)

    assert out is expected
    assert calls == ["first", "second"]


@pytest.mark.parametrize(
    ("pic_bindings", "allow_generic", "expected_route", "expected_reason"),
    [
        (
            ["symbol_binding"],
            False,
            "canonical_pic_pure_c",
            "pic_binding_injected",
        ),
        (
            [],
            True,
            "canonical_public_c",
            "generic_pure_c_accepted",
        ),
    ],
)
def test_translate_a_accepts_integer_block_under_allowed_policy(
    monkeypatch,
    pic_bindings,
    allow_generic,
    expected_route,
    expected_reason,
):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()
    decision = make_decision(level="A")

    integer_block = SimpleNamespace(
        body="do {\nresult = input + 1;\n} while (0);",
        notes=["single-block integer lowering"],
    )

    captured = {}

    def fake_output_from_body(body, notes, **kwargs):
        captured["body"] = body
        captured["notes"] = notes
        captured.update(kwargs)
        return make_output(kind="pure_c", replacement=body, notes=notes)

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(tr, "_try_lrsc_cas", lambda **kwargs: None)
    monkeypatch.setattr(tr, "_try_lrsc_rmw", lambda **kwargs: None)
    monkeypatch.setattr(
        tr,
        "_call_collect_generic_pure_c_proof_failures",
        lambda **kwargs: [],
    )
    monkeypatch.setattr(
        tr,
        "_iter_canonical_pure_c_strategies",
        lambda: [],
    )
    monkeypatch.setattr(
        tr,
        "_pic_bindings_for_intblock",
        lambda *args, **kwargs: pic_bindings,
    )
    monkeypatch.setattr(
        tr,
        "try_integer_block",
        lambda **kwargs: integer_block,
    )
    monkeypatch.setattr(
        tr,
        "_extract_body_or_replacement",
        lambda ib: ib.body,
    )
    monkeypatch.setattr(
        tr,
        "_translation_output_from_body",
        fake_output_from_body,
    )
    monkeypatch.setattr(
        tr,
        "_ALLOW_GENERIC_INTBLOCK_PURE_C",
        allow_generic,
    )

    out = tr.translate(frag, lift, summary)

    assert out.kind == "pure_c"
    assert captured["body"] == integer_block.body
    assert captured["route"] == expected_route
    assert expected_reason in captured["reason_codes"]

    assert "single-block integer lowering" in captured["notes"]


def test_translate_a_rejects_generic_integer_block_when_policy_disabled(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()
    decision = make_decision(level="A")

    integer_block = SimpleNamespace(
        body="do {\nx = y;\n} while (0);",
        notes=["single-block integer lowering"],
    )

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(tr, "_try_lrsc_cas", lambda **kwargs: None)
    monkeypatch.setattr(tr, "_try_lrsc_rmw", lambda **kwargs: None)
    monkeypatch.setattr(
        tr,
        "_call_collect_generic_pure_c_proof_failures",
        lambda **kwargs: [],
    )
    monkeypatch.setattr(
        tr,
        "_iter_canonical_pure_c_strategies",
        lambda: [],
    )
    monkeypatch.setattr(
        tr,
        "_pic_bindings_for_intblock",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        tr,
        "try_integer_block",
        lambda **kwargs: integer_block,
    )
    monkeypatch.setattr(
        tr,
        "_extract_body_or_replacement",
        lambda ib: ib.body,
    )
    monkeypatch.setattr(
        tr,
        "_ALLOW_GENERIC_INTBLOCK_PURE_C",
        False,
    )

    captured = {}

    def fake_close(**kwargs):
        captured.update(kwargs)
        return make_output(
            kind="x86_inline_asm",
            replacement='__asm__ volatile("nop");',
        )

    monkeypatch.setattr(tr, "_close_to_x86_inline_asm_or_route", fake_close)

    out = tr.translate(frag, lift, summary)

    assert out.kind == "x86_inline_asm"
    assert captured["route"] == "needs_semantic_x86_lowering"
    assert captured["preserve_experiment"] is False
    assert "integer-block pure_c lowering is disabled by policy" in captured["reasons"]


def test_translate_a_final_fallback_when_no_pure_c_lowering_exists(monkeypatch):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()
    decision = make_decision(level="A", reasons=["ordinary fragment"])

    monkeypatch.setattr(tr, "_try_pic", lambda *args, **kwargs: None)
    monkeypatch.setattr(tr, "_classify_preservation", lambda *args: decision)
    monkeypatch.setattr(tr, "_try_lrsc_cas", lambda **kwargs: None)
    monkeypatch.setattr(tr, "_try_lrsc_rmw", lambda **kwargs: None)
    monkeypatch.setattr(
        tr,
        "_call_collect_generic_pure_c_proof_failures",
        lambda **kwargs: [],
    )
    monkeypatch.setattr(
        tr,
        "_iter_canonical_pure_c_strategies",
        lambda: [],
    )
    monkeypatch.setattr(
        tr,
        "_pic_bindings_for_intblock",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        tr,
        "try_integer_block",
        lambda **kwargs: None,
    )

    captured = {}

    def fake_close(**kwargs):
        captured.update(kwargs)
        return make_output(kind="unsupported", replacement="")

    monkeypatch.setattr(tr, "_close_to_x86_inline_asm_or_route", fake_close)

    out = tr.translate(frag, lift, summary)

    assert out.kind == "unsupported"
    assert captured["route"] == "needs_semantic_x86_lowering"
    assert captured["preserve_experiment"] is False
    assert "ordinary fragment" in captured["reasons"]
    assert "no accepted pure_c lowering found" in captured["reasons"]


# ---------------------------------------------------------------------------
# pure-C proof gate / barrier 行为
# ---------------------------------------------------------------------------

def test_collect_generic_pure_c_proof_failures_rejects_barrier(monkeypatch):
    monkeypatch.setattr(
        tr,
        "_barrier_requires_semantic_lowering",
        lambda summary: True,
    )
    monkeypatch.setattr(
        tr,
        "_describe_barriers",
        lambda summary: ["fence rw,rw"],
    )

    failures = tr._collect_generic_pure_c_proof_failures(
        frag=make_frag(),
        lift=make_lift(),
        summary=make_summary(has_memory_barrier=True),
        decision=make_decision(level="A"),
        xlen=64,
    )

    assert len(failures) == 1
    assert "generic pure-C lowering rejected for barrier-containing fragment" in failures[0]
    assert "fence rw,rw" in failures[0]


# ---------------------------------------------------------------------------
# x86 emitter / call-ret helper thunk
# ---------------------------------------------------------------------------

def test_emit_call_ret_helper_thunk_lowers_ret(monkeypatch):
    ret_insn = SimpleNamespace(asm_mnem="ret")
    lift = make_lift(insns=[ret_insn])

    monkeypatch.setattr(tr, "_is_ret_like", lambda ins: True)
    monkeypatch.setattr(tr, "_emit_ret_x86", lambda: '__asm__ volatile("ret");')

    out = tr._emit_call_ret_helper_thunk(
        make_frag(),
        lift,
        xlen=64,
    )

    assert out is not None
    assert out.kind == "phase6.lower_to_x86_inline_asm"
    assert out.replacement == '__asm__ volatile("ret");'
    assert "control-preserving x86 ret lowering" in out.notes
    assert "control shape preserved" in out.notes


def test_emit_call_ret_helper_thunk_lowers_direct_call(monkeypatch):
    call_insn = SimpleNamespace(asm_mnem="call")
    lift = make_lift(insns=[call_insn])

    monkeypatch.setattr(tr, "_is_ret_like", lambda ins: False)
    monkeypatch.setattr(tr, "_is_call_like", lambda ins: True)
    monkeypatch.setattr(
        tr,
        "_extract_direct_symbol_target",
        lambda ins: "target_symbol",
    )
    monkeypatch.setattr(
        tr,
        "_emit_direct_call_x86",
        lambda sym: f'__asm__ volatile("call {sym}");',
    )

    out = tr._emit_call_ret_helper_thunk(
        make_frag(),
        lift,
        xlen=64,
    )

    assert out is not None
    assert out.kind == "phase6.lower_to_x86_inline_asm"
    assert "target_symbol" in out.replacement
    assert "control-preserving x86 direct-call lowering" in out.notes
    assert "direct target symbol=target_symbol" in out.notes


def test_try_emit_x86_inline_asm_rejects_barrier_before_any_template(
    monkeypatch,
):
    lift = make_lift(summary=make_summary(has_memory_barrier=True))

    monkeypatch.setattr(
        tr,
        "_barrier_requires_semantic_lowering",
        lambda summary: True,
    )

    def fail_template(*args, **kwargs):
        pytest.fail("barrier fragment 不应继续进入 x86 template emitter")

    monkeypatch.setattr(tr, "_emit_call_ret_helper_thunk", fail_template)

    out = tr._try_emit_x86_inline_asm(
        make_frag(),
        lift,
        xlen=64,
        preserve_experiment=False,
    )

    assert out is None


def test_make_phase6_x86_result_contains_required_phase6_notes():
    decision = make_decision(
        level="C",
        route="needs_control_preserving_lowering",
    )

    out = tr._make_phase6_x86_result(
        decision=decision,
        replacement='__asm__ volatile("call foo");',
        reasons=["direct call lowered"],
    )

    assert out.kind == "phase6.lower_to_x86_inline_asm"
    assert out.replacement == '__asm__ volatile("call foo");'

    assert "phase6.lower_to_x86_inline_asm" in out.notes
    assert "preservation.level=C" in out.notes
    assert "preservation.route=needs_control_preserving_lowering" in out.notes
    assert "translation.target=x86" in out.notes
    assert "direct call lowered" in out.notes


# ---------------------------------------------------------------------------
# _try_pic() 测试
# ---------------------------------------------------------------------------

def test_try_pic_returns_none_for_empty_instruction_list():
    frag = make_frag(rawAsmText="")
    lift = make_lift(insns=[])
    summary = make_summary()

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out is None


def test_try_pic_returns_none_when_fragment_has_no_pic_syntax_or_reloc(
    monkeypatch,
):
    insn = SimpleNamespace(addr=0x1000)
    frag = make_frag(rawAsmText="addi a0, a0, 1")
    lift = make_lift(insns=[insn])
    summary = make_summary()

    monkeypatch.setattr(tr, "fragment_uses_pic_syntax", lambda frag: False)
    monkeypatch.setattr(tr, "has_any_pcrel_reloc", lambda insns: False)

    def fail_detect(*args, **kwargs):
        pytest.fail(
            "既没有 PIC syntax 也没有 PCREL relocation 时，"
            "不应调用 _detect_pic_pairs_or_error"
        )

    monkeypatch.setattr(tr, "_detect_pic_pairs_or_error", fail_detect)

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out is None


def test_try_pic_reports_unsupported_when_pic_syntax_has_no_relocations(
    monkeypatch,
):
    insn = SimpleNamespace(addr=0x1000)
    frag = make_frag(rawAsmText="auipc a0, %pcrel_hi(symbol)")
    lift = make_lift(insns=[insn])
    summary = make_summary()

    monkeypatch.setattr(tr, "fragment_uses_pic_syntax", lambda frag: True)
    monkeypatch.setattr(tr, "has_any_pcrel_reloc", lambda insns: False)

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out.kind == "unsupported"
    assert out.replacement == ""
    assert len(out.notes) == 1
    assert "PIC syntax detected" in out.notes[0]
    assert "no PCREL relocations were attached" in out.notes[0]


def test_try_pic_reports_unsupported_when_pair_detector_returns_error(
    monkeypatch,
):
    insn = SimpleNamespace(addr=0x1000)
    frag = make_frag(rawAsmText="auipc a0, %pcrel_hi(symbol)")
    lift = make_lift(insns=[insn])
    summary = make_summary()

    monkeypatch.setattr(tr, "fragment_uses_pic_syntax", lambda frag: True)
    monkeypatch.setattr(tr, "has_any_pcrel_reloc", lambda insns: True)
    monkeypatch.setattr(
        tr,
        "_detect_pic_pairs_or_error",
        lambda frag, lift, xlen: ([], "orphan %pcrel_lo relocation"),
    )

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out.kind == "unsupported"
    assert out.replacement == ""
    assert out.notes == [
        "PIC translation error: orphan %pcrel_lo relocation",
    ]


def test_try_pic_uses_simple_fallback_when_no_bindings_but_no_error(
    monkeypatch,
):
    insn = SimpleNamespace(addr=0x1000)
    frag = make_frag(rawAsmText="auipc a0, %pcrel_hi(symbol)")
    lift = make_lift(insns=[insn])
    summary = make_summary()

    expected = make_output(
        kind="pure_c",
        replacement="out = (uintptr_t)&symbol;",
        notes=["simple PIC fallback"],
    )

    monkeypatch.setattr(tr, "fragment_uses_pic_syntax", lambda frag: True)
    monkeypatch.setattr(tr, "has_any_pcrel_reloc", lambda insns: True)
    monkeypatch.setattr(
        tr,
        "_detect_pic_pairs_or_error",
        lambda frag, lift, xlen: ([], None),
    )
    monkeypatch.setattr(
        tr,
        "_simple_pic_pair_fallback",
        lambda frag, lift, xlen: expected,
    )

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out is expected


def test_try_pic_returns_none_for_pic_plus_non_pic_remaining_instructions(
    monkeypatch,
):
    auipc = SimpleNamespace(addr=0x1000)
    addi = SimpleNamespace(addr=0x1004)
    load = SimpleNamespace(addr=0x1008)

    binding = SimpleNamespace(
        reg="x10",
        sym_index=0,
        c_expr="((uint64_t)(uintptr_t)&(symbol))",
        consumed_insn_addrs=[0x1000, 0x1004],
    )

    frag = make_frag(rawAsmText="auipc a0, %pcrel_hi(symbol)")
    lift = make_lift(insns=[auipc, addi, load])
    summary = make_summary()

    monkeypatch.setattr(tr, "fragment_uses_pic_syntax", lambda frag: True)
    monkeypatch.setattr(tr, "has_any_pcrel_reloc", lambda insns: True)
    monkeypatch.setattr(
        tr,
        "_detect_pic_pairs_or_error",
        lambda frag, lift, xlen: ([binding], None),
    )

    def fail_output_mapping(*args, **kwargs):
        pytest.fail(
            "PIC pair 后仍有 load 等剩余指令时，应交给 intblock/其它 lowering，"
            "不应尝试 pure PIC 输出映射"
        )

    monkeypatch.setattr(tr, "_binding_to_output_lv", fail_output_mapping)

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out is None


def test_try_pic_lowers_pure_pic_block_to_canonical_pure_c(monkeypatch):
    auipc_a0 = SimpleNamespace(addr=0x1000)
    addi_a0 = SimpleNamespace(addr=0x1004)
    auipc_a1 = SimpleNamespace(addr=0x1008)
    addi_a1 = SimpleNamespace(addr=0x100C)

    b0 = SimpleNamespace(
        reg="x10",
        sym_index=0,
        c_expr="((uint64_t)(uintptr_t)&(symbol_a))",
        consumed_insn_addrs=[0x1000, 0x1004],
    )
    b1 = SimpleNamespace(
        reg="x11",
        sym_index=1,
        c_expr="((uint64_t)(uintptr_t)&(symbol_b))",
        consumed_insn_addrs=[0x1008, 0x100C],
    )

    frag = make_frag(
        rawAsmText=(
            "auipc a0, %pcrel_hi(symbol_a)\n"
            "addi  a0, a0, %pcrel_lo(symbol_a)\n"
            "auipc a1, %pcrel_hi(symbol_b)\n"
            "addi  a1, a1, %pcrel_lo(symbol_b)"
        )
    )
    lift = make_lift(insns=[auipc_a0, addi_a0, auipc_a1, addi_a1])
    summary = make_summary()

    monkeypatch.setattr(tr, "fragment_uses_pic_syntax", lambda frag: True)
    monkeypatch.setattr(tr, "has_any_pcrel_reloc", lambda insns: True)
    monkeypatch.setattr(
        tr,
        "_detect_pic_pairs_or_error",
        lambda frag, lift, xlen: ([b0, b1], None),
    )
    monkeypatch.setattr(
        tr,
        "_pic_binding_notes",
        lambda frag, bindings: [
            "PIC binding: x10 -> symbol_a",
            "PIC binding: x11 -> symbol_b",
        ],
    )

    def fake_binding_to_output_lv(frag, reg):
        return {
            "x10": "out_addr_a",
            "x11": "out_addr_b",
        }.get(reg)

    monkeypatch.setattr(
        tr,
        "_binding_to_output_lv",
        fake_binding_to_output_lv,
    )

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out.kind == "pure_c"
    assert out.replacement == (
        "out_addr_a = ((uint64_t)(uintptr_t)&(symbol_a));\n"
        "out_addr_b = ((uint64_t)(uintptr_t)&(symbol_b));"
    )

    assert out.notes[0] == "pure PIC block lowered canonically"
    assert "PIC binding: x10 -> symbol_a" in out.notes
    assert "PIC binding: x11 -> symbol_b" in out.notes


def test_try_pic_rejects_pure_pic_binding_without_writable_output(monkeypatch):
    auipc = SimpleNamespace(addr=0x1000)
    addi = SimpleNamespace(addr=0x1004)

    binding = SimpleNamespace(
        reg="x10",
        sym_index=3,
        c_expr="((uint64_t)(uintptr_t)&(read_only_symbol))",
        consumed_insn_addrs=[0x1000, 0x1004],
    )

    frag = make_frag(
        rawAsmText="auipc a0, %pcrel_hi(read_only_symbol)",
        outputs=[],
    )
    lift = make_lift(insns=[auipc, addi])
    summary = make_summary()

    monkeypatch.setattr(tr, "fragment_uses_pic_syntax", lambda frag: True)
    monkeypatch.setattr(tr, "has_any_pcrel_reloc", lambda insns: True)
    monkeypatch.setattr(
        tr,
        "_detect_pic_pairs_or_error",
        lambda frag, lift, xlen: ([binding], None),
    )
    monkeypatch.setattr(tr, "_pic_binding_notes", lambda frag, bindings: [])
    monkeypatch.setattr(tr, "_binding_to_output_lv", lambda frag, reg: None)
    monkeypatch.setattr(
        tr,
        "_pic_binding_note",
        lambda frag, reg, sym_index: (
            f"PIC binding unresolved: reg={reg}, sym_index={sym_index}"
        ),
    )

    out = tr._try_pic(frag, lift, summary, xlen=64)

    assert out.kind == "unsupported"
    assert out.replacement == ""
    assert "does not map to a writable output operand" in out.notes[0]
    assert "reg=x10" in out.notes[1]
    assert "sym_index=3" in out.notes[1]


# ---------------------------------------------------------------------------
# _MICROARCH_PATTERNS 测试
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "asm_text",
    [
        "rdcycle a0",
        "rdcycleh a0",
        "rdtime a0",
        "rdtimeh a0",
        "rdinstret a0",
        "rdinstreth a0",
        "rdtsc",
        "rdtscp",
        "rdpmc",
        "csrr a0, cycle",
        "csrrs a0, time",
        "csrrc a0, instreth",
        "fence.i",
        "sfence.vma x0, x0",
        "hfence.gvma x0, x0",
        "ifence",
        "cbo.flush (a0)",
        "cbo.clean (a0)",
        "cbo.inval (a0)",
        "clflush [rax]",
        "clflushopt [rax]",
        "clwb [rax]",
        "prefetchnta [rax]",
        "pause",
        "wfi",
        "spectre gadget",
        "retpoline thunk",
        "rsb stuffing",
        "btb poisoning",
        "side-channel test",
        "flush+reload",
        "prime+probe",
        "evict+reload",
    ],
)
def test_microarch_patterns_detect_sensitive_instructions_and_markers(
    asm_text,
):
    assert any(pattern.search(asm_text) for pattern in tr._MICROARCH_PATTERNS), (
        f"未命中 microarchitecture-sensitive pattern: {asm_text!r}"
    )


@pytest.mark.parametrize(
    "asm_text",
    [
        "addi a0, a0, 1",
        "add a0, a1, a2",
        "sub a0, a1, a2",
        "lw a0, 0(a1)",
        "sw a0, 0(a1)",
        "beq a0, a1, label",
        "jal ra, function",
        "mul a0, a1, a2",
        "fence rw, rw",  # 普通内存屏障不等同于显式 microarch experiment marker
    ],
)
def test_microarch_patterns_do_not_overmatch_regular_instructions(asm_text):
    assert not any(pattern.search(asm_text) for pattern in tr._MICROARCH_PATTERNS)


# ---------------------------------------------------------------------------
# _try_lrsc_cas() 测试
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FakeCasModel:
    addr_operand_idx: int
    expected_operand_idx: int
    desired_operand_idx: int
    old_output_idx: int
    sc_status_output_idx: Optional[int]
    width: int
    is_weak: bool
    success_order: str
    failure_order: str
    explain: str

def _make_cas_model(
    *,
    addr_operand_idx=0,
    expected_operand_idx=1,
    desired_operand_idx=2,
    old_output_idx=0,
    sc_status_output_idx=None,
    width=64,
    is_weak=True,
    success_order="__ATOMIC_SEQ_CST",
    failure_order="__ATOMIC_ACQUIRE",
    explain="LR/SC CAS one-shot",
):
    return FakeCasModel(
        addr_operand_idx=addr_operand_idx,
        expected_operand_idx=expected_operand_idx,
        desired_operand_idx=desired_operand_idx,
        old_output_idx=old_output_idx,
        sc_status_output_idx=sc_status_output_idx,
        width=width,
        is_weak=is_weak,
        success_order=success_order,
        failure_order=failure_order,
        explain=explain,
    )


def test_try_lrsc_cas_returns_none_when_authoritative_cfg_unavailable(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()

    monkeypatch.setattr(
        tr,
        "_build_authoritative_cfg_from_lift",
        lambda lift: None,
    )

    def fail_detect(*args, **kwargs):
        pytest.fail("没有 authoritative CFG 时不应调用 _detect_lrsc_cas")

    monkeypatch.setattr(tr, "_detect_lrsc_cas", fail_detect)

    out = tr._try_lrsc_cas(frag, lift, summary, xlen=64)

    assert out is None


def test_try_lrsc_cas_returns_none_when_detector_does_not_match(monkeypatch):
    cfg = SimpleNamespace()
    frag = make_frag()
    lift = make_lift(insns=[SimpleNamespace()])
    summary = make_summary()

    monkeypatch.setattr(
        tr,
        "_build_authoritative_cfg_from_lift",
        lambda lift: cfg,
    )
    monkeypatch.setattr(
        tr,
        "_build_operand_index_map",
        lambda frag: {"dummy": 0},
    )
    monkeypatch.setattr(
        tr,
        "_detect_lrsc_cas",
        lambda insns, cfg, op_idx, output_count: None,
    )

    out = tr._try_lrsc_cas(frag, lift, summary, xlen=64)

    assert out is None


def test_try_lrsc_cas_corrects_weak_to_strong_when_cfg_has_retry_backedge(
    monkeypatch,
):
    cfg = SimpleNamespace(name="authoritative-cfg")

    outputs = [
        SimpleNamespace(exprText="old_value"),
    ]
    inputs = [
        SimpleNamespace(exprText="mem_word"),
        SimpleNamespace(exprText="expected"),
        SimpleNamespace(exprText="desired"),
    ]

    frag = make_frag(outputs=outputs, inputs=inputs)
    lift = make_lift(insns=[SimpleNamespace()])
    summary = make_summary()

    weak_cas = _make_cas_model(
        is_weak=True,
        explain="LR/SC CAS one-shot",
    )

    monkeypatch.setattr(
        tr,
        "_build_authoritative_cfg_from_lift",
        lambda lift: cfg,
    )
    monkeypatch.setattr(
        tr,
        "_build_operand_index_map",
        lambda frag: {"operand-map": True},
    )
    monkeypatch.setattr(
        tr,
        "_detect_lrsc_cas",
        lambda insns, cfg, op_idx, output_count: weak_cas,
    )
    monkeypatch.setattr(
        tr,
        "_has_retry_backedge",
        lambda lift, cfg: True,
    )

    out = tr._try_lrsc_cas(frag, lift, summary, xlen=64)

    assert out is not None
    assert out.kind == "pure_c"

    # weak 参数应由 1 改为 0，表示 strong CAS。
    assert "/*weak=*/0" in out.replacement
    assert "/*weak=*/1" not in out.replacement

    # one-shot 描述应被改写为 retry。
    assert any("retry" in note for note in out.notes)
    assert any("weak=False" in note for note in out.notes)
    assert "CFG source: pcode_ir.from_lifted() authoritative blocks" in out.notes


def test_try_lrsc_cas_emits_expected_atomic_compare_exchange(monkeypatch):
    cfg = SimpleNamespace()

    outputs = [
        SimpleNamespace(exprText="observed_old"),
    ]
    inputs = [
        SimpleNamespace(exprText="atomic_slot"),
        SimpleNamespace(exprText="expected_value"),
        SimpleNamespace(exprText="desired_value"),
    ]

    frag = make_frag(outputs=outputs, inputs=inputs)
    lift = make_lift(insns=[SimpleNamespace()])
    summary = make_summary()

    cas = _make_cas_model(
        width=32,
        is_weak=True,
        success_order="__ATOMIC_ACQ_REL",
        failure_order="__ATOMIC_ACQUIRE",
        explain="32-bit LR/SC CAS one-shot",
    )

    monkeypatch.setattr(
        tr,
        "_build_authoritative_cfg_from_lift",
        lambda lift: cfg,
    )
    monkeypatch.setattr(
        tr,
        "_build_operand_index_map",
        lambda frag: {},
    )
    monkeypatch.setattr(
        tr,
        "_detect_lrsc_cas",
        lambda insns, cfg, op_idx, output_count: cas,
    )
    monkeypatch.setattr(
        tr,
        "_has_retry_backedge",
        lambda lift, cfg: False,
    )

    out = tr._try_lrsc_cas(frag, lift, summary, xlen=64)

    assert "__atomic_compare_exchange_n(" in out.replacement
    assert "atomic_slot" in out.replacement
    assert "expected_value" in out.replacement
    assert "desired_value" in out.replacement
    assert "/*weak=*/1" in out.replacement
    assert "__ATOMIC_ACQ_REL" in out.replacement
    assert "__ATOMIC_ACQUIRE" in out.replacement
    assert "observed_old = __r2x_old_32;" in out.replacement
    assert out.replacement.endswith("} while (0);")


def test_try_lrsc_cas_preserves_sc_status_output(monkeypatch):
    cfg = SimpleNamespace()

    outputs = [
        SimpleNamespace(exprText="old_value"),
        SimpleNamespace(exprText="sc_status"),
    ]
    inputs = [
        SimpleNamespace(exprText="atomic_slot"),
        SimpleNamespace(exprText="expected_value"),
        SimpleNamespace(exprText="desired_value"),
    ]

    frag = make_frag(outputs=outputs, inputs=inputs)
    lift = make_lift(insns=[SimpleNamespace()])
    summary = make_summary()

    cas = _make_cas_model(
        old_output_idx=0,
        sc_status_output_idx=1,
        width=64,
        is_weak=False,
    )

    monkeypatch.setattr(
        tr,
        "_build_authoritative_cfg_from_lift",
        lambda lift: cfg,
    )
    monkeypatch.setattr(tr, "_build_operand_index_map", lambda frag: {})
    monkeypatch.setattr(
        tr,
        "_detect_lrsc_cas",
        lambda insns, cfg, op_idx, output_count: cas,
    )
    monkeypatch.setattr(
        tr,
        "_has_retry_backedge",
        lambda lift, cfg: False,
    )

    out = tr._try_lrsc_cas(frag, lift, summary, xlen=64)

    assert out.kind == "pure_c"
    assert "sc_status = (__typeof__(sc_status))" in out.replacement
    assert "? 0 : 1" in out.replacement
    assert "sc status output preserved: success->0, failure->1" in out.notes


def test_try_lrsc_cas_returns_none_for_invalid_old_output_index(monkeypatch):
    cfg = SimpleNamespace()

    frag = make_frag(
        outputs=[SimpleNamespace(exprText="only_output")],
        inputs=[
            SimpleNamespace(exprText="ptr"),
            SimpleNamespace(exprText="expected"),
            SimpleNamespace(exprText="desired"),
        ],
    )
    lift = make_lift(insns=[SimpleNamespace()])
    summary = make_summary()

    cas = _make_cas_model(old_output_idx=99)

    monkeypatch.setattr(
        tr,
        "_build_authoritative_cfg_from_lift",
        lambda lift: cfg,
    )
    monkeypatch.setattr(tr, "_build_operand_index_map", lambda frag: {})
    monkeypatch.setattr(
        tr,
        "_detect_lrsc_cas",
        lambda insns, cfg, op_idx, output_count: cas,
    )
    monkeypatch.setattr(
        tr,
        "_has_retry_backedge",
        lambda lift, cfg: False,
    )

    out = tr._try_lrsc_cas(frag, lift, summary, xlen=64)

    assert out is None


# ---------------------------------------------------------------------------
# _try_lrsc_rmw_x86_microarch() 测试
# ---------------------------------------------------------------------------

def test_try_lrsc_rmw_x86_microarch_returns_none_for_empty_lift():
    frag = make_frag()
    lift = make_lift(insns=[])
    summary = make_summary()

    out = tr._try_lrsc_rmw_x86_microarch(
        frag,
        lift,
        summary,
        xlen=64,
    )

    assert out is None


def test_try_lrsc_rmw_x86_microarch_returns_none_when_pattern_not_detected(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift(
        insns=[SimpleNamespace()],
        cfg=SimpleNamespace(name="lift-cfg"),
    )
    summary = make_summary()

    monkeypatch.setattr(
        tr,
        "_detect_lrsc_rmw",
        lambda insns, cfg: None,
    )

    out = tr._try_lrsc_rmw_x86_microarch(
        frag,
        lift,
        summary,
        xlen=64,
    )

    assert out is None


def test_try_lrsc_rmw_x86_microarch_emits_x86_inline_asm(monkeypatch):
    frag = make_frag()
    cfg = SimpleNamespace(name="lift-cfg")
    lift = make_lift(insns=[SimpleNamespace()], cfg=cfg)
    summary = make_summary()

    rmw_model = SimpleNamespace(
        explain="LR/SC atomic fetch_add retry loop",
    )

    captured = {}

    def fake_detect(insns, cfg):
        captured["detect_insns"] = insns
        captured["detect_cfg"] = cfg
        return rmw_model

    def fake_emit(frag, model):
        captured["emit_frag"] = frag
        captured["emit_model"] = model
        return (
            '__asm__ volatile("lock xaddq %%rax, (%0)" : : "r"(ptr) : "memory");',
            [
                "x86 lock xadd lowering",
                "LR/SC retry semantics preserved",
            ],
        )

    monkeypatch.setattr(tr, "_detect_lrsc_rmw", fake_detect)
    monkeypatch.setattr(tr, "_emit_lrsc_rmw_x86", fake_emit)

    out = tr._try_lrsc_rmw_x86_microarch(
        frag,
        lift,
        summary,
        xlen=64,
    )

    assert out is not None
    assert out.kind == "x86_inline_asm"
    assert 'lock xaddq' in out.replacement
    assert "x86 lock xadd lowering" in out.notes

    assert captured["detect_cfg"] is cfg
    assert captured["emit_frag"] is frag
    assert captured["emit_model"] is rmw_model


# ---------------------------------------------------------------------------
# _try_control_preserving_x86() 测试
# ---------------------------------------------------------------------------

def test_try_control_preserving_x86_returns_none_when_thunk_emitter_fails(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()
    decision = make_decision(
        level="C",
        route="needs_control_preserving_lowering",
    )

    monkeypatch.setattr(
        tr,
        "_emit_call_ret_helper_thunk",
        lambda frag, lift, xlen: None,
    )

    out = tr._try_control_preserving_x86(
        frag,
        lift,
        summary,
        decision,
        xlen=64,
    )

    assert out is None


def test_try_control_preserving_x86_adds_phase7_and_contract_notes(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    summary = make_summary()
    decision = make_decision(
        level="C",
        route="needs_control_preserving_lowering",
    )

    thunk_out = make_output(
        kind="phase6.lower_to_x86_inline_asm",
        replacement='__asm__ volatile("call target");',
        notes=["control-preserving x86 direct-call lowering"],
    )

    monkeypatch.setattr(
        tr,
        "_emit_call_ret_helper_thunk",
        lambda frag, lift, xlen: thunk_out,
    )

    out = tr._try_control_preserving_x86(
        frag,
        lift,
        summary,
        decision,
        xlen=64,
    )

    assert out is thunk_out
    assert out.kind == "phase6.lower_to_x86_inline_asm"

    assert "control-preserving x86 direct-call lowering" in out.notes
    assert "phase7 control-preserving path closed" in out.notes
    assert "rewriter should consume phase6.lower_to_x86_inline_asm" in out.notes
    assert "preservation.level=C" in out.notes
    assert "preservation.route=needs_control_preserving_lowering" in out.notes


# ---------------------------------------------------------------------------
# _close_to_x86_inline_asm_or_route() 测试
# ---------------------------------------------------------------------------

def test_close_to_x86_inline_asm_or_route_uses_needs_route_when_emit_fails(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    decision = make_decision(
        level="B",
        route="needs_memory_ordering_lowering",
        reasons=["barrier"],
    )

    monkeypatch.setattr(
        tr,
        "_try_emit_x86_inline_asm",
        lambda frag, lift, xlen, preserve_experiment: None,
    )

    captured = {}

    def fake_needs_route(*, route, decision, reasons):
        captured["route"] = route
        captured["decision"] = decision
        captured["reasons"] = reasons
        return make_output(kind="unsupported", replacement="")

    monkeypatch.setattr(tr, "_needs_route", fake_needs_route)

    out = tr._close_to_x86_inline_asm_or_route(
        route="needs_memory_ordering_lowering",
        decision=decision,
        frag=frag,
        lift=lift,
        xlen=64,
        reasons=["barrier cannot be represented as generic C"],
        preserve_experiment=False,
    )

    assert out.kind == "unsupported"
    assert captured["route"] == "needs_memory_ordering_lowering"
    assert captured["decision"] is decision
    assert captured["reasons"] == [
        "barrier cannot be represented as generic C",
    ]


def test_close_to_x86_inline_asm_or_route_attaches_semantic_x86_contract(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    decision = make_decision(
        level="A",
        route="needs_semantic_x86_lowering",
    )

    emitted = '__asm__ volatile("lock addq $1, (%0)" : : "r"(p) : "memory");'

    captured_emit = {}

    def fake_emit(frag, lift, xlen, preserve_experiment):
        captured_emit["frag"] = frag
        captured_emit["lift"] = lift
        captured_emit["xlen"] = xlen
        captured_emit["preserve_experiment"] = preserve_experiment
        return emitted

    monkeypatch.setattr(tr, "_try_emit_x86_inline_asm", fake_emit)

    out = tr._close_to_x86_inline_asm_or_route(
        route="needs_semantic_x86_lowering",
        decision=decision,
        frag=frag,
        lift=lift,
        xlen=64,
        reasons=["pure-C proof unavailable"],
        preserve_experiment=False,
    )

    assert captured_emit["frag"] is frag
    assert captured_emit["lift"] is lift
    assert captured_emit["xlen"] == 64
    assert captured_emit["preserve_experiment"] is False

    assert out.kind == "x86_inline_asm"
    assert out.replacement == emitted

    assert out.preservationLevel == "A"
    assert out.preservationRoute == "needs_semantic_x86_lowering"
    assert out.buildFamily == "x86_inline_asm"

    assert "fallback_semantic_x86" in out.reasonCodes
    assert "preserve_experiment" not in out.reasonCodes

    assert out.metadata["preserve_experiment"] is False
    assert "pure-C proof unavailable" in out.notes


def test_close_to_x86_inline_asm_or_route_marks_experiment_preservation(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    decision = make_decision(
        level="D",
        route="needs_experiment_preserving_lowering",
    )

    monkeypatch.setattr(
        tr,
        "_try_emit_x86_inline_asm",
        lambda frag, lift, xlen, preserve_experiment: (
            '__asm__ volatile("lfence" ::: "memory");'
        ),
    )

    out = tr._close_to_x86_inline_asm_or_route(
        route="needs_experiment_preserving_lowering",
        decision=decision,
        frag=frag,
        lift=lift,
        xlen=64,
        reasons=["cycle counter ordering must remain explicit"],
        preserve_experiment=True,
    )

    assert out.kind == "x86_inline_asm"
    assert out.preservationLevel == "D"
    assert out.preservationRoute == "needs_experiment_preserving_lowering"
    assert out.buildFamily == "x86_inline_asm"

    assert "fallback_semantic_x86" in out.reasonCodes
    assert "preserve_experiment" in out.reasonCodes
    assert out.metadata["preserve_experiment"] is True

    assert "cycle counter ordering must remain explicit" in out.notes


def test_close_to_x86_inline_asm_or_route_uses_asm_goto_build_family(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    decision = make_decision(
        level="C",
        route="x86_asm_goto",
    )

    monkeypatch.setattr(
        tr,
        "_try_emit_x86_inline_asm",
        lambda frag, lift, xlen, preserve_experiment: (
            '__asm__ goto("jmp %l0" : : : : target);'
        ),
    )

    out = tr._close_to_x86_inline_asm_or_route(
        route="x86_asm_goto",
        decision=decision,
        frag=frag,
        lift=lift,
        xlen=64,
        reasons=["branch target requires asm goto"],
        preserve_experiment=False,
    )

    # 当前实现的 kind 固定为 x86_inline_asm，
    # 但 build family 应显式标记为 x86_asm_goto。
    assert out.kind == "x86_inline_asm"
    assert out.buildFamily == "x86_asm_goto"
    assert out.preservationRoute == "x86_asm_goto"
    assert "fallback_semantic_x86" in out.reasonCodes


def test_close_to_x86_inline_asm_or_route_uses_decision_route_when_route_empty(
    monkeypatch,
):
    frag = make_frag()
    lift = make_lift()
    decision = make_decision(
        level="B",
        route="needs_stack_aware_lowering",
    )

    monkeypatch.setattr(
        tr,
        "_try_emit_x86_inline_asm",
        lambda frag, lift, xlen, preserve_experiment: (
            '__asm__ volatile("subq $16, %%rsp" ::: "memory");'
        ),
    )
    monkeypatch.setattr(
        tr,
        "_normalized_decision_route",
        lambda decision: "needs_stack_aware_lowering",
    )

    out = tr._close_to_x86_inline_asm_or_route(
        route="",
        decision=decision,
        frag=frag,
        lift=lift,
        xlen=64,
        reasons=["stack adjustment requires x86 lowering"],
        preserve_experiment=False,
    )

    assert out.kind == "x86_inline_asm"
    assert out.preservationLevel == "B"
    assert out.preservationRoute == "needs_stack_aware_lowering"


def test_pipeline_real_assemble_lift_translate_verify(tmp_path):
    """
    真实端到端集成测试：

        report JSON
          -> load_report()
          -> pipeline preflight
          -> assemble()
          -> lift()
          -> pcode_ir.from_lifted()
          -> translate()
          -> phase7 shell-semantics gate
          -> verify()
          -> save_report()

    不 mock assemble / lift / translate / verify。

    片段语义：

        asm("add %0, %1, %2"
            : "=r"(dst)
            : "r"(lhs), "r"(rhs));

    即：

        dst = lhs + rhs;
    """
    in_json = tmp_path / "input.json"
    out_json = tmp_path / "output.json"

    report = {
        "findings": [
            {
                "id": "pipeline-real-riscv-add",
                "category": "NeedsAsmTranslation",
                "rawAsmText": "add %0, %1, %2",
                "fragment": {
                    # 部分 schema 实现会从 finding.rawAsmText 读取，
                    # 部分会从 fragment.rawAsmText 读取。
                    # 两边均提供可以提高 fixture 对 schema 兼容性。
                    "rawAsmText": "add %0, %1, %2",

                    # 输出 %0
                    #
                    # 等价于 GCC:
                    #
                    #   "=r"(dst)
                    #
                    "outputs": [
                        {
                            "exprText": "dst",
                            "constraint": "=r",
                        }
                    ],

                    # 输入 %1 / %2
                    #
                    # 等价于 GCC:
                    #
                    #   "r"(lhs), "r"(rhs)
                    #
                    "inputs": [
                        {
                            "exprText": "lhs",
                            "constraint": "r",
                        },
                        {
                            "exprText": "rhs",
                            "constraint": "r",
                        },
                    ],

                    # 无 clobber，因此 pure-C 路径不会被 Phase 7 阻断。
                    "clobbers": [],

                    # 明确不是 volatile。
                    "isVolatile": False,

                    # 明确不是 asm goto。
                    "gotoLabels": [],
                },
            }
        ]
    }

    in_json.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    stats = run(
        str(in_json),
        str(out_json),
        xlen=64,
    )

    saved = json.loads(
        out_json.read_text(encoding="utf-8")
    )

    # ---------- 基本 pipeline 覆盖断言 ----------

    # 该 finding 必须被识别为真正进入 asm pipeline 的条目。
    assert stats["total"] == 1

    # 不应因为 fragment 缺失、rawAsmText 为空等原因进入 deferred 分支。
    assert stats["no_fragment"] == 0
    assert stats["deferred_non_fragment"] == 0

    # 不应被 asm goto 等 Phase 4 preflight blocker 拒绝。
    assert stats["unsupported"] == 0

    # 不应在 assemble / lift / translate / verify 中失败。
    assert stats["failed"] == 0

    # verify 的结果可能是 fully verified，也可能是 build_only。
    #
    # 取决于当前 verify() 是否已经实现运行时语义验证、
    # SMT 验证或仅具备编译验证能力。
    assert stats["verified"] + stats["build_only"] == 1

    # ---------- 输出 report 断言 ----------

    assert "findings" in saved
    assert len(saved["findings"]) == 1

    finding = saved["findings"][0]

    # 必须实际经过 assemble。
    assert finding.get("machineCodeHex"), (
        "pipeline should store assembled machine code"
    )

    # 必须实际经过 lift。
    assert finding.get("pcodeText"), (
        "pipeline should store lifted pcode text"
    )

    # translate 的结果应是可回填的 pure C 或 x86 inline asm。
    #
    # 如果当前 add 模式已被 canonical pure-C strategy 识别，
    # 通常为 pure_c；如果策略保守回退，则可能为 x86_inline_asm。
    assert finding.get("translationKind") in {
        "pure_c",
        "x86_inline_asm",
    }

    # 已经进入可回填阶段。
    assert finding.get("category") == "ReplaceableByRule"

    # 回填类型必须与 translationKind 一致。
    if finding["translationKind"] == "pure_c":
        assert finding.get("ruleName") == "phase6.lower_to_c"
    else:
        assert finding.get("ruleName") == "phase6.lower_to_x86_inline_asm"

    # 对 actionable translation，replacement 不能为空。
    assert finding.get("suggestedReplacement", "").strip()

    # verify() 必须产生最终状态。
    assert finding.get("verificationStatus") in {
        "verified",
        "build_only",
    }

    # 应存在 verification detail，方便确认不是 pipeline 静默跳过。
    assert finding.get("verificationDetail", "").strip()


def test_assemble_inline_asm_add_template(tmp_path):
    """
    验证 assemble() 能处理 GCC extended asm operand placeholder：

        add %0, %1, %2

    并且验证 JSON -> load_report -> fragment -> assemble 的实际链路。
    """
    in_json = tmp_path / "assemble-only-input.json"

    data = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "fragment": {
                    "rawAsmText": "add %0, %1, %2",
                    "outputs": [
                        {
                            "exprText": "dst",
                            "constraint": "=r",
                        }
                    ],
                    "inputs": [
                        {
                            "exprText": "lhs",
                            "constraint": "r",
                        },
                        {
                            "exprText": "rhs",
                            "constraint": "r",
                        },
                    ],
                    "clobbers": [],
                    "isVolatile": False,
                    "gotoLabels": [],
                },
            }
        ]
    }

    in_json.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    findings = load_report(str(in_json))

    assert len(findings) == 1
    assert findings[0].fragment is not None

    frag = findings[0].fragment

    assert frag.rawAsmText == "add %0, %1, %2"
    assert len(frag.outputs) == 1
    assert len(frag.inputs) == 2

    result = assemble(frag, xlen=64)

    assert result.ok, result.error
    assert result.machine_code

import inspect

from riscv2x86_py.translate import _iter_canonical_pure_c_strategies


def test_canonical_pure_c_strategies_accept_dispatcher_keywords():
    required = {
        "frag",
        "lift",
        "summary",
        "decision",
        "xlen",
    }

    for strategy in _iter_canonical_pure_c_strategies():
        params = inspect.signature(strategy).parameters

        accepts_var_kwargs = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in params.values()
        )

        missing = required - set(params)

        assert accepts_var_kwargs or not missing, (
            f"Canonical pure-C strategy {strategy.__name__!r} does not "
            f"implement the dispatcher protocol. Missing parameters: "
            f"{sorted(missing)}. Required protocol: "
            f"{sorted(required)}."
        )

def test_debug_riscv_add_translation_dataflow(tmp_path, monkeypatch):
    import riscv2x86_py.pipeline as pipeline

    captured = {}

    real_assemble = pipeline.assemble
    real_lift = pipeline.lift
    real_translate = pipeline.translate

    def traced_assemble(fragment, *, xlen):
        result = real_assemble(fragment, xlen=xlen)
        captured["assemble_fragment"] = fragment
        captured["assemble_result"] = result
        return result

    def traced_lift(machine_code, *, xlen, relocations):
        result = real_lift(
            machine_code,
            xlen=xlen,
            relocations=relocations,
        )
        captured["lift_machine_code"] = machine_code
        captured["lift_result"] = result
        return result

    def traced_translate(
        frag,
        lift_result,
        summary,
        *,
        machine_code=None,
        xlen=64,
    ):
        result = real_translate(
            frag,
            lift_result,
            summary,
            machine_code=machine_code,
            xlen=xlen,
        )
        captured["translate_fragment"] = frag
        captured["translate_lift"] = lift_result
        captured["translate_summary"] = summary
        captured["translate_result"] = result
        return result

    monkeypatch.setattr(pipeline, "assemble", traced_assemble)
    monkeypatch.setattr(pipeline, "lift", traced_lift)
    monkeypatch.setattr(pipeline, "translate", traced_translate)

    in_json = tmp_path / "input.json"
    out_json = tmp_path / "output.json"

    report = {
        "findings": [
            {
                "id": "debug-riscv-add",
                "category": "NeedsAsmTranslation",
                "rawAsmText": "add %0, %1, %2",
                "fragment": {
                    "rawAsmText": "add %0, %1, %2",
                    "outputs": [
                        {
                            "exprText": "dst",
                            "constraint": "=r",
                        }
                    ],
                    "inputs": [
                        {
                            "exprText": "lhs",
                            "constraint": "r",
                        },
                        {
                            "exprText": "rhs",
                            "constraint": "r",
                        },
                    ],
                    "clobbers": [],
                    "isVolatile": False,
                    "gotoLabels": [],
                },
            }
        ]
    }

    in_json.write_text(
        json.dumps(report, ensure_ascii=False),
        encoding="utf-8",
    )

    stats = pipeline.run(
        str(in_json),
        str(out_json),
        xlen=64,
    )

    tr = captured["translate_result"]
    lr = captured["lift_result"]
    ar = captured["assemble_result"]

    print("stats =", stats)
    print("assemble.ok =", ar.ok)
    print("assemble.machine_code =", ar.machine_code.hex())
    print("assemble.relocations =", ar.relocations)

    print("lift.ok =", lr.ok)
    print("lift.insns =")
    for insn in lr.insns:
        print("  addr:", hex(insn.addr))
        print("  mnem:", insn.asm_mnem)
        print("  body:", insn.asm_body)
        print("  pcode:", insn.pcode_ops)

    print("translate.kind =", tr.kind)
    print("translate.replacement =", repr(tr.replacement))
    print("translate.notes =")
    for note in tr.notes:
        print("  -", note)

    assert ar.ok
    assert lr.ok

    # 当前失败状态下，这个断言预计成立。
    assert tr.kind == "unsupported"

def test_debug_operand_mapper_materialized_vs_placeholder():
    # 原 GNU inline asm placeholder 应保持不变。
    assert translate_mod._map_operand_token("%0") == "%0"
    assert translate_mod._map_operand_token("%1") == "%1"
    assert translate_mod._map_operand_token("%2") == "%2"

    # lift 后 materialized RISC-V register 会被解释为固定 x86 ABI 寄存器。
    assert translate_mod._map_operand_token("a0") == "%rdi"
    assert translate_mod._map_operand_token("a1") == "%rsi"
    assert translate_mod._map_operand_token("a2") == "%rdx"

    print("placeholder mapping:")
    print("  %0 ->", translate_mod._map_operand_token("%0"))
    print("  %1 ->", translate_mod._map_operand_token("%1"))
    print("  %2 ->", translate_mod._map_operand_token("%2"))

    print("materialized register mapping:")
    print("  a0 ->", translate_mod._map_operand_token("a0"))
    print("  a1 ->", translate_mod._map_operand_token("a1"))
    print("  a2 ->", translate_mod._map_operand_token("a2"))

def test_debug_riscv_add_with_generic_intblock_pure_c_enabled(
    tmp_path,
    monkeypatch,
):
    report = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "rawAsmText": "add %0, %1, %2",
                "fragment": {
                    "rawAsmText": "add %0, %1, %2",
                    "outputs": [
                        {
                            "exprText": "dst",
                            "constraint": "=r",
                        }
                    ],
                    "inputs": [
                        {
                            "exprText": "lhs",
                            "constraint": "r",
                        },
                        {
                            "exprText": "rhs",
                            "constraint": "r",
                        },
                    ],
                    "clobbers": [],
                    "isVolatile": False,
                    "gotoLabels": [],
                },
            }
        ]
    }

    in_json = tmp_path / "input.json"
    out_json = tmp_path / "output.json"

    in_json.write_text(
        json.dumps(report, ensure_ascii=False),
        encoding="utf-8",
    )

    # 核心实验变量：
    # 让 translate() 接受 try_integer_block() 已生成的 pure-C block。
    monkeypatch.setattr(
        translate_mod,
        "_ALLOW_GENERIC_INTBLOCK_PURE_C",
        True,
    )

    stats = pipeline_mod.run(
        str(in_json),
        str(out_json),
        xlen=64,
    )

    saved = json.loads(out_json.read_text(encoding="utf-8"))
    finding = saved["findings"][0]

    print("stats =", stats)
    print("category =", finding.get("category"))
    print("ruleName =", finding.get("ruleName"))
    print("translationKind =", finding.get("translationKind"))
    print("verificationStatus =", finding.get("verificationStatus"))
    print("verificationDetail =", finding.get("verificationDetail"))
    print("suggestedReplacement =")
    print(finding.get("suggestedReplacement", ""))
    print("notes =")
    for note in finding.get("notes", []):
        print("  -", note)

    # 重点不在是否一定 verified。
    # 某些工程中 generated C 还需额外 build context。
    # 重点是：不应再是 phase6.unsupported。
    assert stats["unsupported"] == 0
    assert finding.get("ruleName") != "phase6.unsupported"


def test_debug_translate_add_line_to_x86():
    out = translate_mod._translate_one_rv_line_to_x86(
        "add a0,a1,a2"
    )

    print("x86 translation =", out)

    assert out == [
        "movq %rsi, %rdi",
        "addq %rdx, %rdi",
    ]

def test_debug_capture_x86_emit_for_riscv_add(tmp_path, monkeypatch):
    report = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "rawAsmText": "add %0, %1, %2",
                "fragment": {
                    "rawAsmText": "add %0, %1, %2",
                    "outputs": [
                        {
                            "exprText": "dst",
                            "constraint": "=r",
                        }
                    ],
                    "inputs": [
                        {
                            "exprText": "lhs",
                            "constraint": "r",
                        },
                        {
                            "exprText": "rhs",
                            "constraint": "r",
                        },
                    ],
                    "clobbers": [],
                    "isVolatile": False,
                    "gotoLabels": [],
                },
            }
        ]
    }

    in_json = tmp_path / "in.json"
    out_json = tmp_path / "out.json"
    in_json.write_text(json.dumps(report), encoding="utf-8")

    original_emit = translate_mod._try_emit_x86_inline_asm
    captured = {}

    def wrapped_emit(frag, lift, *, xlen, preserve_experiment):
        captured["rawAsmText"] = getattr(frag, "rawAsmText", None)
        captured["outputs"] = getattr(frag, "outputs", None)
        captured["inputs"] = getattr(frag, "inputs", None)
        captured["xlen"] = xlen
        captured["preserve_experiment"] = preserve_experiment

        captured["lifted"] = [
            {
                "mnem": getattr(ins, "asm_mnem", None),
                "body": getattr(ins, "asm_body", None),
                "text": (
                    f"{getattr(ins, 'asm_mnem', '')} "
                    f"{getattr(ins, 'asm_body', '')}"
                ).strip(),
            }
            for ins in (getattr(lift, "insns", None) or [])
        ]

        result = original_emit(
            frag,
            lift,
            xlen=xlen,
            preserve_experiment=preserve_experiment,
        )
        captured["result"] = result
        return result

    monkeypatch.setattr(
        translate_mod,
        "_try_emit_x86_inline_asm",
        wrapped_emit,
    )

    stats = pipeline_mod.run(
        str(in_json),
        str(out_json),
        xlen=64,
    )

    print("stats =", stats)
    print("x86 emitter captured input:")
    print(json.dumps(captured, indent=2, default=str))

    assert captured["rawAsmText"] == "add %0, %1, %2"
    assert captured["lifted"]
    assert captured["lifted"][0]["mnem"] == "add"
    assert captured["result"] is None or captured["result"] == ""