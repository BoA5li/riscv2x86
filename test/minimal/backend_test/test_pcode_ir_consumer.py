from __future__ import annotations

import ast
import importlib
import inspect
import os
import re
import textwrap
import json
from enum import Enum
from types import SimpleNamespace
from typing import Any, Optional

import pytest
from dataclasses import dataclass
from pytools.riscv2x86_py.schema import AsmFragment
from pytools.riscv2x86_py.runtime_facts import TranslationRuntimeFacts, build_translation_runtime_facts 
from pytools.riscv2x86_py.translate import translate
from pytools.riscv2x86_py.schema import AsmOperand, Finding
from pytools.riscv2x86_py.assemble import assemble
from pytools.riscv2x86_py import pipeline
from pytools.riscv2x86_py.lift import lift
from pytools.riscv2x86_py.pcode_ir import from_lifted, CanonicalInsn, Op, CanonicalInsn, _summarize_instructions 
from pytools.riscv2x86_py.cfg import build_cfg_from_blocks
from pytools.riscv2x86_py.x86_att_integer_lowering import lower_normalized_add_sub_to_x86_att
from pathlib import Path

# ---------------------------------------------------------------------------
# Module configuration
#
# Run example:
#
#   PHASE6_X86_MODULE=translator.x86_att_integer_lowering \
#   PCODE_IR_MODULE=translator.pcode_ir \
#   pytest -q tests/test_phase6_structured_ir_contract.py
#
# Or replace defaults below with your real package paths.
# ---------------------------------------------------------------------------

PHASE6_X86_MODULE = os.environ.get(
    "PHASE6_X86_MODULE",
    "pytools.riscv2x86_py.x86_att_integer_lowering",
)

PCODE_IR_MODULE = os.environ.get(
    "PCODE_IR_MODULE",
    "pytools.riscv2x86_py.pcode_ir",
)


@pytest.fixture(scope="module")
def lowering_module():
    return importlib.import_module(PHASE6_X86_MODULE)


@pytest.fixture(scope="module")
def pcode_ir_module():
    return importlib.import_module(PCODE_IR_MODULE)

@pytest.fixture(scope="module")
def Op(pcode_ir_module):
    return pcode_ir_module.Op


@pytest.fixture(scope="module")
def Var(pcode_ir_module):
    return pcode_ir_module.Var


@pytest.fixture(scope="module")
def VarKind(pcode_ir_module):
    return pcode_ir_module.VarKind


@pytest.fixture(scope="module")
def Block(pcode_ir_module):
    """
    Expected pcode_ir exports Block.

    If your concrete block class has a different name, update this fixture
    only. The rest of the tests should not need changes.
    """
    try:
        return pcode_ir_module.Block
    except AttributeError as exc:
        raise AssertionError(
            "pcode_ir must expose a structured Block class for Phase 6 "
            "canonical semantic input"
        ) from exc


# ---------------------------------------------------------------------------
# Low-level object construction helpers
#
# These intentionally avoid relying on exact dataclass constructor signatures.
# They only require the semantic attributes used by the lowering contract:
#
#   Var.kind
#   Var.name
#   Op.opcode
#   Op.output
#   Op.inputs
#   Block.ops
#
# If your IR uses frozen dataclasses or slots, object.__setattr__ still works
# for declared fields.
# ---------------------------------------------------------------------------

def make_var(Var: type, VarKind: Any, name: Any) -> Any:
    var = object.__new__(Var)
    object.__setattr__(var, "kind", VarKind.REG)
    object.__setattr__(var, "name", name)
    return var


def make_op(
    Op: type,
    *,
    opcode: Any,
    output: Any = None,
    inputs: Any = (),
) -> Any:
    op = object.__new__(Op)
    object.__setattr__(op, "opcode", opcode)
    object.__setattr__(op, "output", output)
    object.__setattr__(op, "inputs", list(inputs))
    return op


def make_block(Block: type, ops: list[Any]) -> Any:
    block = object.__new__(Block)
    object.__setattr__(block, "ops", ops)
    return block


class PoisonLiftResultContext:
    """
    If a structured lowering path attempts to access lift_result, this test
    fails immediately.

    This catches accidental regressions such as:

        context.lift_result.insns[*].pcode_ops
        str(op)
        regex parsing of original lifted p-code text
    """

    def __init__(self, *, blocks, cfg):
        self.blocks = blocks
        self.cfg = cfg

    @property
    def lift_result(self):
        raise AssertionError(
            "structured Phase 6 lowering must not access context.lift_result"
        )

    @property
    def lift(self):
        raise AssertionError(
            "structured Phase 6 lowering must not access context.lift"
        )

    @property
    def pcodeText(self):
        raise AssertionError(
            "structured Phase 6 lowering must not access diagnostic pcodeText"
        )

    @property
    def instructions(self):
        raise AssertionError(
            "structured Phase 6 lowering must not access instruction text"
        )


# ---------------------------------------------------------------------------
# Structured semantic extraction tests
# ---------------------------------------------------------------------------

def test_extract_add_sub_uses_blocks_not_lift_result_or_pcode_text(
    lowering_module,
    Op,
    Var,
    VarKind,
    Block,
):
    """
    Core Phase-6 migration test.

    The context deliberately makes lift_result, lift, pcodeText and
    instructions unusable. Successful lowering proves that semantic matching
    comes from context.blocks only.
    """
    a0 = make_var(Var, VarKind, "a0")
    a1 = make_var(Var, VarKind, "a1")
    a2 = make_var(Var, VarKind, "a2")

    add = make_op(
        Op,
        opcode="INT_ADD",
        output=a0,
        inputs=[a1, a2],
    )

    block = make_block(Block, [add])

    context = PoisonLiftResultContext(
        blocks=[block],
        cfg=object(),
    )

    operations, reason, saw_semantic = (
        lowering_module._extract_add_sub_operations(context)
    )

    assert reason is None
    assert saw_semantic is True
    assert operations == [
        ("add", "a0", "a1", "a2"),
    ]


def test_extract_add_sub_accepts_enum_opcode(
    lowering_module,
    Op,
    Var,
    VarKind,
    Block,
):
    """
    Regression test for the old implementation:

        str(op.opcode).upper()

    Enum stringification can produce "Opcode.INT_ADD", which does not equal
    "INT_ADD". The structured helper must prefer .name / .value.
    """

    class Opcode(Enum):
        INT_ADD = "INT_ADD"

    a0 = make_var(Var, VarKind, "a0")
    a1 = make_var(Var, VarKind, "a1")
    a2 = make_var(Var, VarKind, "a2")

    op = make_op(
        Op,
        opcode=Opcode.INT_ADD,
        output=a0,
        inputs=[a1, a2],
    )

    context = SimpleNamespace(
        blocks=[make_block(Block, [op])],
        cfg=object(),
    )

    operations, reason, saw_semantic = (
        lowering_module._extract_add_sub_operations(context)
    )

    assert reason is None
    assert saw_semantic is True
    assert operations == [
        ("add", "a0", "a1", "a2"),
    ]


def test_extract_add_sub_ignores_imark_metadata(
    lowering_module,
    Op,
    Var,
    VarKind,
    Block,
):
    a0 = make_var(Var, VarKind, "a0")
    a1 = make_var(Var, VarKind, "a1")
    a2 = make_var(Var, VarKind, "a2")

    imark = make_op(
        Op,
        opcode="IMARK",
        output=None,
        inputs=[],
    )

    add = make_op(
        Op,
        opcode="INT_ADD",
        output=a0,
        inputs=[a1, a2],
    )

    context = SimpleNamespace(
        blocks=[make_block(Block, [imark, add])],
        cfg=object(),
    )

    operations, reason, saw_semantic = (
        lowering_module._extract_add_sub_operations(context)
    )

    assert reason is None
    assert saw_semantic is True
    assert operations == [
        ("add", "a0", "a1", "a2"),
    ]


def test_extract_add_sub_rejects_missing_cfg(
    lowering_module,
    Op,
    Var,
    VarKind,
    Block,
):
    """
    Phase 6 must operate only after the structured Block/CFG path has been
    established by:

        from_lifted(...)
        build_cfg_from_blocks(...)
        translate(... blocks=..., cfg=...)
    """
    a0 = make_var(Var, VarKind, "a0")
    a1 = make_var(Var, VarKind, "a1")
    a2 = make_var(Var, VarKind, "a2")

    op = make_op(
        Op,
        opcode="INT_ADD",
        output=a0,
        inputs=[a1, a2],
    )

    context = SimpleNamespace(
        blocks=[make_block(Block, [op])],
        cfg=None,
    )

    operations, reason, saw_semantic = (
        lowering_module._extract_add_sub_operations(context)
    )

    assert operations == []
    assert saw_semantic is False
    assert reason is not None
    assert "CFG" in reason


def test_extract_add_sub_rejects_cross_block_linearization(
    lowering_module,
    Op,
    Var,
    VarKind,
    Block,
):
    """
    A lowerer must not silently concatenate semantic operations from multiple
    blocks, because separate blocks can represent branch successors, loop
    bodies, fallthrough edges, or other non-linear CFG paths.
    """
    a0 = make_var(Var, VarKind, "a0")
    a1 = make_var(Var, VarKind, "a1")
    a2 = make_var(Var, VarKind, "a2")
    a3 = make_var(Var, VarKind, "a3")

    add = make_op(
        Op,
        opcode="INT_ADD",
        output=a0,
        inputs=[a1, a2],
    )

    sub = make_op(
        Op,
        opcode="INT_SUB",
        output=a0,
        inputs=[a0, a3],
    )

    context = SimpleNamespace(
        blocks=[
            make_block(Block, [add]),
            make_block(Block, [sub]),
        ],
        cfg=object(),
    )

    operations, reason, saw_semantic = (
        lowering_module._extract_add_sub_operations(context)
    )

    assert operations == []
    assert saw_semantic is True
    assert reason is not None
    assert "one" in reason.lower()
    assert "block" in reason.lower()


def test_extract_add_sub_rejects_non_add_sub_semantic_op(
    lowering_module,
    Op,
    Var,
    VarKind,
    Block,
):
    """
    The minimal structured strategy is intentionally conservative.

    It may recognize INT_ADD / INT_SUB, but must not pretend that unrelated
    p-code operations can be safely ignored.
    """
    a0 = make_var(Var, VarKind, "a0")
    a1 = make_var(Var, VarKind, "a1")

    copy = make_op(
        Op,
        opcode="COPY",
        output=a0,
        inputs=[a1],
    )

    context = SimpleNamespace(
        blocks=[make_block(Block, [copy])],
        cfg=object(),
    )

    operations, reason, saw_semantic = (
        lowering_module._extract_add_sub_operations(context)
    )

    assert operations == []
    assert saw_semantic is True
    assert reason is not None
    assert "COPY" in reason


def test_extract_add_sub_rejects_non_string_register_name(
    lowering_module,
    Op,
    Var,
    VarKind,
    Block,
):
    """
    The lowerer must not do:

        str(var.name)

    A register identity must already be a structured explicit string name.
    """
    a0 = make_var(Var, VarKind, "a0")
    a1 = make_var(Var, VarKind, object())
    a2 = make_var(Var, VarKind, "a2")

    op = make_op(
        Op,
        opcode="INT_ADD",
        output=a0,
        inputs=[a1, a2],
    )

    context = SimpleNamespace(
        blocks=[make_block(Block, [op])],
        cfg=object(),
    )

    operations, reason, saw_semantic = (
        lowering_module._extract_add_sub_operations(context)
    )

    assert operations == []
    assert saw_semantic is True
    assert reason is not None
    assert "register" in reason.lower()


def test_structured_register_name_accepts_only_reg_var_kind(
    lowering_module,
    Var,
    VarKind,
):
    """
    A constant, unique temporary, memory varnode, or other non-register
    varnode must not be silently treated as a RISC-V GPR.
    """
    var = object.__new__(Var)

    # Pick any non-REG enum member available in the implementation.
    non_reg_kind = next(
        kind
        for kind in VarKind
        if kind != VarKind.REG
    )

    object.__setattr__(var, "kind", non_reg_kind)
    object.__setattr__(var, "name", "a0")

    assert lowering_module._structured_riscv_register_name(var) is None


# ---------------------------------------------------------------------------
# Runtime facts / binding authority tests
# ---------------------------------------------------------------------------

def make_binding(
    *,
    operand_index: int,
    width_bits: int,
):
    return SimpleNamespace(
        operandIndex=operand_index,
        widthBits=width_bits,
    )


def make_runtime_context(
    *,
    rv_to_operand_index,
    operand_width_bits,
    binding_rv_to_operand,
    binding_errors=None,
):
    runtime_facts = SimpleNamespace(
        rv_to_operand_index=rv_to_operand_index,
        operand_width_bits=operand_width_bits,
    )

    bindings = SimpleNamespace(
        rv_to_operand=binding_rv_to_operand,
        errors=[] if binding_errors is None else binding_errors,
    )

    return SimpleNamespace(
        runtimeFacts=runtime_facts,
        bindings=bindings,
    )


def test_runtime_facts_are_authoritative_for_operand_binding(
    lowering_module,
):
    """
    Binding must come from:

        runtimeFacts.rv_to_operand_index
        runtimeFacts.operand_width_bits
        bindings.rv_to_operand

    It must not be inferred from register spelling order, x-register number,
    XLEN, p-code position, or host expression ordering.
    """
    binding = make_binding(
        operand_index=7,
        width_bits=64,
    )

    context = make_runtime_context(
        rv_to_operand_index={"a0": 7},
        operand_width_bits={7: 64},
        binding_rv_to_operand={"a0": binding},
    )

    resolved = lowering_module.resolve_pcode_register_x86_binding(
        context,
        "a0",
    )

    assert resolved is binding


def test_runtime_facts_allow_x_register_alias_only_after_canonicalization(
    lowering_module,
):
    """
    RISC-V x10 and ABI name a0 may both represent the same canonical register.

    The implementation may accept this only after canonicalization, not via
    ad hoc string parsing in the lowering strategy.
    """
    binding = make_binding(
        operand_index=3,
        width_bits=64,
    )

    context = make_runtime_context(
        rv_to_operand_index={"x10": 3},
        operand_width_bits={3: 64},
        binding_rv_to_operand={"a0": binding},
    )

    resolved = lowering_module.resolve_pcode_register_x86_binding(
        context,
        "a0",
    )

    assert resolved is binding


def test_runtime_facts_reject_conflicting_canonical_aliases(
    lowering_module,
):
    """
    This catches invalid runtime facts such as:

        a0  -> operand 0
        x10 -> operand 1

    Both canonicalize to a0, so this is ambiguous and must be rejected.
    """
    binding = make_binding(
        operand_index=0,
        width_bits=64,
    )

    context = make_runtime_context(
        rv_to_operand_index={
            "a0": 0,
            "x10": 1,
        },
        operand_width_bits={
            0: 64,
            1: 64,
        },
        binding_rv_to_operand={"a0": binding},
    )

    with pytest.raises(lowering_module.UnsupportedTranslationError):
        lowering_module.resolve_pcode_register_x86_binding(
            context,
            "a0",
        )


def test_runtime_facts_reject_missing_width_fact(
    lowering_module,
):
    binding = make_binding(
        operand_index=0,
        width_bits=64,
    )

    context = make_runtime_context(
        rv_to_operand_index={"a0": 0},
        operand_width_bits={},
        binding_rv_to_operand={"a0": binding},
    )

    with pytest.raises(lowering_module.UnsupportedTranslationError):
        lowering_module.resolve_pcode_register_x86_binding(
            context,
            "a0",
        )


def test_x86_add_sub_requires_proven_64_bit_host_operand(
    lowering_module,
):
    binding = make_binding(
        operand_index=0,
        width_bits=32,
    )

    context = make_runtime_context(
        rv_to_operand_index={"a0": 0},
        operand_width_bits={0: 32},
        binding_rv_to_operand={"a0": binding},
    )

    with pytest.raises(lowering_module.UnsupportedTranslationError) as exc:
        lowering_module.require_x86_att_64bit_pcode_register_binding(
            context,
            "a0",
        )

    assert "64-bit" in str(exc.value)


# ---------------------------------------------------------------------------
# Source-level architecture guards
#
# These tests are intentionally narrow. They do not ban all use of str() or
# regex in the module, because rendering/logging code may legitimately need
# them. They ban semantic extraction from using text parsing.
# ---------------------------------------------------------------------------

def _function_ast(function: Any) -> ast.AST:
    source = inspect.getsource(function)
    return ast.parse(textwrap.dedent(source))


def _called_getattr_fields(tree: ast.AST) -> set[str]:
    fields: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Name):
            continue

        if node.func.id != "getattr":
            continue

        if len(node.args) < 2:
            continue

        field_node = node.args[1]

        if isinstance(field_node, ast.Constant) and isinstance(
            field_node.value,
            str,
        ):
            fields.add(field_node.value)

    return fields


def _contains_str_call_on_name(tree: ast.AST, name: str) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Name):
            continue

        if node.func.id != "str":
            continue

        if not node.args:
            continue

        arg = node.args[0]

        if isinstance(arg, ast.Name) and arg.id == name:
            return True

    return False


def _contains_regex_call(tree: ast.AST) -> bool:
    """
    Detect typical regex use patterns:

        re.match(...)
        re.search(...)
        re.fullmatch(...)
        re.compile(...)
        re.findall(...)
        re.finditer(...)
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func

        if not isinstance(func, ast.Attribute):
            continue

        if not isinstance(func.value, ast.Name):
            continue

        if func.value.id != "re":
            continue

        return True

    return False


def test_semantic_extractor_does_not_access_lift_or_pcode_text(
    lowering_module,
):
    """
    This is a regression guard against accidentally reintroducing:

        context.lift_result.insns[*].pcode_ops
        context.lift.insns[*].pcode_ops
        context.pcodeText
        context.instructions

    as semantic sources.
    """
    tree = _function_ast(
        lowering_module._extract_add_sub_operations
    )

    accessed_fields = _called_getattr_fields(tree)

    forbidden = {
        "lift_result",
        "lift",
        "pcodeText",
        "instructions",
        "insns",
        "pcode_ops",
    }

    assert not (accessed_fields & forbidden), (
        "structured semantic extractor must use canonical context.blocks / "
        "context.cfg, not lifted text fields; "
        f"forbidden accesses={accessed_fields & forbidden}"
    )


def test_semantic_extractor_does_not_use_regex(
    lowering_module,
):
    tree = _function_ast(
        lowering_module._extract_add_sub_operations
    )

    assert not _contains_regex_call(tree), (
        "_extract_add_sub_operations must not parse p-code using regex"
    )


def test_semantic_extractor_does_not_stringify_op(
    lowering_module,
):
    """
    Directly guards against the historical anti-pattern:

        str(op).strip()

    Opcode semantics must come from op.opcode / enum.name / enum.value.
    """
    tree = _function_ast(
        lowering_module._extract_add_sub_operations
    )

    assert not _contains_str_call_on_name(tree, "op"), (
        "_extract_add_sub_operations must not use str(op) as a semantic "
        "source"
    )


def test_structured_opcode_normalizer_does_not_stringify_opcode(
    lowering_module,
):
    """
    The normalization helper may inspect:

        opcode
        opcode.name
        opcode.value

    but should not rely on:

        str(opcode)

    because enum stringification is implementation-defined and can produce
    values such as 'Opcode.INT_ADD'.
    """
    tree = _function_ast(
        lowering_module._structured_opcode_name
    )

    assert not _contains_str_call_on_name(tree, "raw_opcode"), (
        "_structured_opcode_name must not depend on str(raw_opcode)"
    )


def test_structured_register_helper_does_not_stringify_var_name(
    lowering_module,
):
    tree = _function_ast(
        lowering_module._structured_riscv_register_name
    )

    assert not _contains_str_call_on_name(tree, "raw_name"), (
        "_structured_riscv_register_name must reject non-string names rather "
        "than stringify them"
    )

@dataclass
class DummyLift:
    insns: list[Any]


@dataclass
class DummySummary:
    pass

def make_fragment_for_add_a0_a1(
    *,
    fragment_id: str = "test-add-a0-a1",
) -> AsmFragment:
    """
    构造一个最小 GNU extended inline-asm fragment：

        asm("add %0, %0, %1" : "+r"(lhs) : "r"(rhs));

    语义上对应：

        lhs = lhs + rhs

    注意：
      * 输出 operand 0 是 read-write，因此使用 +r；
      * 输入 operand 1 对应 rhs；
      * operand_width_bits 由 Phase 4 输入预先提供；
      * 真正的 RISC-V register -> operand 映射必须由 assemble()
        / build_translation_runtime_facts() 生成，而不是这里猜测。
    """
    return AsmFragment(
        kind="InlineExtended",
        rawAsmText="add %0, %0, %1",
        id=fragment_id,
        fragmentId=fragment_id,
        outputs=[
            AsmOperand(
                constraint="+r",
                exprText="lhs",
                symbolicName="",
                isOutput=True,
                isTied=True,
                isEarlyClobber=False,
            ),
        ],
        inputs=[
            AsmOperand(
                constraint="r",
                exprText="rhs",
                symbolicName="",
                isOutput=False,
                isTied=False,
                isEarlyClobber=False,
            ),
        ],
        operand_width_bits={
            0: 64,
            1: 64,
        },
    )

def make_needs_asm_translation_finding(
    *,
    asm_text: str = "add %0, %0, %1",
    fragment_id: str = "test-needs-asm-translation",
) -> Finding:
    """
    构造一个能够进入 pipeline Phase 4 -> 6 的 Finding。

    不设置 pcodeText：
      pcodeText 是 Phase 5 的诊断输出，不应成为 Phase 6 语义输入。
    """
    fragment = make_fragment_for_add_a0_a1(
        fragment_id=fragment_id,
    )

    fragment.rawAsmText = asm_text

    return Finding(
        category="NeedsAsmTranslation",
        description="test GNU inline asm fragment",
        subjectKind="AsmFragment",
        hasRewriteRange=True,
        rewriteBeginOffset=0,
        rewriteEndOffset=len(asm_text),
        rawSourceText=asm_text,
        fileName="test_add.c",
        line=1,
        column=1,
        fragment=fragment,
    )

def _minimal_inputs():
    frag = AsmFragment(
        rawAsmText="add a0, a0, a1",
        id="frag-translate-contract",
        fragmentId="frag-translate-contract",
    )

    lift = DummyLift(insns=[])
    summary = DummySummary()

    return {
        "frag": frag,
        "lift": lift,
        "summary": summary,
        "machine_code": b"\x00\x00\x00\x00",
        "xlen": 64,
    }

_REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")
def _reason_codes(result) -> set[str]:
    """
    当前 TranslationOutput 尚未将 reason code 作为独立结构化字段保存，
    translator 会把 machine-readable code 附加到 notes 中。

    这里同时兼容未来可能增加的 reason_codes / reasonCodes 字段。
    """
    codes = set()

    for attr_name in ("reason_codes", "reasonCodes"):
        value = getattr(result, attr_name, None)
        if value:
            codes.update(str(item) for item in value)

    for note in getattr(result, "notes", []) or []:
        text = str(note).strip()
        if _REASON_CODE_RE.fullmatch(text):
            codes.add(text)

    return codes


def test_translate_rejects_missing_authoritative_blocks():
    inputs = _minimal_inputs()

    runtime_facts = TranslationRuntimeFacts(
        rv_to_operand_index={"a0": 0},
        operand_width_bits={0: 64},
    )

    result = translate(
        **inputs,
        blocks=None,
        cfg=None,
        runtime_facts=runtime_facts,
    )

    assert result.kind == "unsupported"
    assert "TR_MISSING_AUTHORITATIVE_BLOCKS" in _reason_codes(result)


def test_translate_rejects_missing_runtime_facts():
    inputs = _minimal_inputs()

    result = translate(
        **inputs,
        blocks=[object()],
        cfg=FakeCFG(ok=True),
        runtime_facts=None,
    )

    assert result.kind == "unsupported"
    assert "TR_MISSING_TRANSLATION_RUNTIME_FACTS" in _reason_codes(result)

def test_translate_rejects_runtime_facts_without_register_bindings():
    inputs = _minimal_inputs()

    runtime_facts = TranslationRuntimeFacts(
        rv_to_operand_index={},
        operand_width_bits={0: 64},
    )

    result = translate(
        **inputs,
        blocks=[object()],
        cfg=FakeCFG(ok=True),
        runtime_facts=runtime_facts,
    )

    assert result.kind == "unsupported"
    assert "TR_MISSING_RUNTIME_OPERAND_BINDINGS" in _reason_codes(result)

def test_translate_rejects_runtime_facts_without_operand_widths():
    inputs = _minimal_inputs()

    runtime_facts = TranslationRuntimeFacts(
        rv_to_operand_index={"a0": 0, "a1": 1},
        operand_width_bits={},
    )

    result = translate(
        **inputs,
        blocks=[object()],
        cfg=FakeCFG(ok=True),
        runtime_facts=runtime_facts,
    )

    assert result.kind == "unsupported"
    assert "TR_MISSING_RUNTIME_OPERAND_WIDTHS" in _reason_codes(result)

@dataclass
class FakeAssembleResult:
    ok: bool = True
    machine_code: bytes = b"\x13\x05\x15\x00"  # 示例，不要求真实语义
    relocations: list[Any] = None
    error: str = ""
    translation_runtime_facts: Any = None

    def __post_init__(self):
        if self.relocations is None:
            self.relocations = []


@dataclass
class FakeLiftResult:
    ok: bool = True
    insns: list[Any] = None
    error: str = ""

    def __post_init__(self):
        if self.insns is None:
            self.insns = []


@dataclass
class FakeCFG:
    ok: bool = True
    error: str = ""


@dataclass
class FakeFactsBuildResult:
    ok: bool
    facts: TranslationRuntimeFacts | None
    error: str = ""


@dataclass
class FakeTranslationOutput:
    kind: str = "needs_route"
    replacement: str = ""
    notes: list[str] = None

    def __post_init__(self):
        if self.notes is None:
            self.notes = ["test route result"]


def test_pipeline_passes_same_runtime_facts_object_to_translate(
    monkeypatch,
    tmp_path,
):
    """
    验证：
      Phase 4 build_translation_runtime_facts() 生成的 facts，
      经 f.translationRuntimeFacts 回填后，
      被原样传入 translate()。

    这里使用 `is`，而不是 `==`，确保是同一个对象。
    """

    runtime_facts = TranslationRuntimeFacts(
        rv_to_operand_index={
            "a0": 0,
            "a1": 1,
        },
        operand_width_bits={
            0: 64,
            1: 64,
        },
        provenance="test-authoritative-facts",
    )

    authoritative_blocks = [object()]
    authoritative_summary = object()
    captured = {}

    finding = make_needs_asm_translation_finding(
        asm_text="add a0, a0, a1"
    )

    monkeypatch.setattr(
        pipeline,
        "load_report",
        lambda _: [finding],
    )
    monkeypatch.setattr(
        pipeline,
        "save_report",
        lambda findings, _: None,
    )

    monkeypatch.setattr(
        pipeline,
        "_phase4_preflight_blockers",
        lambda finding: [],
    )
    monkeypatch.setattr(
        pipeline,
        "_get_fragment_operand_width_bits",
        lambda fragment: ({0: 64, 1: 64}, []),
    )

    monkeypatch.setattr(
        pipeline,
        "assemble",
        lambda *args, **kwargs: FakeAssembleResult(
            translation_runtime_facts=None,
        ),
    )

    monkeypatch.setattr(
        pipeline,
        "build_translation_runtime_facts",
        lambda finding, assemble_result: FakeFactsBuildResult(
            ok=True,
            facts=runtime_facts,
        ),
    )

    monkeypatch.setattr(
        pipeline,
        "lift",
        lambda *args, **kwargs: FakeLiftResult(insns=[]),
    )

    monkeypatch.setattr(
        pipeline,
        "from_lifted",
        lambda insns: (authoritative_blocks, authoritative_summary),
    )

    monkeypatch.setattr(
        pipeline,
        "build_cfg_from_blocks",
        lambda blocks: FakeCFG(ok=True),
    )

    monkeypatch.setattr(
        pipeline,
        "_render_lifted_pcode_for_diagnostics",
        lambda lr: "DIAGNOSTIC-PCODE-TEXT-MUST-NOT-BE-SEMANTIC-INPUT",
    )

    def fake_translate(
        *,
        frag,
        lift,
        summary,
        machine_code,
        xlen,
        blocks,
        cfg,
        runtime_facts,
    ):
        captured["blocks"] = blocks
        captured["summary"] = summary
        captured["runtime_facts"] = runtime_facts

        assert blocks is authoritative_blocks
        assert summary is authoritative_summary

        # 最关键的 identity 检查。
        assert runtime_facts is runtime_facts_expected

        return FakeTranslationOutput(kind="needs_route")

    runtime_facts_expected = runtime_facts

    monkeypatch.setattr(
        pipeline,
        "translate",
        fake_translate,
    )

    stats = pipeline.run(
        str("/root/src/poc_trans/path_b/riscv2x86/test/minimal/output/rv_add_sub_report.json"),
        str(tmp_path / "output.json"),
        xlen=64,
    )

    assert captured["blocks"] is authoritative_blocks
    assert captured["summary"] is authoritative_summary
    assert captured["runtime_facts"] is runtime_facts

    assert finding.translationRuntimeFacts is runtime_facts
    assert stats["needs_route"] == 1
    assert stats["failed"] == 0


def _require_supported_translation(result):
    """
    该 helper 的目的不是要求所有指令都一定 lower 到 C，
    而是确保测试 fixture 是当前 translator 已支持的路线。

    如果当前项目对 add 使用 x86 inline asm，则 kind 可能是 x86；
    如果直接 lower 到 C，则可能是 c。
    """
    assert result.kind in {"c", "x86"}, (
        "该测试需要选择一个当前 translator 已支持且可产生 replacement "
        f"的 fixture，实际 kind={result.kind!r}, notes={result.notes!r}"
    )
    assert result.replacement.strip()

def _translation_fingerprint(result):
    """
    用于比较两次 translate() 的语义结果。

    这里刻意包含 kind、replacement、route、notes、reason code 及证明要求，
    以确保 display metadata 或 str(op) 不会改变 Phase 6 决策。
    """
    return {
        "kind": getattr(result, "kind", None),
        "replacement": getattr(result, "replacement", None),
        "route": getattr(result, "route", None),
        "notes": tuple(getattr(result, "notes", []) or []),
        "reason_codes": tuple(sorted(_reason_codes(result))),
        "requires_build_check": getattr(result, "requiresBuildCheck", None),
        "requires_block_proof": getattr(result, "requiresBlockProof", None),
        "requires_path_validation": getattr(result, "requiresPathValidation", None),
    }

def _build_add_fixture():
    """
    使用真实 assemble -> lift -> canonicalize -> CFG 流程构造 fixture。

    重点：
      runtime facts 只能来自 assemble_result.translation_runtime_facts
      经 build_translation_runtime_facts() 校验/规范化后的结果。
    """
    finding = make_needs_asm_translation_finding(
        asm_text="add %0, %0, %1",
        fragment_id="structured-pcode-add-fixture",
    )
    frag = finding.fragment

    operand_width_bits = {
        0: 64,
        1: 64,
    }

    ar = assemble(
        frag,
        xlen=64,
        operand_width_bits=operand_width_bits,
    )
    assert ar.ok, ar.error

    facts_result = build_translation_runtime_facts(
        finding=finding,
        assemble_result=ar,
    )
    assert facts_result.ok, facts_result.error

    runtime_facts = facts_result.facts

    # 测试事实内容来自 assemble 产物，而不是 fragment 或测试猜测。
    assert runtime_facts.rv_to_operand_index
    assert runtime_facts.operand_width_bits

    lr = lift(
        ar.machine_code,
        xlen=64,
        relocations=ar.relocations,
    )
    assert lr.ok, lr.error

    blocks, summary = from_lifted(lr.insns)

    assert blocks
    assert summary is not None

    cfg = build_cfg_from_blocks(blocks)
    assert cfg.ok, cfg.error

    return finding, frag, ar, lr, blocks, summary, cfg, runtime_facts

def _iter_ops(blocks):
    """
    根据项目 Block 的实际字段名调整。

    常见实现可能是：
      block.ops
      block.operations
      block.pcode_ops
    """
    for block in blocks:
        if hasattr(block, "ops"):
            yield from block.ops
        elif hasattr(block, "operations"):
            yield from block.operations
        elif hasattr(block, "pcode_ops"):
            yield from block.pcode_ops
        else:
            raise AssertionError(
                f"unknown Block operation field: {type(block)!r}"
            )

def test_translate_does_not_parse_pcode_operation_string(monkeypatch):
    """
    Phase 6 semantic lowering 必须使用 Block / CanonicalInsn / Op 的结构化字段。

    不允许通过：
      - str(op)
      - f"{op}"
      - regex(str(op))
      - renderer 输出文本
    来恢复 p-code 语义。

    该测试不要求当前 fixture 一定能 lower 到 c/x86。
    即使结果是 fail-closed 的 needs_route，只要禁用 str(op) 后结果不变，
    就证明 translator 没有依赖 operation 的字符串表示恢复语义。
    """
    (
        _finding,
        frag,
        ar,
        lr,
        blocks,
        summary,
        cfg,
        runtime_facts,
    ) = _build_add_fixture()

    baseline = translate(
        frag=frag,
        lift=lr,
        summary=summary,
        machine_code=ar.machine_code,
        xlen=64,
        blocks=blocks,
        cfg=cfg,
        runtime_facts=runtime_facts,
    )

    baseline_fingerprint = _translation_fingerprint(baseline)

    operation_types = {type(op) for op in _iter_ops(blocks)}
    assert operation_types, "fixture produced no structured p-code operations"

    def forbidden_str(self):
        raise AssertionError(
            "Phase 6 attempted to stringify a structured p-code operation. "
            "Semantic lowering must consume typed Operation fields only."
        )

    for operation_type in operation_types:
        monkeypatch.setattr(
            operation_type,
            "__str__",
            forbidden_str,
            raising=False,
        )

    translated = translate(
        frag=frag,
        lift=lr,
        summary=summary,
        machine_code=ar.machine_code,
        xlen=64,
        blocks=blocks,
        cfg=cfg,
        runtime_facts=runtime_facts,
    )

    assert _translation_fingerprint(translated) == baseline_fingerprint

def test_pipeline_translation_is_independent_of_rendered_pcode_text(
    monkeypatch,
    tmp_path,
):
    finding = make_needs_asm_translation_finding(
        asm_text="add %0, %0, %1",
        fragment_id="pipeline-pcode-text-isolation",
    )

    runtime_facts = TranslationRuntimeFacts(
        rv_to_operand_index={
            "a0": 0,
            "a1": 1,
        },
        operand_width_bits={
            0: 64,
            1: 64,
        },
        provenance="pipeline-test",
    )

    authoritative_blocks = [object()]
    authoritative_summary = object()
    rendered_text = (
        "INT_ADD rendered-diagnostic-only-text\n"
        "STORE ram:0xdeadbeef"
    )

    captured = {}

    monkeypatch.setattr(
        pipeline,
        "load_report",
        lambda _path: [finding],
    )

    monkeypatch.setattr(
        pipeline,
        "save_report",
        lambda _findings, _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "_phase4_preflight_blockers",
        lambda _finding: [],
    )

    monkeypatch.setattr(
        pipeline,
        "_get_fragment_operand_width_bits",
        lambda _fragment: ({0: 64, 1: 64}, []),
    )

    monkeypatch.setattr(
        pipeline,
        "assemble",
        lambda *args, **kwargs: FakeAssembleResult(),
    )

    monkeypatch.setattr(
        pipeline,
        "build_translation_runtime_facts",
        lambda **kwargs: FakeFactsBuildResult(
            ok=True,
            facts=runtime_facts,
        ),
    )

    monkeypatch.setattr(
        pipeline,
        "lift",
        lambda *args, **kwargs: FakeLiftResult(insns=[]),
    )

    monkeypatch.setattr(
        pipeline,
        "from_lifted",
        lambda _insns: (
            authoritative_blocks,
            authoritative_summary,
        ),
    )

    monkeypatch.setattr(
        pipeline,
        "build_cfg_from_blocks",
        lambda _blocks: FakeCFG(ok=True),
    )

    monkeypatch.setattr(
        pipeline,
        "_render_lifted_pcode_for_diagnostics",
        lambda _lift_result: rendered_text,
    )

    def fake_translate(
        *,
        frag,
        lift,
        summary,
        machine_code,
        xlen,
        blocks,
        cfg,
        runtime_facts,
    ):
        captured["frag"] = frag
        captured["lift"] = lift
        captured["summary"] = summary
        captured["machine_code"] = machine_code
        captured["xlen"] = xlen
        captured["blocks"] = blocks
        captured["cfg"] = cfg
        captured["runtime_facts"] = runtime_facts

        assert blocks is authoritative_blocks
        assert summary is authoritative_summary
        assert runtime_facts is finding.translationRuntimeFacts

        return FakeTranslationOutput(
            kind="needs_route",
            notes=["test route"],
        )

    monkeypatch.setattr(
        pipeline,
        "translate",
        fake_translate,
    )

    stats = pipeline.run(
        in_json=str(tmp_path / "unused-input.json"),
        out_json=str(tmp_path / "unused-output.json"),
        xlen=64,
    )

    assert finding.pcodeText == rendered_text

    assert captured["blocks"] is authoritative_blocks
    assert captured["summary"] is authoritative_summary
    assert captured["runtime_facts"] is runtime_facts

    assert stats["needs_route"] == 1
    assert stats["failed"] == 0

def test_translate_does_not_infer_semantics_from_asm_display_fields():
    """
    CanonicalInsn.asm_mnem / asm_body 仅是 debug/display metadata。

    Phase 6 不能根据它们推导 add、branch、atomic、barrier 等语义。

    当前 fixture 即使 fail-closed 返回 needs_route，也可以验证：
    修改 display metadata 不得影响 translator 的 Phase 6 决策。
    """
    (
        _finding,
        frag,
        ar,
        lr,
        blocks,
        summary,
        cfg,
        runtime_facts,
    ) = _build_add_fixture()

    baseline = translate(
        frag=frag,
        lift=lr,
        summary=summary,
        machine_code=ar.machine_code,
        xlen=64,
        blocks=blocks,
        cfg=cfg,
        runtime_facts=runtime_facts,
    )

    baseline_fingerprint = _translation_fingerprint(baseline)

    for block in blocks:
        for insn in getattr(block, "instructions", []):
            insn.asm_mnem = "THIS_MUST_NOT_BE_USED_BY_PHASE6"
            insn.asm_body = (
                "fake textual assembly which does not match structured IR"
            )

    translated = translate(
        frag=frag,
        lift=lr,
        summary=summary,
        machine_code=ar.machine_code,
        xlen=64,
        blocks=blocks,
        cfg=cfg,
        runtime_facts=runtime_facts,
    )

    assert _translation_fingerprint(translated) == baseline_fingerprint

def test_pipeline_does_not_pass_rendered_pcode_text_to_translate(
    monkeypatch,
    tmp_path,
):
    finding = make_needs_asm_translation_finding(
        asm_text="add %0, %0, %1",
        fragment_id="pipeline-pcode-text-isolation",
    )

    runtime_facts = TranslationRuntimeFacts(
        rv_to_operand_index={"a0": 0, "a1": 1},
        operand_width_bits={0: 64, 1: 64},
        provenance="test",
    )

    authoritative_blocks = [object()]
    authoritative_summary = object()
    rendered_text = (
        "INT_ADD forbidden-rendered-pcode-text "
        "STORE ram:0xdeadbeef"
    )

    captured = {}

    monkeypatch.setattr(
        pipeline,
        "load_report",
        lambda _path: [finding],
    )
    monkeypatch.setattr(
        pipeline,
        "save_report",
        lambda _findings, _path: None,
    )
    monkeypatch.setattr(
        pipeline,
        "_phase4_preflight_blockers",
        lambda _finding: [],
    )
    monkeypatch.setattr(
        pipeline,
        "_get_fragment_operand_width_bits",
        lambda _fragment: ({0: 64, 1: 64}, []),
    )
    monkeypatch.setattr(
        pipeline,
        "assemble",
        lambda *args, **kwargs: FakeAssembleResult(),
    )
    monkeypatch.setattr(
        pipeline,
        "build_translation_runtime_facts",
        lambda **kwargs: FakeFactsBuildResult(
            ok=True,
            facts=runtime_facts,
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "lift",
        lambda *args, **kwargs: FakeLiftResult(insns=[]),
    )
    monkeypatch.setattr(
        pipeline,
        "from_lifted",
        lambda _insns: (authoritative_blocks, authoritative_summary),
    )
    monkeypatch.setattr(
        pipeline,
        "build_cfg_from_blocks",
        lambda _blocks: FakeCFG(ok=True),
    )
    monkeypatch.setattr(
        pipeline,
        "_render_lifted_pcode_for_diagnostics",
        lambda _lr: rendered_text,
    )

    def fake_translate(
        *,
        frag,
        lift,
        summary,
        machine_code,
        xlen,
        blocks,
        cfg,
        runtime_facts,
    ):
        captured["frag"] = frag
        captured["lift"] = lift
        captured["summary"] = summary
        captured["machine_code"] = machine_code
        captured["blocks"] = blocks
        captured["cfg"] = cfg
        captured["runtime_facts"] = runtime_facts

        assert summary is authoritative_summary
        assert blocks is authoritative_blocks
        assert runtime_facts is finding.translationRuntimeFacts

        return FakeTranslationOutput(
            kind="needs_route",
            notes=["routing required"],
        )

    monkeypatch.setattr(
        pipeline,
        "translate",
        fake_translate,
    )

    stats = pipeline.run(
        str(tmp_path / "input.json"),
        str(tmp_path / "output.json"),
        xlen=64,
    )

    assert finding.pcodeText == rendered_text

    assert captured["blocks"] is authoritative_blocks
    assert captured["summary"] is authoritative_summary
    assert captured["runtime_facts"] is runtime_facts

    assert stats["needs_route"] == 1
    assert stats["failed"] == 0

def test_frontend_json_add_sub_fragment_translates_to_x86(tmp_path):
    """
    验证完整流程：

      frontend JSON
        -> load_report
        -> assemble
        -> lift
        -> structured p-code blocks
        -> CFG
        -> Phase 6 translate
        -> save_report
        -> reload output JSON

    该 fixture 应来自真实前端 parser 输出，
    而不是测试中手写 Finding 后 monkeypatch load_report。
    """
    fixture_path = Path(
        "/root/src/poc_trans/path_b/riscv2x86/test/minimal/output/rv_add_sub_report.json"
    )
    output_path = tmp_path / "translated_report.json"

    findings = pipeline.load_report(str(fixture_path))

    assert len(findings) == 1

    source_finding = findings[0]

    assert source_finding.fragment.rawAsmText == (
        "add %0, %1, %2\n"
        "\tsub %0, %0, %2"
    )

    stats = pipeline.run(
        str(fixture_path),
        str(output_path),
        xlen=64,
    )

    assert output_path.exists()
    assert stats["failed"] == 0

    translated_findings = pipeline.load_report(str(output_path))

    assert len(translated_findings) == 1

    translated = translated_findings[0]

    # 若该 fixture 的预期目标就是 x86 inline asm，则必须严格要求 x86。
    def _translation_debug_payload(translated):
        return {
            "translationKind": getattr(translated, "translationKind", None),
            "suggestedReplacement": getattr(
                translated,
                "suggestedReplacement",
                None,
            ),
            "route": getattr(translated, "route", None),
            "preservationLevel": getattr(
                translated,
                "preservationLevel",
                None,
            ),
            "preservationRoute": getattr(
                translated,
                "preservationRoute",
                None,
            ),
            "buildFamily": getattr(translated, "buildFamily", None),
            "notes": getattr(translated, "notes", None),
            "reasonCodes": getattr(translated, "reasonCodes", None),
            "reason_codes": getattr(translated, "reason_codes", None),
            "metadata": getattr(translated, "metadata", None),
        }


    if translated.translationKind != "x86":
        raise AssertionError(
            "Expected x86 translation, got:\n"
            + json.dumps(
                _translation_debug_payload(translated),
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        )

    replacement = translated.suggestedReplacement.strip()

    assert replacement

    replacement_lower = replacement.lower()

    assert "asm" in replacement_lower

    # xlen=64，正常应生成 qword 形式。
    assert "addq" in replacement_lower or "add " in replacement_lower
    assert "subq" in replacement_lower or "sub " in replacement_lower

    # 验证 frontend JSON 中的 operand expression 被保留。
    assert "result" in replacement
    assert "a" in replacement
    assert "b" in replacement

    # x86 add/sub 修改 flags，正常应该声明 cc clobber。
    assert "cc" in replacement_lower

    # Phase 5 p-code 诊断信息可存在，但不得作为 Phase 6 的文本语义输入。
    assert translated.pcodeText

def test_pure_integer_add_sub_summary_proves_no_special_semantics(Op):
    add = CanonicalInsn(
        addr=0x1000,
        size=4,
        ops=[
            Op(
                addr=0x1000,
                opcode="INT_ADD",
                output=None,
                inputs=[],
            )
        ],
        terminator_kind=None,
        direct_target=None,
        has_branch_op=False,
        has_call_or_return_op=False,
        barrier_info=None,
        has_unknown_barrier=False,
        has_atomic=False,
        atomic_mnemonic=None,
        atomic_orderings=set(),
        atomic_reads_mem=False,
        atomic_writes_mem=False,
        semantic_tags=set(),
        asm_mnem="add",
        asm_body="add a0, a1, a2",
    )

    sub = CanonicalInsn(
        addr=0x1004,
        size=4,
        ops=[
            Op(
                addr=0x1004,
                opcode="INT_SUB",
                output=None,
                inputs=[],
            )
        ],
        terminator_kind=None,
        direct_target=None,
        has_branch_op=False,
        has_call_or_return_op=False,
        barrier_info=None,
        has_unknown_barrier=False,
        has_atomic=False,
        atomic_mnemonic=None,
        atomic_orderings=set(),
        atomic_reads_mem=False,
        atomic_writes_mem=False,
        semantic_tags=set(),
        asm_mnem="sub",
        asm_body="sub a0, a0, a2",
    )

    summary = _summarize_instructions(
        [add, sub],
        is_single_block=True,
    )

    assert summary.has_return is False
    assert summary.has_tail_call is False
    assert summary.has_indirect_control_flow is False

    assert summary.has_timing_source is False
    assert summary.has_cache_operation is False
    assert summary.has_speculation_control is False

def test_unknown_structured_opcode_keeps_special_semantics_unknown(Op):
    unknown = CanonicalInsn(
        addr=0x1000,
        size=4,
        ops=[
            Op(
                addr=0x1000,
                opcode="CALLOTHER",
                output=None,
                inputs=[],
            )
        ],
        terminator_kind=None,
        direct_target=None,
        has_branch_op=False,
        has_call_or_return_op=False,
        barrier_info=None,
        has_unknown_barrier=False,
        has_atomic=False,
        atomic_mnemonic=None,
        atomic_orderings=set(),
        atomic_reads_mem=False,
        atomic_writes_mem=False,
        semantic_tags=set(),
        asm_mnem="",
        asm_body="",
    )

    summary = _summarize_instructions(
        [unknown],
        is_single_block=True,
    )

    # 未识别 opcode 不能被生产者证明为无 timing/cache/speculation 语义。
    assert summary.has_return is None
    assert summary.has_tail_call is None
    assert summary.has_indirect_control_flow is None
    assert summary.has_timing_source is None
    assert summary.has_cache_operation is None
    assert summary.has_speculation_control is None

@dataclass
class FakeVarnode:
    space: str
    offset: int
    size: int
    name: str = ""


class FakeRiscvLanguage:
    def __init__(self):
        self._register_names = {
            ("register", 0x2050, 8): "a0",
            ("register", 0x2058, 8): "a1",
            ("register", 0x2060, 8): "a2",
        }

    def register_name_for(
        self,
        *,
        space: str,
        offset: int,
        size: int,
    ) -> Optional[str]:
        return self._register_names.get((space, offset, size))

def test_lifting_adapter_attaches_authoritative_riscv_register_name():
    raw = FakeVarnode(
        space="register",
        offset=0x2050,
        size=8,
        name="",
    )

    language = FakeRiscvLanguage()

    adapted = adapt_varnode(raw, language=language)

    assert adapted.space == "register"
    assert adapted.offset == 0x2050
    assert adapted.size == 8
    assert adapted.name == "a0"

def test_to_var_preserves_explicit_adapter_register_name():
    raw = AdaptedVarnode(
        space="register",
        offset=0x2050,
        size=8,
        name="a0",
    )

    canonical = _to_var(raw)

    assert canonical.kind is VarKind.REG
    assert canonical.name == "a0"
    assert canonical.offset == 0x2050
    assert canonical.size == 8
