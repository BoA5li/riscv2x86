# x86_att_integer_lowering.py
"""
Conservative normalized p-code -> x86-64 GNU AT&T inline-asm lowering.

This module intentionally supports only a very small, provable subset:

    dst = lhs + rhs
    dst = lhs - rhs

with a single accumulator-shaped final destination chain:

    a0 = a1 + a2
    a0 = a0 - a2

This module does not infer:

    - host C/C++ expressions;
    - GNU operand positions;
    - RISC-V register ABI roles;
    - operand widths;
    - xlen-derived C type widths;
    - constraints;
    - memory semantics;
    - control-flow semantics.

The caller must provide an already validated runtime-only
X86LoweringOperandBindingView through ``context.bindings``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .pcode_ir import Op, Var, VarKind
from .runtime_facts import canonicalize_riscv_register_name


class UnsupportedTranslationError(RuntimeError):
    """Raised when lowering lacks sufficient proven runtime facts."""

def _runtime_operand_index_for_canonical_register(
    context: Any,
    canonical_register: str,
) -> int:
    """
    Resolve a canonical RISC-V ABI register through authoritative runtime
    facts only.

    Runtime facts may initially use either ABI names, such as a0, or xN
    names, such as x10. Conflicts after canonicalization are rejected.
    """
    runtime_facts = getattr(context, "runtimeFacts", None)

    if runtime_facts is None:
        raise UnsupportedTranslationError(
            "missing TranslationRuntimeFacts in x86 lowering context"
        )

    raw_bindings = getattr(
        runtime_facts,
        "rv_to_operand_index",
        None,
    )

    if not isinstance(raw_bindings, Mapping) or not raw_bindings:
        raise UnsupportedTranslationError(
            "missing or invalid authoritative runtime "
            "RISC-V-register-to-GNU-operand bindings"
        )

    found: Optional[int] = None

    for raw_register, operand_index in raw_bindings.items():
        register = canonicalize_riscv_register_name(raw_register)

        if register != canonical_register:
            continue

        if (
            isinstance(operand_index, bool)
            or not isinstance(operand_index, int)
            or operand_index < 0
        ):
            raise UnsupportedTranslationError(
                "invalid GNU operand index in runtime facts: "
                f"register={raw_register!r}, "
                f"canonical_register={canonical_register!r}, "
                f"operand_index={operand_index!r}"
            )

        if found is not None and found != operand_index:
            raise UnsupportedTranslationError(
                "conflicting runtime GNU operand bindings after RISC-V "
                "register canonicalization: "
                f"canonical_register={canonical_register!r}, "
                f"first_operand_index={found}, "
                f"second_operand_index={operand_index}"
            )

        found = operand_index

    if found is None:
        raise UnsupportedTranslationError(
            "missing authoritative runtime binding for p-code register: "
            f"canonical_register={canonical_register!r}"
        )

    return found

def resolve_pcode_register_x86_binding(
    context: Any,
    pcode_register_name: Any,
) -> Any:
    """
    Resolve:

        p-code register
            -> canonical RISC-V register
            -> TranslationRuntimeFacts.rv_to_operand_index
            -> validated GNU operand binding
            -> TranslationRuntimeFacts.operand_width_bits

    No binding inference is permitted from p-code ordering, fragment operand
    ordering, host expression text, xN register numbers, or XLEN.
    """
    canonical_register = canonicalize_riscv_register_name(
        pcode_register_name
    )

    if not canonical_register:
        raise UnsupportedTranslationError(
            "cannot resolve p-code operand as a RISC-V GPR: "
            f"{pcode_register_name!r}"
        )

    operand_index = _runtime_operand_index_for_canonical_register(
        context,
        canonical_register,
    )

    runtime_facts = getattr(context, "runtimeFacts", None)

    if runtime_facts is None:
        raise UnsupportedTranslationError(
            "missing TranslationRuntimeFacts in x86 lowering context"
        )

    width_map = getattr(runtime_facts, "operand_width_bits", None)

    if not isinstance(width_map, Mapping):
        raise UnsupportedTranslationError(
            "missing or invalid authoritative host operand width facts"
        )

    width_bits = width_map.get(operand_index)

    if (
        isinstance(width_bits, bool)
        or not isinstance(width_bits, int)
        or width_bits <= 0
    ):
        raise UnsupportedTranslationError(
            "missing or invalid authoritative host operand width fact: "
            f"canonical_register={canonical_register!r}, "
            f"operand_index={operand_index}, "
            f"width_bits={width_bits!r}"
        )

    binding_view = getattr(context, "bindings", None)

    if binding_view is None:
        raise UnsupportedTranslationError(
            "missing validated x86 lowering binding view"
        )

    binding_errors = getattr(binding_view, "errors", None) or []

    if binding_errors:
        raise UnsupportedTranslationError(
            "x86 lowering binding view is invalid: "
            + "; ".join(str(error) for error in binding_errors)
        )

    rv_to_operand = getattr(binding_view, "rv_to_operand", None)

    if not isinstance(rv_to_operand, Mapping):
        raise UnsupportedTranslationError(
            "validated x86 lowering binding view has no valid "
            "rv_to_operand mapping"
        )

    binding = rv_to_operand.get(canonical_register)

    if binding is None:
        raise UnsupportedTranslationError(
            "runtime facts identify a GNU operand, but no validated host "
            "binding exists for that register: "
            f"canonical_register={canonical_register!r}, "
            f"operand_index={operand_index}"
        )

    binding_operand_index = getattr(binding, "operandIndex", None)
    binding_width_bits = getattr(binding, "widthBits", None)

    if binding_operand_index != operand_index:
        raise UnsupportedTranslationError(
            "runtime facts and validated host binding disagree on GNU "
            "operand index: "
            f"canonical_register={canonical_register!r}, "
            f"runtime_facts_operand_index={operand_index}, "
            f"binding_operand_index={binding_operand_index!r}"
        )

    if binding_width_bits != width_bits:
        raise UnsupportedTranslationError(
            "runtime facts and validated host binding disagree on host "
            "operand width: "
            f"canonical_register={canonical_register!r}, "
            f"operand_index={operand_index}, "
            f"runtime_facts_width_bits={width_bits}, "
            f"binding_width_bits={binding_width_bits!r}"
        )

    return binding

def require_x86_att_64bit_pcode_register_binding(
    context: Any,
    pcode_register_name: Any,
) -> Any:
    """
    The current x86-64 movq/addq/subq lowering requires a proven 64-bit
    host operand. XLEN is not a substitute for operand width facts.
    """
    binding = resolve_pcode_register_x86_binding(
        context,
        pcode_register_name,
    )

    width_bits = getattr(binding, "widthBits", None)
    operand_index = getattr(binding, "operandIndex", None)

    if width_bits != 64:
        raise UnsupportedTranslationError(
            "x86-64 ADD/SUB lowering requires a proven 64-bit host operand: "
            f"pcode_register={pcode_register_name!r}, "
            f"operand_index={operand_index!r}, "
            f"width_bits={width_bits!r}"
        )

    return binding
_SAFE_OPERAND_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _binding_expression_64(
    context: Any,
    register: str,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Return a 64-bit host expression only after validating the complete:

        p-code register
            -> runtime facts
            -> validated host binding
            -> widthBits == 64

    chain.
    """
    try:
        binding = require_x86_att_64bit_pcode_register_binding(
            context,
            register,
        )
    except UnsupportedTranslationError as exc:
        return None, str(exc)

    expression = (binding.expression or "").strip()

    if not expression:
        return None, (
            "validated GNU operand binding has no usable host expression: "
            f"register={register!r}, "
            f"operand_index={binding.operandIndex}"
        )

    return expression, None

@dataclass(frozen=True)
class X86AttIntegerLoweringResult:
    """
    matched=False, error=None:
        The p-code does not belong to this strategy.

    matched=False, error!=None:
        The p-code looked relevant, but cannot safely be emitted.

    matched=True:
        replacement contains a complete GNU inline asm statement.
    """

    matched: bool
    replacement: Optional[str] = None
    error: Optional[str] = None

def lower_normalized_add_sub_to_x86_att(
    context: Any,
) -> X86AttIntegerLoweringResult:
    operations, parse_error, recognized = _extract_add_sub_operations(context)

    if parse_error:
        return X86AttIntegerLoweringResult(matched=False, error=parse_error)
    if not recognized or not operations:
        return X86AttIntegerLoweringResult(matched=False, error="no valid ops")
    try:
        replacement, emit_error = _emit_att_add_sub_chain(context, operations)
    except UnsupportedTranslationError as exc:
        return X86AttIntegerLoweringResult(matched=False, error=str(exc))
    if emit_error:
        return X86AttIntegerLoweringResult(matched=False, error=emit_error)
    return X86AttIntegerLoweringResult(matched=True, replacement=replacement)


def _structured_opcode_name(op: Op) -> str:
    """
    Return a normalized opcode name from structured Op data only.

    This function intentionally does not inspect raw p-code text, call
    str(op), call repr(op), inspect LiftResult, or inspect lifted p-code
    instruction strings.

    It supports either:

        op.opcode == "INT_ADD"

    or enum-like opcode objects exposing:

        op.opcode.name == "INT_ADD"

    or:

        op.opcode.value == "INT_ADD"
    """
    raw_opcode = getattr(op, "opcode", None)

    if isinstance(raw_opcode, str):
        return raw_opcode.strip().upper()

    enum_name = getattr(raw_opcode, "name", None)

    if isinstance(enum_name, str):
        return enum_name.strip().upper()

    enum_value = getattr(raw_opcode, "value", None)

    if isinstance(enum_value, str):
        return enum_value.strip().upper()

    return ""
    
def _structured_riscv_register_name(
    var: Optional[Var],
) -> Optional[str]:
    """
    Resolve a canonical structured register Var to a canonical RISC-V GPR.

    Phase-6 policy:

      * only VarKind.REG is accepted;
      * only Var.name is used as register identity;
      * no offset/size guessing is allowed;
      * no stringification of raw p-code or varnodes is allowed;
      * Var.name must already be an explicit string register name.

    A missing or non-string canonical Var.name is rejected rather than
    reconstructed from register-space offset, size, or display text.
    """
    if var is None:
        return None

    if getattr(var, "kind", None) != VarKind.REG:
        return None

    raw_name = getattr(var, "name", None)

    if not isinstance(raw_name, str):
        return None

    raw_name = raw_name.strip()

    if not raw_name:
        return None

    return canonicalize_riscv_register_name(raw_name) or None

def _extract_add_sub_operations(
    context: Any,
) -> Tuple[List[Tuple[str, str, str, str, Optional[int]]], Optional[str], bool]:
    blocks = getattr(context, "blocks", None)
    if blocks is None:
        return [], "missing authoritative structured IR blocks", False
    if not isinstance(blocks, (list, tuple)):
        return [], "blocks must be list/tuple", False
    cfg = getattr(context, "cfg", None)
    if cfg is None:
        return [], "missing CFG for ADD/SUB lowering", False
    if len(blocks) != 1:
        return [], f"only single block supported, got {len(blocks)}", True

    block = blocks[0]
    ops = getattr(block, "ops", [])
    if not isinstance(ops, (list, tuple)):
        return [], "block has invalid op sequence", True

    operations: List[Tuple[str, str, str, str, Optional[int]]] = []
    saw_semantic_operation = False
    pending_const: Optional[int] = None
    pending_copy_prop = None

    for op_index, op in enumerate(ops):
        if not isinstance(op, Op):
            return [], f"non-Op object at op={op_index}", True
        opcode = _structured_opcode_name(op)
        print(f"[EXTRACT_DEBUG] op{op_index} opcode={opcode}")

        if opcode == "IMARK":
            continue
        saw_semantic_operation = True

        if opcode == "COPY":
            if pending_const is not None:
                return [], "multiple consecutive COPY not supported", True
            copy_inputs = getattr(op, "inputs", [])
            if len(copy_inputs) != 1:
                return [], f"COPY needs exactly one input, op={op_index}", True
            src_var = copy_inputs[0]
            if getattr(src_var, "kind", None) != VarKind.CONST:
                return [], f"COPY source is not CONST, op={op_index}", True
            const_val = getattr(src_var, "offset", None)
            if not isinstance(const_val, int):
                return [], f"CONST value invalid at COPY op={op_index}", True
            pending_const = const_val
            out_var = op.output
            # 修复：取枚举name字符串，不要存枚举对象
            pending_copy_prop = {
                "kind_name": out_var.kind.name,
                "space": out_var.space,
                "offset": out_var.offset,
                "size": out_var.size
            }
            print(f"[EXTRACT_DEBUG] capture COPY const={pending_const}, prop={pending_copy_prop}")
            continue

        if opcode not in {"INT_ADD", "INT_SUB"}:
            return [], f"unsupported opcode={opcode!r}, op={op_index}", True

        output = getattr(op, "output", None)
        inputs = getattr(op, "inputs", [])
        if output is None or len(inputs) != 2:
            return [], f"{opcode} invalid input/output at op={op_index}", True

        dst_reg = _structured_riscv_register_name(output)
        lhs_reg = _structured_riscv_register_name(inputs[0])
        rhs_raw_var = inputs[1]

        if dst_reg is None or lhs_reg is None:
            return [], f"{opcode} dst/lhs not riscv reg op={op_index}", True

        imm_const: Optional[int] = None
        rhs_reg: Optional[str] = None
        match_copy = False

        if pending_const is not None and pending_copy_prop is not None:
            rhs_prop = {
                "kind_name": rhs_raw_var.kind.name,
                "space": rhs_raw_var.space,
                "offset": rhs_raw_var.offset,
                "size": rhs_raw_var.size
            }
            print(f"[EXTRACT_DEBUG] INT_ADD rhs_prop={rhs_prop}, copy_prop={pending_copy_prop}")
            if rhs_prop == pending_copy_prop:
                match_copy = True
                print("[EXTRACT_DEBUG] COPY & INT_ADD MATCH SUCCESS")

        if match_copy:
            imm_const = pending_const
            rhs_reg = ""
            pending_const = None
            pending_copy_prop = None
        else:
            rhs_reg = _structured_riscv_register_name(rhs_raw_var)
            if rhs_reg is None:
                return [], f"{opcode} rhs not riscv register op={op_index}", True

        op_type = "add" if opcode == "INT_ADD" else "sub"
        operations.append((op_type, dst_reg, lhs_reg, rhs_reg, imm_const))
        print(f"[EXTRACT_DEBUG] append op item: {(op_type, dst_reg, lhs_reg, rhs_reg, imm_const)}")

    if not saw_semantic_operation:
        return [], None, False
    if not operations:
        return [], "no valid INT_ADD/INT_SUB found", True
    print(f"[EXTRACT_DEBUG] final operations list = {operations}")
    return operations, None, True

def _asm_operand_constraint_text(operand: Any) -> str:
    """
    从 AsmOperand 或等价 AST/JSON 重建对象中提取 GNU inline asm
    constraint 文本。

    不同 frontend / AST / JSON reconstruction 可能使用不同字段名，
    因此仅从显式 AST metadata 中兼容读取，不从 p-code、寄存器顺序、
    C 表达式文本或 XLEN 推断 constraint。
    """
    if operand is None:
        return ""

    for field_name in (
        "constraint",
        "constraintText",
        "constraint_string",
        "constraintString",
        "raw_constraint",
        "rawConstraint",
        "constraints",
    ):
        value = getattr(operand, field_name, None)

        if value is None:
            continue

        if isinstance(value, str):
            return value

        # 有些 AST 会将 constraint 包装为对象，例如：
        #
        #   Constraint(text="=&r")
        #
        # 只读取该 wrapper 的显式文本字段。
        for nested_field_name in (
            "text",
            "value",
            "raw",
            "constraint",
            "constraintText",
        ):
            nested_value = getattr(value, nested_field_name, None)

            if isinstance(nested_value, str):
                return nested_value

        # enum-like / lightweight wrapper 的兼容处理。
        # 不要把 list/tuple/dict 的 repr 当作 constraint。
        if not isinstance(value, (list, tuple, dict, set)):
            text = str(value)

            if text:
                return text

    return ""

def _asm_operand_has_early_clobber(operand: Any) -> bool:
    """
    判断 source GNU asm output operand 是否具有 early-clobber 语义。

    GNU output constraint 中的 '&' 表示 early-clobber，例如：

        "=&r"
        "+&r"

    优先读取 frontend 的结构化字段；若字段不存在、字段值为 False
    或 frontend 未正确填充，则回退到 authoritative constraint 文本。
    """
    if operand is None:
        return False

    structured_value = getattr(operand, "isEarlyClobber", None)

    if structured_value is None:
        structured_value = getattr(operand, "is_early_clobber", None)

    # 如果 frontend 明确标记 True，直接接受。
    if structured_value is True:
        return True

    # 即使 frontend 标记为 False，也仍检查 constraint 文本。
    # 这是为了兼容某些 AST 重建路径未正确恢复 isEarlyClobber 的情况。
    constraint_text = _asm_operand_constraint_text(operand)

    return "&" in constraint_text

def _fragment_outputs_as_tuple(
    context: Any,
) -> Tuple[Optional[Tuple[Any, ...]], Optional[str]]:
    """
    读取 source AsmFragment.outputs。

    注意：outputs 不保证是 Python list，它可能是 tuple、AST list wrapper
    或其他 iterable。因此不能使用 isinstance(outputs, list) 作为合法性条件。
    """
    fragment = getattr(context, "fragment", None)

    if fragment is None:
        return None, (
            "x86 lowering context has no source AsmFragment; cannot preserve "
            "GNU output early-clobber semantics"
        )

    outputs = getattr(fragment, "outputs", None)

    if outputs is None:
        return None, (
            "source AsmFragment has no outputs collection; cannot preserve "
            "GNU output early-clobber semantics"
        )

    if isinstance(outputs, (str, bytes)):
        return None, (
            "source AsmFragment outputs collection has invalid string type; "
            "cannot preserve GNU output early-clobber semantics"
        )

    try:
        return tuple(outputs), None
    except TypeError:
        return None, (
            "source AsmFragment outputs collection is not iterable; cannot "
            "preserve GNU output early-clobber semantics"
        )

def _source_output_has_early_clobber(
    context: Any,
    output_reg: str,
) -> Tuple[Optional[bool], Optional[str]]:
    """
    使用 authoritative runtime binding 确定 final RISC-V destination
    对应的 source GNU output operand 是否为 early-clobber。

    映射链必须是：

        canonical RV register
            -> validated operand binding.operandIndex
            -> source fragment.outputs[operandIndex]

    不允许依据 p-code 顺序、operand 声明顺序、xN 编号、C 表达式文本或
    XLEN 推断 output 的 source operand index。
    """
    try:
        binding = require_x86_att_64bit_pcode_register_binding(
            context,
            output_reg,
        )
    except UnsupportedTranslationError as exc:
        return None, str(exc)
    except Exception as exc:
        return None, (
            "failed to resolve authoritative x86 output binding for "
            f"register={output_reg!r}: {type(exc).__name__}: {exc}"
        )

    operand_index = getattr(binding, "operandIndex", None)

    if (
        isinstance(operand_index, bool)
        or not isinstance(operand_index, int)
        or operand_index < 0
    ):
        return None, (
            "final destination has no valid authoritative GNU operand index: "
            f"register={output_reg!r}, operand_index={operand_index!r}"
        )

    outputs, outputs_error = _fragment_outputs_as_tuple(context)

    if outputs_error is not None:
        return None, outputs_error

    assert outputs is not None

    # 当前 normalized ADD/SUB emitter 只会生成一个 GNU output operand。
    # 若 source 有多个 output，不能静默忽略其他 output。
    if len(outputs) != 1:
        return None, (
            "normalized ADD/SUB x86 lowering currently supports exactly one "
            "source GNU output operand; "
            f"got source_output_count={len(outputs)}"
        )

    # 对于单 output emitter，final destination 必须映射 source output 0。
    if operand_index != 0:
        return None, (
            "normalized ADD/SUB x86 lowering emits exactly one GNU output "
            "operand, but final destination is not authoritative source "
            f"output 0: register={output_reg!r}, "
            f"operand_index={operand_index}"
        )

    source_output = outputs[operand_index]
    source_constraint = _asm_operand_constraint_text(source_output)
    source_early_clobber = _asm_operand_has_early_clobber(source_output)

    print(
        "[DEBUG] source output early-clobber resolution:",
        {
            "output_reg": output_reg,
            "operand_index": operand_index,
            "source_output_type": type(source_output).__name__,
            "source_output_repr": repr(source_output),
            "source_output_dict": getattr(source_output, "__dict__", None),
            "source_constraint": source_constraint,
            "source_isEarlyClobber": getattr(
                source_output,
                "isEarlyClobber",
                None,
            ),
            "source_is_early_clobber": getattr(
                source_output,
                "is_early_clobber",
                None,
            ),
            "resolved_early_clobber": source_early_clobber,
        },
    )

    return source_early_clobber, None

def _emit_att_add_sub_chain(
    context: Any,
    operations: Sequence[Tuple[str, str, str, str, Optional[int]]],
) -> Tuple[Optional[str], Optional[str]]:
    """
    将已经证明合法的 normalized RV64 ADD/SUB accumulator chain
    lowering 为 x86-64 GNU AT&T inline asm。

    重要约束：

    1. register -> GNU operand 的绑定必须来自 runtime facts；
    2. 不从 p-code 顺序、operand 顺序、xN 编号、C expression 或 XLEN 推断；
    3. source output 若有 GNU early-clobber ('&')，generated output
       constraint 必须保留 '&'；
    4. 当前仅支持一个 source output 对应一个 final destination。
    """
    if not operations:
        return None, "empty op chain"

    normalized_ops = []

    for opcode, raw_dst, raw_lhs, raw_rhs, imm in operations:
        dst = canonicalize_riscv_register_name(raw_dst)
        lhs = canonicalize_riscv_register_name(raw_lhs) if raw_lhs else ""
        rhs = canonicalize_riscv_register_name(raw_rhs) if raw_rhs else ""

        if not dst or not lhs:
            return None, (
                "invalid normalized ADD/SUB register operands: "
                f"dst={raw_dst!r}, lhs={raw_lhs!r}"
            )

        if opcode not in ("add", "sub"):
            return None, f"unsupported normalized integer opcode: {opcode!r}"

        normalized_ops.append((opcode, dst, lhs, rhs, imm))

    destinations = {op[1] for op in normalized_ops}

    if len(destinations) != 1:
        return None, (
            "only single destination register accumulator chain is supported; "
            f"destinations={sorted(destinations)!r}"
        )

    output_reg = next(iter(destinations))
    first_op = normalized_ops[0]
    op_type, f_dst, f_lhs, f_rhs, f_imm = first_op

    if f_dst != output_reg:
        return None, "first op must define final destination"

    # 收集所有真实寄存器输入。
    #
    # rhs 为空表示 immediate placeholder，不能作为寄存器 operand。
    input_reg_set = set()

    for _, _, lhs, rhs, _ in normalized_ops:
        if lhs != output_reg:
            input_reg_set.add(lhs)

        if rhs and rhs != output_reg:
            input_reg_set.add(rhs)

    # 解析 output C expression。
    output_expr, err = _binding_expression_64(context, output_reg)

    if err:
        return None, err

    # 解析 input C expression。
    input_expr_map = {}

    for reg in input_reg_set:
        exp, binding_error = _binding_expression_64(context, reg)

        if binding_error:
            return None, binding_error

        input_expr_map[reg] = exp

    # 验证 register -> operandIndex 的一对一关系。
    #
    # 不允许两个不同的 canonical RV registers 指向同一个 GNU operand index，
    # 否则 generated asm 的 named operand identity 无法被证明。
    all_regs = [output_reg] + sorted(input_reg_set)
    operand_owner = {}

    for reg in all_regs:
        try:
            bind = require_x86_att_64bit_pcode_register_binding(context, reg)
        except Exception as exc:
            return None, (
                "failed to validate x86 operand binding for "
                f"register={reg!r}: {type(exc).__name__}: {exc}"
            )

        operand_index = getattr(bind, "operandIndex", None)
        old_reg = operand_owner.get(operand_index)

        if old_reg is not None and old_reg != reg:
            return None, (
                "register conflict: multiple RISC-V registers map to the "
                f"same authoritative source operand index {operand_index}: "
                f"{old_reg!r} and {reg!r}"
            )

        operand_owner[operand_index] = reg

    output_name = _operand_name("out", output_reg)

    if not output_name:
        return None, f"cannot generate output operand name for {output_reg!r}"

    input_name_map = {
        reg: _operand_name("in", reg)
        for reg in input_reg_set
    }

    if any(name is None for name in input_name_map.values()):
        return None, "input register operand name generation failed"

    # 当前 emitter 使用 rax 作为显式 scratch register。
    #
    # 因此：
    #
    #   - rax 必须在 clobber 中；
    #   - source output 的 early-clobber 仍需保留，确保 generated
    #     output constraint 不弱化 source GNU constraint 语义。
    scratch_reg = "%%rax"
    asm_lines = []
    currently_defined = set()

    def get_op_arg(
        reg: str,
        imm: Optional[int],
        defined: set,
    ) -> Optional[str]:
        del defined

        # immediate 优先。
        if imm is not None:
            return f"${imm}"

        # 若 output_reg 是输入，则读取 output C variable 当前值。
        if reg == output_reg:
            return f"%[{output_name}]"

        # 普通 source input。
        operand_name = input_name_map.get(reg)

        if operand_name is None:
            return None

        return f"%[{operand_name}]"

    # ---------- 第一条操作 ----------
    lhs_arg = get_op_arg(f_lhs, None, currently_defined)
    rhs_arg = get_op_arg(f_rhs, f_imm, currently_defined)

    if lhs_arg is None or rhs_arg is None:
        return None, (
            "failed to resolve first normalized operation operands: "
            f"lhs={lhs_arg!r}, rhs={rhs_arg!r}, "
            f"f_lhs={f_lhs!r}, f_rhs={f_rhs!r}, f_imm={f_imm!r}"
        )

    asm_lines.append(f"movq {lhs_arg}, {scratch_reg}")

    first_instruction = "addq" if op_type == "add" else "subq"
    asm_lines.append(f"{first_instruction} {rhs_arg}, {scratch_reg}")

    currently_defined.add(f_dst)

    # ---------- 后续 accumulator chain ----------
    for opcode, dst, lhs, rhs, imm in normalized_ops[1:]:
        if dst != output_reg or lhs != output_reg:
            return None, (
                "only accumulator chain form dst = dst (+|-) source is "
                "supported after the first operation: "
                f"opcode={opcode!r}, dst={dst!r}, lhs={lhs!r}, "
                f"expected_output_reg={output_reg!r}"
            )

        arg = get_op_arg(rhs, imm, currently_defined)

        if arg is None:
            return None, (
                "failed to resolve accumulator chain operand: "
                f"opcode={opcode!r}, rhs={rhs!r}, imm={imm!r}"
            )

        instruction = "addq" if opcode == "add" else "subq"
        asm_lines.append(f"{instruction} {arg}, {scratch_reg}")
        currently_defined.add(dst)

    # 最终将 scratch 写回 output C variable。
    asm_lines.append(f"movq {scratch_reg}, %[{output_name}]")

    asm_template = "".join(
        f'        "{line}\\n\\t"\n'
        for line in asm_lines
    )

    # 如果 source output 在第一条语义操作中就被读取，则 generated output
    # 必须为 read-write operand。
    output_read_before_write = (
        f_lhs == output_reg
        or (f_imm is None and f_rhs == output_reg)
    )

    # 从 source AsmFragment 的 authoritative output operand 中读取 '&'。
    source_early_clobber, early_clobber_error = (
        _source_output_has_early_clobber(
            context,
            output_reg,
        )
    )

    if early_clobber_error is not None:
        return None, early_clobber_error

    assert source_early_clobber is not None

    if output_read_before_write:
        output_constraint = "+&r" if source_early_clobber else "+r"
    else:
        output_constraint = "=&r" if source_early_clobber else "=r"

    out_decl = (
        f'[{output_name}] "{output_constraint}" ({output_expr})'
    )

    input_decls = [
        f'[{input_name_map[reg]}] "r" ({input_expr_map[reg]})'
        for reg in sorted(input_reg_set)
    ]

    input_section = ",\n              ".join(input_decls)

    # 即使没有 input operands，也必须保留 empty input section：
    #
    #   : outputs
    #   :
    #   : clobbers
    #
    parts = [
        "__asm__ __volatile__(\n",
        asm_template,
        f"        : {out_decl}\n",
        f"        : {input_section}\n",
        '        : "rax", "cc"\n',
        "    );",
    ]

    asm_code = "".join(parts)

    print(
        "[DEBUG] generated x86 AT&T ADD/SUB inline asm:",
        {
            "output_reg": output_reg,
            "output_expr": output_expr,
            "output_read_before_write": output_read_before_write,
            "source_early_clobber": source_early_clobber,
            "output_constraint": output_constraint,
            "input_regs": sorted(input_reg_set),
            "operand_owner": operand_owner,
            "replacement": asm_code,
        },
    )

    return asm_code, None
    
def _operand_name(prefix: str, reg: str) -> Optional[str]:
    """
    Use generated names rather than logical-register names directly.

    For example:

        a0 = a0 - a2

    becomes:

        [out_a0] "=r" (result)
        [in_a0]  "r"  (result)

    This correctly models the old value of result as an input and the final
    value as an output.
    """
    name = f"{prefix}_{reg}"

    if not _SAFE_OPERAND_NAME_RE.fullmatch(name):
        return None

    return name