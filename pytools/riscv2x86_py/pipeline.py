from __future__ import annotations

import re
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Dict, List, Tuple

from .schema import Finding, load_report, save_report
from .assemble import assemble
from .lift import lift, GhidraLanguageRegisterResolver
from .pcode_ir import from_lifted
from .translate import translate, _replacement_has_early_clobber_output_constraint
from .runtime_facts import build_translation_runtime_facts
from .verify import verify
from .cfg import build_cfg_from_blocks
from .phase6c_constraints import TargetEnvironment
from .helper_runtime_manifest import RV64_MULHU_U64, INSTRUCTION_STREAM_SYNC_LOCAL
from .target_register_policy import audit_translator_emitted_target_registers
from .abi_effects import TargetAbiWrapperRegistry
from .abi_sidecar import AbiCallSidecar
from .whole_function_sidecar import WholeFunctionSidecar
from .whole_function_scheduler import schedule_whole_function_replacements
from .privileged_functional_contracts import PrivilegedFunctionalFallbackRegistry
from .privileged_emitted_audit import (
    PRIVILEGED_EMITTED_TEXT_AUDIT_VERSION,
    audit_privileged_emitted_text,
)

def _approval_digest(value: str) -> str:
    state = 14695981039346656037
    for byte in value.encode("utf-8"):
        state = ((state ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"fnv1a64:{state:016x}"



def _phase2_target_environment_id(environment: TargetEnvironment) -> str:
    """Stable public-contract environment identity; never inferred from text."""
    return "phase2-public:" + ":".join((
        environment.architecture.value,
        environment.abi.value,
        environment.asm_dialect.value,
    ))


def _approve_public_replacement_if_compatible(
    finding: Finding,
    environment: TargetEnvironment,
) -> tuple[bool, str]:
    """Promote only a complete pending Phase-2 artifact.

    This is target-environment/capability validation, not a replacement or
    semantic inference engine.  A malformed, stale, or unsupported public
    contract is fail-closed and must not remain ReplaceableByRule.
    """
    artifact = finding.publicApprovalArtifact
    builtin = finding.builtin
    if not isinstance(artifact, dict) or not isinstance(builtin, dict):
        return False, "phase2 public replacement lacks structured artifact or builtin facts"
    if artifact.get("artifactVersion") != "phase2-public-approval-v1":
        return False, "phase2 public replacement artifact version is unsupported"
    if artifact.get("approvalStatus") != "pending_target_validation":
        return False, "phase2 public replacement artifact has invalid approval state"
    contract_id = artifact.get("semanticContractId")
    source_builtin = artifact.get("sourceBuiltin")
    if (not isinstance(contract_id, str) or not contract_id or
            not isinstance(source_builtin, str) or
            source_builtin != builtin.get("calleeName") or
            finding.ruleName != "phase2.public." + contract_id):
        return False, "phase2 public replacement contract/builtin binding is inconsistent"
    if artifact.get("targetEnvironmentId") != _phase2_target_environment_id(environment):
        return False, "phase2 public replacement target environment is unavailable"
    capability = artifact.get("compilerCapability")
    if not isinstance(capability, str):
        return False, "phase2 public replacement compiler capability is malformed"
    if capability and capability not in environment.builtin_capabilities:
        return False, "phase2 public replacement compiler capability is unavailable"
    if artifact.get("compilerFamily") != environment.compiler_family:
        return False, "phase2 public replacement compiler family is unavailable"
    if artifact.get("compilerVersion") != environment.compiler_version:
        return False, "phase2 public replacement compiler version is unavailable"
    headers = artifact.get("requiredHeaders")
    features = artifact.get("requiredTargetFeatures")
    if not isinstance(headers, list) or not all(isinstance(x, str) and x for x in headers):
        return False, "phase2 public replacement required headers are malformed"
    if not isinstance(features, list) or not all(isinstance(x, str) and x for x in features):
        return False, "phase2 public replacement required target features are malformed"
    if any(feature not in environment.available_features for feature in features):
        return False, "phase2 public replacement target feature is unavailable"
    if artifact.get("replacementDigest") != _approval_digest(finding.suggestedReplacement):
        return False, "phase2 public replacement digest does not match replacement"
    if artifact.get("sourceSliceDigest") != _approval_digest(finding.rawSourceText):
        return False, "phase2 public replacement digest does not match source range"
    artifact["approvalStatus"] = "approved"
    return True, ""



_DEFERRED_DETAIL = (
    "finding is not asm-pipeline-ready: missing fragment or empty rawAsmText; "
    "left for upstream classification / Phase 2 rule rewrite"
)

_KEEP_KINDS = {
    "keep",
    "keep_c",
    "preserve",
    "preserve_as_is",
}

_X86_INLINE_ASM_KINDS = {
    "x86_inline_asm",
    "x86_inline_asm_att",
    "lower_to_x86_inline_asm",
    "x86_inline_asm",
}

_TIED_DIGIT_RE = re.compile(r"(?:^|[^A-Za-z0-9_])\d+(?:$|[^A-Za-z0-9_])")

def _render_pcode_op_for_diagnostics(op) -> str:
    """
    将 lifted p-code operation 渲染为人类可读文本。

    重要约束：
      - 此函数仅用于 Finding.pcodeText、日志和诊断；
      - 不得被 Phase 6 lowering 用于 opcode 识别、operand 提取、
        register mapping、immediate parsing 或控制流分析；
      - structured p-code operation 的语义来源必须是 blocks / summary，
        而不是该函数的字符串输出。

    兼容当前 lift 层仍可能返回 str 的实现，同时允许未来 pcode_ops
    变成结构化 PcodeOp / Varnode 对象。
    """
    if op is None:
        return ""

    if isinstance(op, str):
        return op.strip()

    # 如果 structured op 提供显式的文本渲染接口，优先使用。
    #
    # 注意：这里调用 render/to_text 仅用于展示；其返回值绝不能成为
    # 新 lowering strategy 的语义输入。
    for method_name in ("to_text", "render"):
        method = getattr(op, method_name, None)
        if callable(method):
            try:
                rendered = method()
            except TypeError:
                # 某些 render() 可能需要额外参数；此处回退至 str(op)
                # 仅影响诊断展示，不影响 Phase 6 语义。
                rendered = None

            if isinstance(rendered, str):
                return rendered.strip()

    # 最终 diagnostic fallback。
    #
    # str(op) 在这里是允许的，因为该文本只写入 Finding.pcodeText，
    # 不得被任何新的 lowering strategy 重新解析为语义。
    return str(op).strip()


def _render_lifted_pcode_for_diagnostics(lift_result) -> str:
    """
    为 Finding.pcodeText 生成诊断文本。

    此函数明确不参与 canonical semantic IR 的创建：
      canonical semantic source:
          from_lifted(...) -> blocks / summary

      diagnostic-only text:
          _render_lifted_pcode_for_diagnostics(...)
    """
    rendered_insns: List[str] = []

    for insn in list(getattr(lift_result, "insns", None) or []):
        addr = getattr(insn, "addr", 0)
        asm_mnem = getattr(insn, "asm_mnem", "") or ""
        asm_body = getattr(insn, "asm_body", "") or ""
        pcode_ops = list(getattr(insn, "pcode_ops", None) or [])

        header = f"{hex(addr)} {asm_mnem} {asm_body}".rstrip()

        rendered_ops = [
            _render_pcode_op_for_diagnostics(op)
            for op in pcode_ops
        ]
        rendered_ops = [line for line in rendered_ops if line]

        if rendered_ops:
            rendered_insns.append(
                header + "\n  " + "\n  ".join(rendered_ops)
            )
        else:
            rendered_insns.append(header)

    return "\n".join(rendered_insns)


def _mark_deferred_no_fragment(f: Finding) -> None:
    if not f.verificationStatus:
        f.verificationStatus = "deferred"
    if not f.verificationDetail:
        f.verificationDetail = _DEFERRED_DETAIL

    note = "pipeline: deferred non-fragment finding; not sent to Phase 4 assemble"
    if note not in f.notes:
        f.notes.append(note)


# 明确允许走 pure-C replacement 的 translation kind。
#
# 注意：
# 不要把未知 kind 默认视为 "c"。
# 特别是 "needs_route" 的 replacement 为空是合法状态，
# 它表示当前 Phase 6 没有可安全回填的翻译，而不是翻译失败。
_PURE_C_KINDS = {
    "pure_c",
    "c",
    "builtin",
    "lower_to_c",
    "functional_c",
    "instruction_stream_elision",
    "privileged_runtime",
}


_ROUTE_KINDS = {
    "needs_route",
    "route_required",
    "deferred_route",
}


def _phase7_apply_kind(kind: str) -> str:
    """
    将 Phase 6 translation kind 映射为 pipeline 的后续动作。

    返回值：
      unsupported:
          当前 pipeline 不接受该结果；
      keep:
          保留原 inline asm；
      route:
          translate 明确要求其他 lowering route，不应要求 replacement；
      c:
          可进入 pure-C replacement + verify；
      x86:
          可进入 x86 inline-asm replacement + verify；
      unknown:
          未知 translation kind，保守拒绝，不能默认按 pure-C 处理。
    """
    normalized = (kind or "").strip().lower()

    if not normalized or normalized == "unsupported":
        return "unsupported"

    if normalized == "x86_asm_goto":
        return "x86_goto"

    if normalized in _KEEP_KINDS:
        return "keep"

    if normalized in _ROUTE_KINDS:
        return "route"

    if normalized in _X86_INLINE_ASM_KINDS:
        return "x86"

    if normalized in _PURE_C_KINDS:
        return "c"

    return "unknown"


def _extract_constraint_text(op) -> str:
    if op is None:
        return ""

    if isinstance(op, str):
        return op.strip()

    if isinstance(op, Mapping):
        for k in ("constraint", "constraints", "asmConstraint", "asmConstraints"):
            v = op.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    for k in ("constraint", "constraints", "asmConstraint", "asmConstraints"):
        v = getattr(op, k, None)
        if isinstance(v, str) and v.strip():
            return v.strip()

    return ""


def _collect_fragment_constraints(fragment) -> List[str]:
    if fragment is None:
        return []

    out: List[str] = []
    seen = set()

    for attr in (
        "outputs",
        "outputOperands",
        "outOperands",
        "inputs",
        "inputOperands",
        "inOperands",
    ):
        vals = _read_field(fragment, attr, default=None)
        if not vals:
            continue

        for op in list(vals):
            c = _extract_constraint_text(op)
            if c and c not in seen:
                out.append(c)
                seen.add(c)

    return out


def _collect_fragment_clobbers(fragment) -> List[str]:
    if fragment is None:
        return []

    out: List[str] = []
    seen = set()

    for c in list(_read_field(fragment, "clobbers", default=[]) or []):
        s = str(c).strip().strip('"').strip("'").lower()
        if s and s not in seen:
            out.append(s)
            seen.add(s)

    return out


def _constraint_has_early_clobber(constraint: str) -> bool:
    return "&" in (constraint or "")


def _constraint_has_tied_operand(constraint: str) -> bool:
    """
    判断 GNU asm constraint 是否表示 matching/tied operand。

    典型 tied input constraint：

        "0"
        "1"
        "[out]"

    以下不是 tied operand：

        "=&r"
        "+r"
        "+&r"
        "r"
        "m"
    """
    if not isinstance(constraint, str):
        return False

    for alternative in constraint.split(","):
        value = alternative.strip()

        if not value:
            continue

        # 数字 matching constraint，例如 "0"、"1"。
        #
        # 允许前面出现约束修饰符，但最终必须是纯数字编号。
        if re.fullmatch(r"[=+&%*!?#]*\d+", value):
            return True

        # GNU symbolic matching constraint，例如 "[out]"。
        if re.fullmatch(
            r"[=+&%*!?#]*\[[A-Za-z_][A-Za-z0-9_]*\]",
            value,
        ):
            return True

    return False

def _fragment_has_tied_operand(frag, constraints: List[str]) -> bool:
    outputs = list(
        _read_field(frag, "outputs", default=[]) or []
    )
    inputs = list(
        _read_field(frag, "inputs", default=[]) or []
    )

    operands = outputs + inputs

    # 优先使用 frontend 的结构化语义信息。
    for operand in operands:
        if _read_any_true_field(
            operand,
            "isTied",
            "is_tied",
        ):
            return True

    # metadata 不完整时才退回到 constraint 文本判断。
    return any(
        _constraint_has_tied_operand(constraint)
        for constraint in constraints
    )

def _phase4_preflight_blockers(f: Finding) -> List[str]:
    """
    Phase 4 前的确定性拦截。

    此处只处理不依赖 translate() 结果、且无论后续选择 pure-C、
    x86 inline asm 或 keep 均无法由当前流水线安全处理的情况。

    注意：
      - volatile / memory / cc / tied / early-clobber 不在这里拒绝；
        它们是否可接受依赖 translation kind，仍由 Phase 7 判定。
      - asm goto 是控制流语义，当前没有等价 rewrite / CFG 保持实现，
        可以且应当在装配前直接拒绝。
    """
    frag = getattr(f, "fragment", None)
    if frag is None:
        return []

    reasons: List[str] = []

    goto_labels = list(
        _read_field(frag, "gotoLabels", "goto_labels", default=[]) or []
    )
    goto_edges = list(_read_field(frag, "gotoEdges", "goto_edges", default=[]) or [])
    if goto_labels and (len(goto_edges) != len(goto_labels) or
                        {str(_read_field(edge, "cLabel", "c_label", default="")) for edge in goto_edges} != set(goto_labels)):
        reasons.append(
            "asm goto labels lack complete authoritative gotoEdges metadata"
        )
    if goto_labels:
        fallthrough = str(_read_field(
            frag,
            "asmGotoFallthroughContinuationId",
            "asm_goto_fallthrough_continuation_id",
            default="",
        ) or "").strip()
        successors = {
            str(value).strip()
            for value in (_read_field(
                frag,
                "asmGotoSuccessorContinuationIds",
                "asm_goto_successor_continuation_ids",
                default=[],
            ) or [])
            if str(value).strip()
        }
        targets = {
            str(_read_field(
                edge,
                "targetContinuationId",
                "target_continuation_id",
                default="",
            ) or "").strip()
            for edge in goto_edges
        }
        complete = bool(_read_field(
            frag,
            "asmGotoControlFlowComplete",
            "asm_goto_control_flow_complete",
            default=False,
        ))
        if (not complete or not fallthrough or "" in targets or
                successors != ({fallthrough} | targets) or
                len(successors) != len(goto_labels) + 1):
            reasons.append(
                "asm goto lacks complete authoritative host-continuation facts"
            )

    return reasons

def _finding_view(finding_or_fragment):
    """
    将公开 helper 的输入统一为带 ``fragment`` 属性的对象。

    pipeline.run() 内部始终传 Finding；但单元测试通常只想传 asm
    fragment。为了不让测试依赖私有 helper，公开接口同时接受：

      * Finding / 任何具有 ``fragment`` 属性的对象；
      * 单独的 AsmFragment 对象；
      * None。

    该适配器仅服务于无副作用的 preflight / phase7 gate 查询，
    不参与 report 的序列化和主流水线执行。
    """
    if finding_or_fragment is None:
        return SimpleNamespace(fragment=None)

    # dict / Mapping 形式的 Finding。
    #
    # 若对象本身具有 "fragment" 键，应被视为 Finding；
    # 否则它就是一个直接传入的 fragment Mapping。
    if isinstance(finding_or_fragment, Mapping):
        if "fragment" in finding_or_fragment:
            return SimpleNamespace(
                fragment=finding_or_fragment.get("fragment")
            )
        return SimpleNamespace(fragment=finding_or_fragment)

    if hasattr(finding_or_fragment, "fragment"):
        return finding_or_fragment

    return SimpleNamespace(fragment=finding_or_fragment)


def preflight_inline_asm(finding_or_fragment) -> List[str]:
    """
    公开的 Phase 4 inline-asm preflight 查询接口。

    返回阻断原因列表；空列表表示当前 preflight 没有发现 blocker。

    注意：该函数只做“assemble 前即可判定”的检查，例如 asm goto。
    volatile / memory / cc / tied / early-clobber 是否能够保留，
    仍依赖 translate() 的结果，故属于 phase7_gate_inline_asm()。
    """
    return _phase4_preflight_blockers(_finding_view(finding_or_fragment))


def _phase7_shell_semantics_blockers(f: Finding, tr) -> List[str]:
    """
    在 phase7 主体里，把 inline asm 的“外壳语义”纳入最终准入判断。

    策略：

      - asm goto：当前没有控制流保持 rewrite，拒绝。
      - pure C 路径：volatile / memory / cc / tied / early-clobber 一律拒绝。
      - x86 inline asm 路径：
          * volatile、memory、cc 必须在 replacement 中显式保留；
          * early-clobber 允许，但必须在 replacement output constraint 中保留；
          * tied operand 当前仍保守拒绝，除非后续实现显式 tied-preservation proof。
    """
    frag = getattr(f, "fragment", None)
    if frag is None:
        return []

    kind = (getattr(tr, "kind", "") or "").strip().lower()
    replacement = getattr(tr, "replacement", "") or ""

    # keep / unsupported 不在这里拦截。
    if not kind or kind == "unsupported" or kind in _KEEP_KINDS:
        return []

    # This audits translator-emitted replacement text, not compiler output.
    # A normal compiler-generated prologue may use rsp/rbp and is allowed.
    reasons: List[str] = list(audit_translator_emitted_target_registers(
        getattr(tr, "replacement", None)
    ))

    goto_labels = list(
        _read_field(frag, "gotoLabels", "goto_labels", default=[]) or []
    )
    if goto_labels:
        artifact = dict(getattr(tr, "metadata", {}).get("approvalArtifact", {}) or {})
        if (kind != "x86_asm_goto" or
                artifact.get("proofStatus") != "approved" or
                artifact.get("replacementKind") != "gnu_asm_goto"):
            reasons.append("asm goto requires an approved GNU asm-goto renderer artifact")
        return reasons

    constraints = _collect_fragment_constraints(frag)
    clobbers = _collect_fragment_clobbers(frag)

    has_early_clobber = any(
        _constraint_has_early_clobber(constraint)
        for constraint in constraints
    )

    has_tied_operand = _fragment_has_tied_operand(frag, constraints)

    is_volatile = _read_any_true_field(
        frag,
        "isVolatile",
        "is_volatile",
    )

    has_memory_clobber = "memory" in clobbers
    has_cc_clobber = "cc" in clobbers

    is_x86_inline_asm = kind in _X86_INLINE_ASM_KINDS

    # ---------- explicitly opted-in functional fallback ----------
    #
    # This is not a generic pure-C exception.  It is an auditable, explicit
    # downgrade selected by the caller and may only be used by a registered
    # semantic-family adapter.  In particular, it must not become a route for
    # silently discarding volatile/clobber semantics from arbitrary asm.
    if kind in {"privileged_runtime", "functional_c"}:
        artifact = dict(getattr(tr, "metadata", {}).get("approvalArtifact", {}) or {})
        is_registered_privileged = artifact.get("replacementKind") in {
            "privileged_runtime_adapter",
            "privileged_functional_fallback",
        }
        if is_registered_privileged:
            expected_mode = (
                "architecture_equivalent"
                if kind == "privileged_runtime"
                else "functional_equivalence_only"
            )
            required = (
                artifact.get("artifactVersion") == "phase6-approval-v1"
                and artifact.get("proofStatus") == "approved"
                and artifact.get("preservationMode") == expected_mode
                and isinstance(artifact.get("privilegedSemanticContractId"), str)
                and isinstance(artifact.get("privilegedRendererManifestId"), str)
                and isinstance(artifact.get("privilegedRendererManifestVersion"), str)
                and isinstance(artifact.get("rendererContractId"), str)
                and isinstance(artifact.get("requiredHeaders"), list)
                and isinstance(artifact.get("requiredLibraries"), list)
                and all(isinstance(item, str) and item
                        for item in artifact.get("requiredHeaders", ()))
                and all(isinstance(item, str) and item
                        for item in artifact.get("requiredLibraries", ()))
                and artifact.get("privilegedEmittedTextAuditVersion")
                    == PRIVILEGED_EMITTED_TEXT_AUDIT_VERSION
            )
            callable_id = artifact.get("privilegedCallableIdentifier")
            if not isinstance(callable_id, str) or not callable_id:
                required = False
            else:
                reasons.extend(audit_privileged_emitted_text(
                    replacement,
                    expected_callable_identifier=callable_id,
                ))
        else:
            # Compatibility gate for older non-privileged functional routes.
            required = (
                kind == "functional_c"
                and artifact.get("artifactVersion") == "phase6-functional-fallback-v1"
                and artifact.get("proofStatus") == "functional_approved"
                and artifact.get("functionalFallbackEnabled") is True
                and artifact.get("preservationMode") == "functional_equivalence_only"
                and isinstance(artifact.get("sourceSemanticContractId"), str)
                and isinstance(artifact.get("targetSemanticContractId"), str)
            )
        if not required:
            reasons.append(
                "privileged/functional C route lacks its required registered approval artifact"
            )
        return reasons

    # A strict no-op elision is not generic pure C.  It is permitted only
    # when Phase 6 carried the externally supplied instruction-stream proof
    # certificate into an approved artifact.
    if kind == "instruction_stream_elision":
        artifact = dict(getattr(tr, "metadata", {}).get("approvalArtifact", {}) or {})
        if not (
            artifact.get("artifactVersion") == "phase6-approval-v1"
            and artifact.get("proofStatus") == "approved"
            and artifact.get("replacementKind") == "instruction_stream_elision"
            and isinstance(artifact.get("instructionStreamSyncProofId"), str)
            and artifact["instructionStreamSyncProofId"]
        ):
            reasons.append(
                "instruction-stream no-op elision lacks its required proof artifact"
            )
        return reasons

    # ---------- pure C / lower_to_c 路径 ----------
    if not is_x86_inline_asm:
        if is_volatile:
            reasons.append(
                "volatile inline asm cannot be rewritten as generic pure C "
                "in phase7"
            )

        if has_memory_clobber:
            reasons.append(
                '"memory" clobber cannot be discharged by generic pure C '
                "in phase7"
            )

        if has_cc_clobber:
            reasons.append(
                '"cc" clobber cannot be discharged by generic pure C '
                "in phase7"
            )

        if has_early_clobber:
            reasons.append(
                "early-clobber constraint present; operand write timing is "
                "not modeled in phase7 pure-C path"
            )

        if has_tied_operand:
            reasons.append(
                "tied operand constraint present; operand aliasing is not "
                "modeled in phase7 pure-C path"
            )

        return reasons

    # ---------- x86 inline asm 路径 ----------
    lower_repl = replacement.lower()

    # 重要：
    #
    # 不再使用：
    #
    #     if has_early_clobber and kind != "x86_inline_asm":
    #
    # 因为 kind 可能是 x86_att_inline_asm 等其他合法的
    # _X86_INLINE_ASM_KINDS 成员。
    #
    # 对 early-clobber 的正确检查是：
    # source 有 & 时，replacement 的 output constraint 也必须有 &。
    if has_early_clobber and not _replacement_has_early_clobber_output_constraint(
        replacement
    ):
        reasons.append(
            "source inline asm has an early-clobber output constraint, "
            "but emitted x86 inline asm does not preserve an "
            "early-clobber output constraint"
        )

    # tied operand 与 early-clobber 不同。
    #
    # early-clobber 可通过 =&r / +&r 在 x86 replacement 中直接表达；
    # tied operand 需要证明输入、输出共享同一 GCC operand，因此当前
    # 若未实现显式验证仍保守拒绝。
    if has_tied_operand:
        reasons.append(
            "tied operand constraint present; current x86 inline-asm path "
            "has no explicit preservation proof for it"
        )

    if is_volatile and "volatile" not in lower_repl:
        reasons.append(
            "fragment is volatile, but emitted x86 inline asm does not "
            "visibly preserve volatile"
        )

    if has_memory_clobber and (
        '"memory"' not in lower_repl
        and "'memory'" not in lower_repl
    ):
        reasons.append(
            'fragment clobbers "memory", but emitted x86 inline asm does '
            "not visibly preserve it"
        )

    if has_cc_clobber and (
        '"cc"' not in lower_repl
        and "'cc'" not in lower_repl
    ):
        reasons.append(
            'fragment clobbers "cc", but emitted x86 inline asm does not '
            "visibly preserve it"
        )

    return reasons

def _read_field(obj, *names, default=None):
    """
    从 dict、dataclass、SimpleNamespace 等对象读取字段。

    支持 scanner JSON 使用的 camelCase，也兼容 Python 测试中可能出现的
    snake_case 字段。
    """
    if obj is None:
        return default

    for name in names:
        if isinstance(obj, Mapping):
            if name in obj:
                return obj[name]
        elif hasattr(obj, name):
            return getattr(obj, name)

    return default


def _read_any_true_field(obj, *names):
    """
    对 bool 语义字段使用“任意一个字段为真即为真”的策略。

    这能安全处理错误构造的对象，例如：
        isVolatile=False
        is_volatile=True

    对 volatile 这样的语义字段，保守判定为 True 比错误放行更安全。
    """
    if obj is None:
        return False

    values = []

    for name in names:
        if isinstance(obj, Mapping):
            if name in obj:
                values.append(bool(obj[name]))
        elif hasattr(obj, name):
            values.append(bool(getattr(obj, name)))

    return any(values)


def phase7_gate_inline_asm(finding_or_fragment, translation_result) -> List[str]:
    """
    公开的 Phase 7 inline-asm shell-semantics 查询接口。

    参数：
      finding_or_fragment:
        Finding，或直接传入 AsmFragment。
      translation_result:
        translate() 的返回对象。至少应具有 ``kind`` 和
        ``replacement`` 属性；测试中可使用 SimpleNamespace。

    返回：
      阻断原因列表；空列表表示该 translation result 通过当前
      shell semantics gate。

    重要时序：
    Phase 7 需要检查 x86 inline-asm replacement 是否显式保留
    volatile / "memory" / "cc"，因此本 gate 设计上发生在
    translate() 之后，而不是之前。
    """
    return _phase7_shell_semantics_blockers(
        _finding_view(finding_or_fragment),
        translation_result,
    )

def _get_fragment_operand_width_bits(
    fragment: AsmFragment,
) -> Tuple[Dict[int, int], List[str]]:
    """
    读取由 host AST/type analysis/schema 提供的权威：

        GNU operand index -> host type width in bits

    注意：本函数只读取已存在的事实，不推导事实。

    特别禁止根据以下信息生成 width：

      * xlen；
      * RISC-V xN / ABI register 名；
      * p-code varnode size；
      * LLVM asm 输出；
      * GNU operand 在数组中的位置；
      * C expression 文本。

    返回：

        (normalized_width_bits, errors)

    空 mapping 本身并不立即视为错误，因为一个 fragment 可以没有
    register-bound GNU operands。

    但如果最终 materialization 发现某个 RISC-V register 确实绑定了
    GNU operand，而该 operand 没有 width，则
    build_translation_runtime_facts() 会拒绝该 fragment。
    """
    raw_widths = _read_field(
        fragment,
        "operand_width_bits",
        "operandWidthBits",
        default=None,
    )

    if raw_widths is None:
        return {}, []

    if not isinstance(raw_widths, Mapping):
        return {}, [
            "host AST/type-analysis operand_width_bits must be a mapping"
        ]

    normalized: Dict[int, int] = {}
    errors: List[str] = []

    for raw_index, raw_width in raw_widths.items():
        try:
            operand_index = int(raw_index)
        except (TypeError, ValueError):
            errors.append(
                "invalid GNU operand index in host width facts: "
                f"{raw_index!r}"
            )
            continue

        if isinstance(raw_index, bool) or operand_index < 0:
            errors.append(
                "invalid GNU operand index in host width facts: "
                f"{raw_index!r}"
            )
            continue

        if isinstance(raw_width, bool) or not isinstance(raw_width, int):
            errors.append(
                "invalid host type width for GNU operand "
                f"%{operand_index}: {raw_width!r}"
            )
            continue

        if raw_width <= 0:
            errors.append(
                "non-positive host type width for GNU operand "
                f"%{operand_index}: {raw_width!r}"
            )
            continue

        normalized[operand_index] = raw_width

    return normalized, errors

#def run(in_json: str, out_json: str, xlen: int = 64) -> dict:
def run(
    in_json: str,
    out_json: str,
    xlen: int = 64,
    *,
    language: Any = None,
    register_name_resolver: Optional[RegisterNameResolver] = None,
    verify_enabled: bool = True,
    target_environment: TargetEnvironment | None = None,
    abi_call_sidecar: AbiCallSidecar | None = None,
    abi_wrapper_registry: TargetAbiWrapperRegistry | None = None,
    whole_function_sidecar: WholeFunctionSidecar | None = None,
    privileged_functional_registry: PrivilegedFunctionalFallbackRegistry | None = None,
    allow_functional_fallbacks: bool = False,
) -> dict:
    findings: List[Finding] = load_report(in_json)
    default_features = {"x86:gpr_inline_asm", "x86:atomic", "x86:hardware_fence", "compiler:atomic-builtin", "compiler:barrier-builtin", "runtime:" + RV64_MULHU_U64.runtime_contract_id}
    default_builtins = {"c_builtin:atomic", "c_builtin:compiler_barrier"}
    if allow_functional_fallbacks:
        default_features.add("x86:rdtsc")
        default_builtins.add("compiler:x86-rdtsc-builtin")
        default_features.add("runtime:" + INSTRUCTION_STREAM_SYNC_LOCAL.runtime_contract_id)
    public_environment = target_environment or TargetEnvironment.fixed_sysv_amd64_gnu_att(
        available_features=default_features,
        builtin_capabilities=default_builtins,
        supports_gnu_asm_goto=True,
        helper_contract_capabilities={
            RV64_MULHU_U64.runtime_contract_id,
            RV64_MULHU_U64.required_environment_capability,
            *({
                INSTRUCTION_STREAM_SYNC_LOCAL.runtime_contract_id,
                INSTRUCTION_STREAM_SYNC_LOCAL.required_environment_capability,
            } if allow_functional_fallbacks else set()),
        },
    )
    stats = {
        "total": 0,
        "already_rule": 0,
        "unsupported": 0,
        "verified": 0,
        "build_only": 0,
        "failed": 0,
        "needs_route": 0,
        "no_fragment": 0,
        "deferred_non_fragment": 0,
        "shell_semantics_blocked": 0,
        "register_name_blocked": 0,
        "translated_unverified": 0,
        "abi_sidecar_bound": 0,
        "abi_sidecar_missing_for_call": 0,
        "whole_function_rewrites": 0,
    }

    for f in findings:
        if f.category == "ReplaceableByRule":
            if f.ruleName.startswith("phase2.public."):
                approved, reason = _approve_public_replacement_if_compatible(
                    f, public_environment
                )
                if not approved:
                    f.category = "NeedsRoute"
                    f.suggestedReplacement = ""
                    f.verificationStatus = "needs_route"
                    f.verificationDetail = reason
                    f.notes.append("phase2-public: " + reason)
                    stats["needs_route"] += 1
                    continue
            stats["already_rule"] += 1
            continue

        if f.category != "NeedsAsmTranslation":
            continue

        # 只允许“带有有效 asm fragment 的 finding”进入 Phase 4+ 支线。
        if not f.enters_asm_pipeline():
            stats["no_fragment"] += 1
            stats["deferred_non_fragment"] += 1
            _mark_deferred_no_fragment(f)
            continue

        stats["total"] += 1

        # Phase 4
        # ---------- Phase 4 preflight ----------
        # asm goto 等不依赖 translate() 结果、且当前无安全处理路径的情况，
        # 不应继续进入 assemble -> lift -> translate 支线。
        preflight_blockers = _phase4_preflight_blockers(f)
        if preflight_blockers:
            f.category = "Unsupported"
            f.ruleName = "phase4.preflight_unsupported"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"
            f.verificationDetail = "; ".join(preflight_blockers)

            for reason in preflight_blockers:
                f.notes.append(f"phase4-preflight: {reason}")

            stats["unsupported"] += 1
            continue

        # Phase 4
        operand_width_bits, width_fact_errors = (
            _get_fragment_operand_width_bits(f.fragment)
        )

        if width_fact_errors:
            detail = "; ".join(width_fact_errors)

            f.notes.append(f"translation-facts: {detail}")
            f.category = "Unsupported"
            f.ruleName = "phase4.translation_runtime_facts_unsupported"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"
            f.verificationDetail = detail

            stats["unsupported"] += 1
            continue

        print(
            "[DEBUG] before assemble",
            {
                "fragment_type": type(f.fragment).__name__,
                "fragment_operand_width_bits": getattr(
                    f.fragment,
                    "operand_width_bits",
                    "<missing>",
                ),
                "fragment_operandWidthBits": getattr(
                    f.fragment,
                    "operandWidthBits",
                    "<missing>",
                ),
                "extracted_operand_width_bits": operand_width_bits,
            },
        )


        ar = assemble(
            f.fragment,
            xlen=xlen,
            operand_width_bits=operand_width_bits,
        )

        runtime_facts = getattr(ar, "translation_runtime_facts", None)

        print(
            "[DEBUG] after assemble",
            {
                "assemble_ok": ar.ok,
                "assemble_error": getattr(ar, "error", None),
                "runtime_facts_type": (
                    type(runtime_facts).__name__
                    if runtime_facts is not None
                    else None
                ),
                "rv_to_operand_index": getattr(
                    runtime_facts,
                    "rv_to_operand_index",
                    None,
                ),
                "runtime_operand_width_bits": getattr(
                    runtime_facts,
                    "operand_width_bits",
                    None,
                ),
                "runtime_operandWidthBits": getattr(
                    runtime_facts,
                    "operandWidthBits",
                    None,
                ),
            },
        )

        if not ar.ok:
            f.notes.append(f"assemble: {ar.error}")
            f.verificationStatus = "failed"
            f.verificationDetail = ar.error
            stats["failed"] += 1
            continue
        runtime_facts_result = build_translation_runtime_facts(
            finding=f,
            assemble_result=ar,
        )

        if not runtime_facts_result.ok:
            detail = runtime_facts_result.error or (
                "translation runtime facts are unavailable"
            )

            f.notes.append(f"translation-facts: {detail}")
            f.category = "Unsupported"
            f.ruleName = "phase4.translation_runtime_facts_unsupported"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"
            f.verificationDetail = detail

            stats["unsupported"] += 1
            continue

        # Phase 4 -> Phase 5 / 6 事实传递。
        #
        # 这一步必须发生在 lift() 和 translate() 之前。
        #
        # 后续 lowerer 不允许从：
        #   - p-code 中寄存器出现顺序；
        #   - xN 编号；
        #   - operand 顺序；
        #   - XLEN；
        #   - C 源码文本；
        # 猜测 GNU inline asm operand binding。
        #
        # finding 是贯穿后续 phase 的载体，因此 facts 必须写回 finding。
        runtime_facts = runtime_facts_result.facts

        if runtime_facts is None:
            detail = (
                "translation runtime facts builder returned success "
                "without facts"
            )

            f.notes.append(f"translation-facts: {detail}")
            f.category = "Unsupported"
            f.ruleName = "phase4.translation_runtime_facts_unsupported"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"
            f.verificationDetail = detail

            stats["unsupported"] += 1
            continue

        f.translationRuntimeFacts = runtime_facts

        f.machineCodeHex = ar.machine_code.hex()
        if ar.relocations:
            f.notes.append(f"assemble: extracted {len(ar.relocations)} relocations")

        # Phase 5
        #lr = lift(ar.machine_code, xlen=xlen, relocations=ar.relocations)
        lr = lift(
            ar.machine_code,
            xlen=xlen,
            relocations=ar.relocations,
            language=language,
            register_name_resolver=register_name_resolver,

            # Phase 5 之后会进入 canonical IR / CFG / lowerer。
            #
            # 因此不得允许匿名 register varnode 穿透 lift 边界。
            require_authoritative_register_names=True,
        )
        if not lr.ok:
            f.notes.append(f"lift: {lr.error}")

            # 缺 authoritative register-name source 不是普通翻译失败，
            # 而是当前运行环境没有满足安全 lowering 的前置条件。
            #
            # 必须 Unsupported / fail-closed，不能让 Phase 6 根据 offset、
            # xN、操作数顺序或 p-code 文本猜测 register identity。
            if lr.error_code == "register_name_unavailable":
                f.category = "Unsupported"
                f.ruleName = "phase5.authoritative_register_name_unavailable"
                f.suggestedReplacement = ""
                f.verificationStatus = "unsupported"
                f.verificationDetail = lr.error

                f.notes.append(
                    "phase5-register-identity: canonical IR was blocked "
                    "because no authoritative register-name resolver was "
                    "available for a register varnode"
                )

                stats["unsupported"] += 1
                stats["register_name_blocked"] += 1
                continue

            f.verificationStatus = "failed"
            f.verificationDetail = lr.error
            stats["failed"] += 1
            continue

                # Phase 5 -> canonical structured p-code IR。
        #
        # blocks / summary 是 Phase 6 的 authoritative semantic source。
        #
        # 后续 lowering strategy 必须从 blocks 中的 structured operation /
        # varnode 字段读取 opcode、inputs、output、constant、register、
        # memory space 等语义；不得通过 str(op)、pcodeText 或 regex
        # 重新解析 p-code 文本。
        try:
            blocks, summary = from_lifted(lr.insns)
        except Exception as exc:
            detail = (
                "failed to construct canonical structured p-code IR: "
                f"{type(exc).__name__}: {exc}"
            )

            f.notes.append(f"pcode-ir: {detail}")
            f.verificationStatus = "failed"
            f.verificationDetail = detail
            stats["failed"] += 1
            continue

        if blocks is None:
            detail = (
                "from_lifted returned no canonical blocks; "
                "Phase 6 cannot proceed without structured p-code IR"
            )

            f.notes.append(f"pcode-ir: {detail}")
            f.verificationStatus = "failed"
            f.verificationDetail = detail
            stats["failed"] += 1
            continue

        # CFG 必须从 canonical blocks 构建，而不是从 p-code 文本构建。
        cfg = build_cfg_from_blocks(blocks)

        if not cfg.ok:
            f.notes.append(f"cfg: {cfg.error}")
            f.verificationStatus = "failed"
            f.verificationDetail = cfg.error
            stats["failed"] += 1
            continue

        # Finding.pcodeText 是展示和诊断字段，不是 Phase 6 语义输入。
        #
        # 特意放在 from_lifted() 和 CFG 构建之后，明确 canonical semantic
        # IR 的优先级高于任何 rendered p-code text。
        f.pcodeText = _render_lifted_pcode_for_diagnostics(lr)

        # Phase 6: translate
        if f.translationRuntimeFacts is None:
            detail = (
                "translationRuntimeFacts unexpectedly missing before "
                "Phase 6 translate"
            )

            f.notes.append(f"translation-facts: {detail}")
            f.category = "Unsupported"
            f.ruleName = "phase6.translation_runtime_facts_missing"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"
            f.verificationDetail = detail

            stats["unsupported"] += 1
            continue

        print(
            "DEBUG pipeline runtime facts:",
            {
                "rv_to_operand_index": getattr(
                    f.translationRuntimeFacts,
                    "rv_to_operand_index",
                    None,
                ),
                "operand_width_bits": getattr(
                    f.translationRuntimeFacts,
                    "operand_width_bits",
                    None,
                ),
            },
        )

        environment = public_environment
        abi_facts = (
            None if abi_call_sidecar is None
            else abi_call_sidecar.facts_for(f.fragment.id)
        )
        abi_bindings = () if abi_facts is None else abi_facts.bindings
        if abi_facts is not None:
            stats["abi_sidecar_bound"] += 1

        tr = translate(
            frag=f.fragment,
            lift=lr,
            summary=summary,
            machine_code=ar.machine_code,
            xlen=xlen,
            blocks=blocks,
            cfg=cfg,

            # 使用已经回填进 finding 的同一份事实对象。
            #
            # 这样 Phase 5 / Phase 6 / 后续 report serialization 都消费
            # 同一个 authoritative facts source。
            runtime_facts=f.translationRuntimeFacts,
            target_environment=environment,
            abi_call_bindings=abi_bindings,
            abi_wrapper_registry=abi_wrapper_registry,
            privileged_functional_registry=privileged_functional_registry,
            allow_functional_fallbacks=allow_functional_fallbacks,
        )

        # 先读取 translate 结果，但不要立刻把 replacement 写入 finding。
        #
        # 原因：
        # 如果 replacement 只有空白字符，例如 "   "，
        # 则它是无效的 actionable replacement。若提前赋值给
        # suggestedReplacement，错误分支必须额外清理，容易遗漏。
        translation_kind = getattr(tr, "kind", "") or ""
        replacement = getattr(tr, "replacement", "") or ""
        translation_notes = list(getattr(tr, "notes", None) or [])

        f.translationKind = translation_kind
        f.approvalArtifact = dict(getattr(tr, "metadata", {}).get("approvalArtifact", {}) or {})
        if f.approvalArtifact:
            f.approvalArtifact["sourceSliceDigest"] = _approval_digest(f.rawSourceText)
        f.notes.extend(translation_notes)

        # Phase 7: inline-asm 外壳语义检查。
        #
        # 该检查依赖 translate 的 kind/replacement，因此必须发生在
        # translate() 调用之后。
        apply_kind = _phase7_apply_kind(translation_kind)

        # ---------- 显式 Phase 6 / Phase 7 动作分流 ----------

        # needs_route 不是失败。
        #
        # 它表示 translate 已确认当前片段不是 unsupported，
        # 但当前已注册的 lowering strategy 无法安全生成 replacement。
        #
        # 这类结果：
        #   - 不应要求 replacement 非空；
        #   - 不应调用 verify；
        #   - 不应计入 failed；
        #   - 不应覆盖为 ReplaceableByRule。
        if apply_kind == "route":
            f.category = "NeedsAsmTranslation"
            f.ruleName = ""
            f.suggestedReplacement = ""
            f.verificationStatus = "needs_route"
            f.verificationDetail = (
                "; ".join(translation_notes)
                if translation_notes
                else "phase6 requires another lowering route"
            )

            f.notes.append(
                "translate: no safe replacement emitted; "
                "fragment remains routed for further lowering"
            )

            stats["needs_route"] += 1
            continue

        # 未识别的 kind 不能默认当作 pure-C。
        #
        # 旧逻辑将所有未知 kind 都映射为 "c"，导致 "needs_route"
        # 被误判为 actionable translation。这里保守拒绝未知 kind。
        if apply_kind == "unknown":
            f.category = "Unsupported"
            f.ruleName = "phase6.unknown_translation_kind"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"
            f.verificationDetail = (
                f"phase6 returned unknown translation kind: "
                f"{translation_kind!r}"
            )

            f.notes.append(
                f"translate: unknown translation kind {translation_kind!r}"
            )

            stats["unsupported"] += 1
            continue
        
        # unsupported：明确不允许留下此前可能存在的 replacement。
        if apply_kind == "unsupported":
            f.category = "Unsupported"
            f.ruleName = "phase6.unsupported"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"

            # translate 如有 notes，优先将 notes 写入 detail；
            # 没有 notes 时保留稳定、可诊断的默认信息。
            f.verificationDetail = (
                "; ".join(translation_notes)
                if translation_notes
                else "no translation strategy matched"
            )

            stats["unsupported"] += 1
            continue

        # ---------- 显式 phase7 动作分流 ----------
        # keep：不替换原始 inline asm。
        if apply_kind == "keep":
            f.category = "ReplaceableByRule"
            f.ruleName = "phase6.keep"
            f.suggestedReplacement = ""
            f.verificationStatus = "verified"
            f.verificationDetail = (
                "phase6 decided to keep original inline asm unchanged"
            )

            stats["verified"] += 1
            continue

        # Phase 7: inline-asm 外壳语义检查。
        #
        # 只对真正会生成 replacement 的 c/x86 路径运行。
        # needs_route / keep / unsupported 不应被这个 gate 误判。
        shell_blockers = _phase7_shell_semantics_blockers(f, tr)
        if shell_blockers:
            f.category = "Unsupported"
            f.ruleName = "phase7.shell_semantics_unsupported"
            f.suggestedReplacement = ""
            f.verificationStatus = "unsupported"
            f.verificationDetail = "; ".join(shell_blockers)

            for reason in shell_blockers:
                f.notes.append(f"phase7-shell: {reason}")

            stats["unsupported"] += 1
            stats["shell_semantics_blocked"] += 1
            continue       

        # ---------- actionable translation ----------
        #
        # apply_kind 只可能是：
        #   * "c"
        #   * "x86" / "x86_goto"
        #
        # 对这两类必须有非空 replacement。
        #
        # 注意：
        #   replacement.strip() 仅用于“是否为空”的判断；
        #   真正写入 finding 时仍保留 replacement 原样，
        #   以避免损坏多行代码、缩进或格式。
        if not replacement.strip():
            f.category = "NeedsAsmTranslation"
            f.ruleName = ""
            f.suggestedReplacement = ""
            f.verificationStatus = "failed"
            f.verificationDetail = (
                "phase6 returned empty replacement for actionable translation"
            )
            f.notes.append(
                "translate: empty replacement for actionable phase6 result"
            )

            stats["failed"] += 1
            continue

        # 只有确认 replacement 非空后，才允许写入 suggestedReplacement。
        f.suggestedReplacement = replacement
        f.category = "ReplaceableByRule"

        if translation_kind == "functional_c":
            target_contract = f.approvalArtifact.get("targetSemanticContractId", "")
            f.ruleName = "phase6.functional." + (
                target_contract.replace("@", "_").replace(".", "_")
                if isinstance(target_contract, str) and target_contract else "registered"
            )
        elif apply_kind == "x86_goto":
            f.ruleName = "phase6.lower_to_x86_asm_goto"
        elif apply_kind == "x86":
            f.ruleName = "phase6.lower_to_x86_inline_asm"
        else:
            f.ruleName = "phase6.lower_to_c"

        # Phase 8: verify
                # Phase 8: verify
        #
        # verify_enabled=False 仅用于集成链路测试、调试或分阶段部署。
        #
        # 此时已经完成：
        #   JSON -> assemble -> lift -> canonical IR -> CFG -> translate
        #   -> replacement 写回 report.json
        #
        # 但未进行编译、执行或等价性验证，因此绝不能标记为 verified。
        if not verify_enabled:
            f.verificationStatus = "not_verified"
            f.verificationDetail = (
                "Phase 8 verification was explicitly disabled by caller; "
                "translation was emitted but semantic/build verification "
                "was not performed"
            )
            f.notes.append(
                "phase8: verification skipped by explicit caller request"
            )

            stats["translated_unverified"] += 1
            continue

        vr = verify(f.fragment, lr, summary, tr)
        f.verificationStatus = vr.status
        f.verificationDetail = vr.detail

        if vr.status == "verified":
            stats["verified"] += 1

        elif vr.status == "build_only":
            stats["build_only"] += 1

        elif vr.status == "failed":
            # verify 失败时不允许下游将 replacement 当作可安全回填的结果。
            f.category = "NeedsAsmTranslation"
            f.suggestedReplacement = ""
            f.ruleName = ""
            stats["failed"] += 1

        else:
            # 防御式处理未知 verify 状态，避免一个未知状态被误当成成功。
            f.category = "NeedsAsmTranslation"
            f.suggestedReplacement = ""
            f.ruleName = ""
            f.verificationStatus = "failed"
            f.verificationDetail = (
                f"verify returned unexpected status: {vr.status!r}"
            )
            stats["failed"] += 1

    whole_function_findings = schedule_whole_function_replacements(
        findings, whole_function_sidecar
    )
    if whole_function_findings:
        findings.extend(whole_function_findings)
        stats["whole_function_rewrites"] += len(whole_function_findings)
    save_report(findings, out_json)
    return stats
