"""
Phase 8: 块级功能语义校验 + 构建级校验。

Current guarantees:
- 对 pure_c / x86_inline 输出做 clang 编译装配 sanity check。
- 对 AMO / LRSC / fence 等已接线模板，做功能级等价证明或规范级校验。
- 对 preservation level / route 做最小契约一致性检查。

Current limitations:
- 仍未建立通用 block-proof（尚未系统消费 IRSummary / outputBindings / symbols / gotoEdges）。
- 路径级验证（asm goto / 多出口 / helper thunk ABI）仍未完整实现。
- microArch / preservation D 级仍需端到端实验验证，当前只在结果中显式挂出计划。
"""
from __future__ import annotations

import os
import shlex
import inspect
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import  Any, Dict, Iterable, List, Optional, Tuple,Mapping, Sequence
from types import SimpleNamespace

import z3

from .schema import AsmFragment
from .lift import LiftResult
from .pcode_ir import IRSummary, Block, from_lifted
from .translate import TranslationOutput


@dataclass
class VerifyResult:
    status: str                    # verified / build_only / failed / unsupported
    reason_code: str = ""
    detail: str = ""
    notes: List[str] = field(default_factory=list)

    def with_note(self, s: str) -> "VerifyResult":
        if s and s not in self.notes:
            self.notes.append(s)
        return self

def _verify_paths_angr(
    *,
    frag: Any = None,
    out: Any = None,
    lift: Any = None,
    ir_summary: Any = None,
    contract: Any = None,
    blocks: Any = None,
    obligations: Any = None,
    requirements: Any = None,
    **kwargs: Any,
):
    """
    canonical angr 路径验证后端。

    当前后端负责：
      1. 确认 angr 可用；
      2. 确认原始和翻译后的二进制产物存在；
      3. 使用 angr 加载两个真实产物；
      4. 调用配置的路径等价验证命令；
      5. 根据实际执行结果返回 verified/failed/build_only。

    注意：
      仅成功加载二进制不能证明路径等价，因此没有配置
      semantic validator command 时必须返回 build_only。
    """
    try:
        import angr
    except ImportError as exc:
        return _vr_build_only(
            "phase8.path_validator_unavailable",
            f"angr is not installed: {exc}",
        )

    metadata = _phase8_get_metadata(contract)
    config = metadata.get("phase8_angr", {})

    if not isinstance(config, Mapping):
        return _vr_build_only(
            "phase8.path_configuration_invalid",
            "contract.metadata.phase8_angr must be a mapping",
        )

    original_artifact = (
        config.get("original_artifact")
        or _phase8_get_value(
            lift,
            "original_artifact",
            None,
        )
        or _phase8_get_value(
            frag,
            "artifact",
            None,
        )
    )

    translated_artifact = (
        config.get("translated_artifact")
        or _phase8_get_value(
            out,
            "artifact",
            None,
        )
        or _phase8_get_value(
            out,
            "artifact_path",
            None,
        )
        or _phase8_get_value(
            out,
            "binary_path",
            None,
        )
    )

    if not original_artifact or not translated_artifact:
        return _vr_build_only(
            "phase8.path_artifacts_missing",
            (
                "angr path validation requires both "
                "original_artifact and translated_artifact"
            ),
        )

    original_path = Path(
        str(original_artifact)
    ).expanduser()
    translated_path = Path(
        str(translated_artifact)
    ).expanduser()

    missing_artifacts = [
        str(path)
        for path in (original_path, translated_path)
        if not path.is_file()
    ]

    if missing_artifacts:
        return _vr_build_only(
            "phase8.path_artifacts_missing",
            (
                "angr path validation artifacts do not exist: "
                + ", ".join(missing_artifacts)
            ),
        )

    auto_load_libs = bool(
        config.get("auto_load_libs", False)
    )

    try:
        # 在后端入口先验证产物确实可由 angr 加载。
        # 真正的路径状态比较由 validator command 执行。
        angr.Project(
            str(original_path),
            auto_load_libs=auto_load_libs,
        )
        angr.Project(
            str(translated_path),
            auto_load_libs=auto_load_libs,
        )
    except Exception as exc:
        return _vr_build_only(
            "phase8.path_artifact_load_failed",
            (
                "angr could not load validation artifacts: "
                f"{type(exc).__name__}: {exc}"
            ),
        )

    validator_command = (
        config.get("command")
        or config.get("validator_command")
    )

    if validator_command is None:
        return _vr_build_only(
            "phase8.path_validator_not_configured",
            (
                "angr loaded both artifacts, but no semantic "
                "path-equivalence validator command was configured"
            ),
        )

    environment = dict(
        config.get("environment", {}) or {}
    )
    environment.update(
        {
            "PHASE8_ORIGINAL_ARTIFACT": str(
                original_path
            ),
            "PHASE8_TRANSLATED_ARTIFACT": str(
                translated_path
            ),
        }
    )

    original_entry = config.get("original_entry")
    translated_entry = config.get("translated_entry")

    if original_entry is not None:
        environment["PHASE8_ORIGINAL_ENTRY"] = str(
            original_entry
        )

    if translated_entry is not None:
        environment["PHASE8_TRANSLATED_ENTRY"] = str(
            translated_entry
        )

    result = _phase8_execute_check_command(
        check_name="angr.path_equivalence",
        command=validator_command,
        cwd=config.get("cwd"),
        timeout_sec=float(
            config.get("timeout_sec", 300.0)
        ),
        environment=environment,
        failure_exit_codes=tuple(
            config.get("failure_exit_codes", [1])
        ),
    )

    if result.status == "failed":
        return _vr_failed(
            "phase8.path_proof_failed",
            result.detail,
        )

    if result.status == "build_only":
        return _vr_build_only(
            "phase8.path_validation_inconclusive",
            result.detail,
        )

    return _vr_verified(
        "angr path-equivalence validation passed"
    )


def _vr_verified(detail: str = "", notes: Optional[Iterable[str]] = None) -> VerifyResult:
    return VerifyResult(
        status="verified",
        detail=detail,
        notes=list(notes or []),
    )


def _vr_build_only(
    reason_code: str,
    detail: str = "",
    notes: Optional[Iterable[str]] = None,
) -> VerifyResult:
    return VerifyResult(
        status="build_only",
        reason_code=reason_code,
        detail=detail,
        notes=list(notes or []),
    )


def _vr_failed(
    reason_code: str,
    detail: str = "",
    notes: Optional[Iterable[str]] = None,
) -> VerifyResult:
    return VerifyResult(
        status="failed",
        reason_code=reason_code,
        detail=detail,
        notes=list(notes or []),
    )


def _vr_unsupported(
    reason_code: str,
    detail: str = "",
    notes: Optional[Iterable[str]] = None,
) -> VerifyResult:
    return VerifyResult(
        status="unsupported",
        reason_code=reason_code,
        detail=detail,
        notes=list(notes or []),
    )

def _verify_z3_state_transform(
    original,
    translated,
    *,
    inputs=None,
    outputs=None,
    branch_outputs=None,
    memory_inputs=None,
    memory_outputs=None,
    timeout_ms=5000,
) -> VerifyResult:
    """
    使用 Z3 验证两个状态转换函数是否对所有输入语义等价。

    original 和 translated 接收同一个符号状态字典，并返回输出状态字典：

        def transform(state):
            return {
                "rax": state["a"] + state["b"],
                "branch": z3.ULT(state["a"], state["b"]),
                "memory": z3.Store(...),
            }

    参数：
      inputs:
          普通位向量输入，格式为：
              {"a": 64, "b": 64}

      outputs:
          普通位向量输出，格式为：
              {"out": 64, "sp": 64}

      branch_outputs:
          布尔/分支输出，格式为：
              {"branch": "bool"}

      memory_inputs:
          初始内存数组，格式为：
              {
                  "memory": {
                      "address_bits": 64,
                      "value_bits": 8,
                  }
              }

      memory_outputs:
          需要比较的最终内存数组，格式同 memory_inputs。

    验证方法：
      1. 为两个转换构造完全相同的符号初始状态；
      2. 分别执行 original 和 translated；
      3. 构造“至少一个可观察输出不同”的公式；
      4. SAT   表示存在反例，返回 failed；
      5. UNSAT 表示不存在反例，返回 verified；
      6. UNKNOWN 表示求解器无法完成证明，返回 unsupported。
    """
    try:
        import z3
    except Exception as exc:
        return _vr_unsupported(
            "Z3_UNAVAILABLE",
            f"Z3 Python bindings are unavailable: {exc}",
        )

    from collections.abc import Mapping

    inputs = dict(inputs or {})
    outputs = dict(outputs or {})
    branch_outputs = dict(branch_outputs or {})
    memory_inputs = dict(memory_inputs or {})
    memory_outputs = dict(memory_outputs or {})

    if not callable(original):
        return _vr_failed(
            "Z3_INVALID_TRANSFORM",
            "original state transform is not callable",
        )

    if not callable(translated):
        return _vr_failed(
            "Z3_INVALID_TRANSFORM",
            "translated state transform is not callable",
        )

    def _parse_width(value, *, label):
        try:
            width = int(value)
        except (TypeError, ValueError):
            raise ValueError(
                f"{label} width must be an integer, got {value!r}"
            )

        if width <= 0:
            raise ValueError(
                f"{label} width must be positive, got {width}"
            )

        return width

    def _parse_memory_spec(name, spec, *, label):
        if not isinstance(spec, Mapping):
            raise ValueError(
                f"{label} {name!r} must be a mapping containing "
                "'address_bits' and 'value_bits'"
            )

        if "address_bits" not in spec:
            raise ValueError(
                f"{label} {name!r} is missing 'address_bits'"
            )

        if "value_bits" not in spec:
            raise ValueError(
                f"{label} {name!r} is missing 'value_bits'"
            )

        address_bits = _parse_width(
            spec["address_bits"],
            label=f"{label} {name!r} address",
        )
        value_bits = _parse_width(
            spec["value_bits"],
            label=f"{label} {name!r} value",
        )

        return address_bits, value_bits

    try:
        scalar_widths = {
            name: _parse_width(
                width,
                label=f"input {name!r}",
            )
            for name, width in inputs.items()
        }

        output_widths = {
            name: _parse_width(
                width,
                label=f"output {name!r}",
            )
            for name, width in outputs.items()
        }

        parsed_memory_inputs = {
            name: _parse_memory_spec(
                name,
                spec,
                label="memory input",
            )
            for name, spec in memory_inputs.items()
        }

        parsed_memory_outputs = {
            name: _parse_memory_spec(
                name,
                spec,
                label="memory output",
            )
            for name, spec in memory_outputs.items()
        }
    except ValueError as exc:
        return _vr_failed(
            "Z3_INVALID_SCHEMA",
            str(exc),
        )

    overlapping_inputs = (
        set(scalar_widths) & set(parsed_memory_inputs)
    )
    if overlapping_inputs:
        return _vr_failed(
            "Z3_INVALID_SCHEMA",
            "state names cannot be both scalar and memory inputs: "
            + ", ".join(sorted(overlapping_inputs)),
        )

    # 使用每次调用唯一的前缀，避免并行测试或同一进程内多次验证时
    # 出现不必要的 Z3 符号名称碰撞。
    symbol_prefix = f"phase8_{id(original):x}_{id(translated):x}"

    initial_state = {}

    try:
        for name, width in scalar_widths.items():
            initial_state[name] = z3.BitVec(
                f"{symbol_prefix}_input_{name}",
                width,
            )

        for name, (
            address_bits,
            value_bits,
        ) in parsed_memory_inputs.items():
            initial_state[name] = z3.Array(
                f"{symbol_prefix}_memory_{name}",
                z3.BitVecSort(address_bits),
                z3.BitVecSort(value_bits),
            )
    except Exception as exc:
        return _vr_failed(
            "Z3_STATE_CONSTRUCTION_ERROR",
            f"failed to construct symbolic initial state: {exc}",
        )

    # 分别传递浅拷贝，防止某个转换修改 state 字典本身后影响另一个转换。
    # Z3 表达式是不可变的，因此共享其中的符号表达式是正确且必要的。
    try:
        original_result = original(dict(initial_state))
    except Exception as exc:
        return _vr_failed(
            "Z3_ORIGINAL_EXECUTION_ERROR",
            f"original state transform raised "
            f"{type(exc).__name__}: {exc}",
        )

    try:
        translated_result = translated(dict(initial_state))
    except Exception as exc:
        return _vr_failed(
            "Z3_TRANSLATED_EXECUTION_ERROR",
            f"translated state transform raised "
            f"{type(exc).__name__}: {exc}",
        )

    if not isinstance(original_result, Mapping):
        return _vr_failed(
            "Z3_INVALID_TRANSFORM_RESULT",
            "original state transform must return a mapping, "
            f"got {type(original_result).__name__}",
        )

    if not isinstance(translated_result, Mapping):
        return _vr_failed(
            "Z3_INVALID_TRANSFORM_RESULT",
            "translated state transform must return a mapping, "
            f"got {type(translated_result).__name__}",
        )

    differences = []
    observed_names = []

    def _require_output(result, transform_name, output_name):
        if output_name not in result:
            raise ValueError(
                f"{transform_name} state transform did not produce "
                f"required output {output_name!r}"
            )
        return result[output_name]

    def _coerce_bitvector(value, width, *, label):
        if isinstance(value, bool):
            raise ValueError(
                f"{label} must be a {width}-bit bit-vector, "
                "not a boolean"
            )

        if isinstance(value, int):
            return z3.BitVecVal(value, width)

        try:
            sort = value.sort()
        except Exception:
            raise ValueError(
                f"{label} must be a {width}-bit Z3 bit-vector "
                f"or integer, got {type(value).__name__}"
            )

        expected_sort = z3.BitVecSort(width)
        if sort != expected_sort:
            raise ValueError(
                f"{label} has sort {sort}; expected {expected_sort}"
            )

        return value

    def _coerce_bool(value, *, label):
        if isinstance(value, bool):
            return z3.BoolVal(value)

        try:
            sort = value.sort()
        except Exception:
            raise ValueError(
                f"{label} must be a Z3 boolean expression "
                f"or bool, got {type(value).__name__}"
            )

        if sort != z3.BoolSort():
            raise ValueError(
                f"{label} has sort {sort}; expected Bool"
            )

        return value

    def _coerce_memory(
        value,
        address_bits,
        value_bits,
        *,
        label,
    ):
        try:
            sort = value.sort()
        except Exception:
            raise ValueError(
                f"{label} must be a Z3 array expression, "
                f"got {type(value).__name__}"
            )

        expected_sort = z3.ArraySort(
            z3.BitVecSort(address_bits),
            z3.BitVecSort(value_bits),
        )

        if sort != expected_sort:
            raise ValueError(
                f"{label} has sort {sort}; expected {expected_sort}"
            )

        return value

    try:
        # 比较普通寄存器/标量输出。
        for name, width in output_widths.items():
            original_value = _require_output(
                original_result,
                "original",
                name,
            )
            translated_value = _require_output(
                translated_result,
                "translated",
                name,
            )

            original_value = _coerce_bitvector(
                original_value,
                width,
                label=f"original output {name!r}",
            )
            translated_value = _coerce_bitvector(
                translated_value,
                width,
                label=f"translated output {name!r}",
            )

            differences.append(
                original_value != translated_value
            )
            observed_names.append(name)

        # 比较分支条件等布尔输出。
        for name, output_kind in branch_outputs.items():
            normalized_kind = str(
                output_kind or "bool"
            ).strip().lower()

            if normalized_kind not in {
                "bool",
                "boolean",
                "branch",
                "condition",
                "predicate",
            }:
                raise ValueError(
                    f"branch output {name!r} has unsupported "
                    f"type {output_kind!r}; expected 'bool'"
                )

            original_value = _require_output(
                original_result,
                "original",
                name,
            )
            translated_value = _require_output(
                translated_result,
                "translated",
                name,
            )

            original_value = _coerce_bool(
                original_value,
                label=f"original branch output {name!r}",
            )
            translated_value = _coerce_bool(
                translated_value,
                label=f"translated branch output {name!r}",
            )

            differences.append(
                original_value != translated_value
            )
            observed_names.append(name)

        # 比较最终内存。Z3 数组相等采用外延数组语义：
        # 两个数组不等当且仅当存在某个地址，其读取结果不同。
        for name, (
            address_bits,
            value_bits,
        ) in parsed_memory_outputs.items():
            original_value = _require_output(
                original_result,
                "original",
                name,
            )
            translated_value = _require_output(
                translated_result,
                "translated",
                name,
            )

            original_value = _coerce_memory(
                original_value,
                address_bits,
                value_bits,
                label=f"original memory output {name!r}",
            )
            translated_value = _coerce_memory(
                translated_value,
                address_bits,
                value_bits,
                label=f"translated memory output {name!r}",
            )

            differences.append(
                original_value != translated_value
            )
            observed_names.append(name)

    except ValueError as exc:
        return _vr_failed(
            "Z3_INVALID_OUTPUT",
            str(exc),
        )
    except Exception as exc:
        return _vr_failed(
            "Z3_OUTPUT_COMPARISON_ERROR",
            f"failed to construct output comparison: "
            f"{type(exc).__name__}: {exc}",
        )

    if not differences:
        return _vr_verified(
            "no observable outputs were requested; "
            "state transforms are vacuously equivalent"
        )

    try:
        solver = z3.Solver()

        if timeout_ms is not None:
            timeout_value = int(timeout_ms)
            if timeout_value > 0:
                solver.set(timeout=timeout_value)

        # 查找反例：是否存在至少一个可观察输出不同？
        solver.add(z3.Or(*differences))
        check_result = solver.check()
    except Exception as exc:
        return _vr_failed(
            "Z3_SOLVER_ERROR",
            f"Z3 solver execution failed: "
            f"{type(exc).__name__}: {exc}",
        )

    if check_result == z3.unsat:
        return _vr_verified(
            "Z3 proved equivalent state transforms for outputs: "
            + ", ".join(observed_names)
        )

    if check_result == z3.sat:
        try:
            model_text = str(solver.model())
        except Exception:
            model_text = "<counterexample model unavailable>"

        # 防止异常大的数组模型污染测试日志。
        max_model_chars = 4000
        if len(model_text) > max_model_chars:
            model_text = (
                model_text[:max_model_chars]
                + "\n... counterexample model truncated ..."
            )

        return _vr_failed(
            "Z3_SEMANTIC_MISMATCH",
            "Z3 found a counterexample; state transforms differ "
            "for at least one observable output: "
            + ", ".join(observed_names)
            + "\ncounterexample:\n"
            + model_text,
        )

    try:
        unknown_reason = solver.reason_unknown()
    except Exception:
        unknown_reason = "unknown"

    return _vr_unsupported(
        "Z3_PROOF_UNKNOWN",
        "Z3 could not determine semantic equivalence"
        + (
            f": {unknown_reason}"
            if unknown_reason
            else ""
        ),
    )


def _phase8_get_value(
    obj: Any,
    name: str,
    default: Any = None,
) -> Any:
    """
    同时支持字典和属性对象。

    Phase 8 的 contract/metadata 在不同调用路径中可能是 dict、
    dataclass 或 SimpleNamespace，因此后端不直接假设具体类型。
    """
    if obj is None:
        return default

    if isinstance(obj, Mapping):
        return obj.get(name, default)

    return getattr(obj, name, default)


def _phase8_get_metadata(contract: Any) -> dict[str, Any]:
    metadata = _phase8_get_value(
        contract,
        "metadata",
        {},
    )

    if metadata is None:
        return {}

    if isinstance(metadata, Mapping):
        return dict(metadata)

    # 兼容 SimpleNamespace、dataclass 等对象。
    try:
        return dict(vars(metadata))
    except (TypeError, AttributeError):
        return {}


def _phase8_normalize_command(
    command: Any,
) -> list[str] | None:
    """
    将命令规范化为 subprocess 使用的 argv。

    支持：
        ["pytest", "-q", "..."]
        ("pytest", "-q", "...")
        "pytest -q ..."

    不启用 shell=True，避免命令注入和 shell 差异。
    """
    if command is None:
        return None

    if isinstance(command, str):
        command = shlex.split(command)

    if isinstance(command, Sequence) and not isinstance(
        command,
        (str, bytes),
    ):
        argv = [str(item) for item in command]
        return argv or None

    return None


def _phase8_normalize_required_checks(
    requirements: Any,
) -> list[str]:
    """
    将 requirement 列表转换成稳定的字符串检查名。
    """
    if requirements is None:
        return []

    if isinstance(requirements, str):
        return [requirements]

    normalized: list[str] = []

    try:
        iterator = iter(requirements)
    except TypeError:
        iterator = iter([requirements])

    for requirement in iterator:
        if isinstance(requirement, str):
            name = requirement
        elif isinstance(requirement, Mapping):
            name = (
                requirement.get("name")
                or requirement.get("id")
                or requirement.get("kind")
                or requirement.get("requirement")
            )
        else:
            name = (
                getattr(requirement, "name", None)
                or getattr(requirement, "id", None)
                or getattr(requirement, "kind", None)
                or getattr(
                    requirement,
                    "requirement",
                    None,
                )
            )

        if name:
            normalized.append(str(name))

    # 保持原顺序并去重。
    return list(dict.fromkeys(normalized))


def _phase8_safe_cwd(
    configured_cwd: Any,
) -> str | None:
    if configured_cwd is None:
        return None

    path = Path(str(configured_cwd)).expanduser()

    if not path.exists() or not path.is_dir():
        return None

    return str(path)


def _phase8_format_process_output(
    completed: subprocess.CompletedProcess[str],
    *,
    limit: int = 8000,
) -> str:
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    text = (
        f"exit_code={completed.returncode}\n"
        f"stdout:\n{stdout}\n"
        f"stderr:\n{stderr}"
    )

    if len(text) > limit:
        text = text[:limit] + "\n... output truncated ..."

    return text


def _phase8_execute_check_command(
    *,
    check_name: str,
    command: Any,
    cwd: Any = None,
    timeout_sec: float = 120.0,
    environment: Mapping[str, Any] | None = None,
    failure_exit_codes: Sequence[int] = (1,),
):
    """
    执行单个验证命令并转换为 VerificationResult。

    约定：
      0：检查真实执行并通过；
      failure_exit_codes（默认 1）：发现语义/工程行为不一致；
      其他非零退出码：工具或基础设施异常，结果不确定；
      timeout：结果不确定。

    这样可以区分“找到反例”和“验证器自身无法工作”。
    """
    argv = _phase8_normalize_command(command)

    if not argv:
        return _vr_build_only(
            "phase8.check_command_missing",
            f"{check_name}: validation command is not configured",
        )

    executable = argv[0]

    if (
        os.path.sep not in executable
        and shutil.which(executable) is None
    ):
        return _vr_build_only(
            "phase8.check_tool_unavailable",
            (
                f"{check_name}: executable is not available: "
                f"{executable}"
            ),
        )

    run_cwd = _phase8_safe_cwd(cwd)

    if cwd is not None and run_cwd is None:
        return _vr_build_only(
            "phase8.check_working_directory_unavailable",
            (
                f"{check_name}: configured working directory "
                f"does not exist: {cwd}"
            ),
        )

    run_environment = os.environ.copy()

    if environment:
        run_environment.update(
            {
                str(key): str(value)
                for key, value in environment.items()
            }
        )

    try:
        completed = subprocess.run(
            argv,
            cwd=run_cwd,
            env=run_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=float(timeout_sec),
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return _vr_build_only(
            "phase8.check_timeout",
            (
                f"{check_name}: validation timed out after "
                f"{timeout_sec} seconds: {exc}"
            ),
        )
    except FileNotFoundError as exc:
        return _vr_build_only(
            "phase8.check_tool_unavailable",
            f"{check_name}: {exc}",
        )
    except (OSError, ValueError) as exc:
        return _vr_build_only(
            "phase8.check_execution_error",
            (
                f"{check_name}: validation command could not "
                f"be executed: {type(exc).__name__}: {exc}"
            ),
        )

    detail = _phase8_format_process_output(completed)

    if completed.returncode == 0:
        return _vr_verified(
            f"{check_name} passed\n{detail}"
        )

    if completed.returncode in set(failure_exit_codes):
        return _vr_failed(
            "phase8.check_failed",
            f"{check_name} failed\n{detail}",
        )

    return _vr_build_only(
        "phase8.check_inconclusive",
        (
            f"{check_name} terminated with an infrastructure "
            f"or unsupported exit code\n{detail}"
        ),
    )


def _phase8_run_command_suite(
    *,
    suite_name: str,
    commands: Any,
    required_checks: Any = None,
    cwd: Any = None,
    timeout_sec: float = 120.0,
    environment: Mapping[str, Any] | None = None,
    failure_exit_codes: Sequence[int] = (1,),
):
    """
    运行命名检查集合。

    commands 示例：
        {
            "unit_tests": ["pytest", "-q", "tests/unit"],
            "abi_validation": ["pytest", "-q", "tests/abi"],
        }

    只有所有 required_checks 均实际执行并通过，才返回 verified。
    """
    if not isinstance(commands, Mapping) or not commands:
        return _vr_build_only(
            "phase8.validation_suite_not_configured",
            f"{suite_name}: no validation commands are configured",
        )

    required = _phase8_normalize_required_checks(
        required_checks
    )

    # 没有显式 required 时，所有配置的命令都必须通过。
    if not required:
        required = [str(name) for name in commands]

    missing = [
        name
        for name in required
        if name not in commands
    ]

    if missing:
        return _vr_build_only(
            "phase8.required_checks_missing",
            (
                f"{suite_name}: required checks are not "
                f"configured: {', '.join(missing)}"
            ),
        )

    passed: list[str] = []
    details: list[str] = []

    for check_name in required:
        result = _phase8_execute_check_command(
            check_name=f"{suite_name}.{check_name}",
            command=commands[check_name],
            cwd=cwd,
            timeout_sec=timeout_sec,
            environment=environment,
            failure_exit_codes=failure_exit_codes,
        )

        details.append(
            f"{check_name}: {result.status}"
        )

        if result.status != "verified":
            return result

        passed.append(check_name)

    return _vr_verified(
        (
            f"{suite_name} passed; executed required checks: "
            f"{', '.join(passed)}"
        )
    )

@dataclass
class TranslationContract:
    level: str
    route: str
    build_family: str
    reason_codes: List[str] = field(default_factory=list)
    requires_build_check: bool = True
    requires_block_proof: bool = False
    requires_path_validation: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


def _norm_level(level: str) -> str:
    lv = str(level or "").strip().upper()
    return lv if lv in {"A", "B", "C", "D"} else "A"


def _norm_route(route: str) -> str:
    rt = str(route or "").strip()
    return rt or "canonical_public_c"


def _norm_build_family(kind: str, replacement: str, explicit: str = "") -> str:
    fam = str(explicit or "").strip()
    if fam:
        return fam

    k = str(kind or "").strip()
    if k in {
        "pure_c",
        "x86_inline_asm",
        "x86_asm_goto",
        "c_helper",
        "unsupported",
    }:
        return k

    rep = replacement or ""
    if "__asm__" in rep and " goto " in rep:
        return "x86_asm_goto"
    if "__asm__" in rep:
        return "x86_inline_asm"
    if rep.strip():
        return "pure_c"
    return "unsupported"


def _contract_from_output(out: TranslationOutput) -> TranslationContract:
    level = _norm_level(getattr(out, "preservationLevel", ""))
    route = _norm_route(getattr(out, "preservationRoute", ""))
    build_family = _norm_build_family(
        getattr(out, "kind", ""),
        getattr(out, "replacement", ""),
        explicit=getattr(out, "buildFamily", ""),
    )

    reason_codes = list(getattr(out, "reasonCodes", []) or [])
    metadata = dict(getattr(out, "metadata", {}) or {})

    return TranslationContract(
        level=level,
        route=route,
        build_family=build_family,
        reason_codes=reason_codes,
        requires_build_check=bool(getattr(out, "requiresBuildCheck", True)),
        requires_block_proof=bool(getattr(out, "requiresBlockProof", False)),
        requires_path_validation=bool(getattr(out, "requiresPathValidation", False)),
        metadata=metadata,
    )

def _phase8_contract_from_output(
    out: TranslationOutput,
    frag=None,
) -> TranslationContract:
    """
    Phase 8 使用的统一契约解析。

    优先级：
      1. TranslationOutput 显式字段
      2. frag.microArch / notes 中的兼容字段
      3. 旧 _contract_from_output 默认值
    """
    base = _contract_from_output(out)

    explicit_level = str(
        getattr(out, "preservationLevel", "") or ""
    ).strip().upper()

    if explicit_level in {"A", "B", "C", "D"}:
        level = explicit_level
    else:
        level = _preservation_level(out, frag)

    explicit_route = str(
        getattr(out, "preservationRoute", "") or ""
    ).strip()

    route = (
        explicit_route
        or _preservation_route(out, frag)
        or str(getattr(base, "route", "") or "")
        or "canonical_public_c"
    )

    build_family = str(
        getattr(base, "build_family", "") or ""
    ).strip()

    # 只在旧 contract 未识别 family 时使用 canonical kind。
    if build_family in {"", "unknown"}:
        build_family = _normalized_translation_kind(out)

    return TranslationContract(
        level=level,
        route=route,
        build_family=build_family,
        reason_codes=list(
            getattr(base, "reason_codes", []) or []
        ),
        requires_build_check=bool(
            getattr(base, "requires_build_check", True)
        ),
        requires_block_proof=bool(
            getattr(base, "requires_block_proof", False)
        ),
        requires_path_validation=bool(
            getattr(base, "requires_path_validation", False)
        ),
        metadata=dict(
            getattr(base, "metadata", {}) or {}
        ),
    )

RC_BUILD_SKIPPED = "build_skipped"
RC_TOOLCHAIN_UNAVAILABLE = "toolchain_unavailable"
RC_BUILD_STATUS_UNKNOWN = "build_status_unknown"

RC_SEMANTIC_CHECKER_UNAVAILABLE = "semantic_checker_unavailable"
RC_BLOCK_PROOF_UNAVAILABLE = "block_proof_unavailable"
RC_BLOCK_PROOF_UNPROVEN = "block_proof_unproven"
RC_PATH_VALIDATOR_UNAVAILABLE = "path_validator_unavailable"
RC_PATH_VALIDATOR_UNPROVEN = "path_validator_unproven"

RC_ADMISSION_ROUTE_UNMAPPED = "admission_route_unmapped"
RC_ADMISSION_MATRIX_DENIED = "admission_matrix_denied"
RC_OUTPUT_FAMILY_MISMATCH = "output_family_mismatch"
RC_PATH_SURFACE_MISMATCH = "path_surface_mismatch"

RC_BUILD_FAILED = "build_failed"
RC_TRANSLATION_UNSUPPORTED = "translation_unsupported"
RC_SEMANTIC_PROOF_FAILED = "semantic_proof_failed"


# ============================================================
# C/D admission matrix
# ============================================================

_PHASE8_ADMISSION_MATRIX: Dict[Tuple[str, str], set[str]] = {
    # A
    ("A", "canonical_public_c"): {"pure_c"},
    ("A", "canonical_pic_pure_c"): {"pure_c"},
    ("A", "canonical_pure_c_or_semantic_x86"): {"pure_c", "x86_inline_asm"},
    ("A", "needs_semantic_x86_lowering"): {"x86_inline_asm", "x86_asm_goto"},

    # B
    ("B", "needs_stack_aware_lowering"): {"x86_inline_asm", "c_helper"},

    # C
    ("C", "needs_control_preserving_lowering"): {"x86_inline_asm", "x86_asm_goto", "c_helper"},
    ("C", "x86_inline_asm_cfg"): {"x86_inline_asm"},
    ("C", "x86_asm_goto"): {"x86_asm_goto"},
    ("C", "out_of_line_thunk"): {"c_helper"},

    # D
    ("D", "needs_experiment_preserving_lowering"): {"x86_inline_asm", "x86_asm_goto"},
    ("D", "x86_inline_asm"): {"x86_inline_asm"},
    ("D", "x86_asm_goto"): {"x86_asm_goto"},
}


def _validate_admission(contract: TranslationContract) -> VerifyResult:
    allowed = _PHASE8_ADMISSION_MATRIX.get((contract.level, contract.route))
    if allowed is None:
        return _vr_build_only(
            RC_ADMISSION_ROUTE_UNMAPPED,
            f"no phase8 admission entry for ({contract.level}, {contract.route})",
        )

    if contract.build_family not in allowed:
        return _vr_failed(
            RC_ADMISSION_MATRIX_DENIED,
            f"build_family={contract.build_family} is not admitted for "
            f"({contract.level}, {contract.route}); allowed={sorted(allowed)}",
        )

    return _vr_verified(
        detail=(
            f"admission ok: ({contract.level}, {contract.route}) "
            f"accepts {contract.build_family}"
        )
    )


# ============================================================
# Block proof obligation
# ============================================================

@dataclass
class BlockProofObligation:
    block_addr: int
    successor_count: int

    requires_explicit_cfg_surface: bool = False
    requires_callret_surface: bool = False
    requires_barrier_shape: bool = False
    requires_atomic_shape: bool = False
    requires_nonlocal_surface: bool = False

    reason_codes: List[str] = field(default_factory=list)


def _block_opcodes(block: Block) -> set[str]:
    return {str(op.opcode or "") for op in (block.ops or [])}


def _collect_block_proof_obligations(
    frag,
    blocks: List[Block],
    ir_summary: IRSummary,
    contract: TranslationContract,
) -> List[BlockProofObligation]:
    out: List[BlockProofObligation] = []

    micro = getattr(frag, "microArch", None)
    preserve_atomic = bool(getattr(micro, "preserveAtomicRetryShape", False))
    preserve_fence = bool(getattr(micro, "preserveFenceShape", False))
    has_nonlocal = bool(getattr(frag, "hasNonLocalControlDependency", False))

    for block in blocks:
        opcodes = _block_opcodes(block)

        rc: List[str] = []
        req_cfg = False
        req_callret = False
        req_barrier = False
        req_atomic = False
        req_nonlocal = False

        if len(block.successors) > 1:
            req_cfg = True
            rc.append("multi_successor_block")

        if opcodes & {"CALL", "CALLIND", "RETURN"}:
            req_callret = True
            rc.append("callret_surface")

        barrier_infos = _summary_barrier_infos(ir_summary)

        has_any_barrier = (
            bool(barrier_infos)
            or bool(getattr(ir_summary, "has_memory_barrier", False))
            or bool(getattr(ir_summary, "has_instruction_barrier", False))
            or bool(getattr(ir_summary, "has_unknown_barrier", False))
        )

        if preserve_fence or (
            has_any_barrier
            and opcodes & {"FENCE", "MEMORYBARRIER"}
        ):
            req_barrier = True
            rc.append("barrier_shape")

            for barrier in barrier_infos:
                if barrier.kind is BarrierKind.MEMORY_FENCE:
                    rc.append(
                        f"fence_pred_{barrier.pred or 'unknown'}"
                    )
                    rc.append(
                        f"fence_succ_{barrier.succ or 'unknown'}"
                    )

                elif barrier.kind is BarrierKind.TSO_FENCE:
                    rc.append("fence_tso")

                elif barrier.kind is BarrierKind.INSTRUCTION_FENCE:
                    rc.append("fence_i")

                else:
                    rc.append("fence_semantics_unknown")

        if preserve_atomic or bool(getattr(ir_summary, "has_atomic", False)):
            req_atomic = True
            rc.append("atomic_shape")

        atomic_orderings = set(
            getattr(ir_summary, "atomic_orderings", set()) or set()
        )

        if "aq" in atomic_orderings:
            rc.append("atomic_acquire")

        if "rl" in atomic_orderings:
            rc.append("atomic_release")

        if has_nonlocal or bool(opcodes & {"BRANCHIND", "RETURN"} and not block.successors):
            req_nonlocal = True
            rc.append("nonlocal_surface")

        if contract.level in {"C", "D"} and len(blocks) > 1:
            req_cfg = True
            if "multi_block_surface" not in rc:
                rc.append("multi_block_surface")

        if rc:
            out.append(
                BlockProofObligation(
                    block_addr=block.addr,
                    successor_count=len(block.successors),
                    requires_explicit_cfg_surface=req_cfg,
                    requires_callret_surface=req_callret,
                    requires_barrier_shape=req_barrier,
                    requires_atomic_shape=req_atomic,
                    requires_nonlocal_surface=req_nonlocal,
                    reason_codes=rc,
                )
            )

    return out


def _family_satisfies_block_obligation(
    contract: TranslationContract,
    ob: BlockProofObligation,
) -> bool:
    fam = contract.build_family

    if fam == "pure_c":
        if ob.requires_callret_surface:
            return False
        if ob.requires_nonlocal_surface:
            return False
        if contract.level in {"C", "D"} and (
            ob.requires_explicit_cfg_surface
            or ob.requires_barrier_shape
            or ob.requires_atomic_shape
        ):
            return False
        return True

    if fam == "x86_inline_asm":
        if contract.route == "x86_inline_asm_cfg":
            return not ob.requires_callret_surface
        if contract.level == "D":
            return True
        if ob.requires_nonlocal_surface and contract.route != "needs_control_preserving_lowering":
            return False
        return True

    if fam == "x86_asm_goto":
        if ob.requires_callret_surface:
            return False
        return True

    if fam == "c_helper":
        if ob.requires_explicit_cfg_surface and ob.successor_count > 1:
            return False
        return True

    return False


def _validate_block_proofs(
    contract: TranslationContract,
    obligations: List[BlockProofObligation],
) -> VerifyResult:
    if not contract.requires_block_proof:
        return _vr_verified("block proof not required by contract")

    bad: List[str] = []
    for ob in obligations:
        if not _family_satisfies_block_obligation(contract, ob):
            bad.append(
                f"block {hex(ob.block_addr)} requires {','.join(ob.reason_codes)} "
                f"but build_family={contract.build_family} cannot discharge it"
            )

    if bad:
        return _vr_failed(
            RC_BLOCK_PROOF_UNPROVEN,
            " ; ".join(bad),
        )

    return _vr_verified("block structural obligations satisfied structurally")

def _phase8_requires_path_validation(
    *,
    frag,
    ir_summary: IRSummary,
    blocks,
    contract: TranslationContract,
    out: TranslationOutput,
) -> bool:
    if bool(getattr(contract, "requires_path_validation", False)):
        return True

    if _needs_path_validation(frag, ir_summary, blocks):
        return True

    if _has_path_sensitive_surface(frag, out):
        return True

    return False

def _run_strict_path_validation(
    *,
    frag,
    out: TranslationOutput,
    lift,
    ir_summary: IRSummary,
    contract: TranslationContract,
    blocks,
) -> VerifyResult:
    required = _phase8_requires_path_validation(
        frag=frag,
        ir_summary=ir_summary,
        blocks=blocks,
        contract=contract,
        out=out,
    )

    if not required:
        return _vr_verified(
            "path validation not required for this fragment"
        )

    checker = _phase8_find_checker(
        "_verify_paths_angr",
        "_validate_paths_angr",
        "_verify_path_semantics_angr",
        exclude=_run_strict_path_validation,
    )

    if checker is None:
        return _vr_build_only(
            RC_PATH_VALIDATOR_UNAVAILABLE,
            "path-sensitive fragment requires an angr path validator",
        )

    return _run_phase8_checker(
        checker,
        layer="angr path equivalence",
        unavailable_reason=RC_PATH_VALIDATOR_UNAVAILABLE,
        failed_reason=RC_PATH_PROOF_FAILED,
        error_reason=RC_PATH_VALIDATOR_ERROR,
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        blocks=blocks,
    )

def _collect_engineering_requirements(
    *,
    frag,
    out: TranslationOutput,
    ir_summary: IRSummary,
    contract: TranslationContract,
) -> list[str]:
    requirements = [
        "unit_tests",
        "regression_tests",
        "reference_differential",
    ]

    family = str(
        getattr(contract, "build_family", "") or ""
    ).strip().lower()

    text = str(
        getattr(out, "replacement", "") or ""
    )

    asm_family = family in {
        "x86_inline_asm",
        "x86_asm_goto",
        "standalone_asm",
        "standalone_assembly",
        "assembly",
        "assembler",
        "gas",
        ".s",
    }

    if asm_family or "__asm__" in text:
        requirements.extend([
            "abi_validation",
            "register_clobber_validation",
            "stack_alignment_validation",
        ])

    if (
        _is_standalone_assembly_output(out, contract)
        or ".cfi_" in text
    ):
        requirements.extend([
            "unwind_validation",
            "cfi_validation",
            "dwarf_frame_validation",
        ])

    if (
        _is_standalone_assembly_output(out, contract)
        or re.search(
            r"\b(?:GOT|GOTOFF|GOTPCREL|PLT|TLS|pcrel|reloc)\b",
            text,
            re.IGNORECASE,
        )
    ):
        requirements.extend([
            "relocation_validation",
            "pic_pie_validation",
        ])

    if bool(getattr(ir_summary, "has_atomic", False)):
        requirements.extend([
            "multithread_stress",
            "atomic_ordering_validation",
        ])

    if bool(getattr(ir_summary, "has_memory_barrier", False)):
        requirements.append(
            "memory_ordering_validation"
        )

    if bool(getattr(ir_summary, "has_call_or_return", False)):
        requirements.extend([
            "abi_validation",
            "return_point_validation",
            "unwind_validation",
        ])

    # 去重且保持顺序。
    return list(dict.fromkeys(requirements))


def _run_engineering_validation(
    *,
    frag,
    out: TranslationOutput,
    lift,
    ir_summary: IRSummary,
    contract: TranslationContract,
    blocks,
) -> VerifyResult:
    requirements = _collect_engineering_requirements(
        frag=frag,
        out=out,
        ir_summary=ir_summary,
        contract=contract,
    )

    checker = _phase8_find_checker(
        "_run_phase8_engineering_suite",
        "_verify_engineering_behavior",
        exclude=_run_engineering_validation,
    )

    # 避免找到当前函数自身。
    if checker is _run_engineering_validation:
        checker = None

    if checker is None:
        return _vr_build_only(
            RC_ENGINEERING_VALIDATOR_UNAVAILABLE,
            "engineering validation suite is not installed; "
            f"required checks: {', '.join(requirements)}",
        )

    result = _run_phase8_checker(
        checker,
        layer="engineering behavior",
        unavailable_reason=RC_ENGINEERING_VALIDATOR_UNAVAILABLE,
        failed_reason=RC_ENGINEERING_VALIDATION_FAILED,
        error_reason=RC_ENGINEERING_VALIDATOR_ERROR,
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        blocks=blocks,
        requirements=requirements,
    )

    if result.status != "verified":
        result = _append_detail(
            result,
            f"required engineering checks: "
            f"{', '.join(requirements)}",
        )

    return result

def _run_microarch_validation(
    *,
    frag,
    out: TranslationOutput,
    lift,
    ir_summary: IRSummary,
    contract: TranslationContract,
    blocks,
) -> VerifyResult:
    if not _needs_microarch_e2e(out, frag):
        return _vr_verified(
            "microarchitectural end-to-end validation not required"
        )

    checker = _phase8_find_checker(
        "_run_phase8_microarch_suite",
        "_verify_microarchitectural_behavior",
        "_run_microarch_e2e_validation",
        exclude=_run_microarch_validation,
    )

    if checker is None:
        return _vr_build_only(
            RC_MICROARCH_VALIDATOR_UNAVAILABLE,
            "requires end-to-end microarchitectural validation "
            "(timing/PMC/cache/branch-predictor/side-channel PoC)",
        )

    requirements = [
        "timing_distribution",
        "pmc_profile",
        "cache_footprint",
        "branch_predictor_shape",
        "side_channel_poc",
    ]

    micro = getattr(frag, "microArch", None)
    if bool(
        getattr(micro, "preserveAtomicRetryShape", False)
    ):
        requirements.append("atomic_retry_shape")

    if bool(
        getattr(micro, "preserveFenceShape", False)
    ):
        requirements.append("fence_shape")

    if bool(
        getattr(micro, "preserveTimingSource", False)
    ):
        requirements.append("timing_source")

    requirements = list(dict.fromkeys(requirements))

    return _run_phase8_checker(
        checker,
        layer="microarchitectural end-to-end behavior",
        unavailable_reason=RC_MICROARCH_VALIDATOR_UNAVAILABLE,
        failed_reason=RC_MICROARCH_VALIDATION_FAILED,
        error_reason=RC_MICROARCH_VALIDATOR_ERROR,
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        blocks=blocks,
        requirements=requirements,
    )

def _verify_block_semantics_z3(
    *,
    frag,
    out,
    lift,
    ir_summary,
    contract,
    blocks,
    obligations,
):
    if not _z3_available():
        return _vr_build_only(
            RC_BLOCK_SEMANTIC_CHECKER_UNAVAILABLE,
            "z3-solver is not installed",
        )

    # 必须替换为你的 IR -> Z3 编码。
    proof = build_block_equivalence_formula(
        frag=frag,
        out=out,
        lift=lift,
        blocks=blocks,
        obligations=obligations,
    )

    solver = proof.solver
    result = solver.check()

    if str(result) == "unsat":
        return _vr_verified(
            "Z3 proved block-level semantic equivalence"
        )

    if str(result) == "sat":
        model = solver.model()
        return _vr_failed(
            RC_BLOCK_SEMANTIC_PROOF_FAILED,
            f"Z3 found a semantic counterexample: {model}",
        )

    return _vr_build_only(
        RC_BLOCK_SEMANTIC_CHECKER_UNAVAILABLE,
        f"Z3 returned unknown: {solver.reason_unknown()}",
    )


def _vr(
    status: str,
    detail: str,
    reason_code: str = "",
    notes: Optional[Iterable[str]] = None,
) -> VerifyResult:
    """
    给旧代码一个兼容出口：
    以前很多地方习惯写 VerifyResult("failed", "xxx")，
    现在统一改成 _vr("failed", "xxx")，避免 detail/reason_code 串位。
    """
    return VerifyResult(
        status=status,
        reason_code=reason_code,
        detail=detail,
        notes=list(notes or []),
    )

def _clone_vr(
    vr: VerifyResult,
    *,
    status: Optional[str] = None,
    reason_code: Optional[str] = None,
    detail: Optional[str] = None,
    notes: Optional[Iterable[str]] = None,
) -> VerifyResult:
    """
    保留原有 vr 的其余字段，只覆盖指定字段。
    用于 _append_detail / _with_microarch_plan / _apply_path_obligation 之类场景。
    """
    return VerifyResult(
        status=vr.status if status is None else status,
        reason_code=vr.reason_code if reason_code is None else reason_code,
        detail=vr.detail if detail is None else detail,
        notes=list(vr.notes if notes is None else notes),
    )

def _coerce_verify_result(obj) -> VerifyResult:
    if isinstance(obj, VerifyResult):
        return obj

    if isinstance(obj, dict):
        return VerifyResult(
            status=str(obj.get("status", "failed")),
            reason_code=str(obj.get("reason_code", "") or ""),
            detail=str(obj.get("detail", "") or ""),
            notes=list(obj.get("notes", []) or []),
        )

    if hasattr(obj, "status") and hasattr(obj, "detail"):
        return VerifyResult(
            status=str(getattr(obj, "status", "failed")),
            reason_code=str(getattr(obj, "reason_code", "") or ""),
            detail=str(getattr(obj, "detail", "") or ""),
            notes=list(getattr(obj, "notes", []) or []),
        )

    return _vr("failed", f"invalid verify result object: {obj!r}")


def _merge_details(*parts: str) -> str:
    out: list[str] = []
    seen = set()
    for p in parts:
        p = (p or "").strip()
        if not p or p in seen:
            continue
        seen.add(p)
        out.append(p)
    return "; ".join(out)

def _append_detail(vr: VerifyResult, extra: str) -> VerifyResult:
    extra = (extra or "").strip()
    if not extra:
        return vr
    if extra.lower() in (vr.detail or "").lower():
        return vr
    return _clone_vr(vr, detail=_merge_details(vr.detail, extra))

# ---------- 构建级 ----------

_C_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
_RESERVED_BUILD_NAMES = {"p", "v", "q", "expected", "desired", "old"}


def _is_simple_c_ident(expr: str) -> bool:
    return bool(_C_IDENT_RE.fullmatch((expr or "").strip()))


def _operand_stub_decls(frag: Optional[AsmFragment]) -> str:
    """
    为 build harness 自动补齐 frag 中的简单标识符操作数声明。

    目的不是执行真实语义，只是让 replacement 通过 clang build sanity check。
    因此这里的策略是：
      - 仅处理形如 a / out / tmp 的简单 C 标识符
      - 复杂表达式（如 *p, arr[i], obj.x）不在这里伪造声明
      - 输入/读写输出给一个非零初值；纯输出给 0 即可
    """
    if frag is None:
        return ""

    lines: list[str] = []
    seen = set(_RESERVED_BUILD_NAMES)
    next_init = 1

    all_ops = list(getattr(frag, "outputs", []) or []) + list(getattr(frag, "inputs", []) or [])
    for op in all_ops:
        expr = (getattr(op, "exprText", "") or "").strip()
        if not _is_simple_c_ident(expr):
            continue
        if expr in seen:
            continue

        seen.add(expr)
        constraint = getattr(op, "constraint", "") or ""
        is_output = bool(getattr(op, "isOutput", False))
        needs_entry_value = (not is_output) or ("+" in constraint)

        init = str(next_init) if needs_entry_value else "0"
        next_init += 1

        lines.append(f"    long {expr} = {init};")

    return "\n".join(lines)


def _label_stub_block(frag: Optional[AsmFragment]) -> str:
    if frag is None or not getattr(frag, "gotoLabels", None):
        return ""

    lines: list[str] = []
    for lab in list(getattr(frag, "gotoLabels", []) or []):
        lab = (lab or "").strip()
        if _is_simple_c_ident(lab):
            lines.append(f"{lab}: ;")

    return "\n".join(lines)


def _build_tool_available() -> bool:
    return bool(shutil.which("clang"))


def _build_check_c(code: str,
                   frag: Optional[AsmFragment] = None,
                   c_target: str = "x86_64-pc-linux-gnu"):
    """
    legacy 风格：
      - None          => 构建成功
      - "stderr text" => 构建失败
    """
    if not _build_tool_available():
        return None

    operand_decls = _operand_stub_decls(frag)
    label_stubs = _label_stub_block(frag)

    src = f"""
#include <stdatomic.h>
#include <stdint.h>

long __wrap(long *p, long v, long *q,
            long expected, long desired) {{
    long old = 0;
    (void)p; (void)v; (void)q;
    (void)expected; (void)desired; (void)old;
{operand_decls if operand_decls else ""}
    {code}
    goto __r2x_epilogue;
{label_stubs if label_stubs else ""}
__r2x_epilogue:
    return old;
}}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        path = f.name

    try:
        proc = subprocess.run(
            ["clang", "-target", c_target, "-O0", "-c", path, "-o", path + ".o",
             "-Wno-everything"],
            capture_output=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if proc.returncode != 0:
            return proc.stderr.strip()
        return None
    except subprocess.TimeoutExpired:
        return _vr_build_only(
            globals().get(
                "RC_BUILD_STATUS_UNKNOWN",
                "phase8.build_status_unknown",
            ),
            "clang build check timed out",
        )
    except OSError as exc:
        return _vr_build_only(
            globals().get(
                "RC_TOOLCHAIN_UNAVAILABLE",
                "phase8.toolchain_unavailable",
            ),
            f"unable to execute clang: {exc}",
        )
    finally:
        for ext in ("", ".o"):
            try:
                os.unlink(path + ext)
            except OSError:
                pass


def _build_check_c_intblock(code: str,
                            frag: Optional[AsmFragment],
                            c_target: str = "x86_64-pc-linux-gnu"):
    """
    为兼容旧调用点保留的薄封装。
    """
    return _build_check_c(code, frag=frag, c_target=c_target)

def _build_only_reason_from_text(status: str, detail: str) -> str:
    text = f"{status} {detail}".lower()
    if "toolchain" in text or "compiler" in text or "cc" in text or "clang" in text or "gcc" in text:
        return RC_TOOLCHAIN_UNAVAILABLE
    if "skip" in text or "disabled" in text:
        return RC_BUILD_SKIPPED
    return RC_BUILD_STATUS_UNKNOWN

def _coerce_build_check_result(obj: Any) -> VerifyResult:
    """
    统一 _build_check_c 的新旧返回协议。

    Legacy ABI:
      None             -> build passed
      ""               -> build passed
      non-empty str    -> compiler/assembler failure
      True             -> build passed
      False            -> build failed

    Structured ABI:
      VerifyResult
      dict(status=..., detail=...)
    """
    if isinstance(obj, VerifyResult):
        return obj

    if obj is None:
        return _vr_verified("build check passed")

    if obj is True:
        return _vr_verified("build check passed")

    if obj is False:
        return _vr_failed(
            globals().get("RC_BUILD_FAILED", "phase8.build_failed"),
            "build check failed",
        )

    if isinstance(obj, str):
        text = obj.strip()
        if not text:
            return _vr_verified("build check passed")

        return _vr_failed(
            globals().get("RC_BUILD_FAILED", "phase8.build_failed"),
            text,
        )

    if isinstance(obj, dict):
        status = str(obj.get("status", "") or "").strip().lower()
        detail = str(
            obj.get("detail", "")
            or obj.get("stderr", "")
            or obj.get("message", "")
            or ""
        ).strip()

        if status in {
            "ok",
            "verified",
            "pass",
            "passed",
            "success",
        }:
            return _vr_verified(
                detail or "build check passed"
            )

        if status in {
            "failed",
            "fail",
            "error",
            "compile_error",
            "assembler_error",
        }:
            return _vr_failed(
                globals().get(
                    "RC_BUILD_FAILED",
                    "phase8.build_failed",
                ),
                detail or "build check failed",
            )

        if status in {
            "skipped",
            "unavailable",
            "unknown",
            "build_only",
            "timeout",
        }:
            return _vr_build_only(
                globals().get(
                    "RC_TOOLCHAIN_UNAVAILABLE",
                    "phase8.toolchain_unavailable",
                ),
                detail or "build check unavailable",
            )

    return _vr_build_only(
        globals().get(
            "RC_BUILD_STATUS_UNKNOWN",
            "phase8.build_status_unknown",
        ),
        f"unrecognized build checker result: {obj!r}",
    )

def _is_standalone_assembly_output(
    out: TranslationOutput,
    contract: TranslationContract,
) -> bool:
    family = str(
        getattr(contract, "build_family", "") or ""
    ).strip().lower()

    kind = str(getattr(out, "kind", "") or "").strip().lower()
    target = str(_translation_target(out) or "").strip().lower()

    standalone_families = {
        "standalone_asm",
        "standalone_assembly",
        "assembly",
        "assembler",
        "gas",
        "dot_s",
        ".s",
    }

    return (
        family in standalone_families
        or kind in standalone_families
        or target in {"assembly", "assembler", ".s", "dot_s"}
    )


def _run_artifact_build_gate(
    *,
    frag,
    out: TranslationOutput,
    contract: TranslationContract,
) -> Optional[VerifyResult]:
    """
    返回：
      None         -> 构建通过，可以进入下一层
      VerifyResult -> 构建失败或构建设施不可用

    对 standalone .S，优先使用 artifact build checker。
    对 C / inline asm，使用现有 _build_check_c。
    """
    replacement = str(
        getattr(out, "replacement", "") or ""
    )

    if _is_standalone_assembly_output(out, contract):
        checker = _phase8_find_checker(
            "_build_check_translation_artifact",
            "_build_check_assembly",
            "_build_check_dot_s",
        )

        if checker is None:
            return _vr_build_only(
                RC_ARTIFACT_BUILD_CHECKER_UNAVAILABLE,
                "standalone assembly output requires an assembler/"
                "linker artifact build checker",
            )

        result = _run_phase8_checker(
            checker,
            layer="artifact build",
            unavailable_reason=RC_ARTIFACT_BUILD_CHECKER_UNAVAILABLE,
            failed_reason=RC_ARTIFACT_BUILD_FAILED,
            error_reason=RC_ARTIFACT_BUILD_CHECKER_UNAVAILABLE,
            frag=frag,
            out=out,
            contract=contract,
        )

        if result.status == "verified":
            return None
        return result

    if "_build_check_c" not in globals():
        return _vr_build_only(
            globals().get(
                "RC_TOOLCHAIN_UNAVAILABLE",
                "phase8.toolchain_unavailable",
            ),
            "_build_check_c is not available",
        )

    if not _build_tool_available():
        return _vr_build_only(
            globals().get(
                "RC_TOOLCHAIN_UNAVAILABLE",
                "phase8.toolchain_unavailable",
            ),
            "build check unavailable: clang not found",
        )

    try:
        raw = _build_check_c(replacement, frag=frag)
    except Exception as exc:
        return _vr_build_only(
            globals().get(
                "RC_BUILD_STATUS_UNKNOWN",
                "phase8.build_status_unknown",
            ),
            f"build checker raised {type(exc).__name__}: {exc}",
        )

    result = _coerce_build_check_result(raw)
    if result.status == "verified":
        return None

    return result

def _coerce_legacy_semantic_result(
    obj: Any,
    *,
    unavailable_reason: str = RC_SEMANTIC_CHECKER_UNAVAILABLE,
) -> VerifyResult:
    if isinstance(obj, VerifyResult):
        return obj

    if obj is True:
        return _vr_verified("semantic check passed")
    if obj is False:
        return _vr_failed(RC_SEMANTIC_PROOF_FAILED, "semantic check failed")
    if obj is None:
        return _vr_build_only(unavailable_reason, "semantic checker returned None")

    if isinstance(obj, str):
        s = obj.strip().lower()
        if s in {"ok", "verified", "pass", "passed"}:
            return _vr_verified(obj)
        if s in {"skipped", "unavailable", "build_only"}:
            return _vr_build_only(unavailable_reason, obj)
        if s in {"failed", "mismatch", "error"}:
            return _vr_failed(RC_SEMANTIC_PROOF_FAILED, obj)
        return _vr_build_only(unavailable_reason, obj)

    if isinstance(obj, dict):
        status = str(obj.get("status", "")).strip().lower()
        detail = str(obj.get("detail", "") or "")
        if status in {"ok", "verified", "pass", "passed"}:
            return _vr_verified(detail or "semantic check passed")
        if status in {"skipped", "unavailable", "build_only"}:
            return _vr_build_only(unavailable_reason, detail or status)
        if status in {"failed", "mismatch", "error"}:
            return _vr_failed(RC_SEMANTIC_PROOF_FAILED, detail or status)

    return _vr_build_only(unavailable_reason, f"unrecognized semantic checker result: {obj!r}")

# ---------- 统一 build / path / checker 兼容层 ----------

def _checked_build_vr(replacement: str, frag: Optional[AsmFragment] = None) -> VerifyResult:
    """
    统一把 _build_check_c 的各种旧返回规约成 VerifyResult。
    """
    return _coerce_build_check_result(_build_check_c(replacement, frag=frag))


def _validate_path_surface_compat(
    frag: Optional[AsmFragment],
    lift: Optional[LiftResult],
    ir_summary: IRSummary,
    blocks: list[Block],
    tr: TranslationOutput,
) -> Optional[VerifyResult]:
    """
    兼容旧 _verify_core 调用语义：
      - 真正需要 path validation 时，调用新 _validate_path_surface(...)
      - 不需要时返回 None，让旧链路继续走 block obligation
    """
    if not _needs_path_validation(frag, ir_summary, blocks):
        return None

    contract = _contract_from_output(tr)
    return _validate_path_surface(
        frag,
        blocks,
        ir_summary,
        contract,
        tr,
    )


def _invoke_semantic_checker_compat(
    checker,
    *,
    frag,
    out: TranslationOutput,
    lift,
    ir_summary: IRSummary,
    contract: TranslationContract,
):
    """
    兼容两类 checker ABI：
      1) 新式/旧式 phase8 checker:
         checker(frag, out, lift, ir_summary, contract=...)
         checker(frag, out, lift, ir_summary)
      2) 仅 shape/build sanity checker:
         checker(tr, frag=None)
         checker(tr)
    """
    code = getattr(checker, "__code__", None)
    argc = getattr(code, "co_argcount", None)
    names = list(getattr(code, "co_varnames", ())[: argc or 0])

    # 明确匹配 (tr, frag=None) / (tr)
    if names[:2] == ["tr", "frag"] or names == ["tr"]:
        return checker(out, frag=frag)

    # 明确匹配 phase8 风格
    if "contract" in names:
        return checker(frag, out, lift, ir_summary, contract=contract)

    if argc == 4:
        return checker(frag, out, lift, ir_summary)
    if argc == 3:
        return checker(frag, out, lift)
    if argc == 2:
        # 优先尝试 (tr, frag)
        if names and names[0] == "tr":
            return checker(out, frag)
        return checker(frag, out)
    if argc == 1:
        return checker(out)

    # 最保底 fallback
    try:
        return checker(frag, out, lift, ir_summary, contract=contract)
    except TypeError:
        try:
            return checker(frag, out, lift, ir_summary)
        except TypeError:
            try:
                return checker(out, frag=frag)
            except TypeError:
                return checker(out)

def _invoke_family_semantic_checker(
    checker,
    *,
    frag,
    out: TranslationOutput,
    lift,
    ir_summary: IRSummary,
    contract: TranslationContract,
):
    return _invoke_checker_flexibly(
        checker,
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        kind="family_semantic",
        meta=None,
    )


def _run_family_semantic_checker(
    frag,
    out: TranslationOutput,
    lift,
    ir_summary: IRSummary,
    contract: TranslationContract,
) -> VerifyResult:
    fam = contract.build_family

    if fam == "pure_c":
        checker = globals().get("_verify_pure_c_semantics") or globals().get("_verify_c_output")
        if checker is None:
            return _vr_build_only(
                RC_SEMANTIC_CHECKER_UNAVAILABLE,
                "no pure_c semantic checker installed",
            )
        return _coerce_legacy_semantic_result(
            _invoke_family_semantic_checker(
                checker,
                frag=frag,
                out=out,
                lift=lift,
                ir_summary=ir_summary,
                contract=contract,
            ),
        )

    checker = (
        globals().get("_verify_existing_translation")
        or globals().get("_verify_x86_inline_asm_semantics")
        or globals().get("_verify_x86_output")
    )
    if checker is None:
        return _vr_build_only(
            RC_SEMANTIC_CHECKER_UNAVAILABLE,
            f"no semantic checker installed for build_family={fam}",
        )

    return _coerce_legacy_semantic_result(
        _invoke_family_semantic_checker(
            checker,
            frag=frag,
            out=out,
            lift=lift,
            ir_summary=ir_summary,
            contract=contract,
        ),
    )

def _run_semantic_closure(
    frag,
    out: TranslationOutput,
    lift,
    ir_summary: IRSummary,
    contract: TranslationContract,
) -> VerifyResult:
    # 先跑特例语义
    special = _verify_special_semantics(frag, lift, ir_summary, out)
    if special is not None:
        return special
    # 再跑 family checker
    return _run_family_semantic_checker(
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
    )

def _can_close_with_block_proofs(
    contract: TranslationContract,
    ir_summary: IRSummary,
    out: TranslationOutput,
) -> bool:
    if contract.build_family != "pure_c":
        return False
    if contract.level not in {"A", "B"}:
        return False
    if contract.route not in {"", "canonical_public_c"}:
        return False

    if bool(getattr(ir_summary, "has_atomic", False)):
        return False
    if bool(getattr(ir_summary, "has_memory_barrier", False)):
        return False
    if bool(getattr(ir_summary, "has_branch", False)):
        return False
    if bool(getattr(ir_summary, "has_call_or_return", False)):
        return False

    text = str(getattr(out, "replacement", "") or "")
    if "__asm__" in text:
        return False
    if re.search(r"\bgoto\b|\bcall\b|\bret\b", text):
        return False

    return True

def _close_semantic_gap_with_block_proofs(
    contract: TranslationContract,
    ir_summary: IRSummary,
    out: TranslationOutput,
    sem_res: VerifyResult,
) -> Optional[VerifyResult]:
    """
    结构性 block obligation 不能关闭语义证明缺口。

    保留此函数仅为兼容旧调用点。
    """
    _ = (contract, ir_summary, out, sem_res)
    return None

def _run_build_gate(replacement: str, frag: Optional[AsmFragment]) -> Optional[VerifyResult]:
    """
    顶层 build gate：
      - clang 不可用：对外仍返回 build_only（避免破坏 pipeline 统计）
      - build 失败：failed / build_only（取决于底层 build check 结果）
      - build 通过：None（继续后续验证）
    """
    if not _build_tool_available():
        return _vr_build_only(
            globals().get("RC_TOOLCHAIN_UNAVAILABLE", ""),
            "build check unavailable: clang not found",
        )

    raw = _build_check_c(replacement, frag=frag)
    vr = _coerce_build_check_result(raw)

    if vr.status == "verified":
        return None
    return vr


# ---------- TranslationOutput / preservation 契约解析 ----------

_KIND_X86 = {
    "phase6.lower_to_x86_inline_asm",
    "x86_inline_asm",
    "lower_to_x86_inline_asm",
}

_KIND_X86_ASM_GOTO = {
    "x86_asm_goto",
    "phase6.lower_to_x86_asm_goto",
}

_KIND_C_HELPER = {
    "phase6.lower_to_c_helper_thunk",
    "c_helper",
    "lower_to_c_helper_thunk",
}

_KIND_PURE_C = {
    "pure_c",
    "c",
    "lower_to_c",
    "phase6.lower_to_c",
}

_KIND_UNSUPPORTED = {
    "unsupported",
    "phase6.unsupported",
}

_KIND_KEEP = {
    "keep",
    "keep_c",
    "preserve",
    "preserve_as_is",
    "phase6.keep",
}


def _tr_notes(tr) -> list[str]:
    return [str(n) for n in (getattr(tr, "notes", None) or [])]


def _note_value(notes: list[str], *prefixes: str) -> str:
    for n in notes:
        s = str(n).strip()
        for p in prefixes:
            if s.startswith(p):
                return s[len(p):].strip()
    return ""


_PRES_LEVEL_RE = re.compile(
    r"(?:preservation(?:\.level)?|level)\s*=\s*([ABCD])\b",
    re.IGNORECASE,
)

_PRES_ROUTE_RE = re.compile(
    r"(?:preservation(?:\.route)?|route)\s*=\s*([A-Za-z0-9_./-]+)",
    re.IGNORECASE,
)


def _normalized_translation_kind(tr: TranslationOutput) -> str:
    kind = str(getattr(tr, "kind", "") or "").strip()
    repl = str(getattr(tr, "replacement", "") or "")

    if kind in _KIND_KEEP:
        return "keep"

    # 优先依据实际 emitted replacement 识别 asm-goto
    if "__asm__" in repl and re.search(r"\bgoto\b", repl):
        return "x86_asm_goto"

    if kind in _KIND_X86_ASM_GOTO:
        return "x86_asm_goto"
    if kind in _KIND_X86:
        return "x86_inline_asm"
    if kind in _KIND_C_HELPER:
        return "c_helper"
    if kind in _KIND_PURE_C:
        return "pure_c"
    if kind in _KIND_UNSUPPORTED or not kind:
        return "unsupported"

    return kind or "unknown"


def _normalized_kind(tr: TranslationOutput) -> str:
    """
    兼容旧调用点：统一走唯一的 canonical kind normalizer。
    """
    return _normalized_translation_kind(tr)


def _preservation_level(
    tr: TranslationOutput,
    frag: Optional[AsmFragment] = None,
) -> str:
    micro = getattr(frag, "microArch", None) if frag is not None else None
    lv = str(getattr(micro, "level", "") or "").strip().upper()
    if lv in {"A", "B", "C", "D"}:
        return lv

    notes = _tr_notes(tr)

    v = _note_value(
        notes,
        "preservation.level=",
        "preservation_level=",
        "level=",
    )
    v = str(v or "").strip().upper()
    if v in {"A", "B", "C", "D"}:
        return v

    for note in notes:
        m = _PRES_LEVEL_RE.search(str(note))
        if m:
            return m.group(1).upper()

    return "A"


def _preservation_route(
    tr: TranslationOutput,
    frag: Optional[AsmFragment] = None,
) -> str:
    """
    注意：必须保留 frag 可选参数，兼容现有调用点 _preservation_route(tr, frag)。
    """
    notes = _tr_notes(tr)

    v = _note_value(
        notes,
        "preservation.route=",
        "preservation_route=",
        "route=",
    )
    if v:
        return v

    for note in notes:
        m = _PRES_ROUTE_RE.search(str(note))
        if m:
            return m.group(1)

    micro = getattr(frag, "microArch", None) if frag is not None else None
    route = getattr(micro, "route", None) if micro is not None else None
    return str(route or "")


def _translation_target(tr: TranslationOutput) -> str:
    return _note_value(_tr_notes(tr), "translation.target=")


def _contract_mismatch_reasons(
    tr: TranslationOutput,
    frag: Optional[AsmFragment],
) -> list[str]:
    """
    只抓“明显矛盾”的契约，不做激进拒绝。
    """
    reasons: list[str] = []
    kind = _normalized_translation_kind(tr)
    route = _preservation_route(tr, frag)
    text = str(getattr(tr, "replacement", "") or "")

    if kind == "x86_asm_goto":
        if "__asm__" not in text or not re.search(r"\bgoto\b", text):
            reasons.append(
                "translation kind says x86_asm_goto, but emitted replacement is not asm-goto shaped"
            )

    if kind == "x86_inline_asm" and "__asm__" not in text:
        reasons.append(
            "translation kind says x86_inline_asm, but emitted replacement has no __asm__ block"
        )

    if kind == "pure_c" and "__asm__" in text:
        reasons.append(
            "translation kind says pure_c, but emitted replacement still contains __asm__"
        )

    if route in {"out_of_line_thunk", "manual_or_outlined_helper"} and kind in {
        "x86_inline_asm",
        "x86_asm_goto",
    }:
        reasons.append(
            f"preservation route '{route}' conflicts with direct inline-asm emission"
        )

    if route == "x86_inline_asm_cfg" and kind not in {
        "x86_inline_asm",
        "unsupported",
    }:
        reasons.append(
            f"preservation route '{route}' requires x86 inline-asm CFG lowering, but translation kind is {kind}"
        )

    if route.startswith("x86_asm_goto") and kind not in {
        "x86_asm_goto",
        "unsupported",
    }:
        reasons.append(
            f"preservation route '{route}' requires x86 asm-goto style lowering, but translation kind is {kind}"
        )

    if kind == "keep":
        reasons.append(
            "verify() received keep-style translation; keep decisions should bypass Phase 8 actionable replacement verification"
        )

    if kind == "unknown":
        reasons.append(f"unknown translation kind: {getattr(tr, 'kind', '')}")

    return reasons


# ---------- 通用 shape / path / microarch 义务 ----------

def _has_path_sensitive_surface(
    frag: Optional[AsmFragment],
    tr: Optional[TranslationOutput] = None,
) -> bool:
    if frag is None:
        return False

    if list(getattr(frag, "gotoLabels", []) or []):
        return True
    if bool(getattr(frag, "hasAsmGoto", False)):
        return True
    if bool(getattr(frag, "hasLocalLabels", False)):
        return True
    if bool(getattr(frag, "hasMultipleExits", False)):
        return True
    if bool(getattr(frag, "hasNonLocalControlDependency", False)):
        return True

    surface = str(getattr(frag, "controlFlowSurface", "") or "")
    if surface in {"AsmGoto", "InternalCFG", "LocalCFG"}:
        return True

    route = _preservation_route(tr, frag) if tr is not None else ""
    if route in {
        "x86_asm_goto",
        "x86_inline_asm_cfg",
        "x86_inline_asm_goto_dispatch",
        "out_of_line_thunk",
        "manual_or_outlined_helper",
    }:
        return True

    return False


def _path_validation_installed(tr: TranslationOutput) -> bool:
    notes_lc = [n.lower() for n in _tr_notes(tr)]
    return any("phase8.path.proved" in n for n in notes_lc)


def _apply_path_obligation(
    vr: VerifyResult,
    frag: Optional[AsmFragment],
    tr: TranslationOutput,
) -> VerifyResult:
    if vr.status != "verified":
        return vr

    if not _has_path_sensitive_surface(frag, tr):
        return vr

    if _path_validation_installed(tr):
        return vr

    extra = "path-sensitive fragment has no dedicated phase8 path validator yet"
    if extra.lower() in (vr.detail or "").lower():
        return vr

    return _clone_vr(
        vr,
        status="build_only",
        reason_code=vr.reason_code or globals().get("RC_PATH_VALIDATOR_UNPROVEN", ""),
        detail=_merge_details(vr.detail, extra),
    )


def _needs_microarch_e2e(
    tr: TranslationOutput,
    frag: Optional[AsmFragment] = None,
) -> bool:
    notes_lc = " ".join(_tr_notes(tr)).lower()

    if _preservation_level(tr, frag) == "D":
        return True

    markers = (
        "preservation=d/",
        "preservation.level=d",
        "microarch",
        "observable-control-flow",
        "retry-loop",
        "atomic-retry-loop",
        "timing-source",
        "branch-predictor",
        "cache-footprint",
        "fence-shape",
    )
    if any(m in notes_lc for m in markers):
        return True

    micro = getattr(frag, "microArch", None) if frag is not None else None
    if micro is None:
        return False

    sensitive_flags = [
        getattr(micro, "preserveExperiment", False),
        getattr(micro, "preserveControlFlowShape", False),
        getattr(micro, "preserveBranchPredictorShape", False),
        getattr(micro, "preserveCacheFootprint", False),
        getattr(micro, "preserveAtomicRetryShape", False),
        getattr(micro, "preserveFenceShape", False),
        getattr(micro, "preserveTimingSource", False),
    ]
    return any(bool(x) for x in sensitive_flags)

def _with_microarch_plan(
    vr: VerifyResult,
    tr: TranslationOutput,
    frag: Optional[AsmFragment] = None,
    lift=None,
    ir_summary=None,
    contract=None,
) -> VerifyResult:
    _ = (lift, ir_summary, contract)

    if not _needs_microarch_e2e(tr, frag):
        return vr

    extra = (
        "requires phase8 end-to-end microarchitectural validation "
        "(timing/PMC/cache/branch-predictor/side-channel PoC)"
    )

    if vr.status != "verified":
        return _append_detail(vr, extra)

    # 旧调用链没有真正运行 validator 时，禁止保持 verified。
    return _clone_vr(
        vr,
        status="build_only",
        reason_code=RC_MICROARCH_VALIDATOR_UNAVAILABLE,
        detail=_merge_details(vr.detail, extra),
    )


# ---------- Z3 语义等价：AMO ----------

_AMO_F = {
    "amoadd":  lambda a, b: a + b,
    "amoor":   lambda a, b: a | b,
    "amoand":  lambda a, b: a & b,
    "amoxor":  lambda a, b: a ^ b,
    "amoswap": lambda a, b: b,
}

_AMO_FETCH_NAME = {
    "amoadd": "__atomic_fetch_add",
    "amoor": "__atomic_fetch_or",
    "amoand": "__atomic_fetch_and",
    "amoxor": "__atomic_fetch_xor",
    "amoswap": "__atomic_exchange_n",
}


def _extract_atomic_order(replacement: str) -> str:
    m = re.search(r"__ATOMIC_[A-Z_]+", replacement)
    return m.group(0) if m else "unknown-order"


def _amo_lowering_family(replacement: str) -> str:
    rep = replacement or ""
    if "__atomic_fetch_add" in rep:
        return "__atomic_fetch_add"
    if "__atomic_fetch_or" in rep:
        return "__atomic_fetch_or"
    if "__atomic_fetch_and" in rep:
        return "__atomic_fetch_and"
    if "__atomic_fetch_xor" in rep:
        return "__atomic_fetch_xor"
    if "__atomic_exchange_n" in rep:
        return "__atomic_exchange_n"

    rep_lc = rep.lower()
    if re.search(r"\b(lock\s+)?xadd\b", rep_lc):
        return "xadd"
    if re.search(r"\b(lock\s+)?xchg\b", rep_lc):
        return "xchg"
    if re.search(r"\b(lock\s+)?(or|and|xor)\b", rep_lc):
        m = re.search(r"\b(lock\s+)?(or|and|xor)\b", rep_lc)
        return f"x86-lock-{m.group(2)}" if m else "x86-lock-binop"
    if "cmpxchg" in rep_lc:
        return "cmpxchg-loop"
    return "unknown"


def _amo_family_compatible(op: str, family: str) -> bool:
    if family == "unknown":
        return False
    if family == "cmpxchg-loop":
        return True
    if family == "xadd":
        return op == "amoadd"
    if family == "xchg":
        return op == "amoswap"
    if family == "x86-lock-or":
        return op == "amoor"
    if family == "x86-lock-and":
        return op == "amoand"
    if family == "x86-lock-xor":
        return op == "amoxor"
    return family == _AMO_FETCH_NAME.get(op, "")

def _amo_semantics_for_family(op: str, family: str, M, V):
    if family == "__atomic_fetch_add":
        return M, M + V
    if family == "__atomic_fetch_or":
        return M, M | V
    if family == "__atomic_fetch_and":
        return M, M & V
    if family == "__atomic_fetch_xor":
        return M, M ^ V
    if family == "__atomic_exchange_n":
        return M, V

    if family == "xadd":
        return M, M + V
    if family == "xchg":
        return M, V
    if family == "x86-lock-or":
        return M, M | V
    if family == "x86-lock-and":
        return M, M & V
    if family == "x86-lock-xor":
        return M, M ^ V
    if family == "cmpxchg-loop":
        return M, _AMO_F[op](M, V)

    return None

def _verify_amo(frag: AsmFragment, lift: LiftResult, tr: TranslationOutput) -> VerifyResult:
    if len(getattr(lift, "insns", []) or []) != 1:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            "amo verification expects single insn; build passed only",
        )

    mnem = str(getattr(lift.insns[0], "asm_mnem", "") or "").strip().lower()
    m = _AMO_SRC_RE.match(mnem)
    if not m:
        raw = str(getattr(frag, "rawAsmText", "") or "").strip().lower()
        m = _AMO_SRC_RE.search(raw)

    if not m:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"unrecognized amo source mnemonic: {mnem}",
        )

    op = m.group(1).lower()
    width = 32 if m.group(2).lower() == "w" else 64

    family = _amo_lowering_family(tr.replacement)
    if not _amo_family_compatible(op, family):
        return _vr_failed(
            RC_SEMANTIC_PROOF_FAILED,
            f"actual emitted lowering family '{family}' is incompatible with source op '{op}'",
        )

    M = z3.BitVec("M", width)
    V = z3.BitVec("V", width)

    src_old = M
    src_new = _AMO_F[op](M, V)

    dst = _amo_semantics_for_family(op, family, M, V)
    if dst is None:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"no family semantics installed for AMO lowering family={family}",
        )
    dst_old, dst_new = dst

    s = z3.Solver()
    s.add(z3.Or(src_old != dst_old, src_new != dst_new))
    if s.check() == z3.unsat:
        func_vr = _vr_verified(
            f"Z3 proved functional RMW equivalence for {op} "
            f"(width={width}, family={family})"
        )
    else:
        func_vr = _vr_failed(
            RC_SEMANTIC_PROOF_FAILED,
            f"Z3 found counter-example for {op}: {s.model()}",
        )

    required_order = _source_order_from_amo(frag, lift, tr)
    order_vr = _check_atomic_order(
        required_order,
        _extract_atomic_orders(tr.replacement),
        what=f"AMO {op}",
    )

    weak_vr = _run_weak_memory_validator(
        "amo",
        frag,
        lift,
        tr,
        meta={
            "op": op,
            "width": width,
            "family": family,
            "required_order": required_order,
        },
    )
    return _merge_semantic_layers(func_vr, order_vr, weak_vr)

# ---------- Z3 语义等价：fence ----------

_FULL_FENCE_RE = re.compile(
    r"^\s*fence\s+(rw|iorw)\s*,\s*(rw|iorw)\s*$",
    re.IGNORECASE,
)


def _fence_lowering_family(replacement: str) -> str:
    rep = replacement or ""
    rep_lc = rep.lower()
    if "__atomic_thread_fence" in rep:
        return "__atomic_thread_fence"
    if re.search(r"\bmfence\b", rep_lc):
        return "mfence"
    if re.search(r"\blfence\b", rep_lc):
        return "lfence"
    if re.search(r"\bsfence\b", rep_lc):
        return "sfence"
    return "unknown"


def _verify_fence(frag: AsmFragment, lift: LiftResult, tr: TranslationOutput) -> VerifyResult:
    raw = (getattr(frag, "rawAsmText", "") or "").strip().rstrip(";").strip()
    family = _fence_lowering_family(tr.replacement)

    if family == "unknown":
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"fence build passed, but actual emitted lowering family is unrecognized for proof: '{raw}'",
        )

    emitted_orders = _extract_atomic_orders(tr.replacement)

    if _FULL_FENCE_RE.match(raw) or raw.lower() == "fence":
        # full fence 不能被 lfence/sfence 误判成 verified
        if family in {"lfence", "sfence"}:
            return _vr_failed(
                RC_SEMANTIC_PROOF_FAILED,
                f"full fence source '{raw}' cannot be discharged by lowering family={family}",
            )

        # mfence 天然按 full barrier 处理；atomic_thread_fence 则至少要看 order
        if family == "mfence":
            func_vr = _vr_verified(
                f"full-fence semantics matched lowering family={family}"
            )
        else:
            func_vr = _vr_verified(
                f"full-fence lowering family={family} recognized"
            )

        order_vr = _check_atomic_order(
            "seq_cst",
            emitted_orders if family == "__atomic_thread_fence" else ["seq_cst"],
            what="fence",
        )
        weak_vr = _run_weak_memory_validator(
            "fence",
            frag,
            lift,
            tr,
            meta={"raw": raw, "family": family},
        )
        return _merge_semantic_layers(func_vr, order_vr, weak_vr)

    # 弱 fence 先不做过强宣称
    func_vr = _vr_build_only(
        _RC_WEAKMEM_UNPROVEN,
        f"weak fence variant '{raw}' lowered as family={family}; functional class recognized conservatively",
    )
    order_vr = _check_atomic_order(
        "relaxed",
        emitted_orders,
        what=f"weak fence '{raw}'",
    )
    weak_vr = _run_weak_memory_validator(
        "fence",
        frag,
        lift,
        tr,
        meta={"raw": raw, "family": family},
    )
    return _merge_semantic_layers(func_vr, order_vr, weak_vr)



# ---------- LR/SC CAS ----------

def _cas_lowering_family(replacement: str) -> str:
    rep = replacement or ""
    rep_lc = rep.lower()
    if "__atomic_compare_exchange_n" in rep or "__atomic_compare_exchange" in rep:
        return "__atomic_compare_exchange"
    if "cmpxchg" in rep_lc:
        return "cmpxchg"
    return "unknown"

def _cas_semantics_for_family(family: str, M, E, D, weak: bool):
    if family not in {"__atomic_compare_exchange", "cmpxchg"}:
        return None

    b = z3.Bool("scOK") if weak else z3.BoolVal(True)
    success = z3.And(M == E, b)
    observed_old = z3.If(success, E, M)
    M2 = z3.If(success, D, M)
    return success, observed_old, M2

def _verify_cas(frag, lift, tr) -> VerifyResult:
    family = _cas_lowering_family(getattr(tr, "replacement", "") or "")
    if family == "unknown":
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            "LR/SC CAS build passed, but actual emitted lowering family is not recognized as compare_exchange/cmpxchg",
        )

    notes = " ".join(_tr_notes(tr)).lower()
    width = _infer_lrsc_width(frag, lift, tr, default=32)
    is_weak = "weak=true" in notes

    M = z3.BitVec("M", width)
    E = z3.BitVec("E", width)
    D = z3.BitVec("D", width)

    src_success, src_old, src_M2 = _cas_semantics_for_family(
        "__atomic_compare_exchange",
        M, E, D, is_weak,
    )
    dst = _cas_semantics_for_family(family, M, E, D, is_weak)
    if dst is None:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"no family semantics installed for LR/SC CAS lowering family={family}",
        )
    dst_success, dst_old, dst_M2 = dst

    s = z3.Solver()
    s.add(z3.Or(src_old != dst_old, src_M2 != dst_M2, src_success != dst_success))
    if s.check() == z3.unsat:
        func_vr = _vr_verified(
            f"Z3 proved LR/SC↔CAS functional equivalence "
            f"(width={width}, {'weak' if is_weak else 'strong'}, family={family})"
        )
    else:
        func_vr = _vr_failed(
            RC_SEMANTIC_PROOF_FAILED,
            f"Z3 counter-example for LR/SC CAS: {s.model()}",
        )

    required_order = _source_order_from_lrsc(frag, lift, tr)
    order_vr = _check_cas_orders(
        required_order,
        _extract_atomic_orders(tr.replacement),
    )

    weak_vr = _run_weak_memory_validator(
        "lrsc_cas",
        frag,
        lift,
        tr,
        meta={
            "width": width,
            "family": family,
            "weak": is_weak,
            "required_order": required_order,
        },
    )
    return _merge_semantic_layers(func_vr, order_vr, weak_vr)

# ---------- LR/SC RMW ----------

_LRSC_RMW_NOTE_RE = re.compile(
    r"LR/SC RMW:\s*(add|sub|and|or|xor)\s+([wd])\b",
    re.IGNORECASE,
)

_RMW_F = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "and": lambda a, b: a & b,
    "or":  lambda a, b: a | b,
    "xor": lambda a, b: a ^ b,
}


def _lrsc_rmw_lowering_family(replacement: str) -> str:
    rep = replacement or ""
    rep_lc = rep.lower()

    if "__atomic_fetch_add" in rep:
        return "__atomic_fetch_add"
    if "__atomic_fetch_sub" in rep:
        return "__atomic_fetch_sub"
    if "__atomic_fetch_and" in rep:
        return "__atomic_fetch_and"
    if "__atomic_fetch_or" in rep:
        return "__atomic_fetch_or"
    if "__atomic_fetch_xor" in rep:
        return "__atomic_fetch_xor"

    # 这些 post-op-return builtins 是否等价取决于 source observable result；
    # 没有显式 notes 不宜直接 verified。
    if "__atomic_add_fetch" in rep:
        return "__atomic_add_fetch"
    if "__atomic_sub_fetch" in rep:
        return "__atomic_sub_fetch"
    if "__atomic_and_fetch" in rep:
        return "__atomic_and_fetch"
    if "__atomic_or_fetch" in rep:
        return "__atomic_or_fetch"
    if "__atomic_xor_fetch" in rep:
        return "__atomic_xor_fetch"

    if re.search(r"\b(lock\s+)?xadd\b", rep_lc):
        return "xadd"
    if "cmpxchg" in rep_lc:
        return "cmpxchg-loop"
    return "unknown"

def _lrsc_rmw_semantics_for_family(op: str, family: str, M, V):
    if family == "__atomic_fetch_add":
        return M, M + V
    if family == "__atomic_fetch_sub":
        return M, M - V
    if family == "__atomic_fetch_and":
        return M, M & V
    if family == "__atomic_fetch_or":
        return M, M | V
    if family == "__atomic_fetch_xor":
        return M, M ^ V

    if family == "xadd":
        return M, M + V
    if family == "cmpxchg-loop":
        return M, _RMW_F[op](M, V)

    return None


def _verify_lrsc_rmw(frag, lift, tr) -> VerifyResult:
    text = " | ".join(_tr_notes(tr))
    m = _LRSC_RMW_NOTE_RE.search(text)
    if not m:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            "LR/SC RMW build passed, but op/width note missing for SMT proof",
        )

    op = m.group(1).lower()
    width = 32 if m.group(2).lower() == "w" else 64

    family = _lrsc_rmw_lowering_family(getattr(tr, "replacement", "") or "")
    if family == "unknown":
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"LR/SC RMW build passed, but actual emitted lowering family is unrecognized for proof (op={op}, width={width})",
        )

    if family in {
        "__atomic_add_fetch",
        "__atomic_sub_fetch",
        "__atomic_and_fetch",
        "__atomic_or_fetch",
        "__atomic_xor_fetch",
    }:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"LR/SC RMW lowered as {family}, but source observable return shape is not disambiguated yet",
        )

    if family == "xadd" and op != "add":
        return _vr_failed(
            RC_SEMANTIC_PROOF_FAILED,
            f"actual emitted lowering family '{family}' is incompatible with LR/SC RMW op '{op}'",
        )

    M = z3.BitVec("M", width)
    V = z3.BitVec("V", width)

    src_old = M
    src_new = _RMW_F[op](M, V)

    dst = _lrsc_rmw_semantics_for_family(op, family, M, V)
    if dst is None:
        return _vr_build_only(
            _RC_WEAKMEM_UNPROVEN,
            f"no family semantics installed for LR/SC RMW lowering family={family}",
        )
    dst_old, dst_new = dst

    s = z3.Solver()
    s.add(z3.Or(src_old != dst_old, src_new != dst_new))
    if s.check() == z3.unsat:
        func_vr = _vr_verified(
            f"Z3 proved LR/SC RMW functional equivalence "
            f"(op={op}, width={width}, family={family})"
        )
    else:
        func_vr = _vr_failed(
            RC_SEMANTIC_PROOF_FAILED,
            f"Z3 counter-example for LR/SC RMW: {s.model()}",
        )

    required_order = _source_order_from_lrsc(frag, lift, tr)
    order_vr = _check_atomic_order(
        required_order,
        _extract_atomic_orders(tr.replacement),
        what=f"LR/SC RMW {op}",
    )

    weak_vr = _run_weak_memory_validator(
        "lrsc_rmw",
        frag,
        lift,
        tr,
        meta={
            "op": op,
            "width": width,
            "family": family,
            "required_order": required_order,
        },
    )
    return _merge_semantic_layers(func_vr, order_vr, weak_vr)


def _recover_blocks_and_summary(
    lift: Optional[LiftResult],
    summary: Optional[IRSummary],
) -> tuple[list[Block], IRSummary]:
    insns = list(getattr(lift, "insns", []) or [])
    try:
        blocks, rebuilt = from_lifted(insns)
    except Exception:
        blocks = []
        rebuilt = None

    if summary is None and rebuilt is not None:
        return blocks, rebuilt

    if summary is not None:
        return blocks, summary

    # 最保底
    empty = IRSummary(
        is_single_block=(len(blocks) <= 1),
        has_branch=False,
        has_call_or_return=False,
        has_memory_barrier=False,
        has_atomic=False,
        reads_regs=set(),
        writes_regs=set(),
        reads_mem=False,
        writes_mem=False,
    )
    return blocks, empty


def _expected_c_labels(frag: Optional[AsmFragment]) -> list[str]:
    if frag is None:
        return []

    labels: list[str] = []

    for ge in (getattr(frag, "gotoEdges", None) or []):
        lab = (getattr(ge, "cLabel", "") or "").strip()
        if _is_simple_c_ident(lab):
            labels.append(lab)

    for lab in (getattr(frag, "gotoLabels", None) or []):
        lab = (lab or "").strip()
        if _is_simple_c_ident(lab):
            labels.append(lab)

    out: list[str] = []
    seen = set()
    for x in labels:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _control_surface_kind(
    frag: Optional[AsmFragment],
    summary: IRSummary,
    blocks: list[Block],
) -> str:
    cf = getattr(frag, "controlFlow", None) if frag is not None else None
    style = (getattr(cf, "style", "") or "").strip()
    if style and style != "Unknown":
        return "CallRetLike" if style == "CallLike" else style

    surf = (getattr(frag, "controlFlowSurface", "") or "").strip()
    if surf:
        return "CallRetLike" if surf == "CallLike" else surf

    if frag is not None:
        if getattr(frag, "hasAsmGoto", False) or _expected_c_labels(frag):
            return "AsmGoto"
        if getattr(frag, "hasExternalControlFlow", False):
            return "NonLocal"
        if getattr(frag, "hasLocalLabels", False) or getattr(frag, "hasMultipleExits", False):
            return "InternalCFG"

    if getattr(summary, "has_call_or_return", False):
        return "CallRetLike"
    if getattr(summary, "has_branch", False) or len(blocks) > 1:
        return "InternalCFG"
    return "StraightLine"

def _observed_path_surface(
    frag: Optional[AsmFragment],
    blocks: list[Block],
    summary: IRSummary,
) -> str:
    """
    统一 path surface 命名，避免 CallLike / CallRetLike 漂移。
    """
    surface = _control_surface_kind(frag, summary, blocks)
    if surface == "CallLike":
        return "CallRetLike"
    return surface


def _needs_path_validation(
    frag: Optional[AsmFragment],
    summary: IRSummary,
    blocks: list[Block],
) -> bool:
    surface = _observed_path_surface(frag, blocks, summary)
    if surface in {"AsmGoto", "InternalCFG", "LocalCFG", "CallRetLike", "NonLocal"}:
        return True

    if len(blocks) > 1:
        return True
    if getattr(summary, "has_branch", False):
        return True
    if getattr(summary, "has_call_or_return", False):
        return True

    return False


_X86_BRANCH_SHAPE_RE = re.compile(
    r"\b(?:jmp|je|jne|jz|jnz|ja|jae|jb|jbe|jg|jge|jl|jle|jo|jno|js|jns|loop|loope|loopne)\b",
    re.IGNORECASE,
)
_X86_CALLRET_SHAPE_RE = re.compile(
    r"\b(?:call|ret|jmp)\b",
    re.IGNORECASE,
)
_RETRY_SHAPE_RE = re.compile(
    r"\b(?:while|for|do|goto|cmpxchg|xadd|pause|jnz|jne|loop)\b|(?:^|\W)\d+:",
    re.IGNORECASE,
)


def _replacement_has_branch_shape(text: str) -> bool:
    text = text or ""
    return (
        bool(_X86_BRANCH_SHAPE_RE.search(text))
        or (" goto " in text and "__asm__" in text)
        or bool(re.search(r"\bif\b|\bgoto\b", text))
    )


def _replacement_has_callret_shape(text: str) -> bool:
    text = text or ""
    return bool(_X86_CALLRET_SHAPE_RE.search(text))


def _replacement_has_retry_shape(text: str) -> bool:
    text = text or ""
    return bool(_RETRY_SHAPE_RE.search(text))


def _replacement_mentions_symbols(text: str, frag: Optional[AsmFragment]) -> bool:
    if frag is None:
        return True

    syms = list(getattr(frag, "symbols", None) or [])
    if not syms:
        return True

    text = text or ""
    for s in syms:
        asm_name = (getattr(s, "asmName", "") or "").strip()
        c_name = (getattr(s, "cName", "") or "").strip()
        candidates = [x for x in (asm_name, c_name) if x]
        for name in candidates:
            if re.search(rf"\b{re.escape(name)}\b", text):
                return True
            if name in text:
                return True
    return False

def _validate_path_surface(
    frag,
    blocks: List[Block],
    ir_summary: IRSummary,
    contract: TranslationContract,
    out: TranslationOutput,
) -> VerifyResult:
    if not contract.requires_path_validation:
        return _vr_verified("path validation not required by contract")

    surface = _observed_path_surface(frag, blocks, ir_summary)

    # asm goto 路由必须来自 asm-goto surface
    if contract.build_family == "x86_asm_goto":
        if surface != "AsmGoto":
            return _vr_failed(
                RC_PATH_SURFACE_MISMATCH,
                f"x86_asm_goto requires AsmGoto surface, observed={surface}",
            )

    # InternalCFG 必须走 x86_inline_asm_cfg
    if contract.route == "x86_inline_asm_cfg":
        if surface != "InternalCFG":
            return _vr_failed(
                RC_PATH_SURFACE_MISMATCH,
                f"x86_inline_asm_cfg requires InternalCFG surface, observed={surface}",
            )

    # out_of_line_thunk / c_helper 必须是 call/ret 类 surface
    if contract.route == "out_of_line_thunk" or contract.build_family == "c_helper":
        if surface != "CallRetLike":
            return _vr_failed(
                RC_PATH_SURFACE_MISMATCH,
                f"c_helper/out_of_line_thunk requires CallRetLike surface, observed={surface}",
            )

    # D 级必须有显式 preserve_experiment 痕迹
    if contract.level == "D":
        has_preserve_marker = (
            bool(contract.metadata.get("preserve_experiment", False))
            or ("preserve_experiment" in set(contract.reason_codes))
        )
        if contract.build_family not in {"x86_inline_asm", "x86_asm_goto"}:
            return _vr_failed(
                RC_OUTPUT_FAMILY_MISMATCH,
                f"D-level output must be x86_inline_asm/x86_asm_goto, got {contract.build_family}",
            )
        if not has_preserve_marker:
            return _vr_build_only(
                RC_PATH_VALIDATOR_UNPROVEN,
                "D-level contract lacks explicit preserve_experiment marker",
            )

    return _vr_verified(
        f"path surface ok: observed={surface}, route={contract.route}, family={contract.build_family}"
    )

def _validate_block_obligation(
    frag: Optional[AsmFragment],
    lift: Optional[LiftResult],
    summary: IRSummary,
    blocks: list[Block],
    tr,
) -> Optional[VerifyResult]:
    if _needs_path_validation(frag, summary, blocks):
        return None

    kind = _normalized_translation_kind(tr)
    repl = str(getattr(tr, "replacement", "") or "")

    if kind == "x86_asm_goto":
        return _vr("failed", "x86_asm_goto emitted for straight-line block fragment")

    reasons: list[str] = []

    if frag is not None and getattr(frag, "hasRetryLoop", False):
        if not _replacement_has_retry_shape(repl):
            reasons.append("retry-loop source not structurally visible in emitted replacement")

    if frag is not None and list(getattr(frag, "outputBindings", None) or []):
        reasons.append(
            f"outputBindings={len(getattr(frag, 'outputBindings', []) or [])} checked structurally"
        )

    if frag is not None and list(getattr(frag, "symbols", None) or []):
        if not _replacement_mentions_symbols(repl, frag):
            reasons.append("source symbol references are not obvious in emitted replacement")

    mem_sig = (
        f"regs(r={len(getattr(summary, 'reads_regs', set()) or set())},"
        f"w={len(getattr(summary, 'writes_regs', set()) or set())}), "
        f"mem(r={bool(getattr(summary, 'reads_mem', False))},"
        f"w={bool(getattr(summary, 'writes_mem', False))})"
    )

    base = (
        f"block proof obligation accepted for straight-line fragment "
        f"(blocks={len(blocks) or 1}, {mem_sig}, kind={kind})"
    )

    if reasons:
        return _vr("build_only", _merge_details(base, *reasons))

    return _vr("build_only", base)

# ---------- 一般输出形状验证（build 已通过后的保底验证） ----------

def _verify_x86_inline_asm_output(tr, frag=None):
    build_vr = _checked_build_vr(str(getattr(tr, "replacement", "") or ""), frag=frag)
    if build_vr.status != "verified":
        return _append_detail(build_vr, "x86 inline asm output validation stopped at build gate")

    text = str(getattr(tr, "replacement", "") or "")
    kind = _normalized_translation_kind(tr)

    if "__asm__" not in text:
        return _vr("failed", "x86-inline-asm translation missing __asm__ block")

    if kind == "x86_asm_goto" and not re.search(r"__asm__\s+goto\b", text):
        return _vr("failed", "x86_asm_goto translation missing __asm__ goto form")

    level = _preservation_level(tr, frag=frag)

    if level == "D":
        has_atomic = bool(
            re.search(r"cmpxchg|xadd|mfence|lfence|rdtsc|pause|lock\b", text)
        )
        if not has_atomic:
            return _vr(
                "build_only",
                "D-level x86 output builds, but lacks recognizable experiment-preserving opcode template",
            )
        return _vr("verified", "D-level x86 output passed build + shape sanity")

    if level == "C":
        has_cf = _replacement_has_callret_shape(text)
        if not has_cf:
            return _vr(
                "build_only",
                "C-level x86 output builds, but call/ret contour is not obvious in emitted template",
            )
        return _vr("verified", "C-level x86 output passed build + control-shape sanity")

    return _vr("verified", "x86 inline asm output passed build sanity")


def _verify_c_helper_output(tr, frag=None):
    build_vr = _checked_build_vr(str(getattr(tr, "replacement", "") or ""), frag=frag)
    if build_vr.status != "verified":
        return _append_detail(build_vr, "c helper output validation stopped at build gate")

    return _vr("verified", "c helper output passed build sanity")


def _verify_pure_c_output(tr, frag=None) -> VerifyResult:
    text = str(getattr(tr, "replacement", "") or "")
    level = _preservation_level(tr, frag)
    route = _preservation_route(tr, frag)

    if "__asm__" in text:
        return _vr("failed", "pure_c translation still contains __asm__")

    if level in {"C", "D"}:
        return _vr(
            "build_only",
            f"pure C output passed build sanity, but preservation level={level} exceeds current generic proof envelope",
        )

    if route and route not in {"canonical_public_c", ""}:
        return _vr(
            "build_only",
            f"pure C output passed build sanity, but route={route} has no dedicated validator",
        )

    return _vr(
        "build_only",
        "pure C output passed build sanity only; no generic block proof installed",
    )


def _verify_translation_shape_only(tr, frag=None) -> VerifyResult:
    kind = _normalized_kind(tr)

    if kind == "unsupported":
        return _vr("unsupported", "no translation produced")
    if kind in {"x86_inline_asm", "x86_asm_goto"}:
        return _verify_x86_inline_asm_output(tr, frag=frag)
    if kind == "c_helper":
        return _verify_c_helper_output(tr, frag=frag)
    if kind == "pure_c":
        return _verify_pure_c_output(tr, frag=frag)

    return _vr("failed", f"unsupported translation kind for verification: {getattr(tr, 'kind', '')}")

def _verify_family_shape_only(tr, frag=None) -> Optional[VerifyResult]:
    kind = _normalized_translation_kind(tr)
    text = str(getattr(tr, "replacement", "") or "")

    if kind in {"x86_inline_asm", "x86_asm_goto"}:
        if "__asm__" not in text:
            return _vr("failed", "x86 route selected, but emitted replacement lacks __asm__ block")

        if kind == "x86_asm_goto" and not re.search(r"__asm__\s+goto\b", text):
            return _vr("failed", "x86_asm_goto route selected, but emitted replacement lacks goto form")

        level = _preservation_level(tr, frag=frag)
        if level == "D":
            if not re.search(r"cmpxchg|xadd|mfence|lfence|rdtsc|pause|lock\b", text):
                return _vr(
                    "build_only",
                    "D-level x86 output passed build, but experiment-preserving opcode contour is weak",
                )
            return _vr("verified", "x86 inline asm output passed shape sanity")

        if level == "C":
            if not _replacement_has_callret_shape(text):
                return _vr(
                    "build_only",
                    "C-level x86 output passed build, but call/ret contour is weak",
                )
            return _vr("verified", "x86 inline asm output passed control-shape sanity")

        return _vr("verified", "x86 route shape sanity passed")

    if kind == "c_helper":
        return _vr("verified", "c helper shape sanity passed")

    if kind == "unsupported":
        return _vr("unsupported", "no translation produced")

    return None

# ---------- 兼容旧辅助 ----------

def _verify_special_semantics(
    frag: Optional[AsmFragment],
    lift: Optional[LiftResult],
    summary: Optional[IRSummary],
    tr,
) -> Optional[VerifyResult]:
    replacement = str(getattr(tr, "replacement", "") or "")
    notes = list(getattr(tr, "notes", []) or [])
    notes_lc = [str(n).lower() for n in notes]

    raw_text = (getattr(frag, "rawAsmText", "") or "").lower() if frag is not None else ""
    insns = list(getattr(lift, "insns", []) or [])
    mnems = [(getattr(i, "asm_mnem", "") or "").lower() for i in insns]
    mnem0 = mnems[0] if mnems else ""
    repl_lc = replacement.lower()

    has_lrsc_source = (
        any(m.startswith("lr.") or m.startswith("sc.") for m in mnems)
        or "lr." in raw_text
        or "sc." in raw_text
        or "lr/" in raw_text
        or "sc/" in raw_text
        or "lr.w/sc.w" in raw_text
        or "lr.d/sc.d" in raw_text
    )

    is_lrsc_cas = (
        any("lr/sc cas" in n for n in notes_lc)
        or (has_lrsc_source and "__atomic_compare_exchange" in repl_lc)
        or (
            has_lrsc_source
            and any("lr/sc width=" in n for n in notes_lc)
            and any("weak=" in n for n in notes_lc)
            and "__atomic_compare_exchange" in repl_lc
        )
    )
    if is_lrsc_cas:
        return _verify_cas(frag, lift, tr)

    is_lrsc_rmw = (
        any("lr/sc rmw" in n for n in notes_lc)
        or (
            has_lrsc_source
            and (
                "__atomic_fetch_" in repl_lc
                or "__atomic_add_fetch" in repl_lc
                or "__atomic_sub_fetch" in repl_lc
                or "__atomic_and_fetch" in repl_lc
                or "__atomic_or_fetch" in repl_lc
                or "__atomic_xor_fetch" in repl_lc
            )
        )
    )
    if is_lrsc_rmw:
        return _verify_lrsc_rmw(frag, lift, tr)

    if mnem0.startswith("amo"):
        return _verify_amo(frag, lift, tr)

    if mnem0.startswith("fence") or any(m.startswith("fence") for m in mnems):
        return _verify_fence(frag, lift, tr)

    return None


def _lift_mnems(lift):
    return [str(getattr(i, "asm_mnem", "") or "").lower() for i in getattr(lift, "insns", []) or []]


# ---------- 兼容旧入口：仅 translation 级验证 ----------
def _verify_core(
    frag: Optional[AsmFragment],
    lift: Optional[LiftResult],
    summary: Optional[IRSummary],
    tr,
) -> VerifyResult:
    kind = _normalized_translation_kind(tr)

    if kind == "unsupported":
        return _vr("unsupported", "no translation produced")

    # 没有 lift 时，保留旧的 shape-only fallback
    if lift is None:
        return verify_translation(tr, frag=frag, lift=None, summary=summary)

    return verify_translation_phase8(
        frag=frag,
        out=tr,
        lift=lift,
        summary=summary,
    )


def verify_translation(tr, frag=None, lift=None, summary=None):
    kind = _normalized_translation_kind(tr)

    if lift is None and summary is None:
        if kind in ("x86_inline_asm", "x86_asm_goto"):
            return _coerce_verify_result(_verify_x86_inline_asm_output(tr, frag=frag))
        if kind == "c_helper":
            return _coerce_verify_result(_verify_c_helper_output(tr, frag=frag))
        if kind == "unsupported":
            return _vr("unsupported", "no translation produced")

        err = _build_check_c(getattr(tr, "replacement", "") or "", frag=frag)
        if err is not None:
            return _vr("failed", f"build check failed: {err}")
        return _vr(
            "build_only",
            f"build passed for translation kind '{kind}'; semantic/path validation requires lift+summary",
        )

    if lift is None:
        # 有 summary 但没 lift 时，仍无法统一到 phase8
        return _vr(
            "build_only",
            f"translation kind '{kind}' has summary but no lift; phase8 semantic/path validation requires lift",
        )

    return verify_translation_phase8(
        frag=frag,
        out=tr,
        lift=lift,
        summary=summary,
    )

RC_BLOCK_SEMANTIC_CHECKER_UNAVAILABLE = (
    "phase8.block_semantic_checker_unavailable"
)
RC_BLOCK_SEMANTIC_PROOF_FAILED = (
    "phase8.block_semantic_proof_failed"
)
RC_BLOCK_SEMANTIC_CHECKER_ERROR = (
    "phase8.block_semantic_checker_error"
)

RC_PATH_VALIDATOR_UNAVAILABLE = (
    "phase8.path_validator_unavailable"
)
RC_PATH_PROOF_FAILED = (
    "phase8.path_proof_failed"
)
RC_PATH_VALIDATOR_ERROR = (
    "phase8.path_validator_error"
)

RC_ENGINEERING_VALIDATOR_UNAVAILABLE = (
    "phase8.engineering_validator_unavailable"
)
RC_ENGINEERING_VALIDATION_FAILED = (
    "phase8.engineering_validation_failed"
)
RC_ENGINEERING_VALIDATOR_ERROR = (
    "phase8.engineering_validator_error"
)

RC_MICROARCH_VALIDATOR_UNAVAILABLE = (
    "phase8.microarch_validator_unavailable"
)
RC_MICROARCH_VALIDATION_FAILED = (
    "phase8.microarch_validation_failed"
)
RC_MICROARCH_VALIDATOR_ERROR = (
    "phase8.microarch_validator_error"
)

RC_ARTIFACT_BUILD_CHECKER_UNAVAILABLE = (
    "phase8.artifact_build_checker_unavailable"
)
RC_ARTIFACT_BUILD_FAILED = (
    "phase8.artifact_build_failed"
)

RC_CHECKER_PROTOCOL_ERROR = (
    "phase8.checker_protocol_error"
)

def _phase8_find_checker(
    *names: str,
    exclude: Any = None,
):
    """
    从当前模块中查找第一个可调用 checker。

    exclude 可用于排除当前包装函数，避免 finder 返回调用者自身。
    """
    namespace = globals()

    for name in names:
        checker = namespace.get(name)

        if checker is None:
            continue

        if not callable(checker):
            continue

        if exclude is not None and checker is exclude:
            continue

        return checker

    return None


def _phase8_invoke_checker(
    checker,
    *,
    frag=None,
    out=None,
    lift=None,
    ir_summary=None,
    contract=None,
    blocks=None,
    obligations=None,
    requirements=None,
):
    """
    使用 inspect.signature 选择兼容 ABI。

    与通过捕获 TypeError 猜测 ABI 的旧实现不同，本函数只在调用前判断
    参数是否可绑定。checker 内部真正发生的 TypeError 不会被吞掉。

    推荐的新式 ABI：

        checker(
            *,
            frag,
            out,
            lift,
            ir_summary,
            contract,
            blocks,
            obligations,
            requirements,
        )

    同时兼容若干旧式 positional ABI。
    """
    sig = inspect.signature(checker)

    values = {
        "frag": frag,
        "fragment": frag,

        "out": out,
        "tr": out,
        "translation": out,

        "lift": lift,

        "summary": ir_summary,
        "ir_summary": ir_summary,

        "contract": contract,
        "blocks": blocks,
        "obligations": obligations,
        "requirements": requirements,
    }

    params = sig.parameters
    has_var_kw = any(
        p.kind == inspect.Parameter.VAR_KEYWORD
        for p in params.values()
    )

    keyword_args = {}
    if has_var_kw:
        keyword_args = {
            "frag": frag,
            "out": out,
            "lift": lift,
            "ir_summary": ir_summary,
            "contract": contract,
            "blocks": blocks,
            "obligations": obligations,
            "requirements": requirements,
        }
    else:
        for name, param in params.items():
            if param.kind in {
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            } and name in values:
                keyword_args[name] = values[name]

    try:
        sig.bind(**keyword_args)
    except TypeError:
        pass
    else:
        return checker(**keyword_args)

    positional_candidates = [
        (
            frag,
            out,
            lift,
            ir_summary,
            contract,
            blocks,
            obligations,
            requirements,
        ),
        (
            frag,
            out,
            lift,
            ir_summary,
            contract,
            blocks,
            obligations,
        ),
        (
            frag,
            out,
            lift,
            ir_summary,
            contract,
        ),
        (
            frag,
            out,
            lift,
            ir_summary,
        ),
        (
            frag,
            out,
            lift,
        ),
        (
            frag,
            out,
        ),
        (
            out,
            frag,
        ),
        (out,),
    ]

    for args in positional_candidates:
        try:
            sig.bind(*args)
        except TypeError:
            continue
        return checker(*args)

    raise TypeError(
        f"unsupported Phase 8 checker ABI: "
        f"{getattr(checker, '__name__', repr(checker))}{sig}"
    )

def _coerce_phase8_checker_result(
    obj: Any,
    *,
    layer: str,
    unavailable_reason: str,
    failed_reason: str,
) -> VerifyResult:
    """
    统一规约 Z3、angr、工程验证和微架构验证 checker 的结果。

    支持：
      - VerifyResult
      - True / False / None
      - 字符串
      - 字典

    约定：
      True             -> verified
      False            -> failed
      None             -> build_only/checker unavailable
      status=unknown   -> build_only
    """
    if isinstance(obj, VerifyResult):
        return obj

    if obj is True:
        return _vr_verified(f"{layer} verification passed")

    if obj is False:
        return _vr_failed(
            failed_reason,
            f"{layer} verification found a counterexample or mismatch",
        )

    if obj is None:
        return _vr_build_only(
            unavailable_reason,
            f"{layer} checker returned None",
        )

    if isinstance(obj, str):
        text = obj.strip()
        normalized = text.lower()

        if normalized in {
            "ok",
            "verified",
            "pass",
            "passed",
            "sat-equivalent",
            "unsat-counterexample",
            "equivalent",
        }:
            return _vr_verified(text or f"{layer} verification passed")

        if normalized in {
            "failed",
            "fail",
            "mismatch",
            "counterexample",
            "not-equivalent",
            "error",
        }:
            return _vr_failed(
                failed_reason,
                text or f"{layer} verification failed",
            )

        if normalized in {
            "skipped",
            "unavailable",
            "unknown",
            "timeout",
            "build_only",
        }:
            return _vr_build_only(
                unavailable_reason,
                text or f"{layer} verification unavailable",
            )

        # 自由文本不能视为证明成功。
        return _vr_build_only(
            unavailable_reason,
            text or f"unrecognized {layer} checker result",
        )

    if isinstance(obj, dict):
        status = str(obj.get("status", "") or "").strip().lower()
        detail = str(
            obj.get("detail", "")
            or obj.get("message", "")
            or ""
        ).strip()

        notes = list(obj.get("notes", []) or [])

        if status in {
            "ok",
            "verified",
            "pass",
            "passed",
            "equivalent",
        }:
            vr = _vr_verified(
                detail or f"{layer} verification passed"
            )
            if hasattr(vr, "notes"):
                vr.notes.extend(str(n) for n in notes if n)
            return vr

        if status in {
            "failed",
            "fail",
            "mismatch",
            "counterexample",
            "not_equivalent",
            "not-equivalent",
        }:
            vr = _vr_failed(
                failed_reason,
                detail or f"{layer} verification failed",
            )
            if hasattr(vr, "notes"):
                vr.notes.extend(str(n) for n in notes if n)
            return vr

        if status in {
            "skipped",
            "unavailable",
            "unknown",
            "timeout",
            "build_only",
        }:
            vr = _vr_build_only(
                unavailable_reason,
                detail or f"{layer} verification unavailable",
            )
            if hasattr(vr, "notes"):
                vr.notes.extend(str(n) for n in notes if n)
            return vr

    return _vr_build_only(
        unavailable_reason,
        f"unrecognized {layer} checker result: {obj!r}",
    )

def _run_phase8_engineering_suite(
    *,
    frag: Any = None,
    out: Any = None,
    lift: Any = None,
    ir_summary: Any = None,
    contract: Any = None,
    blocks: Any = None,
    obligations: Any = None,
    requirements: Any = None,
    **kwargs: Any,
):
    """
    canonical 工程级验证后端。

    可覆盖：
      - unit_tests
      - regression_tests
      - reference_differential
      - multithread_stress
      - abi_validation
      - unwind_validation
      - relocation_validation
      - pic_pie_validation
      - inline_asm_contract
    """
    metadata = _phase8_get_metadata(contract)
    config = metadata.get(
        "phase8_engineering",
        {},
    )

    if not isinstance(config, Mapping):
        return _vr_build_only(
            "phase8.engineering_configuration_invalid",
            (
                "contract.metadata.phase8_engineering "
                "must be a mapping"
            ),
        )

    commands = config.get("commands", {})

    explicitly_required = config.get("required")
    if explicitly_required is None:
        explicitly_required = requirements

    result = _phase8_run_command_suite(
        suite_name="phase8.engineering",
        commands=commands,
        required_checks=explicitly_required,
        cwd=config.get("cwd"),
        timeout_sec=float(
            config.get("timeout_sec", 300.0)
        ),
        environment=config.get("environment"),
        failure_exit_codes=tuple(
            config.get("failure_exit_codes", [1])
        ),
    )

    if result.status == "failed":
        return _vr_failed(
            "phase8.engineering_validation_failed",
            result.detail,
        )

    if result.status == "build_only":
        return _vr_build_only(
            "phase8.engineering_validator_unavailable",
            result.detail,
        )

    return _vr_verified(
        result.detail
    )

def _run_phase8_microarch_suite(
    *,
    frag: Any = None,
    out: Any = None,
    lift: Any = None,
    ir_summary: Any = None,
    contract: Any = None,
    blocks: Any = None,
    obligations: Any = None,
    requirements: Any = None,
    **kwargs: Any,
):
    """
    canonical 微架构端到端验证后端。

    典型检查：
      - timing_distribution
      - pmc_validation
      - cache_behavior
      - branch_predictor_behavior
      - instruction_count
      - memory_access_pattern
    """
    metadata = _phase8_get_metadata(contract)
    config = metadata.get(
        "phase8_microarch",
        {},
    )

    if not isinstance(config, Mapping):
        return _vr_build_only(
            "phase8.microarch_configuration_invalid",
            (
                "contract.metadata.phase8_microarch "
                "must be a mapping"
            ),
        )

    commands = config.get("commands", {})

    explicitly_required = config.get("required")
    if explicitly_required is None:
        explicitly_required = requirements

    result = _phase8_run_command_suite(
        suite_name="phase8.microarch",
        commands=commands,
        required_checks=explicitly_required,
        cwd=config.get("cwd"),
        timeout_sec=float(
            config.get("timeout_sec", 600.0)
        ),
        environment=config.get("environment"),
        failure_exit_codes=tuple(
            config.get("failure_exit_codes", [1])
        ),
    )

    if result.status == "failed":
        return _vr_failed(
            "phase8.microarch_validation_failed",
            result.detail,
        )

    if result.status == "build_only":
        return _vr_build_only(
            "phase8.microarch_validator_unavailable",
            result.detail,
        )

    return _vr_verified(
        result.detail
    )

def _run_phase8_checker(
    checker,
    *,
    layer: str,
    unavailable_reason: str,
    failed_reason: str,
    error_reason: str,
    frag=None,
    out=None,
    lift=None,
    ir_summary=None,
    contract=None,
    blocks=None,
    obligations=None,
    requirements=None,
) -> VerifyResult:
    try:
        raw = _phase8_invoke_checker(
            checker,
            frag=frag,
            out=out,
            lift=lift,
            ir_summary=ir_summary,
            contract=contract,
            blocks=blocks,
            obligations=obligations,
            requirements=requirements,
        )
    except Exception as exc:
        # checker 异常表示验证设施失效，不等价于翻译已被证明错误。
        return _vr_build_only(
            error_reason,
            f"{layer} checker raised "
            f"{type(exc).__name__}: {exc}",
        )

    return _coerce_phase8_checker_result(
        raw,
        layer=layer,
        unavailable_reason=unavailable_reason,
        failed_reason=failed_reason,
    )


def verify_translation_phase8(
    frag,
    out: TranslationOutput,
    lift,
    summary: Optional[IRSummary] = None,
) -> VerifyResult:
    """
    Phase 8 严格分层主链：

      0. translation/contract preflight
      1. build / assemble validation
      2. admission validation
      3. block structural obligations
      4. Z3 block semantic equivalence
      5. angr path equivalence when required
      6. translation-family semantic closure
      7. engineering behavior validation
      8. microarchitectural E2E validation when required

    状态原则：
      - checker 不存在、超时或 unknown：build_only
      - checker 找到反例或行为不一致：failed
      - 所有必需层均通过：verified
    """
    if out is None:
        return _vr_unsupported(
            globals().get(
                "RC_TRANSLATION_UNSUPPORTED",
                "phase8.translation_unsupported",
            ),
            "translation output is None",
        )

    contract = _phase8_contract_from_output(out, frag)

    replacement = str(
        getattr(out, "replacement", "") or ""
    )

    if (
        contract.build_family == "unsupported"
        or not replacement.strip()
    ):
        return _vr_unsupported(
            globals().get(
                "RC_TRANSLATION_UNSUPPORTED",
                "phase8.translation_unsupported",
            ),
            "unsupported translation output: "
            f"family={contract.build_family}, "
            f"route={contract.route}",
        )

    # 契约与 emitted artifact 的明显矛盾应在执行编译前拒绝。
    mismatch_reasons = _contract_mismatch_reasons(out, frag)
    if mismatch_reasons:
        return _vr_failed(
            globals().get(
                "RC_OUTPUT_FAMILY_MISMATCH",
                "phase8.output_family_mismatch",
            ),
            "; ".join(mismatch_reasons),
        )

    # admission 属于策略检查，不是编译结果。
    admission_res = _validate_admission(contract)
    if admission_res.status != "verified":
        return admission_res

    # 第一层：构建/装配。
    if contract.requires_build_check:
        build_res = _run_artifact_build_gate(
            frag=frag,
            out=out,
            contract=contract,
        )
        if build_res is not None:
            return build_res

    if lift is None:
        return _vr_build_only(
            globals().get(
                "RC_BLOCK_PROOF_UNAVAILABLE",
                "phase8.block_proof_unavailable",
            ),
            "lift is None; Phase 8 requires lifted semantics "
            "for block and path verification",
        )

    if (
        hasattr(lift, "ok")
        and not bool(getattr(lift, "ok", False))
    ):
        return _vr_build_only(
            globals().get(
                "RC_BLOCK_PROOF_UNAVAILABLE",
                "phase8.block_proof_unavailable",
            ),
            f"lift unavailable: {getattr(lift, 'error', '')}",
        )

    try:
        blocks, ir_summary = _recover_blocks_and_summary(
            lift,
            summary,
        )
    except Exception as exc:
        return _vr_build_only(
            globals().get(
                "RC_BLOCK_PROOF_UNAVAILABLE",
                "phase8.block_proof_unavailable",
            ),
            "failed to recover blocks/IR summary: "
            f"{type(exc).__name__}: {exc}",
        )

    # 第 3 层的前置结构义务。
    obligations = _collect_block_proof_obligations(
        frag,
        blocks,
        ir_summary,
        contract,
    )

    structural_res = _validate_block_proofs(
        contract,
        obligations,
    )

    if structural_res.status != "verified":
        return _append_detail(
            structural_res,
            "block structural obligation validation did not pass",
        )

    # 第 4 层：真正的 Z3 块级语义等价证明。
    block_semantic_res = _verify_block_semantics_z3(
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        blocks=blocks,
        obligations=obligations,
    )

    if block_semantic_res.status != "verified":
        block_semantic_res = _append_detail(
            block_semantic_res,
            f"structural obligations: {structural_res.detail}",
        )
        return _with_microarch_plan(
            block_semantic_res,
            out,
            frag=frag,
            lift=lift,
            ir_summary=ir_summary,
            contract=contract,
        )

    # 第 5 层：路径敏感片段必须运行 angr。
    path_res = _run_strict_path_validation(
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        blocks=blocks,
    )

    if path_res.status != "verified":
        path_res = _append_detail(
            path_res,
            f"Z3 block semantics: {block_semantic_res.detail}",
        )
        return _with_microarch_plan(
            path_res,
            out,
            frag=frag,
            lift=lift,
            ir_summary=ir_summary,
            contract=contract,
        )

    # 第 6 层：translation family 的额外语义 closure。
    semantic_res = _run_semantic_closure(
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
    )

    if semantic_res.status != "verified":
        # 禁止再通过 structural block result 将语义 unavailable
        # 提升为 verified。
        semantic_res = _append_detail(
            semantic_res,
            f"Z3 block semantics: {block_semantic_res.detail}",
        )
        semantic_res = _append_detail(
            semantic_res,
            f"path validation: {path_res.detail}",
        )
        return _with_microarch_plan(
            semantic_res,
            out,
            frag=frag,
            lift=lift,
            ir_summary=ir_summary,
            contract=contract,
        )

    # 第 7 层：工程行为验证。
    engineering_res = _run_engineering_validation(
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        blocks=blocks,
    )

    if engineering_res.status != "verified":
        engineering_res = _append_detail(
            engineering_res,
            f"Z3 block semantics: {block_semantic_res.detail}",
        )
        engineering_res = _append_detail(
            engineering_res,
            f"path validation: {path_res.detail}",
        )
        engineering_res = _append_detail(
            engineering_res,
            f"family semantics: {semantic_res.detail}",
        )
        return _with_microarch_plan(
            engineering_res,
            out,
            frag=frag,
            lift=lift,
            ir_summary=ir_summary,
            contract=contract,
        )

    # 第 8 层：只有需要时才执行微架构 E2E。
    microarch_res = _run_microarch_validation(
        frag=frag,
        out=out,
        lift=lift,
        ir_summary=ir_summary,
        contract=contract,
        blocks=blocks,
    )

    if microarch_res.status != "verified":
        microarch_res = _append_detail(
            microarch_res,
            f"engineering validation: {engineering_res.detail}",
        )
        return microarch_res

    final = _vr_verified(
        "Phase 8 layered verification passed"
    )

    final = _append_detail(
        final,
        f"build: passed",
    )
    final = _append_detail(
        final,
        f"block structural obligations: {structural_res.detail}",
    )
    final = _append_detail(
        final,
        f"Z3 block semantics: {block_semantic_res.detail}",
    )
    final = _append_detail(
        final,
        f"path validation: {path_res.detail}",
    )
    final = _append_detail(
        final,
        f"family semantics: {semantic_res.detail}",
    )
    final = _append_detail(
        final,
        f"engineering validation: {engineering_res.detail}",
    )
    final = _append_detail(
        final,
        f"microarchitecture: {microarch_res.detail}",
    )

    return final

def apply_verify_result_to_finding(
    finding,
    vr: VerifyResult,
    out: Optional[TranslationOutput] = None,
):
    finding.verificationStatus = vr.status

    detail = str(vr.detail or "").strip()

    if vr.reason_code:
        detail = (
            f"[{vr.reason_code}] {detail}"
            if detail
            else str(vr.reason_code)
        )

        if hasattr(finding, "notes"):
            reason_note = (
                f"phase8.reason_code={vr.reason_code}"
            )
            if reason_note not in finding.notes:
                finding.notes.append(reason_note)

    finding.verificationDetail = detail

    if hasattr(finding, "notes"):
        for note in (vr.notes or []):
            if note and note not in finding.notes:
                finding.notes.append(note)

    if out is not None:
        if hasattr(finding, "translationKind"):
            if hasattr(out, "normalized_build_family"):
                family = out.normalized_build_family()
            else:
                family = (
                    getattr(out, "buildFamily", "")
                    or getattr(out, "kind", "")
                )
            finding.translationKind = family

        if hasattr(finding, "preservationLevel"):
            level = getattr(
                out,
                "preservationLevel",
                "",
            )
            if level:
                finding.preservationLevel = level

        if hasattr(finding, "preservationRoute"):
            route = getattr(
                out,
                "preservationRoute",
                "",
            )
            if route:
                finding.preservationRoute = route

    return finding

def verify(frag, lift, summary, tr):
    return verify_translation_phase8(
        frag=frag,
        out=tr,
        lift=lift,
        summary=summary,
    )