from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Optional


# 请先通过后文的语言枚举脚本确认这两个 Language ID。
#
# 在常见 Ghidra 安装中，RISC-V language ID 通常为：
#
#   RISCV:LE:32:default
#   RISCV:LE:64:default
#
DEFAULT_RISCV32_LANGUAGE_ID = "RISCV:LE:32:default"
DEFAULT_RISCV64_LANGUAGE_ID = "RISCV:LE:64:default"


class GhidraRuntimeError(RuntimeError):
    """Ghidra / PyGhidra runtime 或 Language 加载失败。"""


_runtime_lock = threading.Lock()
_runtime_started = False
_language_cache: dict[str, Any] = {}


def _resolve_install_dir(
    ghidra_install_dir: Optional[str],
) -> Optional[Path]:
    """
    解析 Ghidra 安装目录。

    优先级：

        1. CLI --ghidra-install-dir
        2. GHIDRA_INSTALL_DIR 环境变量
        3. None，交给 PyGhidra 自身的发现逻辑
    """
    raw = (
        ghidra_install_dir
        or os.environ.get("GHIDRA_INSTALL_DIR")
    )

    if not raw:
        return None

    path = Path(raw).expanduser().resolve()

    if not path.is_dir():
        raise GhidraRuntimeError(
            f"Ghidra install directory does not exist or is not a directory: "
            f"{path}"
        )

    return path


def start_ghidra_runtime(
    *,
    ghidra_install_dir: Optional[str] = None,
) -> None:
    """
    启动 PyGhidra JVM runtime。

    本项目当前 grep 结果显示没有既有的 PyGhidra / JPype 初始化逻辑，
    因此这里作为唯一的初始化边界。

    注意：
      * 必须在 import ghidra.* Java 类之前调用；
      * 不应在 translate() / lift() 内部隐式启动 JVM；
      * CLI / 应用入口负责组合 runtime 与 pipeline。
    """
    global _runtime_started

    with _runtime_lock:
        if _runtime_started:
            return

        try:
            import pyghidra
        except ImportError as exc:
            raise GhidraRuntimeError(
                "pyghidra is not installed. Install PyGhidra before running "
                "the production translator."
            ) from exc

        install_dir = _resolve_install_dir(ghidra_install_dir)

        try:
            if install_dir is not None:
                pyghidra.start(install_dir=install_dir)
            else:
                # 允许 PyGhidra 使用其默认安装发现逻辑。
                pyghidra.start()

        except Exception as exc:
            raise GhidraRuntimeError(
                "failed to start PyGhidra runtime"
                + (
                    f" with GHIDRA_INSTALL_DIR={install_dir}"
                    if install_dir is not None
                    else ""
                )
                + f": {type(exc).__name__}: {exc}"
            ) from exc

        _runtime_started = True


def get_ghidra_language_service(
    *,
    ghidra_install_dir: Optional[str] = None,
) -> Any:
    """
    返回真实 Ghidra DefaultLanguageService。

    该函数用于替换此前修订方案中未定义的
    get_ghidra_language_service() 占位引用。
    """
    start_ghidra_runtime(
        ghidra_install_dir=ghidra_install_dir,
    )

    try:
        from ghidra.program.util import DefaultLanguageService
    except Exception as exc:
        raise GhidraRuntimeError(
            "PyGhidra was started, but "
            "ghidra.program.util.DefaultLanguageService could not be imported"
        ) from exc

    try:
        service = DefaultLanguageService.getLanguageService()
    except Exception as exc:
        raise GhidraRuntimeError(
            f"failed to obtain Ghidra DefaultLanguageService: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if service is None:
        raise GhidraRuntimeError(
            "Ghidra DefaultLanguageService.getLanguageService() returned None"
        )

    return service


def available_ghidra_language_ids(
    *,
    ghidra_install_dir: Optional[str] = None,
) -> list[str]:
    """
    返回当前 Ghidra 安装中的所有 Language ID。

    主要用于首次部署时诊断实际 RISC-V language ID。
    """
    service = get_ghidra_language_service(
        ghidra_install_dir=ghidra_install_dir,
    )

    try:
        descriptions = service.getLanguageDescriptions()
        return sorted(
            str(description.getLanguageID())
            for description in descriptions
        )
    except Exception as exc:
        raise GhidraRuntimeError(
            f"failed to enumerate Ghidra languages: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def load_real_ghidra_language(
    language_id: str,
    *,
    ghidra_install_dir: Optional[str] = None,
) -> Any:
    """
    根据 Language ID 加载真实 Ghidra Language。

    返回的对象会被 pipeline.run(..., language=language) 注入至 lift()，
    最终被 GhidraLanguageRegisterResolver 消费。

    所需能力：

        language.getAddressFactory()
        language.getRegister(address, size)
    """
    if not isinstance(language_id, str) or not language_id.strip():
        raise GhidraRuntimeError(
            f"language_id must be a non-empty string, got {language_id!r}"
        )

    language_id = language_id.strip()

    cached = _language_cache.get(language_id)
    if cached is not None:
        return cached

    service = get_ghidra_language_service(
        ghidra_install_dir=ghidra_install_dir,
    )

    try:
        from ghidra.program.model.lang import LanguageID
    except Exception as exc:
        raise GhidraRuntimeError(
            "PyGhidra was started, but "
            "ghidra.program.model.lang.LanguageID could not be imported"
        ) from exc

    try:
        language = service.getLanguage(LanguageID(language_id))
    except Exception as exc:
        raise GhidraRuntimeError(
            f"failed to load Ghidra Language {language_id!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if language is None:
        riscv_candidates = [
            item
            for item in available_ghidra_language_ids(
                ghidra_install_dir=ghidra_install_dir,
            )
            if "RISCV" in item.upper()
        ]

        raise GhidraRuntimeError(
            f"Ghidra Language {language_id!r} is unavailable. "
            f"Available RISC-V language IDs: {riscv_candidates!r}"
        )

    if not callable(getattr(language, "getAddressFactory", None)):
        raise GhidraRuntimeError(
            f"Ghidra Language {language_id!r} does not provide "
            "getAddressFactory()"
        )

    if not callable(getattr(language, "getRegister", None)):
        raise GhidraRuntimeError(
            f"Ghidra Language {language_id!r} does not provide "
            "getRegister()"
        )

    _language_cache[language_id] = language
    return language


def riscv_language_id_for_xlen(xlen: int) -> str:
    """
    根据 pipeline 的 XLEN 选择对应 RISC-V Ghidra Language ID。
    """
    if xlen == 32:
        return DEFAULT_RISCV32_LANGUAGE_ID

    if xlen == 64:
        return DEFAULT_RISCV64_LANGUAGE_ID

    raise GhidraRuntimeError(
        f"unsupported RISC-V XLEN: {xlen!r}; expected 32 or 64"
    )

def _validate_loaded_riscv_language(
    language: Any,
    *,
    expected_xlen: int,
    selected_language_id: str,
) -> None:
    """
    校验实际加载的 Ghidra Language 与 pipeline 的 xlen 一致。

    不能只相信 CLI 输入的 Language ID，因为用户可能显式传入：
        --xlen 64 --ghidra-language-id RISCV:LE:32:default

    这会使 assembler、lifter 和 register resolver 的位宽事实不一致。
    """
    try:
        processor = str(language.getProcessor())
    except Exception as exc:
        raise GhidraRuntimeError(
            f"loaded Language {selected_language_id!r} does not expose "
            f"getProcessor(): {type(exc).__name__}: {exc}"
        ) from exc

    if "RISCV" not in processor.upper():
        raise GhidraRuntimeError(
            f"loaded Language {selected_language_id!r} is not RISC-V: "
            f"processor={processor!r}"
        )

    try:
        default_space = language.getDefaultSpace()
        actual_xlen = int(default_space.getSize())
    except Exception as exc:
        raise GhidraRuntimeError(
            f"cannot determine default address-space size for "
            f"Language {selected_language_id!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    if actual_xlen != expected_xlen:
        raise GhidraRuntimeError(
            f"Ghidra Language / XLEN mismatch: requested xlen={expected_xlen}, "
            f"but Language {selected_language_id!r} has default address "
            f"space size {actual_xlen}"
        )

def load_riscv_ghidra_language(
    *,
    xlen: int,
    ghidra_install_dir: Optional[str] = None,
    language_id: Optional[str] = None,
) -> Any:
    """
    加载并校验真实 RISC-V Ghidra Language。

    language_id 非空时优先使用它，便于兼容不同 Ghidra 版本中的
    Language ID 差异。

    即使用户显式传入 language_id，也必须验证：
      1. 实际 processor 是 RISCV；
      2. 实际默认 address space 位宽与 xlen 一致。
    """
    selected_id = language_id or riscv_language_id_for_xlen(xlen)

    language = load_real_ghidra_language(
        selected_id,
        ghidra_install_dir=ghidra_install_dir,
    )

    _validate_loaded_riscv_language(
        language,
        expected_xlen=xlen,
        selected_language_id=selected_id,
    )

    return language