# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


class GhidraPythonRunError(RuntimeError):
    """support/pythonRun 调用失败或返回无效数据。"""


@dataclass(frozen=True)
class PythonRunRegisterNameResolver:
    """
    一个由 support/pythonRun + Ghidra Language API 生成的
    authoritative register resolver。

    该 resolver 在 CPython 中运行，但 register identity 数据
    来自真实 Ghidra Language。
    """

    names: Dict[Tuple[str, int, int], str]

    def register_name_for_varnode(
        self,
        *,
        space: str,
        offset: int,
        size: int,
    ) -> Optional[str]:
        return self.names.get(
            (space.lower(), int(offset), int(size))
        )


def _default_ghidra_install_dir() -> Path:
    configured = os.environ.get("GHIDRA_INSTALL_DIR")

    if configured:
        return Path(configured)

    return Path("/opt/ghidra_11.2_PUBLIC")


def _default_python_run_path() -> Path:
    return _default_ghidra_install_dir() / "support" / "pythonRun"


def _default_register_query_script() -> Path:
    script_path = "/root/src/poc_trans/path_b/riscv2x86/test/minimal/backend_test/riscv_register_query.py"
    return Path(script_path)

def riscv_language_id_for_xlen(xlen: int) -> str:
    if xlen == 32:
        return "RISCV:LE:32:default"

    if xlen == 64:
        return "RISCV:LE:64:default"

    raise GhidraPythonRunError(
        f"Unsupported RISC-V XLEN: {xlen}; expected 32 or 64"
    )

def load_riscv64_register_resolver_via_pythonrun(
    *,
    python_run: Optional[Path] = None,
    query_script: Optional[Path] = None,
    ghidra_install_dir: Optional[str] = None,
) -> PythonRunRegisterNameResolver:
    """
    使用 Ghidra support/pythonRun 获取 RISCV:LE:64:default
    的真实寄存器定义，并在 CPython 中构造 resolver。
    """

    if python_run is None:
        if ghidra_install_dir is not None:
            python_run = (
                Path(ghidra_install_dir)
                / "support"
                / "pythonRun"
            )
        else:
            python_run = _default_python_run_path()

    query_script = (
        query_script
        or _default_register_query_script()
    )

    if not python_run.is_file():
        raise GhidraPythonRunError(
            "Ghidra support/pythonRun not found: "
            f"{python_run}. "
            "Set GHIDRA_INSTALL_DIR correctly."
        )

    if not os.access(python_run, os.X_OK):
        raise GhidraPythonRunError(
            f"Ghidra support/pythonRun is not executable: {python_run}"
        )

    if not query_script.is_file():
        raise GhidraPythonRunError(
            f"Ghidra register query script not found: {query_script}"
        )

    completed = subprocess.run(
        [str(python_run), str(query_script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=60,
    )

    if completed.returncode != 0:
        raise GhidraPythonRunError(
            "support/pythonRun failed.\n"
            f"command: {python_run} {query_script}\n"
            f"returncode: {completed.returncode}\n"
            f"stdout raw:\n{repr(completed.stdout)}\n"
            f"stderr:\n{completed.stderr}"
        )

    raw_stdout = completed.stdout

    content = "".join(
        [
            line.strip()
            for line in raw_stdout.splitlines()
            if line.strip()
        ]
    )

    start = content.find("{")
    end = content.rfind("}")

    if start == -1 or end == -1 or start >= end:
        raise GhidraPythonRunError(
            "Valid JSON block not found\n"
            f"Raw cleaned content: {repr(content)}"
        )

    pure_json_str = content[start:end + 1]

    try:
        data = json.loads(pure_json_str)
    except json.JSONDecodeError as exc:
        raise GhidraPythonRunError(
            "JSON parse failed\n"
            f"Cut JSON: {repr(pure_json_str)}\n"
            f"Raw stdout: {repr(raw_stdout)}\n"
            f"STDERR:\n{completed.stderr}"
        ) from exc

    if not data.get("ok"):
        raise GhidraPythonRunError(
            f"Ghidra query returned failure: {data}"
        )

    if data.get("language_id") != "RISCV:LE:64:default":
        raise GhidraPythonRunError(
            "unexpected Ghidra language ID: "
            f"{data.get('language_id')!r}"
        )

    names = {}

    for register in data.get("registers", []):
        name = str(register["name"])
        offset = int(register["offset"])
        size = int(register["size"])

        if size <= 0:
            continue

        key = ("register", offset, size)

        names.setdefault(key, name)

    if not names:
        raise GhidraPythonRunError(
            "Ghidra query returned no usable RISC-V registers"
        )

    return PythonRunRegisterNameResolver(names=names)



def load_riscv_register_resolver_via_pythonrun(
    *,
    xlen: int,
    ghidra_install_dir: Optional[str] = None,
    language_id: Optional[str] = None,
) -> PythonRunRegisterNameResolver:

    selected_language_id = (
        language_id
        or riscv_language_id_for_xlen(xlen)
    )

    if xlen != 64:
        raise GhidraPythonRunError(
            "The current pythonRun register resolver implementation "
            f"supports RV64 only; got xlen={xlen}, "
            f"language_id={selected_language_id!r}"
        )

    if (
        language_id is not None
        and language_id != "RISCV:LE:64:default"
    ):
        raise GhidraPythonRunError(
            "The current pythonRun resolver loader does not yet support "
            f"custom language_id={language_id!r}"
        )

    return load_riscv64_register_resolver_via_pythonrun(
        ghidra_install_dir=ghidra_install_dir
    )