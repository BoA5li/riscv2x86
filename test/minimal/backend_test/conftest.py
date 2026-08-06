from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest


TEST_ROOT = Path(__file__).parent
DATA_ROOT = TEST_ROOT / "data"


@pytest.fixture
def backend_module():
    """
    指向定义 run() 的模块。

    示例：
        BACKEND_RUN_MODULE=translator.backend pytest -q
    """
    module_name = os.environ.get("BACKEND_RUN_MODULE", "pytools.riscv2x86_py.pipeline")

    module = importlib.import_module(module_name)

    assert hasattr(module, "run"), (
        f"{module_name!r} does not expose run(in_json, out_json, xlen)"
    )
    return module


@pytest.fixture
def input_c_path() -> Path:
    return Path(__file__).parents[1] / "input" / "rv_add_sub.c"


@pytest.fixture
def input_json_path() -> Path:
    # __file__ 是 conftest.py，目录：backend_test
    return Path(__file__).parents[1] / "output" / "rv_add_sub_report.json"


@pytest.fixture
def copied_input_json(tmp_path: Path, input_json_path: Path) -> Path:
    target = tmp_path / "input.json"
    target.write_bytes(input_json_path.read_bytes())
    return target


def read_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, dict):
        findings = data.get("findings")
        assert isinstance(findings, list)
        return findings

    assert isinstance(data, list)
    return data


@pytest.fixture
def load_output_findings():
    return read_findings