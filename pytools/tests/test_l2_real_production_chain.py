"""Real frontend -> Phase 6D -> provider -> closer tests. No mocked tools.

Run with RISCV2X86_TEST_FRONTEND set to the rebuilt frontend and the selected
Clang on PATH. Missing tools skip; a failing installed tool is a test failure.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


SOURCES = {
    "scalar": '#include <stdint.h>\nuint64_t probe(uint64_t x, uint64_t y) {\n'
              'uint64_t result; __asm__ volatile("add %0, %1, %2" : "=r"(result) : "r"(x), "r"(y));\n'
              'return result; }\n',
    "fence": 'void probe(void) { __asm__ volatile("fence rw, rw" ::: "memory"); }\n',
}


def _tools():
    frontend = os.environ.get("RISCV2X86_TEST_FRONTEND", "")
    missing = [tool for tool in ("clang", "llvm-mc", "riscv64-linux-gnu-gcc", "qemu-riscv64", "gcc")
               if shutil.which(tool) is None]
    if not frontend or not Path(frontend).is_file() or not os.access(frontend, os.X_OK):
        missing.append("RISCV2X86_TEST_FRONTEND (rebuilt executable)")
    if missing:
        pytest.skip("real production toolchain unavailable: " + ", ".join(missing))
    return str(Path(frontend).resolve())


def _objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values(): yield from _objects(child)
    elif isinstance(value, list):
        for child in value: yield from _objects(child)
    elif isinstance(value, str) and value.startswith("{"):
        try: decoded = json.loads(value)
        except ValueError: return
        yield from _objects(decoded)


@pytest.mark.parametrize("route", ["scalar", "fence"])
def test_real_production_chain_closes_required_dimensions(tmp_path, route):
    frontend = _tools()
    source = tmp_path / "inputs"; source.mkdir()
    (source / "probe.c").write_text(SOURCES[route])
    output = tmp_path / "results"
    completed = subprocess.run([
        sys.executable, "-m", "riscv2x86_py.automatic_batch_cli",
        "--input", str(source), "--frontend", frontend,
        "--output-directory", str(output), "--jobs", "1", "--timeout-seconds", "120",
    ], capture_output=True, text=True, timeout=300, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    batch = json.loads((output / "batch-evaluation.json").read_text())
    assert batch["caseCount"] == 1
    assert batch["statusCounts"] == {"verified": 1}
    report_path, = output.glob("cases/*/work/translation-work/translated_report.json")
    report = json.loads(report_path.read_text())
    finding, = report["findings"]
    approval = finding["approvalArtifact"]
    assert approval["proofStatus"] == "approved"
    assert approval["l2EffectProofFacts"]["complete"] is True
    assert approval["l2AuthoritySidecar"]["complete"] is True
    assert Path(str(report_path) + ".requirement-staging.json").is_file()
    assert list(output.glob("cases/*/work/replay/*-l2-resolved-plan.json")), "resolver plan missing"
    if route == "scalar":
        assert any(item.get("candidateIdentity") for item in _objects(report))
        assert approval["l2FragmentOperandBoundary"]["complete"] is True
        operands = approval["l2AuthoritySidecar"]["operands"]
        assert len(operands) == 3
        assert operands[0]["accessMode"] == "output"
        assert operands[1]["accessMode"] == operands[2]["accessMode"] == "input"
        expected_dimensions = {"logical_operands", "shell_semantics"}
    else:
        assert approval["l2AuthoritySidecar"]["operands"] == []
        expected_dimensions = {"memory_effects", "shell_semantics"}
    results = [item["dimensionResults"] for item in _objects(batch)
               if isinstance(item.get("dimensionResults"), dict)]
    assert results, "central closer dimension results were not recorded"
    for dimension in expected_dimensions:
        matches = [result[dimension] for result in results if dimension in result]
        assert matches
        for result in matches:
            assert result["status"] == "verified"
            for key in ("authorityIdentity", "effectRelationIdentity", "executionIdentity",
                        "sourceObservationIdentity", "targetObservationIdentity"):
                assert re.fullmatch(r"sha256:[0-9a-f]{64}", result[key])
    providers = [item for item in _objects(batch) if item.get("executionDisposition") == "executed_verified"]
    assert providers
    assert any("executionPlan" in item and "executionPayload" in item for item in providers)
