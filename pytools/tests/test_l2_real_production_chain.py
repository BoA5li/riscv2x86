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
from riscv2x86_py.l2_evidence_reader import load_case_evaluation_result, read_l2_fragment_results, read_l2_provider_results
from riscv2x86_py.compiler_provenance import bind_compiler_provenance, validate_compiler_snapshot
from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict


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
        # The report preserves the closed provenance as compilerCandidateIdentity.
        # Check membership in the independent raw compiler candidate set.
        raw = json.loads(report_path.with_name("compiler-candidates.json").read_text())
        actual = bind_compiler_provenance(
            finding["fragment"], l2_authority_sidecar_from_dict(approval["l2AuthoritySidecar"]))
        assert actual == approval["compilerAuthorityConsumption"]
        assert actual is not None
        candidates = validate_compiler_snapshot(raw)
        original = candidates[actual["compilerCandidateIdentity"]]
        closed = finding["fragment"]["compilerFragmentAuthority"]["candidate"]
        for field in ("fragmentBindingKey", "operandCarriers", "valueNodes"):
            assert closed[field] == original[field]
        original_frontend = json.loads(report_path.with_name("frontend-report.json").read_text())
        from riscv2x86_py.l2_evidence_reader import _identity
        assert _identity(original_frontend) == raw["frontendReportIdentity"]
        candidate_ids = set(candidates)
        closed_ids = {item["compilerCandidateIdentity"] for item in _objects(report)
                      if isinstance(item.get("compilerCandidateIdentity"), str)}
        assert closed_ids and closed_ids <= candidate_ids
        assert approval["l2FragmentOperandBoundary"]["complete"] is True
        operands = approval["l2AuthoritySidecar"]["operands"]
        assert len(operands) == 3
        assert operands[0]["accessMode"] == "output"
        assert operands[1]["accessMode"] == operands[2]["accessMode"] == "input"
        expected_dimensions = {"logical_operands", "shell_semantics"}
    else:
        assert approval["l2AuthoritySidecar"]["operands"] == []
        expected_dimensions = {"memory_effects", "shell_semantics"}
    case, = batch["cases"]
    evaluation = load_case_evaluation_result(output, case)
    requirements = json.loads(Path(str(report_path) + ".l2-requirements.json").read_text())
    results = [result.to_dict()["dimensionResults"]
               for _attempt, result in read_l2_fragment_results(evaluation, requirements)]
    assert results, "central closer dimension results were not recorded"
    for dimension in expected_dimensions:
        matches = [result[dimension] for result in results if dimension in result]
        assert matches
        for result in matches:
            assert result["status"] == "verified"
            for key in ("authorityIdentity", "effectRelationIdentity", "executionIdentity",
                        "sourceObservationIdentity", "targetObservationIdentity"):
                assert re.fullmatch(r"sha256:[0-9a-f]{64}", result[key])
    records = read_l2_provider_results(evaluation, output / "cases" / case["caseId"], requirements)
    assert records
    providers = [json.loads(item["envelope"]["normalizedResult"]["detail"]) for item in records]
    assert all(item["executionDisposition"] == "executed_verified" for item in providers)
    assert all("executionPlan" in item and "executionPayload" in item for item in providers)


@pytest.mark.parametrize("cc_members", [(), (0,), (1,), (0, 1)])
def test_real_downstream_fragment_program_observation(tmp_path, cc_members):
    frontend = _tools()
    source = tmp_path / 'inputs'; source.mkdir()
    clobbers = [' : "cc"' if index in cc_members else '' for index in (0, 1)]
    (source / 'sequence.c').write_text(
        '#include <stdint.h>\nuint64_t sequence(uint64_t lhs,uint64_t rhs,uint64_t mask){\n'
        'uint64_t middle,result;\n'
        '__asm__ volatile("add %0,%1,%2" : "=r"(middle) : "r"(lhs),"r"(rhs)' + clobbers[0] + ');\n'
        '__asm__ volatile("xor %0,%1,%2" : "=r"(result) : "r"(middle),"r"(mask)' + clobbers[1] + ');\n'
        'return result; }\n')
    output = tmp_path / 'results'
    completed = subprocess.run([
        sys.executable, '-m', 'riscv2x86_py.automatic_batch_cli',
        '--input', str(source), '--frontend', frontend,
        '--output-directory', str(output), '--jobs', '1', '--timeout-seconds', '120',
    ], capture_output=True, text=True, timeout=300)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    batch = json.loads((output / 'batch-evaluation.json').read_text())
    assert batch['statusCounts'] == {'verified': 1}
    observations = list(output.glob('cases/*/work/**/operand-observation.json'))
    assert len(observations) >= 2
    observed = [json.loads(p.read_text()) for p in observations]
    assert len({x['dependencyPlanIdentity'] for x in observed}) == 1
    assert all(x['sourceDependencyEvents'] for x in observed)
    assert all(x['sourceDependencyEvents'] == x['targetDependencyEvents'] for x in observed)
    assert len({x['fragmentId'] for x in observed}) == 2
