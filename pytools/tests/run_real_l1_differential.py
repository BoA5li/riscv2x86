#!/usr/bin/env python3
"""Exercise the production L1 runner with RV64 QEMU and native x86-64."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile

from riscv2x86_py.l1_differential import L1RunnerConfig, run_l1_differential
from riscv2x86_py.validation_case import INPUT_GENERATOR_VERSION, VALIDATION_CASE_SCHEMA
from riscv2x86_py.validation_status import ValidationStatus


HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 3) return 90;
  FILE *in = fopen(argv[1], "rb");
  if (!in) return 91;
  char data[8192]; size_t n = fread(data, 1, sizeof(data)-1, in); fclose(in); data[n] = 0;
  char *key = strstr(data, "\"inputIdentity\"");
  if (!key || !(key = strchr(key, ':')) || !(key = strchr(key, '\"'))) return 92;
  ++key; char *end = strchr(key, '\"'); if (!end) return 93; *end = 0;
  FILE *out = fopen(argv[2], "wb"); if (!out) return 94;
  fprintf(out,
    "{\"schemaVersion\":\"riscv2x86.l1-harness-output.v1\","
    "\"testId\":\"real-l1-rv64-x86\",\"inputIdentity\":\"%s\","
    "\"returnValue\":{\"type\":\"u64\",\"bits\":\"0x000000000000002a\",\"widthBits\":64},"
    "\"assertions\":{\"constant-result\":true},"
    "\"exportedState\":{\"out\":{\"type\":\"u64\",\"bits\":\"0x000000000000002a\",\"widthBits\":64}},"
    "\"memoryObjects\":{},\"apiResults\":{}}", key);
  fclose(out); puts("PASS"); return 0;
}
'''


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="riscv2x86-real-l1-") as directory:
        root = Path(directory)
        source, target = root / "source.c", root / "target.c"
        source.write_text(HARNESS, encoding="utf-8"); target.write_text(HARNESS, encoding="utf-8")
        case = root / "case.json"
        case.write_text(json.dumps({
            "schemaVersion": VALIDATION_CASE_SCHEMA, "testId": "real-l1-rv64-x86",
            "inputGenerator": INPUT_GENERATOR_VERSION, "seed": 20260906,
            "inputDomain": {"arguments": [{"name": "lhs", "type": "u64"},
                                           {"name": "rhs", "type": "u64"}], "randomCases": 4},
            "comparison": {"returnValue": True, "exitCode": True, "stdout": True,
                           "stderr": True, "assertions": True, "exportedState": ["out"]},
        }, sort_keys=True), encoding="utf-8")
        config = L1RunnerConfig(
            (str(case),), str(source), _digest(source), str(target), _digest(target),
            "riscv64-linux-gnu-gcc", "gcc", ("-march=rv64gc", "-mabi=lp64d", "-static", "-Werror"),
            ("-Werror",), "qemu-riscv64", "", str(root / "work"), str(root / "replay"), 30,
        )
        result = run_l1_differential(
            config, validation_plan=SimpleNamespace(source_runner="qemu", target_runner="native", seed=20260906),
            target_environment={"sourceIsa": "rv64gc", "sourceAbi": "lp64d",
                                "targetIsa": "x86_64", "targetAbi": "sysv_amd64"},
            translation_artifact=SimpleNamespace(identity="sha256:" + "1" * 64),
            source_program_artifact=SimpleNamespace(artifact_digest="sha256:" + "2" * 64),
            target_program_artifact=SimpleNamespace(artifact_digest="sha256:" + "3" * 64),
            comparison_policy="riscv2x86.l1-observable-comparison.v1",
        )
        if result.status is not ValidationStatus.VERIFIED:
            raise RuntimeError(result.detail)
        print(json.dumps({"status": result.status.value,
                          "evidenceIdentity": result.evidence_identity}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
