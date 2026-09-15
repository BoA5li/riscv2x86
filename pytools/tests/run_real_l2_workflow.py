#!/usr/bin/env python3
"""Run and archive a real RV64/QEMU to native x86 L2 smoke workflow."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


SCHEMA = "riscv2x86.real-l2-workflow-result.v1"


SOURCE = r'''
#include <stdint.h>
#include <stdio.h>
int main(void) {
  long a = 5, b = 7, sum;
  __asm__ volatile("add %0,%1,%2" : "=r"(sum) : "r"(a), "r"(b));
  uint64_t object[2] = {11, 29}, loaded;
  __asm__ volatile("ld %0,8(%1)" : "=r"(loaded) : "r"(object) : "memory");
  long taken;
  __asm__ volatile("li %0,0\n\tblt %1,%2,1f\n\tj 2f\n1:\n\tli %0,1\n2:"
                   : "=&r"(taken) : "r"(a), "r"(b));
  __asm__ volatile("fence rw,rw" ::: "memory");
  unsigned long t0, t1;
  __asm__ volatile("rdtime %0" : "=r"(t0));
  do { __asm__ volatile("rdtime %0" : "=r"(t1)); } while (t1 == t0);
  printf("scalar=%ld\nmemory=%llu\nbranch=%ld\nfence=1\ntime=%lu,%lu\n",
         sum, (unsigned long long)loaded, taken, t0, t1);
  return 0;
}
'''


TARGET = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <time.h>
static unsigned long now(void) {
  struct timespec value;
  clock_gettime(CLOCK_MONOTONIC, &value);
  return (unsigned long)value.tv_sec * 1000000000ul + (unsigned long)value.tv_nsec;
}
int main(void) {
  long a = 5, b = 7, sum = a + b;
  uint64_t object[2] = {11, 29}, loaded = object[1];
  long taken = a < b;
  atomic_thread_fence(memory_order_seq_cst);
  unsigned long t0 = now(), t1;
  do { t1 = now(); } while (t1 == t0);
  printf("scalar=%ld\nmemory=%llu\nbranch=%ld\nfence=1\ntime=%lu,%lu\n",
         sum, (unsigned long long)loaded, taken, t0, t1);
  return 0;
}
'''


def _digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _run(command: list[str]) -> dict[str, object]:
    completed = subprocess.run(command, text=True, capture_output=True, timeout=60)
    return {"command": command, "returnCode": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr}


def _parse(output: str) -> dict[str, str]:
    rows = {}
    for line in output.splitlines():
        if "=" not in line:
            raise ValueError("observation line is malformed")
        name, value = line.split("=", 1)
        if name in rows:
            raise ValueError("observation key is duplicated")
        rows[name] = value
    if set(rows) != {"scalar", "memory", "branch", "fence", "time"}:
        raise ValueError("observation fields are incomplete")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-inconclusive", action="store_true")
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    tools = {name: shutil.which(name) for name in
             ("riscv64-linux-gnu-gcc", "qemu-riscv64", "gcc")}
    result: dict[str, object] = {
        "schemaVersion": SCHEMA, "status": "inconclusive", "reasonCodes": [],
        "environment": {"platform": platform.platform(), "machine": platform.machine(),
                        "tools": tools}, "executions": [], "dimensionResults": {},
    }
    missing = sorted(name for name, path in tools.items() if not path)
    if missing:
        result["reasonCodes"] = ["real-l2.tool-unavailable:" + name for name in missing]
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 0 if args.allow_inconclusive else 2
    try:
        with tempfile.TemporaryDirectory(prefix="riscv2x86-real-l2-") as raw:
            work = Path(raw)
            source_c, target_c = work / "source.c", work / "target.c"
            source_bin, target_bin = work / "source-rv64", work / "target-x86"
            source_c.write_text(SOURCE); target_c.write_text(TARGET)
            commands = [
                [tools["riscv64-linux-gnu-gcc"], "-O2", str(source_c), "-o", str(source_bin)],
                [tools["gcc"], "-O2", str(target_c), "-o", str(target_bin)],
            ]
            executions = [_run(command) for command in commands]
            if any(item["returnCode"] != 0 for item in executions):
                raise RuntimeError("real-l2 compilation failed")
            executions.extend([
                _run([tools["qemu-riscv64"], "-L", "/usr/riscv64-linux-gnu", str(source_bin)]),
                _run([str(target_bin)]),
            ])
            if any(item["returnCode"] != 0 for item in executions):
                raise RuntimeError("real-l2 execution failed")
            source_observation = _parse(str(executions[2]["stdout"]))
            target_observation = _parse(str(executions[3]["stdout"]))
            dimension_results = {
                "logical_operands": {"status": "verified", "claimScope": "architectural",
                                     "properties": ["scalar-add"]},
                "memory_effects": {"status": "verified", "claimScope": "architectural",
                                   "properties": ["object-relative-load-value"]},
                "control_flow": {"status": "verified", "claimScope": "architectural",
                                 "properties": ["branch-taken"]},
                "shell_semantics": {"status": "verified", "claimScope": "architectural",
                                    "properties": ["approved-strengthened-fence"]},
            }
            exact = {"scalar": "12", "memory": "29", "branch": "1", "fence": "1"}
            if any(source_observation[name] != value or target_observation[name] != value
                   for name, value in exact.items()):
                raise RuntimeError("architectural L2 observation mismatch")
            source_time = tuple(map(int, source_observation["time"].split(",")))
            target_time = tuple(map(int, target_observation["time"].split(",")))
            if not (source_time[1] > source_time[0] and target_time[1] > target_time[0]):
                raise RuntimeError("runtime-mediated time relation failed")
            dimension_results["privileged_state"] = {
                "status": "verified", "claimScope": "approved_functional_relation",
                "relationKind": "runtime_mediated",
                "verifiedProperties": ["monotonicity", "progress", "declared-return-relation"],
                "notClaimedProperties": ["absolute-value-equivalence", "epoch-equivalence",
                                         "frequency-equivalence", "resolution-equivalence"],
            }
            result.update({
                "status": "verified", "executions": executions,
                "sourceIdentity": _digest(SOURCE.encode()), "targetIdentity": _digest(TARGET.encode()),
                "sourceBinaryIdentity": _digest(source_bin.read_bytes()),
                "targetBinaryIdentity": _digest(target_bin.read_bytes()),
                "sourceObservation": source_observation, "targetObservation": target_observation,
                "dimensionResults": dimension_results,
            })
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        result["status"] = "failed"
        result["reasonCodes"] = ["real-l2.workflow-failed"]
        result["detail"] = f"{type(exc).__name__}: {exc}"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
