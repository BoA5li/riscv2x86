"""Validators used by the zero-configuration corpus entry point."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping, Sequence

from .l0_build_matrix import run_l0_build_matrix
from .l0_manifest_builder import build_l0_reference_manifest
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus

AUTO_L0_SCHEMA = "riscv2x86.auto-l0-runner.v1"
AUTO_L1_SCHEMA = "riscv2x86.auto-l1-runner.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


def _evidence(payload: Mapping[str, object]) -> str:
    value = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(value).hexdigest()


def build_auto_l0_validator(config: Mapping[str, object]):
    expected = {"schemaVersion", "sourcePath", "sourceDigest", "targetPath",
                "targetDigest", "workDirectory", "linkKind", "timeoutSeconds"}
    if set(config) != expected or config.get("schemaVersion") != AUTO_L0_SCHEMA:
        raise ValueError("automatic L0 config fields/schema are invalid")
    for name in ("sourcePath", "targetPath", "workDirectory", "linkKind"):
        if not isinstance(config.get(name), str) or not config[name]:
            raise ValueError("automatic L0 " + name + " is invalid")
    for name in ("sourceDigest", "targetDigest"):
        if not isinstance(config.get(name), str) or _SHA.fullmatch(str(config[name])) is None:
            raise ValueError("automatic L0 digest is invalid")
    timeout = config.get("timeoutSeconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("automatic L0 timeout is invalid")
    if config["linkKind"] not in {"executable", "shared_library"}:
        raise ValueError("automatic L0 link kind is invalid")

    def validate(**kwargs: object) -> ValidationLayerResult:
        if kwargs.get("level") is not ValidationLevel.L0:
            return ValidationLayerResult(ValidationLevel.L0, ValidationStatus.FAILED,
                                         detail="automatic L0 invoked for wrong level")
        source, target = Path(str(config["sourcePath"])), Path(str(config["targetPath"]))
        if ("sha256:" + sha256(source.read_bytes()).hexdigest() != config["sourceDigest"] or
                "sha256:" + sha256(target.read_bytes()).hexdigest() != config["targetDigest"]):
            return ValidationLayerResult(ValidationLevel.L0, ValidationStatus.FAILED,
                                         detail="automatic L0 source/target digest mismatch")
        try:
            matrix, reference_source, reference_target = build_l0_reference_manifest(
                source_path=source, target_path=target,
                output_directory=Path(str(config["workDirectory"])),
                translation=kwargs["translation_artifact"],
                link_kind=str(config["linkKind"]), timeout=timeout,
            )
            # Evaluation build artifacts are an independent binding.  Their bytes
            # must equal the oracle build before the matrix is replayed.
            supplied_source = kwargs["source_program_artifact"]
            supplied_target = kwargs["target_program_artifact"]
            if (supplied_source.artifact_digest != reference_source.artifact_digest or
                    supplied_target.artifact_digest != reference_target.artifact_digest):
                return ValidationLayerResult(ValidationLevel.L0, ValidationStatus.FAILED,
                                             detail="evaluation/reference artifact mismatch")
            return run_l0_build_matrix(
                matrix, kwargs["translation_artifact"], supplied_source, supplied_target,
                target_environment=kwargs.get("target_environment"),
            )
        except OSError as exc:
            return ValidationLayerResult(ValidationLevel.L0, ValidationStatus.INCONCLUSIVE,
                                         detail=f"automatic L0 unavailable: {type(exc).__name__}: {exc}")
        except (RuntimeError, ValueError) as exc:
            return ValidationLayerResult(ValidationLevel.L0, ValidationStatus.FAILED,
                                         detail=f"automatic L0 failed: {type(exc).__name__}: {exc}")
    return validate


def _run(argv: Sequence[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True,
                          timeout=timeout, check=False)


def _scalar_wrapper(source: Path, functions: Sequence[Mapping[str, object]]) -> str:
    lines = ["#include <stdint.h>", "#include <stdio.h>", f'#include "{source}"',
             "int main(void){"]
    values = ("0", "1", "UINT64_MAX", "UINT64_C(0x7fffffff)",
              "UINT64_C(0x80000000)", "UINT64_C(0xffffffff)",
              "UINT64_C(0x5a17d3e4c29b806f)", "UINT64_C(0xc4ceb9fe1a85ec53)")
    for function in functions:
        name, arity = function.get("name"), function.get("arity")
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None:
            raise ValueError("automatic scalar harness function name is invalid")
        if isinstance(arity, bool) or not isinstance(arity, int) or arity < 0 or arity > 3:
            raise ValueError("automatic scalar harness supports zero to three arguments")
        if arity == 0:
            lines.append(f'printf("{name}=%llu\\n",(unsigned long long){name}());')
        else:
            indices = [f"i{n}" for n in range(arity)]
            loops = "".join(f"for(unsigned {i}=0;{i}<8;++{i}){{" for i in indices)
            args = ",".join(f"(uint64_t)v[{i}]" for i in indices)
            lines.append("{static const uint64_t v[8]={" + ",".join(values) + "};" + loops)
            lines.append(f'printf("{name}:%llu\\n",(unsigned long long){name}({args}));')
            lines.append("}" * arity + "}")
    lines.append("return 0;}")
    return "\n".join(lines) + "\n"


def build_auto_l1_validator(config: Mapping[str, object]):
    expected = {"schemaVersion", "mode", "sourcePath", "sourceDigest", "targetPath",
                "targetDigest", "functions", "workDirectory", "replayDirectory",
                "timeoutSeconds", "qemuBinary", "seed"}
    if set(config) != expected or config.get("schemaVersion") != AUTO_L1_SCHEMA:
        raise ValueError("automatic L1 config fields/schema are invalid")
    mode = config.get("mode")
    if mode not in {"main", "scalar-functions"}:
        raise ValueError("automatic L1 mode is unsupported")
    functions = config.get("functions")
    if not isinstance(functions, list):
        raise ValueError("automatic L1 functions must be an array")
    timeout = config.get("timeoutSeconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("automatic L1 timeout is invalid")
    seed = config.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("automatic L1 seed is invalid")

    def validate(**kwargs: object) -> ValidationLayerResult:
        if kwargs.get("level") is not ValidationLevel.L1:
            return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                         detail="automatic L1 invoked for wrong level")
        source, target = Path(str(config["sourcePath"])), Path(str(config["targetPath"]))
        work, replay = Path(str(config["workDirectory"])), Path(str(config["replayDirectory"]))
        work.mkdir(parents=True, exist_ok=True); replay.mkdir(parents=True, exist_ok=True)
        if ("sha256:" + sha256(source.read_bytes()).hexdigest() != config["sourceDigest"] or
                "sha256:" + sha256(target.read_bytes()).hexdigest() != config["targetDigest"]):
            return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                         detail="automatic L1 source/target digest mismatch")
        try:
            source_unit, target_unit = source, target
            if mode == "scalar-functions":
                source_wrapper, target_wrapper = work / "source-harness.c", work / "target-harness.c"
                source_wrapper.write_text(_scalar_wrapper(source, functions), encoding="utf-8")
                target_wrapper.write_text(_scalar_wrapper(target, functions), encoding="utf-8")
                source_unit, target_unit = source_wrapper, target_wrapper
                (replay / "source-harness.c").write_text(source_wrapper.read_text(), encoding="utf-8")
                (replay / "target-harness.c").write_text(target_wrapper.read_text(), encoding="utf-8")
            source_exe, target_exe = work / "source.rv64", work / "target.x86_64"
            source_build = _run(("riscv64-linux-gnu-gcc", "-std=gnu11", "-O2", "-Wall",
                                 "-Wextra", "-Werror", "-march=rv64gc", "-mabi=lp64d",
                                 "-static", str(source_unit), "-o", str(source_exe)), work, timeout)
            target_build = _run(("gcc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                                 str(target_unit), "-o", str(target_exe)), work, timeout)
            if source_build.returncode or target_build.returncode:
                detail = {"sourceBuild": source_build.stderr, "targetBuild": target_build.stderr}
                return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                             _evidence(detail), json.dumps(detail, sort_keys=True))
            left = _run((str(config["qemuBinary"]), str(source_exe)), work, timeout)
            right = _run((str(target_exe),), work, timeout)
            observation = {"schemaVersion": "riscv2x86.auto-l1-observation.v1",
                           "mode": mode, "seed": seed, "inputDomain": "boundary-and-fixed-random-v1",
                           "source": {"exitCode": left.returncode,
                           "stdout": left.stdout, "stderr": left.stderr},
                           "target": {"exitCode": right.returncode,
                           "stdout": right.stdout, "stderr": right.stderr}}
            (replay / "l1-observation.json").write_text(
                json.dumps(observation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            status = (ValidationStatus.VERIFIED
                      if (left.returncode, left.stdout, left.stderr) ==
                         (right.returncode, right.stdout, right.stderr)
                      else ValidationStatus.FAILED)
            return ValidationLayerResult(ValidationLevel.L1, status,
                                         _evidence(observation), json.dumps(observation, sort_keys=True))
        except subprocess.TimeoutExpired as exc:
            return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                         detail="automatic L1 timeout: " + str(exc))
        except (OSError, ValueError) as exc:
            return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.INCONCLUSIVE,
                                         detail=f"automatic L1 unavailable: {type(exc).__name__}: {exc}")
    return validate
