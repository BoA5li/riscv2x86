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
from .runtime_dependency_binding import resolve_runtime_contracts
from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_status import ValidationStatus

AUTO_L0_SCHEMA = "riscv2x86.auto-l0-runner.v1"
AUTO_L1_SCHEMA = "riscv2x86.auto-l1-runner.v1"
AUTO_L1_SCHEMA_V2 = "riscv2x86.auto-l1-runner.v2"
AUTO_L1_SCHEMA_V3 = "riscv2x86.auto-l1-runner.v3"
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


def _scalar_wrapper(functions: Sequence[Mapping[str, object]]) -> str:
    lines = ["#include <stdint.h>", "#include <stdio.h>"]
    for function in functions:
        name = function.get("name")
        return_type = function.get("returnType")
        parameter_types = function.get("parameterTypes")
        if (not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None
                or not isinstance(return_type, str) or not return_type
                or not isinstance(parameter_types, list)
                or not all(isinstance(item, str) and item for item in parameter_types)):
            raise ValueError("automatic scalar harness function signature is invalid")
        params = ", ".join(parameter_types) if parameter_types else "void"
        lines.append(f"{return_type} {name}({params});")
    lines.append("int main(void){")
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
            if function.get("returnType") == "void":
                lines.append(f'{name}(); printf("{name}=completed\\n");')
            else:
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
    legacy = {"schemaVersion", "mode", "sourcePath", "sourceDigest", "targetPath",
                "targetDigest", "functions", "workDirectory", "replayDirectory",
                "timeoutSeconds", "qemuBinary", "seed"}
    additions = {"harnessPath", "harnessDigest", "harnessManifestPath",
                 "harnessManifestDigest", "inputDomainId"}
    claim_fields = {"observationContract", "observableDimensions", "semanticLimitations"}
    schema = config.get("schemaVersion")
    if not ((schema == AUTO_L1_SCHEMA and set(config) == legacy)
            or (schema == AUTO_L1_SCHEMA_V2 and set(config) == legacy | additions)
            or (schema == AUTO_L1_SCHEMA_V3
                and set(config) == legacy | additions | claim_fields)):
        raise ValueError("automatic L1 config fields/schema are invalid")
    mode = config.get("mode")
    if mode not in {"main", "scalar-functions", "explicit-common-harness"}:
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
    harness_path = str(config.get("harnessPath", ""))
    harness_digest = str(config.get("harnessDigest", ""))
    harness_manifest_path = str(config.get("harnessManifestPath", ""))
    harness_manifest_digest = str(config.get("harnessManifestDigest", ""))
    input_domain_id = str(config.get("inputDomainId", "boundary-and-fixed-random-v1"))
    observation_contract = str(config.get(
        "observationContract", "legacy-process-observation-v1"
    ))
    dimensions = config.get(
        "observableDimensions", ["exit_code", "stderr", "stdout", "termination"]
    )
    limitations = config.get("semanticLimitations", [])
    if (not observation_contract
            or not isinstance(dimensions, list) or not dimensions
            or dimensions != sorted(set(dimensions))
            or not all(isinstance(item, str) and item for item in dimensions)
            or not isinstance(limitations, list)
            or limitations != sorted(set(limitations))
            or not all(isinstance(item, str) and item for item in limitations)):
        raise ValueError("automatic L1 observation claim is invalid")
    if mode == "explicit-common-harness":
        if (not harness_path or not harness_manifest_path
                or _SHA.fullmatch(harness_digest) is None
                or _SHA.fullmatch(harness_manifest_digest) is None or not input_domain_id):
            raise ValueError("explicit common harness binding is incomplete")
    elif schema in {AUTO_L1_SCHEMA_V2, AUTO_L1_SCHEMA_V3} and any((
            harness_path, harness_digest, harness_manifest_path,
            harness_manifest_digest)):
        raise ValueError("automatic L1 mode cannot carry an explicit harness")

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
            source_units, target_units = [source], [target]
            if mode == "scalar-functions":
                source_wrapper, target_wrapper = work / "source-harness.c", work / "target-harness.c"
                wrapper = _scalar_wrapper(functions)
                source_wrapper.write_text(wrapper, encoding="utf-8")
                target_wrapper.write_text(wrapper, encoding="utf-8")
                source_units, target_units = [source_wrapper, source], [target_wrapper, target]
                (replay / "source-harness.c").write_text(source_wrapper.read_text(), encoding="utf-8")
                (replay / "target-harness.c").write_text(target_wrapper.read_text(), encoding="utf-8")
            elif mode == "explicit-common-harness":
                harness = Path(harness_path)
                manifest = Path(harness_manifest_path)
                if (not harness.is_file()
                        or "sha256:" + sha256(harness.read_bytes()).hexdigest() != harness_digest
                        or not manifest.is_file()
                        or "sha256:" + sha256(manifest.read_bytes()).hexdigest() != harness_manifest_digest):
                    return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                                 detail="explicit harness manifest/content binding mismatch")
                replay_harness = replay / "explicit-common-harness.c"
                replay_harness.write_bytes(harness.read_bytes())
                (replay / "explicit-harness-manifest.json").write_bytes(manifest.read_bytes())
                source_units, target_units = [harness, source], [harness, target]
            dependencies = resolve_runtime_contracts(
                (kwargs["translation_artifact"].runtime_contract_id,)
            )
            runtime_includes = tuple("-I" + item for item in dependencies.include_directories)
            source_exe, target_exe = work / "source.rv64", work / "target.x86_64"
            source_build = _run(("riscv64-linux-gnu-gcc", "-std=gnu11", "-O2", "-Wall",
                                 "-Wextra", "-Werror", "-march=rv64gc", "-mabi=lp64d",
                                 "-static", *(str(item) for item in source_units),
                                 "-o", str(source_exe)), work, timeout)
            target_build = _run(("gcc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                                 *runtime_includes, *(str(item) for item in target_units),
                                 *dependencies.library_paths, "-o", str(target_exe)),
                                work, timeout)
            if source_build.returncode or target_build.returncode:
                detail = {"sourceBuild": source_build.stderr, "targetBuild": target_build.stderr}
                return ValidationLayerResult(ValidationLevel.L1, ValidationStatus.FAILED,
                                             _evidence(detail), json.dumps(detail, sort_keys=True))
            left = _run((str(config["qemuBinary"]), str(source_exe)), work, timeout)
            right = _run((str(target_exe),), work, timeout)
            observation = {"schemaVersion": "riscv2x86.auto-l1-observation.v1",
                           "mode": mode, "seed": seed, "inputDomain": input_domain_id,
                           "observationContract": observation_contract,
                           "observableDimensions": dimensions,
                           "semanticLimitations": limitations,
                           "harnessDigest": harness_digest,
                           "harnessManifestDigest": harness_manifest_digest,
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
