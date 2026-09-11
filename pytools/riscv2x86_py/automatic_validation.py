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


def _memory_object_wrapper(functions: Sequence[Mapping[str, object]]) -> str:
    """Build a bounded L1 harness for one declared integer-pointer object.

    The object is deliberately larger than the currently supported fixed load/store
    offsets.  Its entire post-call state is serialized, so stores cannot pass merely
    because the function returned successfully.
    """
    lines = ["#include <stdint.h>", "#include <stdio.h>"]
    for function in functions:
        name = function.get("name")
        return_type = function.get("returnType")
        parameter_types = function.get("parameterTypes")
        pointer_parameters = function.get("pointerParameters")
        if (not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None
                or not isinstance(return_type, str) or not return_type
                or not isinstance(parameter_types, list)
                or not all(isinstance(item, str) and item for item in parameter_types)
                or not isinstance(pointer_parameters, list)
                or len(pointer_parameters) > 1
                or any(isinstance(item, bool) or not isinstance(item, int)
                       or item < 0 or item >= len(parameter_types)
                       for item in pointer_parameters)):
            raise ValueError("automatic memory-object harness signature is invalid")
        params = ", ".join(parameter_types) if parameter_types else "void"
        lines.append(f"{return_type} {name}({params});")
    lines.append("static void dump_object(const char *name,const uint64_t *p){")
    lines.append('printf("%s=[%016llx,%016llx,%016llx,%016llx]\\n",name,')
    lines.append("(unsigned long long)p[0],(unsigned long long)p[1],")
    lines.append("(unsigned long long)p[2],(unsigned long long)p[3]);}")
    lines.append("int main(void){")
    values = ("0", "1", "UINT64_MAX", "UINT64_C(0x7fffffff)",
              "UINT64_C(0x80000000)", "UINT64_C(0xffffffff)",
              "UINT64_C(0x5a17d3e4c29b806f)", "UINT64_C(0xc4ceb9fe1a85ec53)")
    lines.append("static const uint64_t v[8]={" + ",".join(values) + "};")
    for function in functions:
        name = str(function["name"])
        return_type = str(function["returnType"])
        parameter_types = list(function["parameterTypes"])
        pointer_parameters = list(function["pointerParameters"])
        if not pointer_parameters:
            arity = len(parameter_types)
            indices = [f"i{index}" for index in range(arity)]
            loops = "".join(f"for(unsigned {item}=0;{item}<8;++{item}){{"
                            for item in indices)
            args = ",".join(
                f"({parameter_types[index]})v[{indices[index]}]"
                for index in range(arity)
            )
            lines.append("{" + loops)
            invocation = f"{name}({args})"
            if return_type == "void":
                lines.append(invocation + ";")
            else:
                lines.append(f'printf("{name}:return=%016llx\\n",'
                             f'(unsigned long long){invocation});')
            lines.append("}" * len(indices) + "}")
            continue
        pointer_index = int(pointer_parameters[0])
        scalar_indices = [index for index in range(len(parameter_types))
                          if index != pointer_index]
        loop_names = [f"i{index}" for index in range(len(scalar_indices))]
        loops = "".join(f"for(unsigned {item}=0;{item}<8;++{item}){{"
                        for item in loop_names)
        lines.append("{" + loops)
        lines.append("uint64_t object[4]={UINT64_C(0x1122334455667788),"
                     "UINT64_C(0x8877665544332211),UINT64_C(0x0123456789abcdef),"
                     "UINT64_C(0xfedcba9876543210)};")
        scalar_by_param = dict(zip(scalar_indices, loop_names))
        args = []
        for index, parameter_type in enumerate(parameter_types):
            if index == pointer_index:
                args.append(f"({parameter_type})object")
            else:
                args.append(f"({parameter_type})v[{scalar_by_param[index]}]")
        invocation = f"{name}({','.join(args)})"
        if return_type == "void":
            lines.append(invocation + ";")
        else:
            lines.append(f'printf("{name}:return=%016llx\\n",'
                         f'(unsigned long long){invocation});')
        lines.append(f'dump_object("{name}:object",object);')
        lines.append("}" * len(loop_names) + "}")
    lines.append("return 0;}")
    return "\n".join(lines) + "\n"


def _memory_object_observations(stdout: str) -> list[dict[str, object]]:
    pattern = re.compile(
        r"^(?P<function>[A-Za-z_]\w*):object=\["
        r"(?P<values>[0-9a-f]{16}(?:,[0-9a-f]{16}){3})\]$"
    )
    observations = []
    for order, line in enumerate(stdout.splitlines()):
        match = pattern.fullmatch(line)
        if match is not None:
            observations.append({
                "objectId": match.group("function") + ":arg-object",
                "order": order,
                "values": ["0x" + item for item in match.group("values").split(",")],
            })
    return observations


def _branch_domain_wrapper(functions: Sequence[Mapping[str, object]]) -> str:
    """Exercise four-argument branch selectors without an exponential product.

    Arguments zero and one receive equality, inequality, ordering, and width-boundary
    pairs.  Arguments two and three are distinct result sentinels.  This validates
    functional branch selection; normalized branch-event traces remain an L2 concern.
    """
    lines = ["#include <stdint.h>", "#include <stdio.h>"]
    for function in functions:
        name = function.get("name")
        return_type = function.get("returnType")
        parameter_types = function.get("parameterTypes")
        arity = function.get("arity")
        if (not isinstance(name, str) or re.fullmatch(r"[A-Za-z_]\w*", name) is None
                or not isinstance(return_type, str) or not return_type
                or not isinstance(parameter_types, list)
                or not all(isinstance(item, str) and item for item in parameter_types)
                or isinstance(arity, bool) or not isinstance(arity, int)
                or arity != len(parameter_types) or arity < 0 or arity > 4
                or function.get("pointerParameters", []) != []):
            raise ValueError("automatic branch-domain harness signature is invalid")
        lines.append(f"{return_type} {name}({', '.join(parameter_types) or 'void'});")
    lines.append("int main(void){")
    branch_cases = (
        ("0", "0", "UINT64_C(0x1111111111111111)", "UINT64_C(0x2222222222222222)"),
        ("1", "1", "UINT64_C(0x3333333333333333)", "UINT64_C(0x4444444444444444)"),
        ("0", "1", "UINT64_C(0x5555555555555555)", "UINT64_C(0xaaaaaaaaaaaaaaaa)"),
        ("1", "0", "UINT64_C(0x0123456789abcdef)", "UINT64_C(0xfedcba9876543210)"),
        ("UINT64_MAX", "0", "UINT64_C(0x13579bdf2468ace0)", "UINT64_C(0x02468ace13579bdf)"),
        ("0", "UINT64_MAX", "UINT64_C(0x7fffffffffffffff)", "UINT64_C(0x8000000000000000)"),
        ("UINT64_C(0x7fffffff)", "UINT64_C(0x80000000)", "3", "5"),
        ("UINT64_C(0x80000000)", "UINT64_C(0x7fffffff)", "7", "11"),
        ("UINT64_C(0x7fffffffffffffff)", "UINT64_C(0x8000000000000000)", "13", "17"),
        ("UINT64_C(0x8000000000000000)", "UINT64_C(0x7fffffffffffffff)", "19", "23"),
        ("UINT64_MAX", "UINT64_MAX", "29", "31"),
    )
    scalar_values = ("0", "1", "UINT64_MAX", "UINT64_C(0x7fffffff)",
                     "UINT64_C(0x80000000)", "UINT64_C(0xffffffff)",
                     "UINT64_C(0x5a17d3e4c29b806f)",
                     "UINT64_C(0xc4ceb9fe1a85ec53)")
    if any(function.get("arity") != 4 for function in functions):
        lines.append("static const uint64_t v[8]={" + ",".join(scalar_values) + "};")
    for function in functions:
        name = str(function["name"])
        return_type = str(function["returnType"])
        parameter_types = list(function["parameterTypes"])
        arity = int(function["arity"])
        if arity == 4:
            for case_index, values in enumerate(branch_cases):
                args = ",".join(
                    f"({parameter_types[index]})({values[index]})" for index in range(4)
                )
                invocation = f"{name}({args})"
                if return_type == "void":
                    lines.append(invocation + ";")
                    lines.append(f'printf("{name}:case={case_index}:completed\\n");')
                else:
                    lines.append(f'printf("{name}:case={case_index}:return=%016llx\\n",'
                                 f'(unsigned long long){invocation});')
            continue
        indices = [f"i{index}" for index in range(arity)]
        lines.append("{" + "".join(
            f"for(unsigned {item}=0;{item}<8;++{item}){{" for item in indices
        ))
        args = ",".join(
            f"({parameter_types[index]})v[{indices[index]}]" for index in range(arity)
        )
        invocation = f"{name}({args})"
        if return_type == "void":
            lines.append(invocation + ";")
        else:
            lines.append(f'printf("{name}:return=%016llx\\n",'
                         f'(unsigned long long){invocation});')
        lines.append("}" * len(indices) + "}")
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
    if mode not in {"main", "scalar-functions", "memory-object-functions",
                    "branch-domain-functions",
                    "explicit-common-harness"}:
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
            if mode in {"scalar-functions", "memory-object-functions",
                        "branch-domain-functions"}:
                source_wrapper, target_wrapper = work / "source-harness.c", work / "target-harness.c"
                wrapper = (_memory_object_wrapper(functions)
                           if mode == "memory-object-functions"
                           else _branch_domain_wrapper(functions)
                           if mode == "branch-domain-functions"
                           else _scalar_wrapper(functions))
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
            source_observation = {"exitCode": left.returncode,
                                  "stdout": left.stdout, "stderr": left.stderr}
            target_observation = {"exitCode": right.returncode,
                                  "stdout": right.stdout, "stderr": right.stderr}
            if mode == "memory-object-functions":
                source_observation["memoryObjects"] = _memory_object_observations(left.stdout)
                target_observation["memoryObjects"] = _memory_object_observations(right.stdout)
            observation = {"schemaVersion": "riscv2x86.auto-l1-observation.v1",
                           "mode": mode, "seed": seed, "inputDomain": input_domain_id,
                           "observationContract": observation_contract,
                           "observableDimensions": dimensions,
                           "semanticLimitations": limitations,
                           "harnessDigest": harness_digest,
                           "harnessManifestDigest": harness_manifest_digest,
                           "source": source_observation,
                           "target": target_observation}
            (replay / "l1-observation.json").write_text(
                json.dumps(observation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            generated_harness_completed = (
                mode == "main" or (left.returncode == 0 and right.returncode == 0)
            )
            memory_observations_complete = (
                mode != "memory-object-functions"
                or (bool(source_observation.get("memoryObjects"))
                    and bool(target_observation.get("memoryObjects")))
            )
            status = (ValidationStatus.VERIFIED
                      if generated_harness_completed and memory_observations_complete
                      and source_observation == target_observation
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
