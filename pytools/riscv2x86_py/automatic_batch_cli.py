"""Zero-configuration translation and L0/L1 corpus evaluation entry point."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Mapping

from .batch_evaluation_cli import BATCH_CASE_SCHEMA, BATCH_DESCRIPTOR_NAME, run_batch_evaluation

AUTO_INVENTORY_SCHEMA = "riscv2x86.automatic-corpus-inventory.v1"
EXPLICIT_HARNESS_SCHEMA = "riscv2x86.explicit-harness.v1"
_INTEGER_TYPE = re.compile(
    r"^(?:(?:const|volatile) )*(?:u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)$"
)
_INTEGER_POINTER_TYPE = re.compile(
    r"^(?:(?:const|volatile) )*(?:u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)(?: (?:const|volatile))* \*$"
)


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _sysroot() -> str:
    result = subprocess.run(("riscv64-linux-gnu-gcc", "-print-sysroot"), text=True,
                            capture_output=True, check=False)
    if result.returncode:
        raise ValueError("riscv64-linux-gnu-gcc cannot report a sysroot")
    value = result.stdout.strip()
    return "/usr/riscv64-linux-gnu" if value == "/" and Path("/usr/riscv64-linux-gnu/include").is_dir() else value


def _walk_ast(node: object):
    if not isinstance(node, Mapping):
        return
    yield node
    for child in node.get("inner", []):
        yield from _walk_ast(child)


def inspect_entry_points(source: Path, clang: str = "clang") -> tuple[bool, tuple[dict[str, object], ...]]:
    """Use the compiler AST, never textual `main`/signature guessing."""
    command = (clang, "--target=riscv64-linux-gnu", "--sysroot=" + _sysroot(),
               "-std=gnu11", "-march=rv64gc", "-mabi=lp64d", "-fsyntax-only",
               "-Xclang", "-ast-dump=json", str(source))
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("entry-point AST inspection failed: " + result.stderr.strip())
    root = json.loads(result.stdout)
    functions = []
    has_main = False
    for node in _walk_ast(root):
        if node.get("kind") != "FunctionDecl" or not any(
                isinstance(child, Mapping) and child.get("kind") == "CompoundStmt"
                for child in node.get("inner", [])):
            continue
        location = node.get("loc", {})
        file_name = location.get("file", "") if isinstance(location, Mapping) else ""
        if isinstance(location, Mapping) and location.get("includedFrom"):
            continue
        if file_name and Path(str(file_name)).resolve() != source.resolve():
            continue
        name = node.get("name")
        if name == "main":
            has_main = True; continue
        if not isinstance(name, str) or node.get("storageClass") == "static":
            continue
        qualified = node.get("type", {}).get("qualType", "") if isinstance(node.get("type"), Mapping) else ""
        return_type = str(qualified).split(" (", 1)[0]
        params = [child for child in node.get("inner", [])
                  if isinstance(child, Mapping) and child.get("kind") == "ParmVarDecl"]
        param_types = [str(child.get("type", {}).get("qualType", "")) for child in params]
        safe_scalar = (
            return_type != "void"
            and _INTEGER_TYPE.fullmatch(return_type)
            and len(params) <= 4
            and all(_INTEGER_TYPE.fullmatch(item) for item in param_types)
        )
        pointer_parameters = [
            index for index, item in enumerate(param_types)
            if _INTEGER_POINTER_TYPE.fullmatch(item)
        ]
        safe_memory_object = (
            len(params) <= 3
            and len(pointer_parameters) == 1
            and (return_type == "void" or _INTEGER_TYPE.fullmatch(return_type))
            and all(
                _INTEGER_TYPE.fullmatch(item) or _INTEGER_POINTER_TYPE.fullmatch(item)
                for item in param_types
            )
        )
        safe_void_call = return_type == "void" and not params
        if safe_scalar or safe_memory_object or safe_void_call:
            functions.append({"name": name, "arity": len(params),
                              "returnType": return_type, "parameterTypes": param_types,
                              "pointerParameters": pointer_parameters})
    if not has_main and not functions:
        raise ValueError("no main and no safe externally visible scalar-integer function for L1 harness")
    return has_main, tuple(sorted(functions, key=lambda item: str(item["name"])))


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _explicit_harness(
    source: Path, source_root: Path, harness_root: Path | None,
) -> dict[str, str] | None:
    """Resolve one strict, content-bound common harness sidecar."""
    relative = source.relative_to(source_root)
    candidates = [source.with_suffix(".harness.json")]
    if harness_root is not None:
        candidates.insert(0, harness_root / relative.with_suffix(".harness.json"))
    manifests = [item.resolve() for item in candidates if item.is_file()]
    if len(manifests) > 1:
        raise ValueError("more than one explicit harness manifest applies to " + relative.as_posix())
    if not manifests:
        return None
    manifest = manifests[0]
    value = json.loads(manifest.read_text(encoding="utf-8"))
    expected = {"schemaVersion", "sourceRelativePath", "harnessPath", "inputDomainId"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ValueError("explicit harness fields are invalid: " + str(manifest))
    if value.get("schemaVersion") != EXPLICIT_HARNESS_SCHEMA:
        raise ValueError("explicit harness schema is unsupported: " + str(manifest))
    for name in ("sourceRelativePath", "harnessPath", "inputDomainId"):
        if not isinstance(value.get(name), str) or not str(value[name]).strip():
            raise ValueError("explicit harness " + name + " is invalid: " + str(manifest))
    if value["sourceRelativePath"] != relative.as_posix():
        raise ValueError("explicit harness sourceRelativePath does not match corpus source")
    raw_harness = Path(str(value["harnessPath"]))
    harness = (manifest.parent / raw_harness).resolve()
    if raw_harness.is_absolute() or not harness.is_file():
        raise ValueError("explicit harness path is unsafe or unavailable: " + str(manifest))
    try:
        harness.relative_to(manifest.parent.resolve())
    except ValueError as exc:
        raise ValueError("explicit harness escapes its manifest directory") from exc
    return {
        "manifestPath": str(manifest), "manifestDigest": _digest(manifest),
        "harnessPath": str(harness), "harnessDigest": _digest(harness),
        "inputDomainId": str(value["inputDomainId"]),
    }


def prepare_automatic_inventory(
    input_path: str | Path, inventory_directory: str | Path, *, frontend: str | Path,
    timeout: int = 60, allow_functional_fallbacks: bool = False,
    harness_directory: str | Path | None = None,
) -> dict[str, object]:
    root, inventory = Path(input_path).resolve(), Path(inventory_directory).resolve()
    sources = ([root] if root.is_file() else
               sorted(item for item in root.rglob("*.c")
                      if not item.name.endswith(".harness.c")))
    source_root = root.parent if root.is_file() else root
    harness_root = None if harness_directory is None else Path(harness_directory).resolve()
    if harness_root is not None and not harness_root.is_dir():
        raise ValueError("explicit harness directory is unavailable")
    if not sources:
        raise ValueError("automatic evaluation found no C sources")
    if inventory.exists():
        raise ValueError("automatic inventory exists; refusing to overwrite")
    frontend_path = Path(frontend).resolve()
    if not frontend_path.is_file() or not frontend_path.stat().st_mode & 0o111:
        raise ValueError("riscv2x86 frontend is unavailable")
    inventory.mkdir(parents=True)
    environment = {"schemaVersion": "riscv2x86.target-environment.v1",
                   "environmentId": "auto-rv64gc-qemu-x86-native-v1",
                   "sourceIsa": "rv64gc", "sourceAbi": "lp64d",
                   "targetIsa": "x86_64", "targetAbi": "sysv_amd64",
                   "sourceRunnerCapabilities": ["qemu"],
                   "targetRunnerCapabilities": ["native"],
                   "sanitizerCapabilities": ["asan", "none", "ubsan"],
                   "runtimeIdentity": "riscv2x86-runtime-v1",
                   "loaderIdentity": "linux-elf-loader-v1"}
    _write_json(inventory / "config/target-environment.json", environment)
    entries = []
    for source in sources:
        relative = source.relative_to(source_root).as_posix()
        case_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", relative[:-2].replace("/", "--")).strip("-")
        case_dir = inventory / "cases" / case_id
        explicit = _explicit_harness(source, source_root, harness_root)
        try:
            has_main, functions = inspect_entry_points(source)
            inspection_error = ""
        except ValueError as exc:
            has_main, functions, inspection_error = False, (), str(exc)
        profile = "functional" if explicit is not None or not inspection_error else "build"
        plan = {"schemaVersion": "riscv2x86.validation-plan.v1",
                "planId": f"auto-{case_id}-{profile}-v1", "profile": profile,
                "sourceRunner": "qemu", "targetRunner": "native", "seed": 20260910,
                "timeoutSeconds": timeout, "runtimeRegistryVersion": "auto-registry-v1",
                "experimentContractId": ""}
        _write_json(case_dir / "validation-plan.json", plan)
        has_memory_objects = any(item.get("pointerParameters") for item in functions)
        has_four_argument_function = any(item.get("arity") == 4 for item in functions)
        mode = ("explicit-common-harness" if explicit is not None else
                "main" if has_main else
                "memory-object-functions" if has_memory_objects else
                "branch-domain-functions" if has_four_argument_function else
                "scalar-functions")
        link_kind = "executable" if has_main else "shared_library"
        translation = [sys.executable, "-m", "riscv2x86_py.automatic_translation_command",
                       "--frontend", str(frontend_path),
                       "--source", "${SOURCE_ROOT}/" + relative,
                       "--source-root", "${SOURCE_ROOT}",
                       "--report", "${TRANSLATED_REPORT}"]
        if allow_functional_fallbacks:
            translation.append("--allow-functional-fallbacks")
        validators: dict[str, object] = {
            "L0": {"type": "automatic-l0-build-matrix", "config": {
                "schemaVersion": "riscv2x86.auto-l0-runner.v1",
                "sourcePath": "${SOURCE_PATH}", "sourceDigest": "${SOURCE_DIGEST}",
                "targetPath": "${TARGET_PATH}", "targetDigest": "${TARGET_DIGEST}",
                "workDirectory": "${WORK_DIR}/automatic-l0/${ATTEMPT_ID}",
                "linkKind": link_kind, "timeoutSeconds": timeout}},
        }
        if explicit is not None or not inspection_error:
            limitations = (
                [
                    "memory-order-and-microarchitecture-not-observed-by-l1",
                    "undeclared-memory-and-global-side-effects-not-observed-by-l1",
                ]
                if any(item.get("returnType") == "void" for item in functions)
                else []
            )
            observation_contract = "process-and-declared-return-values-v1"
            dimensions = ["exit_code", "stderr", "stdout", "termination"]
            input_domain = "boundary-and-fixed-random-v1"
            if mode == "memory-object-functions":
                observation_contract = "process-declared-return-and-memory-objects-v1"
                dimensions = ["declared_memory_objects", "exit_code", "stderr", "stdout",
                              "termination"]
                input_domain = "aligned-memory-object-boundary-v1"
                limitations = sorted(set(limitations) | {
                    "aliasing-and-overlap-not-observed-by-automatic-l1",
                    "unaligned-and-out-of-bounds-access-not-observed-by-automatic-l1",
                })
            elif mode == "branch-domain-functions":
                input_domain = "branch-four-argument-boundaries-v1"
                limitations = sorted(set(limitations) | {
                    "control-flow-event-trace-not-observed-by-l1",
                })
            validators["L1"] = {"type": "automatic-l1-functional-differential", "config": {
                "schemaVersion": "riscv2x86.auto-l1-runner.v3", "mode": mode,
                "sourcePath": "${SOURCE_PATH}", "sourceDigest": "${SOURCE_DIGEST}",
                "targetPath": "${TARGET_PATH}", "targetDigest": "${TARGET_DIGEST}",
                "functions": list(functions), "workDirectory": "${WORK_DIR}/automatic-l1/${ATTEMPT_ID}",
                "replayDirectory": "${REPLAY_DIR}/${ATTEMPT_ID}-l1",
                "timeoutSeconds": timeout, "seed": 20260910,
                "qemuBinary": shutil.which("qemu-riscv64") or "qemu-riscv64",
                "harnessPath": "" if explicit is None else explicit["harnessPath"],
                "harnessDigest": "" if explicit is None else explicit["harnessDigest"],
                "harnessManifestPath": "" if explicit is None else explicit["manifestPath"],
                "harnessManifestDigest": "" if explicit is None else explicit["manifestDigest"],
                "inputDomainId": (input_domain if explicit is None
                                  else explicit["inputDomainId"]),
                "observationContract": observation_contract,
                "observableDimensions": dimensions,
                "semanticLimitations": limitations} }
        request = {"schemaVersion": "riscv2x86.evaluation-request.v2",
                   "sourceRoot": str(source_root), "sourceRelativePath": relative,
                   "targetRelativePath": relative,
                   "translatedReport": "translation-work/translated_report.json",
                   "attemptArchive": "translation-work/translated_report.json.attempts.json",
                   "validationPlan": str((case_dir / "validation-plan.json").resolve()),
                   "targetEnvironment": str((inventory / "config/target-environment.json").resolve()),
                   "runtimeRegistryTemplate": {"schemaVersion": "riscv2x86.validation-runtime-registry.v2",
                                               "version": "auto-registry-v1", "validators": validators},
                   "translationArtifacts": {},
                   "sourceBuild": {"artifactId": "source-" + case_id, "artifactKind": "object",
                                   "outputRelativePath": "build/source.rv64.o",
                                   "command": ["riscv64-linux-gnu-gcc", "-std=gnu11", "-O0", "-Wall",
                                               "-Wextra", "-Werror", "-march=rv64gc", "-mabi=lp64d",
                                               "-c", "${SOURCE_PATH}", "-o", "${OUTPUT}"]},
                   "targetBuild": {"artifactId": "target-" + case_id, "artifactKind": link_kind,
                                   "outputRelativePath": "build/target" + (".so" if link_kind == "shared_library" else ".x86_64"),
                                   "command": [sys.executable, "-m", "riscv2x86_py.automatic_build_command",
                                               "--target", "${TARGET_PATH}", "--output", "${OUTPUT}",
                                               "--kind", link_kind]},
                   "translationCommand": translation,
                   "comparisonPolicy": "riscv2x86.l1-observable-comparison.v1",
                   "validationUnit": "program", "validationGroupId": "", "selectedAttemptIds": []}
        _write_json(case_dir / BATCH_DESCRIPTOR_NAME,
                    {"schemaVersion": BATCH_CASE_SCHEMA, "caseId": case_id,
                     "category": "automatic", "request": request})
        entries.append({"caseId": case_id, "sourceRelativePath": relative,
                        "sourceDigest": _digest(source), "hasMain": has_main,
                        "harnessFunctions": list(functions), "inspectionError": inspection_error,
                        "harnessMode": mode,
                        "explicitHarnessManifest": "" if explicit is None else explicit["manifestPath"],
                        "explicitHarnessDigest": "" if explicit is None else explicit["harnessDigest"],
                        "validationProfile": profile})
    payload = {"schemaVersion": AUTO_INVENTORY_SCHEMA, "sourceRoot": str(source_root),
               "frontend": str(frontend_path), "programCount": len(entries), "programs": entries,
               "statisticsUnits": {"L1": "program", "translation": "fragment",
                                    "bootstrapCluster": "program"}}
    _write_json(inventory / "automatic-inventory.json", payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser("riscv2x86-auto-evaluate")
    parser.add_argument("--input", required=True, help="C file or corpus directory")
    parser.add_argument("--frontend", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--allow-functional-fallbacks", action="store_true")
    parser.add_argument("--harness-directory",
                        help="directory containing <source>.harness.json sidecars")
    args = parser.parse_args()
    output = Path(args.output_directory).resolve()
    inventory = output.with_name(output.name + "-inventory")
    try:
        prepare_automatic_inventory(args.input, inventory, frontend=args.frontend,
                                    timeout=args.timeout_seconds,
                                    allow_functional_fallbacks=args.allow_functional_fallbacks,
                                    harness_directory=args.harness_directory)
        result = run_batch_evaluation(inventory / "cases", output, jobs=args.jobs)
    except Exception as exc:
        print(json.dumps({"status": "inconclusive", "reasonCode": "automatic.configuration-error",
                          "detail": f"{type(exc).__name__}: {exc}"}, sort_keys=True))
        return 2
    print(json.dumps({"batchIdentity": result["batchIdentity"], "caseCount": result["caseCount"],
                      "statusCounts": result["statusCounts"], "inventory": str(inventory)}, sort_keys=True))
    return 0 if set(result["statusCounts"]).issubset({"verified"}) else 1


if __name__ == "__main__":
    raise SystemExit(main())
