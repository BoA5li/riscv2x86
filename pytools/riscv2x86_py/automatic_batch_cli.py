"""Zero-configuration translation, L0/L1 evaluation, and L2 planning entry point."""
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
from .l2_dimensions import L2Dimension
from .l2_validator_resolution import (
    L2BindingKind, L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA, provider_from_dict,
)
from .l3_provider_resolution import provider_from_dict as l3_provider_from_dict

AUTO_INVENTORY_SCHEMA = "riscv2x86.automatic-corpus-inventory.v1"
EXPLICIT_HARNESS_SCHEMA = "riscv2x86.explicit-harness.v1"
PRIVILEGED_BINDING_SCHEMA = "riscv2x86.privileged-evaluation-binding.v1"
_INTEGER_TYPE = re.compile(
    r"^(?:(?:const|volatile) )*(?:u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)$"
)
_INTEGER_POINTER_TYPE = re.compile(
    r"^(?:(?:const|volatile) )*(?:u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)(?: (?:const|volatile))* \*$"
)


def _digest(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + sha256(encoded).hexdigest()


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


def _unwrap_expression(node: object) -> Mapping[str, object] | None:
    """Remove AST wrappers which do not change a returned value's provenance."""
    wrappers = {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr", "ExprWithCleanups"}
    current = node
    while isinstance(current, Mapping) and current.get("kind") in wrappers:
        children = [item for item in current.get("inner", []) if isinstance(item, Mapping)]
        if len(children) != 1:
            return None
        current = children[0]
    return current if isinstance(current, Mapping) else None


def _decl_identity(node: object) -> str:
    current = _unwrap_expression(node)
    if current is None or current.get("kind") != "DeclRefExpr":
        return ""
    referenced = current.get("referencedDecl")
    if not isinstance(referenced, Mapping):
        return ""
    return str(referenced.get("id") or referenced.get("name") or "")


def _asm_output_identity(node: Mapping[str, object]) -> str:
    """Return Clang's first authoritative GNU asm output expression identity.

    Clang orders GCCAsmStmt expression children as outputs followed by inputs.
    A missing identity is deliberately treated as unproved rather than guessed.
    """
    children = [item for item in node.get("inner", []) if isinstance(item, Mapping)]
    return _decl_identity(children[0]) if children else ""


def _counter_return_semantics(function: Mapping[str, object]) -> dict[str, str]:
    """Conservatively classify counter-to-return value flow from compiler AST."""
    asm_nodes = [item for item in _walk_ast(function) if item.get("kind") == "GCCAsmStmt"]
    returns = [item for item in _walk_ast(function) if item.get("kind") == "ReturnStmt"]
    outputs = [_asm_output_identity(item) for item in asm_nodes]
    if len(returns) != 1 or not outputs or any(not item for item in outputs):
        return {"counterReturnSemantics": "unproved", "counterRelationOperator": ""}
    return_children = [item for item in returns[0].get("inner", []) if isinstance(item, Mapping)]
    if len(return_children) != 1:
        return {"counterReturnSemantics": "unproved", "counterRelationOperator": ""}
    expression = _unwrap_expression(return_children[0])
    if expression is None:
        return {"counterReturnSemantics": "unproved", "counterRelationOperator": ""}
    if len(outputs) == 1 and _decl_identity(expression) == outputs[0]:
        return {"counterReturnSemantics": "direct", "counterRelationOperator": ""}
    operator = str(expression.get("opcode", ""))
    operands = [item for item in expression.get("inner", []) if isinstance(item, Mapping)]
    operand_ids = [_decl_identity(item) for item in operands]
    if (len(outputs) == 2 and operator in {">", ">=", "<", "<=", "==", "!="}
            and len(operand_ids) == 2 and set(operand_ids) == set(outputs)):
        return {"counterReturnSemantics": "relational", "counterRelationOperator": operator}
    return {"counterReturnSemantics": "unproved", "counterRelationOperator": ""}


def _l2_operand_boundary_facts(function: Mapping[str, object]) -> dict[str, object]:
    """Export compiler-AST identities needed for bounded automatic L2-A.

    The report-side GNU constraints are joined later.  Here we only establish
    declaration identities and the direct function-boundary value flow.
    """
    params = [item for item in function.get("inner", [])
              if isinstance(item, Mapping) and item.get("kind") == "ParmVarDecl"]
    asm_nodes = [item for item in _walk_ast(function) if item.get("kind") == "GCCAsmStmt"]
    returns = [item for item in _walk_ast(function) if item.get("kind") == "ReturnStmt"]
    declarations = {
        str(item.get("id") or item.get("name") or ""): {
            "name": str(item.get("name") or ""),
            "type": str(item.get("type", {}).get("qualType", ""))
            if isinstance(item.get("type"), Mapping) else "",
        }
        for item in _walk_ast(function)
        if item.get("kind") in {"ParmVarDecl", "VarDecl"}
    }
    reference_counts: dict[str, int] = {}
    for item in _walk_ast(function):
        # Count each compiler DeclRefExpr exactly once.  Calling _decl_identity
        # on its wrapping casts/parentheses counted one source reference more
        # than once and made every direct-return scalar authority inconclusive.
        identity = _decl_identity(item) if item.get("kind") == "DeclRefExpr" else ""
        if identity:
            reference_counts[identity] = reference_counts.get(identity, 0) + 1
    parameter_ids = [str(item.get("id") or item.get("name") or "") for item in params]
    memory_bindings: dict[str, object] = {}
    for parameter, declaration_id in zip(params, parameter_ids):
        raw_type = parameter.get("type")
        type_name = (str(raw_type.get("qualType", ""))
                     if isinstance(raw_type, Mapping) else "")
        match = _INTEGER_POINTER_TYPE.fullmatch(type_name)
        if match and declaration_id:
            # This is the automatic harness's declared object, not an address
            # reconstructed from a runtime sample.  The L1/L2 memory runner
            # allocates this exact bounded object for every invocation.
            pointee = type_name.replace("const", "").replace("volatile", "")
            pointee = pointee.replace("*", "").strip()
            fixed = re.fullmatch(r"u?int(8|16|32|64)_t", pointee)
            alignment = int(fixed.group(1)) // 8 if fixed else 8
            memory_bindings[declaration_id] = {
                "objectIdentity": "parameter-object:" + declaration_id,
                "objectSizeBytes": 32,
                "provenAlignmentBytes": alignment,
                "aliasDomainIdentity": "parameter-alias-domain:" + declaration_id,
                "addressSpaceIdentity": "c.default",
                "volatile": "volatile" in type_name.split(),
                "bindingOrigin": "automatic-aligned-memory-object-harness-v1",
            }
    asm_ids: list[str] = []
    asm_statement_end = -1
    fragment_candidates: list[dict[str, object]] = []
    for asm_index, asm_node in enumerate(asm_nodes):
        candidate_ids = [_decl_identity(item) for item in asm_node.get("inner", [])
                         if isinstance(item, Mapping)]
        source_range = asm_node.get("range")
        begin = source_range.get("begin") if isinstance(source_range, Mapping) else None
        end = source_range.get("end") if isinstance(source_range, Mapping) else None
        begin_offset = begin.get("offset") if isinstance(begin, Mapping) else None
        end_offset = end.get("offset") if isinstance(end, Mapping) else None
        token_length = end.get("tokLen") if isinstance(end, Mapping) else None
        range_complete = all(isinstance(item, int) and not isinstance(item, bool)
                             for item in (begin_offset, end_offset, token_length))
        fragment_candidates.append({
            "schemaVersion": "riscv2x86.compiler-fragment-boundary-candidate.v1",
            "asmIndex": asm_index,
            "beginOffset": begin_offset if range_complete else -1,
            "endOffset": end_offset + token_length if range_complete else -1,
            "asmOperandDeclarationIds": candidate_ids,
            "complete": bool(range_complete and candidate_ids and all(candidate_ids)),
        })
    if len(asm_nodes) == 1:
        asm_ids = [_decl_identity(item) for item in asm_nodes[0].get("inner", [])
                   if isinstance(item, Mapping)]
        source_range = asm_nodes[0].get("range")
        end = source_range.get("end") if isinstance(source_range, Mapping) else None
        if isinstance(end, Mapping):
            offset, token_length = end.get("offset"), end.get("tokLen")
            if (isinstance(offset, int) and not isinstance(offset, bool)
                    and isinstance(token_length, int) and not isinstance(token_length, bool)
                    and token_length > 0):
                asm_statement_end = offset + token_length
    return_id = ""
    if len(returns) == 1:
        children = [item for item in returns[0].get("inner", []) if isinstance(item, Mapping)]
        if len(children) == 1:
            return_id = _decl_identity(children[0])
    function_type = (function.get("type", {}).get("qualType", "")
                     if isinstance(function.get("type"), Mapping) else "")
    returns_void = str(function_type).split(" (", 1)[0].strip() == "void"
    complete = bool(
        len(asm_nodes) == 1 and asm_ids and all(asm_ids)
        and (return_id or returns_void)
        and all(parameter_ids) and all(item in declarations for item in asm_ids)
        and (returns_void or return_id in declarations)
    )
    return {
        "schemaVersion": "riscv2x86.compiler-operand-boundary.v2",
        "complete": complete,
        "parameterDeclarationIds": parameter_ids,
        "asmOperandDeclarationIds": asm_ids,
        "returnDeclarationId": return_id,
        "declarations": declarations,
        "declarationReferenceCounts": reference_counts,
        "asmStatementEndOffset": asm_statement_end,
        "memoryObjectBindings": memory_bindings,
        "fragmentCandidates": fragment_candidates,
    }


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
            function = {"name": name,
                        "functionId": str(node.get("id") or name),
                        "arity": len(params),
                        "returnType": return_type, "parameterTypes": param_types,
                        "pointerParameters": pointer_parameters}
            function.update(_counter_return_semantics(node))
            function["l2OperandBoundary"] = _l2_operand_boundary_facts(node)
            functions.append(function)
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


def _privileged_binding(
    source: Path, source_root: Path, binding_root: Path | None,
    environment_id: str,
) -> dict[str, object] | None:
    """Load one content-addressed L2-C binding; never infer a privileged route."""
    if binding_root is None:
        return None
    relative = source.relative_to(source_root).as_posix()
    path = (binding_root / (relative + ".privileged.json")).resolve()
    if not path.is_file():
        return None
    try:
        path.relative_to(binding_root)
    except ValueError as exc:
        raise ValueError("privileged binding escapes its configuration directory") from exc
    value = json.loads(path.read_text(encoding="utf-8"))
    fields = {"schemaVersion", "sourceRelativePath", "sourceCapability",
              "targetCapability", "runnerConfig", "bindingIdentity"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("privileged binding fields are incomplete or unknown: " + relative)
    payload = dict(value); identity = payload.pop("bindingIdentity")
    if (value.get("schemaVersion") != PRIVILEGED_BINDING_SCHEMA
            or value.get("sourceRelativePath") != relative
            or identity != _identity(payload)):
        raise ValueError("privileged binding identity/source association is invalid: " + relative)
    source_cap = value.get("sourceCapability")
    target_cap = value.get("targetCapability")
    if source_cap not in {"spike", "qemu-system", "controlled-linux-guest", "real-riscv"}:
        raise ValueError("privileged source capability is invalid: " + relative)
    if target_cap not in {"native", "logical-csr-runtime", "system-adapter",
                          "vmm-adapter", "debug-adapter", "emulator-only"}:
        raise ValueError("privileged target capability is invalid: " + relative)
    raw_config = value.get("runnerConfig")
    if not isinstance(raw_config, Mapping):
        raise ValueError("privileged runner config is missing: " + relative)
    config = dict(raw_config)
    declared_environment = config.get("requiredEnvironmentId")
    if declared_environment not in {None, environment_id}:
        raise ValueError("privileged binding environment identity is inconsistent: " + relative)
    config["schemaVersion"] = "riscv2x86.l2-privileged-runner.v2"
    config["requiredEnvironmentId"] = environment_id
    for name in ("initialStatePath", "privilegedManifestPath", "csrRouteContractPath"):
        item = config.get(name)
        if not isinstance(item, str) or not item:
            raise ValueError("privileged runner path is missing: " + name)
        raw_path = Path(item)
        resolved = raw_path.resolve() if raw_path.is_absolute() else (path.parent / raw_path).resolve()
        if not resolved.is_file():
            raise ValueError("privileged runner input is unavailable: " + str(resolved))
        config[name] = str(resolved)
    base = config.get("baseEffectRunner")
    if not isinstance(base, Mapping):
        raise ValueError("privileged base effect runner is missing")
    base = dict(base)
    for name in ("operandAuthoritySidecarPath", "effectAuthoritySidecarPath"):
        item = base.get(name)
        if not isinstance(item, str) or not item:
            raise ValueError("privileged effect sidecar path is missing: " + name)
        raw_path = Path(item)
        base[name] = str(raw_path.resolve() if raw_path.is_absolute()
                         else (path.parent / raw_path).resolve())
    config["baseEffectRunner"] = base
    from .l2_privileged_runner import load_l2_privileged_runner_config
    parsed = load_l2_privileged_runner_config(config)
    source_kind_capability = {
        "spike": "spike", "qemu-system": "qemu-system",
        "controlled-linux-guest": "controlled-linux-guest", "real-riscv": "real-riscv",
    }[parsed.source_runner.runner_kind]
    target_mode_capability = {
        "ordinary-user-process": "native", "logical-csr-runtime": "logical-csr-runtime",
        "system-adapter": "system-adapter", "vmm-adapter": "vmm-adapter",
        "debug-adapter": "debug-adapter", "emulator-only": "emulator-only",
    }[parsed.target_runner.target_execution_mode]
    if source_kind_capability != source_cap or target_mode_capability != target_cap:
        raise ValueError("privileged binding capability does not match runner kind/mode: " + relative)
    return {"identity": identity, "config": config,
            "sourceCapability": source_cap, "targetCapability": target_cap,
            "path": str(path)}


def _explicit_l2_providers(
    source: Path, source_root: Path, provider_root: Path | None,
) -> tuple[tuple[dict[str, object], ...], tuple[str, ...]]:
    """Load a source-bound provider plug-in manifest without guessing bindings."""
    if provider_root is None:
        return (), ()
    relative = source.relative_to(source_root).as_posix()
    path = (provider_root / (relative + ".l2-providers.json")).resolve()
    if not path.is_file():
        return (), ()
    try:
        path.relative_to(provider_root)
    except ValueError as exc:
        raise ValueError("explicit L2 provider manifest escapes its directory") from exc
    value = json.loads(path.read_text(encoding="utf-8"))
    fields = {"schemaVersion", "sourceRelativePath", "sourceDigest",
              "environmentCapabilities",
              "providers", "manifestIdentity"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("explicit L2 provider manifest fields are incomplete or unknown")
    payload = dict(value); identity = payload.pop("manifestIdentity")
    if (value.get("schemaVersion") != L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA
            or value.get("sourceRelativePath") != relative
            or value.get("sourceDigest") != _digest(source)
            or identity != _identity(payload)):
        raise ValueError("explicit L2 provider manifest identity/source binding is invalid")
    raw_providers = value.get("providers")
    environment_capabilities = value.get("environmentCapabilities")
    if not isinstance(raw_providers, list) or not raw_providers:
        raise ValueError("explicit L2 provider manifest requires providers")
    if (not isinstance(environment_capabilities, list)
            or environment_capabilities != sorted(set(environment_capabilities))
            or not all(isinstance(item, str) and item for item in environment_capabilities)):
        raise ValueError("explicit L2 provider environment capabilities are invalid")
    providers = []
    for raw in raw_providers:
        if not isinstance(raw, Mapping):
            raise ValueError("explicit L2 provider descriptor is malformed")
        parsed = provider_from_dict(raw)
        if parsed.binding_kind is not L2BindingKind.EXPLICIT:
            raise ValueError("explicit L2 provider manifest contains a non-explicit provider")
        if parsed.validator_type == "l2-explicit-harness":
            from .l2_explicit_harness import validate_explicit_l2_harness_provider
            validate_explicit_l2_harness_provider(parsed)
        providers.append(dict(raw))
    return tuple(providers), tuple(environment_capabilities)


def prepare_automatic_inventory(
    input_path: str | Path, inventory_directory: str | Path, *, frontend: str | Path,
    timeout: int = 60, allow_functional_fallbacks: bool = False,
    harness_directory: str | Path | None = None,
    privileged_config_directory: str | Path | None = None,
    l2_provider_directory: str | Path | None = None,
    l3_provider_directory: str | Path | None = None,
    atomic_authority_directory: str | Path | None = None,
    csr_authority_directory: str | Path | None = None,
    l3_diagnostic: bool = False,
) -> dict[str, object]:
    root, inventory = Path(input_path).resolve(), Path(inventory_directory).resolve()
    sources = ([root] if root.is_file() else
               sorted(item for item in root.rglob("*.c")
                      if not item.name.endswith(".harness.c")))
    source_root = root.parent if root.is_file() else root
    harness_root = None if harness_directory is None else Path(harness_directory).resolve()
    if harness_root is not None and not harness_root.is_dir():
        raise ValueError("explicit harness directory is unavailable")
    privileged_root = (None if privileged_config_directory is None
                       else Path(privileged_config_directory).resolve())
    if privileged_root is not None and not privileged_root.is_dir():
        raise ValueError("privileged configuration directory is unavailable")
    provider_root = (None if l2_provider_directory is None
                     else Path(l2_provider_directory).resolve())
    if provider_root is not None and not provider_root.is_dir():
        raise ValueError("explicit L2 provider directory is unavailable")
    l3_root = None if l3_provider_directory is None else Path(l3_provider_directory).resolve()
    if l3_root is not None and not l3_root.is_dir():
        raise ValueError("L3 provider directory is unavailable")
    atomic_root = (None if atomic_authority_directory is None
                   else Path(atomic_authority_directory).resolve())
    if atomic_root is not None and not atomic_root.is_dir():
        raise ValueError("atomic authority directory is unavailable")
    csr_root = (None if csr_authority_directory is None
                else Path(csr_authority_directory).resolve())
    if csr_root is not None and not csr_root.is_dir():
        raise ValueError("CSR authority directory is unavailable")
    if l3_diagnostic and l3_root is None:
        raise ValueError("L3 diagnostic profile requires a provider directory")
    if not sources:
        raise ValueError("automatic evaluation found no C sources")
    if inventory.exists():
        raise ValueError("automatic inventory exists; refusing to overwrite")
    frontend_path = Path(frontend).resolve()
    if not frontend_path.is_file() or not frontend_path.stat().st_mode & 0o111:
        raise ValueError("riscv2x86 frontend is unavailable")
    inventory.mkdir(parents=True)
    privileged_environment_id = "auto-rv64gc-privileged-x86-v2"
    privileged_bindings = {
        source: _privileged_binding(source, source_root, privileged_root,
                                    privileged_environment_id)
        for source in sources
    }
    source_capabilities = {"qemu"}
    target_capabilities = {"native"}
    for binding in privileged_bindings.values():
        if binding is not None:
            source_capabilities.add(str(binding["sourceCapability"]))
            target_capabilities.add(str(binding["targetCapability"]))
    environment_id = (privileged_environment_id
                      if any(item is not None for item in privileged_bindings.values())
                      else "auto-rv64gc-qemu-x86-native-v1")
    environment = {"schemaVersion": "riscv2x86.target-environment.v1",
                   "environmentId": environment_id,
                   "sourceIsa": "rv64gc", "sourceAbi": "lp64d",
                   "targetIsa": "x86_64", "targetAbi": "sysv_amd64",
                   "sourceRunnerCapabilities": sorted(source_capabilities),
                   "targetRunnerCapabilities": sorted(target_capabilities),
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
        privileged_binding = privileged_bindings[source]
        explicit_l2_providers, explicit_environment_capabilities = _explicit_l2_providers(
            source, source_root, provider_root,
        )
        l3_binding = None
        if l3_root is not None:
            binding_path = l3_root / (relative + ".l3-providers.json")
            if binding_path.is_file():
                raw_binding = json.loads(binding_path.read_text(encoding="utf-8"))
                required_fields = {"schemaVersion", "sourceRelativePath", "sourceDigest",
                                   "executionProfile", "environmentId", "sourceCapabilities",
                                   "targetCapabilities", "providers", "manifestIdentity"}
                if (not isinstance(raw_binding, Mapping) or set(raw_binding) != required_fields
                        or raw_binding["schemaVersion"] != "riscv2x86.l3-batch-provider-binding.v1"
                        or raw_binding["sourceRelativePath"] != relative
                        or raw_binding["sourceDigest"] != _digest(source)
                        or raw_binding["environmentId"] != environment_id
                        or raw_binding["executionProfile"] != "rv64gc-user-to-x86_64-user"
                        or raw_binding["manifestIdentity"] != _identity({
                            key: value for key, value in raw_binding.items()
                            if key != "manifestIdentity"})):
                    raise ValueError("L3 provider binding is stale or malformed: " + str(binding_path))
                for key in ("sourceCapabilities", "targetCapabilities"):
                    values = raw_binding[key]
                    if (not isinstance(values, list) or values != sorted(set(values))
                            or any(not isinstance(value, str) or not value for value in values)):
                        raise ValueError("L3 provider capabilities are malformed")
                providers = raw_binding["providers"]
                if not isinstance(providers, list) or not providers:
                    raise ValueError("L3 provider list must be nonempty")
                parsed = [l3_provider_from_dict(item) for item in providers]
                ids = [item.provider_id for item in parsed]
                if ids != sorted(set(ids)):
                    raise ValueError("L3 providers must be sorted and unique")
                l3_binding = raw_binding
        try:
            has_main, functions = inspect_entry_points(source)
            program_id = _identity({
                "schemaVersion": "riscv2x86.source-program.v1",
                "sourceRelativePath": relative,
                "sourceDigest": _digest(source),
            })
            for function in functions:
                function["programId"] = program_id
            inspection_error = ""
        except ValueError as exc:
            has_main, functions, inspection_error = False, (), str(exc)
        profile = "functional" if explicit is not None or not inspection_error else "build"
        plan = {"schemaVersion": "riscv2x86.validation-plan.v1",
                "planId": f"auto-{case_id}-{profile}-v1", "profile": profile,
                "sourceRunner": "qemu", "targetRunner": "native", "seed": 20260910,
                "timeoutSeconds": timeout, "runtimeRegistryVersion": "auto-registry-v1",
                "experimentContractId": ""}
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
        if atomic_root is not None:
            atomic_sidecar = atomic_root / (relative + ".atomic-authority.json")
            if atomic_sidecar.is_file():
                translation.extend(("--atomic-authority-sidecar", str(atomic_sidecar)))
        if csr_root is not None:
            csr_sidecar = csr_root / (relative + ".csr-authority.json")
            if csr_sidecar.is_file():
                translation.extend(("--csr-authority-sidecar", str(csr_sidecar)))
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
            l1_config = {
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
                "semanticLimitations": limitations}
            validators["L1"] = {
                "type": "automatic-l1-functional-differential", "config": l1_config,
            }
            def fragment_observation_capable(item):
                """Return whether the runner can resolve this function per fragment.

                A complete boundary proves a single-fragment function immediately.
                A compiler v2 boundary may be incomplete solely because the function
                contains multiple asm statements; in that case the catalogue must
                still expose the fragment-scoped runner.  Authority materialization
                and the validator remain responsible for accepting or rejecting each
                individual fragment.  Ad-hoc or unversioned incomplete boundaries do
                not enable an automatic provider.
                """
                arity = item.get("arity")
                boundary = item.get("l2OperandBoundary")
                return bool(
                    isinstance(arity, int) and not isinstance(arity, bool)
                    and 1 <= arity <= 4
                    and isinstance(boundary, Mapping)
                    and (boundary.get("complete") is True
                         or boundary.get("schemaVersion")
                            == "riscv2x86.compiler-operand-boundary.v2")
                )

            # Providers describe executable observation capability, not proof
            # completeness.  Empty fragmentIds deliberately means that the
            # requirement-driven resolver applies the provider independently to
            # every fragment/profile.  A missing per-fragment authority sidecar
            # still yields inconclusive in the validator; it is never inferred
            # from the function-level boundary.
            l2_operand_possible = any(
                fragment_observation_capable(item) for item in functions)
            def composite_boundary(item):
                boundary = item.get("l2OperandBoundary")
                if not isinstance(boundary, Mapping):
                    return False
                asm_ids, params = (boundary.get("asmOperandDeclarationIds"),
                                   boundary.get("parameterDeclarationIds"))
                return (boundary.get("complete") is True
                        and isinstance(asm_ids, list) and isinstance(params, list)
                        and len(asm_ids) - len(params) > 1)
            l2_composite_possible = any(composite_boundary(item) for item in functions)
            operand_config = {
                    "schemaVersion": "riscv2x86.auto-l2-operand-runner.v1",
                    "sourcePath": "${SOURCE_PATH}", "sourceDigest": "${SOURCE_DIGEST}",
                    "targetPath": "${TARGET_PATH}", "targetDigest": "${TARGET_DIGEST}",
                    "translatedReport": "${TRANSLATED_REPORT}",
                    "functions": list(functions),
                    "workDirectory": "${WORK_DIR}/automatic-l2/${ATTEMPT_ID}",
                    "replayDirectory": "${REPLAY_DIR}/${ATTEMPT_ID}-l2",
                    "timeoutSeconds": timeout, "seed": 20260910,
                    "qemuBinary": shutil.which("qemu-riscv64") or "qemu-riscv64"}
            def effect_config(effect_mode):
                return {
                "schemaVersion": "riscv2x86.auto-l2-effect-runner.v1",
                "mode": effect_mode,
                "sourcePath": "${SOURCE_PATH}", "sourceDigest": "${SOURCE_DIGEST}",
                "targetPath": "${TARGET_PATH}", "targetDigest": "${TARGET_DIGEST}",
                "translatedReport": "${TRANSLATED_REPORT}", "functions": list(functions),
                "workDirectory": "${WORK_DIR}/automatic-l2-effects/${ATTEMPT_ID}",
                "replayDirectory": "${REPLAY_DIR}/${ATTEMPT_ID}-l2-effects",
                "timeoutSeconds": timeout,
                "qemuBinary": shutil.which("qemu-riscv64") or "qemu-riscv64"}
            execution_profiles = ["rv64gc-user-to-x86_64-user"]
            def provider(provider_id, dimensions, patterns, capabilities,
                         validator_type, config, binding_kind="automatic", fragment_ids=()):
                return {
                    "providerId": provider_id,
                    "supportedDimensions": sorted(dimensions),
                    "supportedPatterns": sorted(patterns),
                    "requiredCapabilities": sorted(capabilities),
                    "executionProfiles": execution_profiles,
                    "bindingKind": binding_kind,
                    "validatorType": validator_type,
                    "configSchemaVersion": str(config.get("schemaVersion") or ""),
                    "config": config, "fragmentIds": sorted(fragment_ids),
                }
            l2_providers = []
            l2_environment_capabilities = set(explicit_environment_capabilities)
            if l2_operand_possible:
                l2_environment_capabilities.add("logical_operand_observation")
                l2_providers.append(provider(
                    "automatic-l2-operand-v2", [L2Dimension.LOGICAL_OPERANDS.value],
                    ["branch", "jump", "scalar"],
                    ["logical_operand_observation"],
                    "automatic-l2-operand-differential", operand_config,
                ))
                if l2_composite_possible:
                    l2_environment_capabilities.add("composite_fragment_observation")
                    l2_providers.append(provider(
                        "automatic-l2-composite-operand-v1",
                        [L2Dimension.LOGICAL_OPERANDS.value,
                         L2Dimension.SHELL_SEMANTICS.value], ["composite"],
                        ["composite_fragment_observation", "logical_operand_observation",
                         "shell_observation"],
                        "automatic-l2-operand-differential", operand_config,
                    ))
            if l2_operand_possible:
                l2_environment_capabilities.add("shell_observation")
                l2_providers.append(provider(
                    "automatic-l2-scalar-effect-v2", [L2Dimension.SHELL_SEMANTICS.value],
                    ["scalar"], ["shell_observation"],
                    "automatic-l2-effect-differential",
                    effect_config("scalar-effect-functions"),
                ))
            if l2_operand_possible:
                l2_environment_capabilities.update(("control_flow_observation",
                                                    "shell_observation"))
                l2_providers.append(provider(
                    "automatic-l2-control-flow-v1",
                    [L2Dimension.CONTROL_FLOW.value, L2Dimension.SHELL_SEMANTICS.value],
                    ["branch", "jump"],
                    ["control_flow_observation", "shell_observation"],
                    "automatic-l2-effect-differential",
                    effect_config("control-flow-functions"),
                ))
            if has_memory_objects:
                l2_environment_capabilities.update(("logical_operand_observation",
                                                    "object_relative_memory_observation",
                                                    "shell_observation"))
                l2_providers.append(provider(
                    "automatic-l2-memory-object-v1",
                    [L2Dimension.LOGICAL_OPERANDS.value, L2Dimension.MEMORY_EFFECTS.value,
                     L2Dimension.SHELL_SEMANTICS.value],
                    ["memory_load", "memory_store"],
                    ["logical_operand_observation", "object_relative_memory_observation",
                     "shell_observation"],
                    "automatic-l2-effect-differential",
                    effect_config("memory-object-functions"),
                ))
            if functions and any(item.get("arity") == 0 and item.get("returnType") == "void"
                                 for item in functions):
                l2_environment_capabilities.update(("ordering_observation",
                                                    "shell_observation"))
                l2_providers.append(provider(
                    "automatic-l2-fence-ordering-v1",
                    [L2Dimension.MEMORY_EFFECTS.value, L2Dimension.SHELL_SEMANTICS.value],
                    ["fence"],
                    ["ordering_observation", "shell_observation"],
                    "automatic-l2-effect-differential", effect_config("fence-functions"),
                ))
            if privileged_binding is not None:
                l2_environment_capabilities.update((
                    "privileged_route_selection", "privileged_state_observation",
                ))
                l2_providers.append(provider(
                    "explicit-privileged-" + str(privileged_binding["identity"]),
                    [L2Dimension.PRIVILEGED_STATE.value, L2Dimension.TRAP_SEMANTICS.value],
                    ["privileged_read", "privileged_write"],
                    ["privileged_route_selection", "privileged_state_observation"],
                    "l2-privileged-real-runner",
                    privileged_binding["config"], binding_kind="explicit",
                ))
            # Functional fallbacks use the same executable observation boundary
            # as L1, but close a separately typed runtime-mediated L2 relation.
            # Applicability is profile/capability based, never path/name based.
            if allow_functional_fallbacks:
                l2_environment_capabilities.update((
                    "instruction_visibility", "privileged_state_observation",
                    "shell_observation",
                ))
                functional_relation_config = {
                    "schemaVersion":
                        "riscv2x86.auto-l2-functional-relation-runner.v1",
                    "translatedReport": "${TRANSLATED_REPORT}",
                    "l1Config": {
                        **l1_config,
                        "workDirectory":
                            "${WORK_DIR}/automatic-l2-functional/${ATTEMPT_ID}",
                        "replayDirectory":
                            "${REPLAY_DIR}/${ATTEMPT_ID}-l2-functional",
                    },
                }
                l2_providers.append(provider(
                    "automatic-l2-functional-relation-v1",
                    [L2Dimension.MEMORY_EFFECTS.value,
                     L2Dimension.PRIVILEGED_STATE.value,
                     L2Dimension.SHELL_SEMANTICS.value],
                    ["instruction_visibility_fence", "privileged_read"],
                    ["instruction_visibility", "privileged_state_observation",
                     "shell_observation"],
                    "automatic-l2-functional-relation",
                    functional_relation_config,
                    binding_kind="runtime_adapter",
                ))
            l2_providers.extend(explicit_l2_providers)
            l2_providers.sort(key=lambda item: str(item["providerId"]))
            validators["L2"] = {
                "type": "requirement-driven",
                "config": {
                    "schemaVersion": "riscv2x86.l2-requirement-driven-registry.v3",
                    "requirementManifestPath": "${TRANSLATED_REPORT}.l2-requirements.json",
                    "semanticProfilePath": "${TRANSLATED_REPORT}",
                    "fragmentId": "${FRAGMENT_ID}",
                    # L1 harness mode remains program-level.  L2 selection is
                    # deliberately keyed by the authoritative per-fragment
                    # profile carried by the requirement and resolved plan.
                    "semanticProfileSource": "translated-report",
                    "providerSelectionUnit": "fragment",
                    "environmentCapabilities": sorted(l2_environment_capabilities),
                    "environmentExecutionProfiles": execution_profiles,
                    "executionProfile": "rv64gc-user-to-x86_64-user",
                    "resolvedPlanPath": "${REPLAY_DIR}/${ATTEMPT_ID}-l2-resolved-plan.json",
                    "providers": l2_providers,
                },
            }
            if "L2" in validators:
                profile = "architectural"
                plan["profile"] = profile
                plan["planId"] = f"auto-{case_id}-{profile}-v1"
        if l3_binding is not None:
            if "L2" not in validators or "L1" not in validators:
                raise ValueError("L3 experiment requires registered L0-L2 prerequisites")
            profile = "microarch_diagnostic" if l3_diagnostic else "microarch"
            plan.update(profile=profile, planId=f"auto-{case_id}-{profile}-v1",
                        experimentContractId="resolved-per-fragment")
            validators["L3"] = {"type": "l3-capability-provider-registry", "config": {
                "schemaVersion": "riscv2x86.l3-capability-provider-registry.v1",
                "providers": l3_binding["providers"],
                "executionProfile": l3_binding["executionProfile"],
                "environmentId": l3_binding["environmentId"],
                "sourceCapabilities": l3_binding["sourceCapabilities"],
                "targetCapabilities": l3_binding["targetCapabilities"],
            }}
        _write_json(case_dir / "validation-plan.json", plan)
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
                   "comparisonPolicy": (
                       "riscv2x86.comparison-policy.architectural.v1"
                       if "L2" in validators else "riscv2x86.l1-observable-comparison.v1"
                   ),
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
                        "privilegedBindingIdentity": ("" if privileged_binding is None
                                                       else privileged_binding["identity"]),
                        "privilegedBindingPath": ("" if privileged_binding is None
                                                   else privileged_binding["path"]),
                        "explicitL2ProviderCount": len(explicit_l2_providers),
                        "l3ProviderCount": len(l3_binding["providers"]) if l3_binding else 0,
                        "l3BindingDigest": _digest(binding_path) if l3_binding else "",
                        "validationProfile": profile})
    payload = {"schemaVersion": AUTO_INVENTORY_SCHEMA, "sourceRoot": str(source_root),
               "frontend": str(frontend_path), "programCount": len(entries), "programs": entries,
               "statisticsUnits": {"L1": "program", "L2Requirements": "fragment",
                                    "L2SemanticProfile": "fragment",
                                    "L3Intent": "fragment", "L3Execution": "program/entry/campaign",
                                    "translation": "fragment",
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
    parser.add_argument("--privileged-config-directory",
                        help="directory containing <source>.c.privileged.json bindings")
    parser.add_argument("--l2-provider-directory",
                        help="directory containing <source>.c.l2-providers.json bindings")
    parser.add_argument("--l3-provider-directory",
                        help="directory containing <source>.c.l3-providers.json bindings")
    parser.add_argument("--atomic-authority-directory",
                        help="directory containing <source>.c.atomic-authority.json bindings")
    parser.add_argument("--csr-authority-directory",
                        help="directory containing <source>.c.csr-authority.json bindings")
    parser.add_argument("--l3-diagnostic", action="store_true",
                        help="run explicitly bound target-only experiment diagnostics")
    args = parser.parse_args()
    output = Path(args.output_directory).resolve()
    inventory = output.with_name(output.name + "-inventory")
    try:
        prepare_automatic_inventory(args.input, inventory, frontend=args.frontend,
                                    timeout=args.timeout_seconds,
                                    allow_functional_fallbacks=args.allow_functional_fallbacks,
                                    harness_directory=args.harness_directory,
                                    privileged_config_directory=args.privileged_config_directory,
                                    l2_provider_directory=args.l2_provider_directory,
                                    l3_provider_directory=args.l3_provider_directory,
                                    atomic_authority_directory=args.atomic_authority_directory,
                                    csr_authority_directory=args.csr_authority_directory,
                                    l3_diagnostic=args.l3_diagnostic)
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
