"""Canonical cross-ISA execution observation schema.

Runners are evidence producers, not schema designers.  This module is the
single JSON contract consumed by L1/L2/L3 comparators and deliberately records
logical objects rather than ABI registers, host addresses, or raw PCs.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from .validation_status import PreservationMode


VALIDATION_OBSERVATION_SCHEMA = "riscv2x86.validation-observation.v1"
_HEX = re.compile(r"^0x[0-9a-f]+$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_FLOAT_WIDTHS = {"f16": 16, "f32": 32, "f64": 64, "f128": 128}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: str, field_name: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ValueError(field_name + " must be a sha256 identity")


@dataclass(frozen=True)
class CanonicalValue:
    """A scalar integer, IEEE floating-point value, or logical pointer."""
    type_name: str
    bits: str = ""
    width_bits: int = 0
    nan_class: str = ""
    exception_flags: tuple[str, ...] = ()
    object_id: str = ""
    offset: int | None = None
    pointee_value: "CanonicalValue | None" = None

    def __post_init__(self) -> None:
        if not self.type_name:
            raise ValueError("canonical value type is required")
        is_pointer = self.type_name == "ptr"
        is_float = self.type_name in _FLOAT_WIDTHS
        if is_pointer:
            if not self.object_id or self.offset is None or self.bits or self.width_bits:
                raise ValueError("pointer values use objectId and offset only")
            return
        expected_width = _FLOAT_WIDTHS.get(self.type_name, self.width_bits)
        if expected_width <= 0 or not _HEX.fullmatch(self.bits):
            raise ValueError("scalar values require explicit hexadecimal bits and width")
        if self.width_bits and self.width_bits != expected_width:
            raise ValueError("scalar width does not match its declared type")
        if int(self.bits, 16) >= (1 << expected_width):
            raise ValueError("scalar bits exceed declared width")
        if len(self.bits) != 2 + ((expected_width + 3) // 4):
            raise ValueError("scalar bits must be zero-padded to declared width")
        if is_float:
            allowed_nan = {"", "finite", "quiet_nan", "signaling_nan", "infinity", "zero", "subnormal"}
            if self.nan_class not in allowed_nan:
                raise ValueError("floating-point nanClass is invalid")
        elif self.nan_class or self.exception_flags:
            raise ValueError("integer values cannot carry floating-point metadata")
        if tuple(sorted(set(self.exception_flags))) != self.exception_flags:
            raise ValueError("floating-point exception flags must be unique and sorted")

    def to_dict(self) -> dict[str, object]:
        if self.type_name == "ptr":
            value: dict[str, object] = {"type": "ptr", "objectId": self.object_id, "offset": self.offset}
            if self.pointee_value is not None:
                value["pointeeValue"] = self.pointee_value.to_dict()
            return value
        value = {"type": self.type_name, "bits": self.bits}
        if self.type_name in _FLOAT_WIDTHS:
            value["nanClass"] = self.nan_class or "finite"
            value["exceptionFlags"] = list(self.exception_flags)
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "CanonicalValue":
        type_name = str(value.get("type", ""))
        if type_name == "ptr":
            pointee = value.get("pointeeValue")
            return cls(
                type_name="ptr", object_id=str(value.get("objectId", "")),
                offset=value.get("offset") if isinstance(value.get("offset"), int) else None,
                pointee_value=cls.from_dict(pointee) if isinstance(pointee, Mapping) else None,
            )
        width = _FLOAT_WIDTHS.get(type_name)
        if width is None:
            digits = re.search(r"(\d+)$", type_name)
            width = int(digits.group(1)) if digits else 0
        return cls(
            type_name=type_name, bits=str(value.get("bits", "")), width_bits=width,
            nan_class=str(value.get("nanClass", "")),
            exception_flags=tuple(sorted(set(map(str, value.get("exceptionFlags", ()))))),
        )


@dataclass(frozen=True)
class TextObservation:
    normalized_text: str
    sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.sha256, "text sha256")
        if self.sha256 != _sha256_text(self.normalized_text):
            raise ValueError("text sha256 does not match normalized text")

    def to_dict(self) -> dict[str, str]:
        return {"text": self.normalized_text, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "TextObservation":
        return cls(str(value.get("text", "")), str(value.get("sha256", "")))


@dataclass(frozen=True)
class ExecutionResult:
    return_value: CanonicalValue | None
    exit_code: int
    stdout: TextObservation
    stderr: TextObservation
    exported_state: tuple[tuple[str, CanonicalValue], ...] = ()
    files: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.exit_code, int):
            raise ValueError("exit code must be an integer")
        if tuple(sorted(self.exported_state)) != self.exported_state or len(dict(self.exported_state)) != len(self.exported_state):
            raise ValueError("exported state must be unique and sorted")
        if tuple(sorted(self.files)) != self.files or len(dict(self.files)) != len(self.files):
            raise ValueError("file observations must be unique and sorted")
        for _, digest in self.files:
            _require_sha256(digest, "file digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "returnValue": None if self.return_value is None else self.return_value.to_dict(),
            "exitCode": self.exit_code,
            "stdout": self.stdout.normalized_text, "stdoutSha256": self.stdout.sha256,
            "stderr": self.stderr.normalized_text, "stderrSha256": self.stderr.sha256,
            "exportedState": {key: value.to_dict() for key, value in self.exported_state},
            "files": dict(self.files),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ExecutionResult":
        return cls(
            return_value=CanonicalValue.from_dict(value["returnValue"]) if isinstance(value.get("returnValue"), Mapping) else None,
            exit_code=value.get("exitCode") if isinstance(value.get("exitCode"), int) else -1,
            stdout=TextObservation(str(value.get("stdout", "")), str(value.get("stdoutSha256", ""))),
            stderr=TextObservation(str(value.get("stderr", "")), str(value.get("stderrSha256", ""))),
            exported_state=tuple(sorted((str(key), CanonicalValue.from_dict(item)) for key, item in dict(value.get("exportedState", {})).items() if isinstance(item, Mapping))),
            files=tuple(sorted((str(key), str(item)) for key, item in dict(value.get("files", {})).items())),
        )


@dataclass(frozen=True)
class LogicalOperandObservation:
    operand_id: str
    access: str
    before: CanonicalValue | None
    after: CanonicalValue | None
    tied_to_operand_id: str = ""
    early_clobber: bool = False
    fixed_register_constraint: str = ""

    def __post_init__(self) -> None:
        if not self.operand_id or self.access not in {"input", "output", "read_write"}:
            raise ValueError("logical operand identity/access is invalid")
        if self.access == "input" and self.after is not None:
            raise ValueError("input operand cannot have an after value")
        if self.access == "output" and self.before is not None:
            raise ValueError("output operand cannot have a before value")

    def to_dict(self) -> dict[str, object]:
        return {"operandId": self.operand_id, "access": self.access,
                "before": None if self.before is None else self.before.to_dict(),
                "after": None if self.after is None else self.after.to_dict(),
                "tiedToOperandId": self.tied_to_operand_id,
                "earlyClobber": self.early_clobber,
                "fixedRegisterConstraint": self.fixed_register_constraint}


@dataclass(frozen=True)
class MemoryObjectObservation:
    object_id: str
    size_bytes: int
    content_digest: str
    accesses: tuple[tuple[int, str, int, int, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.object_id or self.size_bytes < 0:
            raise ValueError("memory object identity/size is invalid")
        _require_sha256(self.content_digest, "memory content digest")
        for offset, access, size, alignment, atomicity in self.accesses:
            if offset < 0 or size <= 0 or alignment <= 0 or access not in {"read", "write", "read_write"} or not atomicity:
                raise ValueError("memory access is invalid")

    def to_dict(self) -> dict[str, object]:
        return {"objectId": self.object_id, "sizeBytes": self.size_bytes,
                "contentDigest": self.content_digest,
                "accesses": [{"offset": offset, "access": access, "size": size,
                              "alignment": alignment, "atomicity": atomicity}
                             for offset, access, size, alignment, atomicity in self.accesses]}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "MemoryObjectObservation":
        accesses = []
        for item in value.get("accesses", ()):
            if not isinstance(item, Mapping):
                raise ValueError("memory access must be an object")
            accesses.append((
                item.get("offset") if isinstance(item.get("offset"), int) else -1,
                str(item.get("access", "")), item.get("size") if isinstance(item.get("size"), int) else 0,
                item.get("alignment") if isinstance(item.get("alignment"), int) else 0,
                str(item.get("atomicity", "")),
            ))
        return cls(str(value.get("objectId", "")), value.get("sizeBytes") if isinstance(value.get("sizeBytes"), int) else -1,
                   str(value.get("contentDigest", "")), tuple(accesses))


@dataclass(frozen=True)
class ExecutionObservation:
    test_id: str
    fragment_ids: tuple[str, ...]
    runner: str
    runner_version: str
    compiler: str
    compiler_version: str
    optimization: str
    sanitizer: str
    source_execution_profile: str
    target_execution_mode: str
    runtime_version: str
    initial_state_identity: str
    preservation_mode: PreservationMode
    result: ExecutionResult
    logical_operands: tuple[LogicalOperandObservation, ...]
    memory_objects: tuple[MemoryObjectObservation, ...]
    control_flow: tuple[tuple[str, str], ...]
    traps: tuple[tuple[str, str], ...]
    privileged_state: tuple[tuple[str, str], ...]
    external_events: tuple[tuple[str, str], ...]
    ignored_state: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    schema_version: str = VALIDATION_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_OBSERVATION_SCHEMA:
            raise ValueError("observation schema version is unsupported")
        if not all((self.test_id, self.runner, self.runner_version, self.compiler,
                    self.compiler_version, self.source_execution_profile,
                    self.target_execution_mode, self.runtime_version,
                    self.initial_state_identity)):
            raise ValueError("observation provenance is incomplete")
        if tuple(sorted(set(self.fragment_ids))) != self.fragment_ids:
            raise ValueError("fragment IDs must be unique and sorted")
        if tuple(item.operand_id for item in self.logical_operands) != tuple(sorted(item.operand_id for item in self.logical_operands)):
            raise ValueError("logical operands must be sorted by logical operand ID")
        if len({item.operand_id for item in self.logical_operands}) != len(self.logical_operands):
            raise ValueError("logical operand IDs must be unique")
        if tuple(item.object_id for item in self.memory_objects) != tuple(sorted(item.object_id for item in self.memory_objects)):
            raise ValueError("memory objects must be sorted by object ID")
        if len({item.object_id for item in self.memory_objects}) != len(self.memory_objects):
            raise ValueError("memory object IDs must be unique")
        for name in ("control_flow", "traps", "privileged_state", "external_events", "provenance"):
            values = getattr(self, name)
            if tuple(sorted(values)) != values or len(dict(values)) != len(values):
                raise ValueError(name + " must be unique and stably sorted")
        if tuple(sorted(set(self.ignored_state))) != self.ignored_state:
            raise ValueError("ignored state must be unique and sorted")
        for required in ("artifactDigest", "translationManifestDigest", "sourceModelIdentity",
                         "runtimeContract", "runtimeContractVersion", "runnerCommandProfile",
                         "testSeed", "generatedInputsIdentity", "comparisonPolicy"):
            if not dict(self.provenance).get(required):
                raise ValueError("observation provenance is missing " + required)
        provenance = dict(self.provenance)
        for field_name in ("artifactDigest", "translationManifestDigest", "generatedInputsIdentity"):
            _require_sha256(provenance[field_name], "provenance." + field_name)

    @property
    def identity(self) -> str:
        return "sha256:" + sha256(_canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version, "testId": self.test_id,
            "fragmentIds": list(self.fragment_ids), "runner": self.runner,
            "runnerVersion": self.runner_version, "compiler": self.compiler,
            "compilerVersion": self.compiler_version, "optimization": self.optimization,
            "sanitizer": self.sanitizer, "sourceExecutionProfile": self.source_execution_profile,
            "targetExecutionMode": self.target_execution_mode, "runtimeVersion": self.runtime_version,
            "initialStateIdentity": self.initial_state_identity,
            "preservationMode": self.preservation_mode.value, "result": self.result.to_dict(),
            "logicalOperands": [item.to_dict() for item in self.logical_operands],
            "memoryObjects": [item.to_dict() for item in self.memory_objects],
            "controlFlow": dict(self.control_flow), "traps": dict(self.traps),
            "privilegedState": dict(self.privileged_state), "externalEvents": dict(self.external_events),
            "ignoredState": list(self.ignored_state), "provenance": dict(self.provenance),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ExecutionObservation":
        fields = {
            "schemaVersion", "testId", "fragmentIds", "runner", "runnerVersion",
            "compiler", "compilerVersion", "optimization", "sanitizer",
            "sourceExecutionProfile", "targetExecutionMode", "runtimeVersion",
            "initialStateIdentity", "preservationMode", "result", "logicalOperands",
            "memoryObjects", "controlFlow", "traps", "privilegedState",
            "externalEvents", "ignoredState", "provenance",
        }
        if set(value) != fields:
            raise ValueError("observation fields are incomplete or unknown")
        if value.get("schemaVersion") != VALIDATION_OBSERVATION_SCHEMA:
            raise ValueError("observation schema version is unsupported")
        operands = []
        for item in value.get("logicalOperands", ()):
            if not isinstance(item, Mapping):
                raise ValueError("logical operand must be an object")
            before, after = item.get("before"), item.get("after")
            operands.append(LogicalOperandObservation(
                operand_id=str(item.get("operandId", "")), access=str(item.get("access", "")),
                before=CanonicalValue.from_dict(before) if isinstance(before, Mapping) else None,
                after=CanonicalValue.from_dict(after) if isinstance(after, Mapping) else None,
                tied_to_operand_id=str(item.get("tiedToOperandId", "")),
                early_clobber=bool(item.get("earlyClobber", False)),
                fixed_register_constraint=str(item.get("fixedRegisterConstraint", "")),
            ))
        def stable_mapping(name: str) -> tuple[tuple[str, str], ...]:
            source = value.get(name, {})
            if not isinstance(source, Mapping):
                raise ValueError(name + " must be an object")
            return tuple(sorted((str(key), str(item)) for key, item in source.items()))
        return cls(
            test_id=str(value.get("testId", "")),
            fragment_ids=tuple(sorted(set(map(str, value.get("fragmentIds", ()))))),
            runner=str(value.get("runner", "")), runner_version=str(value.get("runnerVersion", "")),
            compiler=str(value.get("compiler", "")), compiler_version=str(value.get("compilerVersion", "")),
            optimization=str(value.get("optimization", "")), sanitizer=str(value.get("sanitizer", "")),
            source_execution_profile=str(value.get("sourceExecutionProfile", "")),
            target_execution_mode=str(value.get("targetExecutionMode", "")),
            runtime_version=str(value.get("runtimeVersion", "")), initial_state_identity=str(value.get("initialStateIdentity", "")),
            preservation_mode=PreservationMode(str(value.get("preservationMode", ""))),
            result=ExecutionResult.from_dict(value.get("result", {})),
            logical_operands=tuple(sorted(operands, key=lambda item: item.operand_id)),
            memory_objects=tuple(sorted((MemoryObjectObservation.from_dict(item) for item in value.get("memoryObjects", ()) if isinstance(item, Mapping)), key=lambda item: item.object_id)),
            control_flow=stable_mapping("controlFlow"), traps=stable_mapping("traps"),
            privileged_state=stable_mapping("privilegedState"), external_events=stable_mapping("externalEvents"),
            ignored_state=tuple(sorted(set(map(str, value.get("ignoredState", ()))))),
            provenance=stable_mapping("provenance"), schema_version=str(value.get("schemaVersion", "")),
        )


def validation_identity(
    *, source_artifact_hash: str, target_artifact_hash: str,
    translation_manifest_hash: str, source_model_identity: str,
    runtime_contract: str, runtime_version: str,
    source_observation: ExecutionObservation | None,
    target_observation: ExecutionObservation | None,
    comparison_policy: str,
) -> str:
    """Stable identity for a cross-ISA validation decision."""
    for name, value in (("source artifact hash", source_artifact_hash),
                        ("target artifact hash", target_artifact_hash),
                        ("translation manifest hash", translation_manifest_hash)):
        _require_sha256(value, name)
    if not all((source_model_identity, runtime_contract, runtime_version, comparison_policy)):
        raise ValueError("validation identity inputs are incomplete")
    payload = {
        "schemaVersion": VALIDATION_OBSERVATION_SCHEMA,
        "sourceArtifactHash": source_artifact_hash, "targetArtifactHash": target_artifact_hash,
        "translationManifestHash": translation_manifest_hash,
        "sourceModelIdentity": source_model_identity, "runtimeContract": runtime_contract,
        "runtimeVersion": runtime_version, "comparisonPolicy": comparison_policy,
        "sourceObservation": None if source_observation is None else source_observation.to_dict(),
        "targetObservation": None if target_observation is None else target_observation.to_dict(),
    }
    return "sha256:" + sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
