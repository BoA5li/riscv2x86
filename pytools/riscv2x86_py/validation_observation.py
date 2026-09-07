"""Versioned L1 summaries and L2 ordered cross-ISA semantic traces.

Parsing is deliberately non-repairing: producers must emit canonical v2 data.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from .validation_status import PreservationMode

VALIDATION_OBSERVATION_SCHEMA = "riscv2x86.validation-observation.v2"
RUNNER_COMMAND_PROFILE_SCHEMA = "riscv2x86.runner-command-profile.v1"
OBSERVATION_CANONICALIZER_VERSION = "riscv2x86.observation-canonicalizer.v1"
_HEX = re.compile(r"^0x[0-9a-f]+$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_FLOAT_WIDTHS = {"f16": 16, "f32": 32, "f64": 64, "f128": 128}
_EVENT_KINDS = {"read_operand", "write_operand", "read_memory", "write_memory",
                "branch", "call", "return", "trap", "fence", "atomic",
                "external", "csr_read", "csr_write", "privilege_transition",
                "privileged_state"}
_MEMORY_ORDERS = {"not_applicable", "relaxed", "consume", "acquire", "release",
                  "acq_rel", "seq_cst", "compiler", "hardware"}
_ATOMICITIES = {"none", "atomic", "lr_sc", "amo", "lock_prefixed"}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode()).hexdigest()


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(label + " must be a sha256 identity")


def _fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(label + " fields are incomplete or unknown")


def _str(value: Mapping[str, object], name: str, label: str, empty: bool = False) -> str:
    item = value.get(name)
    if not isinstance(item, str) or (not empty and not item):
        raise ValueError(f"{label}.{name} must be a string")
    return item


def _int(value: Mapping[str, object], name: str, label: str) -> int:
    item = value.get(name)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{label}.{name} must be an integer")
    return item


def _strs(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(label + " must be a string array")
    return tuple(value)


def _canonical_set(value: tuple[str, ...], label: str) -> None:
    if tuple(sorted(set(value))) != value:
        raise ValueError(label + " must already be unique and canonically sorted")


@dataclass(frozen=True)
class CanonicalValue:
    type_name: str
    bits: str = ""
    width_bits: int = 0
    nan_class: str = ""
    exception_flags: tuple[str, ...] = ()
    object_id: str = ""
    offset: int | None = None
    pointee_value: "CanonicalValue | None" = None

    def __post_init__(self) -> None:
        if self.type_name == "ptr":
            if not self.object_id or self.offset is None or self.bits or self.width_bits:
                raise ValueError("pointer values use objectId and offset only")
            return
        width = _FLOAT_WIDTHS.get(self.type_name, self.width_bits)
        if not self.type_name or width <= 0 or not _HEX.fullmatch(self.bits):
            raise ValueError("scalar value requires a type, width and hexadecimal bits")
        if self.width_bits != width or int(self.bits, 16) >= 1 << width:
            raise ValueError("scalar value exceeds its declared width")
        if len(self.bits) != 2 + ((width + 3) // 4):
            raise ValueError("scalar bits must be zero-padded")
        if self.type_name in _FLOAT_WIDTHS:
            if self.nan_class not in {"finite", "quiet_nan", "signaling_nan", "infinity", "zero", "subnormal"}:
                raise ValueError("floating-point class is invalid")
            _canonical_set(self.exception_flags, "floating-point flags")
        elif self.nan_class or self.exception_flags:
            raise ValueError("integer values cannot carry float metadata")

    def to_dict(self) -> dict[str, object]:
        if self.type_name == "ptr":
            result: dict[str, object] = {"type": "ptr", "objectId": self.object_id, "offset": self.offset}
            if self.pointee_value is not None: result["pointeeValue"] = self.pointee_value.to_dict()
            return result
        result = {"type": self.type_name, "bits": self.bits, "widthBits": self.width_bits}
        if self.type_name in _FLOAT_WIDTHS:
            result.update(nanClass=self.nan_class, exceptionFlags=list(self.exception_flags))
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "CanonicalValue":
        kind = _str(value, "type", "value")
        if kind == "ptr":
            if not {"type", "objectId", "offset"}.issubset(value) or not set(value).issubset({"type", "objectId", "offset", "pointeeValue"}):
                raise ValueError("pointer fields are invalid")
            nested = value.get("pointeeValue")
            if nested is not None and not isinstance(nested, Mapping): raise ValueError("pointeeValue is invalid")
            return cls("ptr", object_id=_str(value, "objectId", "value"), offset=_int(value, "offset", "value"),
                       pointee_value=cls.from_dict(nested) if isinstance(nested, Mapping) else None)
        expected = {"type", "bits", "widthBits"}
        if kind in _FLOAT_WIDTHS: expected |= {"nanClass", "exceptionFlags"}
        _fields(value, expected, "canonical value")
        return cls(kind, _str(value, "bits", "value"), _int(value, "widthBits", "value"),
                   _str(value, "nanClass", "value") if kind in _FLOAT_WIDTHS else "",
                   _strs(value.get("exceptionFlags"), "exceptionFlags") if kind in _FLOAT_WIDTHS else ())


@dataclass(frozen=True)
class TextObservation:
    normalized_text: str
    sha256: str
    def __post_init__(self) -> None:
        _require_digest(self.sha256, "text digest")
        if self.sha256 != _digest(self.normalized_text): raise ValueError("text digest mismatch")


@dataclass(frozen=True)
class ToolIdentity:
    tool_id: str
    version: str
    binary_digest: str
    def __post_init__(self) -> None:
        if not self.tool_id or not self.version: raise ValueError("tool identity is incomplete")
        _require_digest(self.binary_digest, "tool binary digest")
    def to_dict(self) -> dict[str, str]:
        return {"id": self.tool_id, "version": self.version, "binaryDigest": self.binary_digest}
    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ToolIdentity":
        _fields(value, {"id", "version", "binaryDigest"}, "tool identity")
        return cls(_str(value, "id", "tool"), _str(value, "version", "tool"), _str(value, "binaryDigest", "tool"))


@dataclass(frozen=True)
class RunnerCommandProfile:
    profile_id: str
    argv_digest: str
    schema_version: str = RUNNER_COMMAND_PROFILE_SCHEMA
    def __post_init__(self) -> None:
        if self.schema_version != RUNNER_COMMAND_PROFILE_SCHEMA or not self.profile_id:
            raise ValueError("runner command profile is invalid")
        _require_digest(self.argv_digest, "runner argv digest")
    def to_dict(self) -> dict[str, str]:
        return {"schemaVersion": self.schema_version, "profileId": self.profile_id, "argvDigest": self.argv_digest}
    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "RunnerCommandProfile":
        _fields(value, {"schemaVersion", "profileId", "argvDigest"}, "runner command profile")
        return cls(_str(value, "profileId", "command"), _str(value, "argvDigest", "command"),
                   _str(value, "schemaVersion", "command"))


@dataclass(frozen=True)
class ExecutionResult:
    return_value: CanonicalValue | None
    exit_code: int
    stdout: TextObservation
    stderr: TextObservation
    exported_state: tuple[tuple[str, CanonicalValue], ...] = ()
    files: tuple[tuple[str, str], ...] = ()
    def __post_init__(self) -> None:
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int): raise ValueError("exit code is invalid")
        for values, label in ((self.exported_state, "exported state"), (self.files, "files")):
            keys = tuple(x[0] for x in values)
            if tuple(sorted(set(keys))) != keys: raise ValueError(label + " must be unique and sorted")
        for _, digest in self.files: _require_digest(digest, "file digest")
    def to_dict(self) -> dict[str, object]:
        return {"returnValue": None if self.return_value is None else self.return_value.to_dict(), "exitCode": self.exit_code,
                "stdout": {"text": self.stdout.normalized_text, "sha256": self.stdout.sha256},
                "stderr": {"text": self.stderr.normalized_text, "sha256": self.stderr.sha256},
                "exportedState": [{"name": k, "value": v.to_dict()} for k, v in self.exported_state],
                "files": [{"path": k, "sha256": v} for k, v in self.files]}
    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ExecutionResult":
        _fields(value, {"returnValue", "exitCode", "stdout", "stderr", "exportedState", "files"}, "execution result")
        def text(name: str) -> TextObservation:
            raw = value.get(name)
            if not isinstance(raw, Mapping): raise ValueError(name + " must be an object")
            _fields(raw, {"text", "sha256"}, name)
            return TextObservation(_str(raw, "text", name, True), _str(raw, "sha256", name))
        exported, files = value.get("exportedState"), value.get("files")
        if not isinstance(exported, list) or not isinstance(files, list): raise ValueError("result collections must be arrays")
        eout, fout = [], []
        for raw in exported:
            if not isinstance(raw, Mapping): raise ValueError("exported state entry is invalid")
            _fields(raw, {"name", "value"}, "exported state")
            val = raw.get("value")
            if not isinstance(val, Mapping): raise ValueError("exported state value is invalid")
            eout.append((_str(raw, "name", "state"), CanonicalValue.from_dict(val)))
        for raw in files:
            if not isinstance(raw, Mapping): raise ValueError("file entry is invalid")
            _fields(raw, {"path", "sha256"}, "file")
            fout.append((_str(raw, "path", "file"), _str(raw, "sha256", "file")))
        ret = value.get("returnValue")
        if ret is not None and not isinstance(ret, Mapping): raise ValueError("returnValue is invalid")
        return cls(CanonicalValue.from_dict(ret) if isinstance(ret, Mapping) else None, _int(value, "exitCode", "result"),
                   text("stdout"), text("stderr"), tuple(eout), tuple(fout))


@dataclass(frozen=True)
class LogicalOperandObservation:
    fragment_id: str
    operand_index: int
    operand_name: str
    operand_id: str
    access: str
    width_bits: int
    signedness: str
    escaped: bool
    shell_fact_identity: str
    before: CanonicalValue | None
    after: CanonicalValue | None
    tied_to_operand_id: str = ""
    early_clobber: bool = False
    fixed_register_constraint: str = ""

    def __post_init__(self) -> None:
        if not self.fragment_id or self.operand_index < 0 or not self.operand_name or not self.operand_id:
            raise ValueError("logical operand identity is incomplete")
        if self.access not in {"input", "output", "read_write"} or self.width_bits <= 0:
            raise ValueError("logical operand access/width is invalid")
        if self.signedness not in {"signed", "unsigned", "not_applicable"}:
            raise ValueError("logical operand signedness is invalid")
        if not isinstance(self.escaped, bool): raise ValueError("operand escaped must be boolean")
        _require_digest(self.shell_fact_identity, "operand shell fact identity")
        if self.access == "input" and (self.before is None or self.after is not None):
            raise ValueError("input operand requires only a before value")
        if self.access == "output" and (self.before is not None or self.after is None):
            raise ValueError("output operand requires only an after value")
        if self.access == "read_write" and (self.before is None or self.after is None):
            raise ValueError("read-write operand requires before and after values")

    def to_dict(self) -> dict[str, object]:
        return {"fragmentId": self.fragment_id, "operandIndex": self.operand_index,
                "operandName": self.operand_name, "operandId": self.operand_id,
                "access": self.access, "widthBits": self.width_bits,
                "signedness": self.signedness, "escaped": self.escaped,
                "shellFactIdentity": self.shell_fact_identity,
                "before": None if self.before is None else self.before.to_dict(),
                "after": None if self.after is None else self.after.to_dict(),
                "tiedToOperandId": self.tied_to_operand_id, "earlyClobber": self.early_clobber,
                "fixedRegisterConstraint": self.fixed_register_constraint}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "LogicalOperandObservation":
        _fields(value, {"fragmentId", "operandIndex", "operandName", "operandId", "access", "widthBits",
                        "signedness", "escaped", "shellFactIdentity", "before", "after",
                        "tiedToOperandId", "earlyClobber", "fixedRegisterConstraint"}, "logical operand")
        before, after = value.get("before"), value.get("after")
        if (before is not None and not isinstance(before, Mapping)) or (after is not None and not isinstance(after, Mapping)):
            raise ValueError("operand values are invalid")
        escaped, early = value.get("escaped"), value.get("earlyClobber")
        if not isinstance(escaped, bool) or not isinstance(early, bool): raise ValueError("operand boolean facts are invalid")
        return cls(_str(value, "fragmentId", "operand"), _int(value, "operandIndex", "operand"),
                   _str(value, "operandName", "operand"), _str(value, "operandId", "operand"),
                   _str(value, "access", "operand"), _int(value, "widthBits", "operand"),
                   _str(value, "signedness", "operand"), escaped, _str(value, "shellFactIdentity", "operand"),
                   CanonicalValue.from_dict(before) if isinstance(before, Mapping) else None,
                   CanonicalValue.from_dict(after) if isinstance(after, Mapping) else None,
                   _str(value, "tiedToOperandId", "operand", True), early,
                   _str(value, "fixedRegisterConstraint", "operand", True))


@dataclass(frozen=True)
class MemoryObjectObservation:
    object_id: str
    size_bytes: int
    content_digest: str
    def __post_init__(self) -> None:
        if not self.object_id or self.size_bytes < 0: raise ValueError("memory object is invalid")
        _require_digest(self.content_digest, "memory content digest")
    def to_dict(self) -> dict[str, object]:
        return {"objectId": self.object_id, "sizeBytes": self.size_bytes, "contentDigest": self.content_digest}
    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "MemoryObjectObservation":
        _fields(value, {"objectId", "sizeBytes", "contentDigest"}, "memory object")
        return cls(_str(value, "objectId", "memory"), _int(value, "sizeBytes", "memory"),
                   _str(value, "contentDigest", "memory"))


@dataclass(frozen=True)
class SemanticEvent:
    event_id: str
    sequence: int
    fragment_id: str
    kind: str
    subject_id: str
    value: CanonicalValue | None
    object_id: str
    offset: int | None
    access_size: int
    alignment: int
    atomicity: str
    memory_order: str
    branch_taken: bool | None
    target_id: str
    detail: str
    ordering_predecessors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.event_id or self.sequence < 0 or not self.fragment_id or self.kind not in _EVENT_KINDS:
            raise ValueError("semantic event identity/kind is invalid")
        _canonical_set(self.ordering_predecessors, "ordering predecessors")
        memory = self.kind in {"read_memory", "write_memory", "atomic"}
        if memory:
            if not self.object_id or self.offset is None or self.offset < 0 or self.access_size <= 0 or self.alignment <= 0:
                raise ValueError("memory event coordinates are invalid")
            if self.atomicity not in _ATOMICITIES or self.memory_order not in _MEMORY_ORDERS or self.value is None:
                raise ValueError("memory event value/ordering is invalid")
            if ((self.atomicity == "none" and self.memory_order not in {"not_applicable", "relaxed"}) or
                    (self.atomicity != "none" and self.memory_order == "not_applicable") or
                    self.kind == "atomic" and self.atomicity == "none"):
                raise ValueError("memory order and atomicity are inconsistent")
        elif self.object_id or self.offset is not None or self.access_size or self.alignment:
            raise ValueError("non-memory event cannot carry memory coordinates")
        if self.kind == "fence":
            if self.memory_order not in _MEMORY_ORDERS - {"not_applicable"}:
                raise ValueError("fence event requires an explicit ordering")
        elif not memory and self.memory_order:
            raise ValueError("memory order is only valid on memory or fence events")
        if (self.kind == "branch") != isinstance(self.branch_taken, bool):
            raise ValueError("branch taken fact is present on the wrong event kind")

    def to_dict(self) -> dict[str, object]:
        return {"eventId": self.event_id, "sequence": self.sequence, "fragmentId": self.fragment_id,
                "kind": self.kind, "subjectId": self.subject_id,
                "value": None if self.value is None else self.value.to_dict(), "objectId": self.object_id,
                "offset": self.offset, "accessSize": self.access_size, "alignment": self.alignment,
                "atomicity": self.atomicity, "memoryOrder": self.memory_order,
                "branchTaken": self.branch_taken, "targetId": self.target_id, "detail": self.detail,
                "orderingPredecessors": list(self.ordering_predecessors)}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "SemanticEvent":
        _fields(value, {"eventId", "sequence", "fragmentId", "kind", "subjectId", "value", "objectId",
                        "offset", "accessSize", "alignment", "atomicity", "memoryOrder", "branchTaken",
                        "targetId", "detail", "orderingPredecessors"}, "semantic event")
        val, offset, taken = value.get("value"), value.get("offset"), value.get("branchTaken")
        if val is not None and not isinstance(val, Mapping): raise ValueError("event value is invalid")
        if offset is not None and (isinstance(offset, bool) or not isinstance(offset, int)): raise ValueError("event offset is invalid")
        if taken is not None and not isinstance(taken, bool): raise ValueError("branchTaken is invalid")
        return cls(_str(value, "eventId", "event"), _int(value, "sequence", "event"),
                   _str(value, "fragmentId", "event"), _str(value, "kind", "event"),
                   _str(value, "subjectId", "event", True), CanonicalValue.from_dict(val) if isinstance(val, Mapping) else None,
                   _str(value, "objectId", "event", True), offset, _int(value, "accessSize", "event"),
                   _int(value, "alignment", "event"), _str(value, "atomicity", "event", True),
                   _str(value, "memoryOrder", "event", True), taken, _str(value, "targetId", "event", True),
                   _str(value, "detail", "event", True), _strs(value.get("orderingPredecessors"), "orderingPredecessors"))


@dataclass(frozen=True)
class EffectRelation:
    source_event_id: str
    target_event_ids: tuple[str, ...]
    relation: str
    def __post_init__(self) -> None:
        if not self.source_event_id or self.relation not in {"equivalent", "strengthened", "best_effort"}:
            raise ValueError("effect relation is invalid")
        if not self.target_event_ids: raise ValueError("effect relation requires targets")
        _canonical_set(self.target_event_ids, "target event IDs")
    def to_dict(self) -> dict[str, object]:
        return {"sourceEventId": self.source_event_id, "targetEventIds": list(self.target_event_ids), "relation": self.relation}
    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "EffectRelation":
        _fields(value, {"sourceEventId", "targetEventIds", "relation"}, "effect relation")
        return cls(_str(value, "sourceEventId", "relation"), _strs(value.get("targetEventIds"), "targetEventIds"),
                   _str(value, "relation", "relation"))


@dataclass(frozen=True)
class ObservationProvenance:
    artifact_digest: str
    translation_manifest_digest: str
    translation_artifact_identity: str
    source_model_identity: str
    proof_identity: str
    shell_facts_identity: str
    runtime_contract_id: str
    runtime_contract_version: str
    test_seed: int
    generated_inputs_identity: str
    comparison_policy: str
    command_profile: RunnerCommandProfile
    canonicalizer_version: str = ""

    def __post_init__(self) -> None:
        for label, value in (("artifact", self.artifact_digest), ("manifest", self.translation_manifest_digest),
                             ("translation artifact", self.translation_artifact_identity),
                             ("source model", self.source_model_identity), ("proof", self.proof_identity),
                             ("shell facts", self.shell_facts_identity), ("generated inputs", self.generated_inputs_identity)):
            _require_digest(value, label + " identity")
        if not self.runtime_contract_id or not self.runtime_contract_version or not self.comparison_policy:
            raise ValueError("provenance contract is incomplete")
        if self.test_seed < 0: raise ValueError("test seed is invalid")
        if self.canonicalizer_version and self.canonicalizer_version != OBSERVATION_CANONICALIZER_VERSION:
            raise ValueError("canonicalizer version is unsupported")

    def to_dict(self) -> dict[str, object]:
        return {"artifactDigest": self.artifact_digest, "translationManifestDigest": self.translation_manifest_digest,
                "translationArtifactIdentity": self.translation_artifact_identity,
                "sourceModelIdentity": self.source_model_identity, "proofIdentity": self.proof_identity,
                "shellFactsIdentity": self.shell_facts_identity, "runtimeContractId": self.runtime_contract_id,
                "runtimeContractVersion": self.runtime_contract_version, "testSeed": self.test_seed,
                "generatedInputsIdentity": self.generated_inputs_identity, "comparisonPolicy": self.comparison_policy,
                "runnerCommandProfile": self.command_profile.to_dict(), "canonicalizerVersion": self.canonicalizer_version}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ObservationProvenance":
        names = {"artifactDigest", "translationManifestDigest", "translationArtifactIdentity", "sourceModelIdentity",
                 "proofIdentity", "shellFactsIdentity", "runtimeContractId", "runtimeContractVersion", "testSeed",
                 "generatedInputsIdentity", "comparisonPolicy", "runnerCommandProfile", "canonicalizerVersion"}
        _fields(value, names, "observation provenance")
        command = value.get("runnerCommandProfile")
        if not isinstance(command, Mapping): raise ValueError("runner command profile is invalid")
        strings = {name: _str(value, name, "provenance") for name in names - {"testSeed", "runnerCommandProfile", "canonicalizerVersion"}}
        return cls(strings["artifactDigest"], strings["translationManifestDigest"], strings["translationArtifactIdentity"],
                   strings["sourceModelIdentity"], strings["proofIdentity"], strings["shellFactsIdentity"],
                   strings["runtimeContractId"], strings["runtimeContractVersion"], _int(value, "testSeed", "provenance"),
                   strings["generatedInputsIdentity"], strings["comparisonPolicy"], RunnerCommandProfile.from_dict(command),
                   _str(value, "canonicalizerVersion", "provenance", True))


@dataclass(frozen=True)
class ExecutionObservation:
    test_id: str
    fragment_ids: tuple[str, ...]
    runner: ToolIdentity
    compiler: ToolIdentity
    runtime: ToolIdentity
    loader: ToolIdentity
    optimization: str
    sanitizer: str
    source_execution_profile: str
    target_execution_mode: str
    initial_state_identity: str
    preservation_mode: PreservationMode
    result: ExecutionResult
    logical_operands: tuple[LogicalOperandObservation, ...]
    memory_objects: tuple[MemoryObjectObservation, ...]
    semantic_events: tuple[SemanticEvent, ...]
    effect_relations: tuple[EffectRelation, ...]
    privileged_state: tuple[tuple[str, CanonicalValue], ...]
    ignored_state: tuple[str, ...]
    provenance: ObservationProvenance
    schema_version: str = VALIDATION_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_OBSERVATION_SCHEMA or not self.test_id:
            raise ValueError("observation schema/test identity is invalid")
        _require_digest(self.initial_state_identity, "initial state identity")
        _canonical_set(self.fragment_ids, "fragment IDs")
        _canonical_set(self.ignored_state, "ignored state")
        operand_keys = tuple((x.fragment_id, x.operand_index, x.operand_id) for x in self.logical_operands)
        if tuple(sorted(set(operand_keys))) != operand_keys:
            raise ValueError("logical operands must be unique and canonically ordered")
        if any(x.fragment_id not in self.fragment_ids for x in self.logical_operands):
            raise ValueError("operand references unknown fragment")
        object_ids = tuple(x.object_id for x in self.memory_objects)
        if tuple(sorted(set(object_ids))) != object_ids:
            raise ValueError("memory objects must be unique and canonically ordered")
        seen: set[str] = set()
        for sequence, event in enumerate(self.semantic_events):
            if event.sequence != sequence or event.event_id in seen:
                raise ValueError("events require unique IDs and contiguous execution order")
            if event.fragment_id not in self.fragment_ids: raise ValueError("event references unknown fragment")
            if any(pred not in seen for pred in event.ordering_predecessors):
                raise ValueError("ordering predecessor must be an earlier event")
            if event.object_id and event.object_id not in object_ids: raise ValueError("event references unknown memory object")
            seen.add(event.event_id)
        sources = tuple(x.source_event_id for x in self.effect_relations)
        if tuple(sorted(set(sources))) != sources: raise ValueError("effect relations must be unique and sorted")
        if any(target not in seen for x in self.effect_relations for target in x.target_event_ids):
            raise ValueError("effect relation references unknown target event")
        state_keys = tuple(x[0] for x in self.privileged_state)
        if tuple(sorted(set(state_keys))) != state_keys: raise ValueError("privileged state must be unique and sorted")

    @property
    def identity(self) -> str:
        return _digest(_canonical_json(self.to_dict()))

    def validate_translation_artifact(self, artifact: object) -> None:
        fragment_id = getattr(artifact, "fragment_id", None)
        if fragment_id not in self.fragment_ids: raise ValueError("observation does not bind artifact fragment")
        checks = (("source_model_identity", self.provenance.source_model_identity),
                  ("proof_identity", self.provenance.proof_identity),
                  ("shell_facts_identity", self.provenance.shell_facts_identity),
                  ("runtime_contract_id", self.provenance.runtime_contract_id),
                  ("runtime_contract_version", self.provenance.runtime_contract_version),
                  ("preservation_mode", self.preservation_mode))
        if any(getattr(artifact, name, None) != expected for name, expected in checks):
            raise ValueError("observation and translation artifact identities differ")
        if any(x.shell_fact_identity != self.provenance.shell_facts_identity for x in self.logical_operands):
            raise ValueError("operand shell facts do not bind provenance")

    def validate_effect_relations(self, source: "ExecutionObservation") -> None:
        source_ids = {x.event_id for x in source.semantic_events}
        if any(x.source_event_id not in source_ids for x in self.effect_relations):
            raise ValueError("effect relation references unknown source event")

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion": self.schema_version, "testId": self.test_id, "fragmentIds": list(self.fragment_ids),
                "runner": self.runner.to_dict(), "compiler": self.compiler.to_dict(), "runtime": self.runtime.to_dict(),
                "loader": self.loader.to_dict(), "optimization": self.optimization, "sanitizer": self.sanitizer,
                "sourceExecutionProfile": self.source_execution_profile, "targetExecutionMode": self.target_execution_mode,
                "initialStateIdentity": self.initial_state_identity, "preservationMode": self.preservation_mode.value,
                "result": self.result.to_dict(), "logicalOperands": [x.to_dict() for x in self.logical_operands],
                "memoryObjects": [x.to_dict() for x in self.memory_objects],
                "semanticEvents": [x.to_dict() for x in self.semantic_events],
                "effectRelations": [x.to_dict() for x in self.effect_relations],
                "privilegedState": [{"name": k, "value": v.to_dict()} for k, v in self.privileged_state],
                "ignoredState": list(self.ignored_state), "provenance": self.provenance.to_dict()}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ExecutionObservation":
        expected = {"schemaVersion", "testId", "fragmentIds", "runner", "compiler", "runtime", "loader",
                    "optimization", "sanitizer", "sourceExecutionProfile", "targetExecutionMode", "initialStateIdentity",
                    "preservationMode", "result", "logicalOperands", "memoryObjects", "semanticEvents",
                    "effectRelations", "privilegedState", "ignoredState", "provenance"}
        _fields(value, expected, "observation")
        if value.get("schemaVersion") != VALIDATION_OBSERVATION_SCHEMA: raise ValueError("unsupported observation schema")
        def obj(name: str) -> Mapping[str, object]:
            raw = value.get(name)
            if not isinstance(raw, Mapping): raise ValueError(name + " must be an object")
            return raw
        def arr(name: str) -> list[object]:
            raw = value.get(name)
            if not isinstance(raw, list): raise ValueError(name + " must be an array")
            return raw
        def parse(name: str, parser):
            output = []
            for raw in arr(name):
                if not isinstance(raw, Mapping): raise ValueError(name + " entry is invalid")
                output.append(parser(raw))
            return tuple(output)
        state = []
        for raw in arr("privilegedState"):
            if not isinstance(raw, Mapping): raise ValueError("privileged state entry is invalid")
            _fields(raw, {"name", "value"}, "privileged state")
            state_value = raw.get("value")
            if not isinstance(state_value, Mapping): raise ValueError("privileged state value is invalid")
            state.append((_str(raw, "name", "state"), CanonicalValue.from_dict(state_value)))
        return cls(_str(value, "testId", "observation"), _strs(value.get("fragmentIds"), "fragmentIds"),
                   ToolIdentity.from_dict(obj("runner")), ToolIdentity.from_dict(obj("compiler")),
                   ToolIdentity.from_dict(obj("runtime")), ToolIdentity.from_dict(obj("loader")),
                   _str(value, "optimization", "observation"), _str(value, "sanitizer", "observation"),
                   _str(value, "sourceExecutionProfile", "observation"),
                   _str(value, "targetExecutionMode", "observation"),
                   _str(value, "initialStateIdentity", "observation"),
                   PreservationMode(_str(value, "preservationMode", "observation")), ExecutionResult.from_dict(obj("result")),
                   parse("logicalOperands", LogicalOperandObservation.from_dict),
                   parse("memoryObjects", MemoryObjectObservation.from_dict), parse("semanticEvents", SemanticEvent.from_dict),
                   parse("effectRelations", EffectRelation.from_dict), tuple(state),
                   _strs(value.get("ignoredState"), "ignoredState"), ObservationProvenance.from_dict(obj("provenance")),
                   _str(value, "schemaVersion", "observation"))


def canonicalize_observation_input(value: Mapping[str, object], *, version: str) -> dict[str, object]:
    """Explicitly canonicalize set-like collections without reordering events."""
    if version != OBSERVATION_CANONICALIZER_VERSION:
        raise ValueError("unsupported observation canonicalizer")
    result = json.loads(json.dumps(value))
    for name in ("fragmentIds", "ignoredState"):
        raw = result.get(name)
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            raise ValueError(name + " cannot be canonicalized")
        result[name] = sorted(set(raw))
    specifications = (
        ("logicalOperands", lambda x: (x.get("fragmentId"), x.get("operandIndex"), x.get("operandId"))),
        ("memoryObjects", lambda x: x.get("objectId")),
        ("effectRelations", lambda x: x.get("sourceEventId")),
    )
    for name, key in specifications:
        raw = result.get(name)
        if not isinstance(raw, list) or not all(isinstance(x, dict) for x in raw):
            raise ValueError(name + " cannot be canonicalized")
        result[name] = sorted(raw, key=key)
    provenance = result.get("provenance")
    if not isinstance(provenance, dict): raise ValueError("provenance cannot record canonicalization")
    provenance["canonicalizerVersion"] = version
    return result


def validation_identity(*, source_artifact_hash: str, target_artifact_hash: str,
                        translation_manifest_hash: str, source_model_identity: str,
                        runtime_contract: str, runtime_version: str,
                        source_observation: ExecutionObservation | None,
                        target_observation: ExecutionObservation | None,
                        comparison_policy: str) -> str:
    for label, value in (("source artifact", source_artifact_hash), ("target artifact", target_artifact_hash),
                         ("translation manifest", translation_manifest_hash)):
        _require_digest(value, label + " hash")
    if not all((source_model_identity, runtime_contract, runtime_version, comparison_policy)):
        raise ValueError("validation identity inputs are incomplete")
    payload = {"schemaVersion": VALIDATION_OBSERVATION_SCHEMA,
               "sourceArtifactHash": source_artifact_hash, "targetArtifactHash": target_artifact_hash,
               "translationManifestHash": translation_manifest_hash, "sourceModelIdentity": source_model_identity,
               "runtimeContract": runtime_contract, "runtimeVersion": runtime_version,
               "comparisonPolicy": comparison_policy,
               "sourceObservation": None if source_observation is None else source_observation.to_dict(),
               "targetObservation": None if target_observation is None else target_observation.to_dict()}
    return _digest(_canonical_json(payload))
