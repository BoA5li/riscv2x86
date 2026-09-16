"""Proof-owned L2 observation plans for internal values and composite fragments.

The translation proof describes *what* may be observed.  A later compiler-AST
join supplies declaration identities and exact source boundaries.  Runners may
only execute the resulting plan; they must not rediscover variables from C or
assembly text.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence


INTERNAL_VALUE_PROOF_SCHEMA = "riscv2x86.l2-internal-value-proof-facts.v1"
INSTRUMENTATION_PLAN_SCHEMA = "riscv2x86.l2-instrumentation-plan.v1"
COMPOSITE_SLICE_SCHEMA = "riscv2x86.l2-composite-slices.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_PHASE = re.compile(r"^(?:after_fragment|after_operation:[0-9]+)$")


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


@dataclass(frozen=True)
class L2CanonicalType:
    type_kind: str
    width_bits: int
    signedness: str

    def __post_init__(self) -> None:
        if (self.type_kind != "integer" or self.width_bits not in {8, 16, 32, 64}
                or self.signedness not in {"signed", "unsigned"}):
            raise ValueError("internal-value canonical type is unsupported")

    def to_dict(self) -> dict[str, object]:
        return {"typeKind": self.type_kind, "widthBits": self.width_bits,
                "signedness": self.signedness}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2CanonicalType":
        if set(value) != {"typeKind", "widthBits", "signedness"}:
            raise ValueError("canonical type fields are incomplete or unknown")
        width = value.get("widthBits")
        if isinstance(width, bool) or not isinstance(width, int):
            raise ValueError("canonical type width is invalid")
        return cls(str(value.get("typeKind", "")), width,
                   str(value.get("signedness", "")))


@dataclass(frozen=True)
class L2NonInterferenceProof:
    operand_allocation_preserved: bool
    memory_clobber_preserved: bool
    control_flow_preserved: bool
    volatile_behavior_preserved: bool
    internal_state_non_escaping: bool
    equivalent_observation_boundary: bool
    proof_identity: str = ""

    def __post_init__(self) -> None:
        if not all(isinstance(item, bool) for item in self._claims()):
            raise TypeError("non-interference claims must be boolean")
        expected = _identity(self._payload(False))
        if self.proof_identity and self.proof_identity != expected:
            raise ValueError("non-interference proof identity is stale")
        object.__setattr__(self, "proof_identity", expected)

    def _claims(self) -> tuple[bool, ...]:
        return (self.operand_allocation_preserved, self.memory_clobber_preserved,
                self.control_flow_preserved, self.volatile_behavior_preserved,
                self.internal_state_non_escaping,
                self.equivalent_observation_boundary)

    @property
    def complete(self) -> bool:
        return all(self._claims())

    def _payload(self, include_identity: bool) -> dict[str, object]:
        result = {
            "operandAllocationPreserved": self.operand_allocation_preserved,
            "memoryClobberPreserved": self.memory_clobber_preserved,
            "controlFlowPreserved": self.control_flow_preserved,
            "volatileBehaviorPreserved": self.volatile_behavior_preserved,
            "internalStateNonEscaping": self.internal_state_non_escaping,
            "equivalentObservationBoundary": self.equivalent_observation_boundary,
        }
        if include_identity:
            result["proofIdentity"] = self.proof_identity
        return result

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2NonInterferenceProof":
        fields = {"operandAllocationPreserved", "memoryClobberPreserved",
                  "controlFlowPreserved", "volatileBehaviorPreserved",
                  "internalStateNonEscaping", "equivalentObservationBoundary",
                  "proofIdentity"}
        if set(value) != fields or any(not isinstance(value[name], bool)
                                       for name in fields - {"proofIdentity"}):
            raise ValueError("non-interference proof fields are invalid")
        proof = value.get("proofIdentity")
        if not isinstance(proof, str) or _SHA.fullmatch(proof) is None:
            raise ValueError("non-interference proof identity is invalid")
        return cls(*(bool(value[name]) for name in (
            "operandAllocationPreserved", "memoryClobberPreserved",
            "controlFlowPreserved", "volatileBehaviorPreserved",
            "internalStateNonEscaping", "equivalentObservationBoundary")), proof)


@dataclass(frozen=True)
class L2InternalValueProofPoint:
    logical_value_id: str
    operand_index: int
    operation_index: int
    type_contract: L2CanonicalType

    def __post_init__(self) -> None:
        if (not self.logical_value_id or isinstance(self.operand_index, bool)
                or not isinstance(self.operand_index, int) or self.operand_index < 0
                or isinstance(self.operation_index, bool)
                or not isinstance(self.operation_index, int) or self.operation_index < 0):
            raise ValueError("internal-value proof point is invalid")

    def to_dict(self) -> dict[str, object]:
        return {"logicalValueId": self.logical_value_id,
                "operandIndex": self.operand_index,
                "operationIndex": self.operation_index,
                "typeContract": self.type_contract.to_dict()}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2InternalValueProofPoint":
        if set(value) != {"logicalValueId", "operandIndex", "operationIndex",
                          "typeContract"}:
            raise ValueError("internal-value proof point fields are invalid")
        operand, operation, contract = (value.get("operandIndex"),
                                        value.get("operationIndex"),
                                        value.get("typeContract"))
        if (isinstance(operand, bool) or not isinstance(operand, int)
                or isinstance(operation, bool) or not isinstance(operation, int)
                or not isinstance(contract, Mapping)):
            raise ValueError("internal-value proof point types are invalid")
        return cls(str(value.get("logicalValueId", "")), operand, operation,
                   L2CanonicalType.from_dict(contract))


@dataclass(frozen=True)
class L2InternalValueProofFacts:
    fragment_id: str
    points: tuple[L2InternalValueProofPoint, ...]
    non_interference: L2NonInterferenceProof
    complete: bool
    facts_identity: str = ""
    schema_version: str = INTERNAL_VALUE_PROOF_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != INTERNAL_VALUE_PROOF_SCHEMA or not self.fragment_id:
            raise ValueError("internal-value proof facts schema/fragment is invalid")
        keys = tuple((item.operation_index, item.operand_index) for item in self.points)
        if not self.points or keys != tuple(sorted(set(keys))):
            raise ValueError("internal-value proof points are not canonical")
        if self.complete and not self.non_interference.complete:
            raise ValueError("complete internal-value facts require non-interference proof")
        expected = _identity(self._payload(False))
        if self.facts_identity and self.facts_identity != expected:
            raise ValueError("internal-value proof facts identity is stale")
        object.__setattr__(self, "facts_identity", expected)

    def _payload(self, include_identity: bool) -> dict[str, object]:
        result = {"schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
                  "points": [item.to_dict() for item in self.points],
                  "nonInterference": self.non_interference.to_dict(),
                  "complete": self.complete}
        if include_identity:
            result["factsIdentity"] = self.facts_identity
        return result

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2InternalValueProofFacts":
        fields = {"schemaVersion", "fragmentId", "points", "nonInterference",
                  "complete", "factsIdentity"}
        if set(value) != fields:
            raise ValueError("internal-value proof facts fields are invalid")
        points, proof = value.get("points"), value.get("nonInterference")
        if (not isinstance(points, list) or not all(isinstance(item, Mapping) for item in points)
                or not isinstance(proof, Mapping) or not isinstance(value.get("complete"), bool)):
            raise ValueError("internal-value proof facts types are invalid")
        return cls(str(value.get("fragmentId", "")),
                   tuple(L2InternalValueProofPoint.from_dict(item) for item in points),
                   L2NonInterferenceProof.from_dict(proof), bool(value["complete"]),
                   str(value.get("factsIdentity", "")), str(value.get("schemaVersion", "")))


def internal_value_proof_facts_from_dict(
    value: Mapping[str, object],
) -> L2InternalValueProofFacts:
    return L2InternalValueProofFacts.from_dict(value)


@dataclass(frozen=True)
class L2InstrumentationPoint:
    point_id: str
    fragment_id: str
    logical_value_id: str
    observation_phase: str
    type_contract: L2CanonicalType
    non_interference_proof_identity: str
    declaration_id: str
    declaration_name: str
    operand_index: int

    def __post_init__(self) -> None:
        if (not self.point_id or not self.fragment_id or not self.logical_value_id
                or _PHASE.fullmatch(self.observation_phase) is None
                or _SHA.fullmatch(self.non_interference_proof_identity) is None
                or not self.declaration_id or not self.declaration_name
                or isinstance(self.operand_index, bool)
                or not isinstance(self.operand_index, int) or self.operand_index < 0):
            raise ValueError("L2 instrumentation point is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"pointId": self.point_id, "fragmentId": self.fragment_id,
                "logicalValueId": self.logical_value_id,
                "observationPhase": self.observation_phase,
                "typeContract": self.type_contract.to_dict(),
                "nonInterferenceProofIdentity": self.non_interference_proof_identity,
                "declarationId": self.declaration_id,
                "declarationName": self.declaration_name,
                "operandIndex": self.operand_index}

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2InstrumentationPoint":
        fields = {"pointId", "fragmentId", "logicalValueId", "observationPhase",
                  "typeContract", "nonInterferenceProofIdentity", "declarationId",
                  "declarationName", "operandIndex"}
        if set(value) != fields or not isinstance(value.get("typeContract"), Mapping):
            raise ValueError("instrumentation point fields are invalid")
        operand = value.get("operandIndex")
        if isinstance(operand, bool) or not isinstance(operand, int):
            raise ValueError("instrumentation point operand index is invalid")
        return cls(str(value["pointId"]), str(value["fragmentId"]),
                   str(value["logicalValueId"]), str(value["observationPhase"]),
                   L2CanonicalType.from_dict(value["typeContract"]),
                   str(value["nonInterferenceProofIdentity"]),
                   str(value["declarationId"]), str(value["declarationName"]), operand)


@dataclass(frozen=True)
class L2InstrumentationPlan:
    fragment_id: str
    source_insertion_offset: int
    points: tuple[L2InstrumentationPoint, ...]
    non_interference: L2NonInterferenceProof
    proof_facts_identity: str
    complete: bool
    plan_identity: str = ""
    schema_version: str = INSTRUMENTATION_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != INSTRUMENTATION_PLAN_SCHEMA or not self.fragment_id
                or isinstance(self.source_insertion_offset, bool)
                or not isinstance(self.source_insertion_offset, int)
                or self.source_insertion_offset < 0
                or _SHA.fullmatch(self.proof_facts_identity) is None):
            raise ValueError("L2 instrumentation plan header is invalid")
        ids = tuple(item.point_id for item in self.points)
        if (not self.points or ids != tuple(sorted(set(ids)))
                or any(item.fragment_id != self.fragment_id for item in self.points)
                or any(item.non_interference_proof_identity
                       != self.non_interference.proof_identity for item in self.points)):
            raise ValueError("L2 instrumentation plan points are inconsistent")
        if self.complete and not self.non_interference.complete:
            raise ValueError("complete instrumentation plan lacks non-interference proof")
        expected = _identity(self._payload(False))
        if self.plan_identity and self.plan_identity != expected:
            raise ValueError("L2 instrumentation plan identity is stale")
        object.__setattr__(self, "plan_identity", expected)

    def _payload(self, include_identity: bool) -> dict[str, object]:
        result = {"schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
                  "sourceInsertionOffset": self.source_insertion_offset,
                  "points": [item.to_dict() for item in self.points],
                  "nonInterference": self.non_interference.to_dict(),
                  "proofFactsIdentity": self.proof_facts_identity,
                  "complete": self.complete}
        if include_identity:
            result["planIdentity"] = self.plan_identity
        return result

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "L2InstrumentationPlan":
        fields = {"schemaVersion", "fragmentId", "sourceInsertionOffset", "points",
                  "nonInterference", "proofFactsIdentity", "complete", "planIdentity"}
        if set(value) != fields:
            raise ValueError("instrumentation plan fields are invalid")
        offset, points, proof = (value.get("sourceInsertionOffset"), value.get("points"),
                                 value.get("nonInterference"))
        if (isinstance(offset, bool) or not isinstance(offset, int)
                or not isinstance(points, list)
                or not all(isinstance(item, Mapping) for item in points)
                or not isinstance(proof, Mapping) or not isinstance(value.get("complete"), bool)):
            raise ValueError("instrumentation plan types are invalid")
        return cls(str(value["fragmentId"]), offset,
                   tuple(L2InstrumentationPoint.from_dict(item) for item in points),
                   L2NonInterferenceProof.from_dict(proof),
                   str(value["proofFactsIdentity"]), bool(value["complete"]),
                   str(value["planIdentity"]), str(value["schemaVersion"]))


def instrumentation_plan_from_dict(value: Mapping[str, object]) -> L2InstrumentationPlan:
    return L2InstrumentationPlan.from_dict(value)


def internal_value_proof_facts_from_source_model(
    fragment_id: str, source_model: object,
) -> L2InternalValueProofFacts | None:
    """Derive point identities exclusively from the canonical value program."""
    program = getattr(source_model, "value_program", None)
    instructions = tuple(getattr(program, "instructions", ()) or ())
    if len(instructions) < 2 or not bool(getattr(program, "complete", False)):
        return None
    width = getattr(program, "width_bits", 0)
    if width not in {32, 64}:
        return None
    points = tuple(sorted((L2InternalValueProofPoint(
        f"value:operand:{int(item.output_operand_index)}",
        int(item.output_operand_index), operation_index,
        L2CanonicalType("integer", int(width), "unsigned"),
    ) for operation_index, item in enumerate(instructions)),
        key=lambda item: (item.operation_index, item.operand_index)))
    shell = getattr(source_model, "shell", None)
    operation = getattr(source_model, "operation", None)
    control = getattr(source_model, "control_flow", None)
    completeness = getattr(source_model, "completeness", None)
    proof = L2NonInterferenceProof(
        operand_allocation_preserved=bool(getattr(getattr(source_model, "operands", None), "complete", False)),
        memory_clobber_preserved=shell is not None,
        control_flow_preserved=bool(getattr(completeness, "cfg_ok", False))
            and not bool(getattr(control, "has_nonlocal_control_flow", False)),
        volatile_behavior_preserved=shell is not None,
        internal_state_non_escaping=bool(getattr(operation, "may_trap", None) is False),
        equivalent_observation_boundary=True,
    )
    return L2InternalValueProofFacts(fragment_id, points, proof,
                                     proof.complete)


def bind_instrumentation_plan(
    facts: L2InternalValueProofFacts, boundary: Mapping[str, object],
    *, insertion_offset: int | None = None,
) -> L2InstrumentationPlan:
    """Join proof value indexes to compiler declaration IDs and one AST offset."""
    if not facts.complete or boundary.get("complete") is not True:
        raise ValueError("internal-value instrumentation authority is incomplete")
    offset = (boundary.get("asmStatementEndOffset") if insertion_offset is None
              else insertion_offset)
    asm_ids, declarations = (boundary.get("asmOperandDeclarationIds"),
                              boundary.get("declarations"))
    if (isinstance(offset, bool) or not isinstance(offset, int) or offset < 0
            or not isinstance(asm_ids, list) or not isinstance(declarations, Mapping)):
        raise ValueError("compiler instrumentation boundary is unavailable")
    points = []
    for raw in facts.points:
        if raw.operand_index >= len(asm_ids):
            raise ValueError("proof point operand is absent from compiler shell")
        declaration_id = asm_ids[raw.operand_index]
        declaration = declarations.get(declaration_id)
        if not isinstance(declaration_id, str) or not isinstance(declaration, Mapping):
            raise ValueError("instrumentation declaration binding is missing")
        name = declaration.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_]\w*", name):
            raise ValueError("instrumentation declaration name is invalid")
        points.append(L2InstrumentationPoint(
            f"point:{raw.operation_index}:{raw.operand_index}", facts.fragment_id,
            # One inline-asm statement is the non-interference boundary.  The
            # operation index identifies the produced value; claiming an
            # observation inside the statement would be false.
            raw.logical_value_id, "after_fragment",
            raw.type_contract, facts.non_interference.proof_identity,
            declaration_id, name, raw.operand_index,
        ))
    return L2InstrumentationPlan(facts.fragment_id, offset,
        tuple(sorted(points, key=lambda item: item.point_id)), facts.non_interference,
        facts.facts_identity, True)


def composite_slice_manifest(fragment_id: str, dimensions: Sequence[str],
                             execution_identity: str) -> dict[str, object]:
    """Bind many dimension slices to one fragment execution, never many programs."""
    canonical = tuple(sorted(set(dimensions)))
    if (not fragment_id or not canonical or _SHA.fullmatch(execution_identity) is None
            or any(not item for item in canonical)):
        raise ValueError("composite slice manifest is invalid")
    payload = {"schemaVersion": COMPOSITE_SLICE_SCHEMA, "fragmentId": fragment_id,
               "executionIdentity": execution_identity,
               "slices": [{"sliceId": f"slice:{item}", "dimension": item,
                            "executionIdentity": execution_identity}
                           for item in canonical]}
    payload["manifestIdentity"] = _identity(payload)
    return payload
