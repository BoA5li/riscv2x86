"""Proof-owned object-relative memory facts and strict L2 observations."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .effect_relation import ApprovedEffectRelation
from .l2_authority import L2MemoryObjectAuthority, L2OperandAuthority


L2_MEMORY_PROOF_FACTS_SCHEMA = "riscv2x86.l2-memory-proof-facts.v1"
L2_MEMORY_OBSERVATION_SCHEMA = "riscv2x86.l2-memory-observation.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

L2_MEMORY_MATERIALIZATION_DECISION_SCHEMA = \
    "riscv2x86.l2-memory-authority-decision.v1"


def _c_scalar_width_bytes(type_name: object) -> int:
    name = " ".join(str(type_name).replace("const", "")
                    .replace("volatile", "").split())
    fixed = re.fullmatch(r"u?int(8|16|32|64)_t", name)
    if fixed:
        return int(fixed.group(1)) // 8
    return {"char": 1, "signed char": 1, "unsigned char": 1,
            "short": 2, "signed short": 2, "unsigned short": 2,
            "int": 4, "signed int": 4, "unsigned int": 4,
            "long": 8, "signed long": 8, "unsigned long": 8,
            "long long": 8, "signed long long": 8,
            "unsigned long long": 8}.get(name, 0)


@dataclass(frozen=True)
class MemoryAccessAuthority:
    """Compiler/harness-owned coordinates for one logical memory access.

    Object identity is deliberately a declaration/contract identity.  This
    type has no field capable of carrying a sampled runtime address.
    """
    fragment_id: str
    access_kind: str
    object_identity: str
    address_value_node: str
    base_operand_identity: str
    offset_bytes: int
    access_width_bytes: int
    required_alignment_bytes: int
    proven_alignment_bytes: int
    object_size_bytes: int | None
    bounds_relation: str
    alias_domain_identity: str
    address_space_identity: str
    value_operand_identity: str
    volatile: bool
    complete: bool

    def __post_init__(self) -> None:
        if self.access_kind not in {"load", "store", "rmw"}:
            raise ValueError("memory access authority kind is unsupported")
        numeric = (self.offset_bytes, self.access_width_bytes,
                   self.required_alignment_bytes, self.proven_alignment_bytes)
        if (any(isinstance(item, bool) or not isinstance(item, int) for item in numeric)
                or self.offset_bytes < 0 or min(numeric[1:]) <= 0
                or (self.object_size_bytes is not None and
                    (isinstance(self.object_size_bytes, bool)
                     or not isinstance(self.object_size_bytes, int)
                     or self.object_size_bytes <= 0))):
            raise ValueError("memory access authority numeric facts are invalid")
        identities = (self.fragment_id, self.object_identity,
                      self.address_value_node, self.base_operand_identity,
                      self.bounds_relation, self.alias_domain_identity,
                      self.address_space_identity, self.value_operand_identity)
        if any(not isinstance(item, str) or not item for item in identities):
            raise ValueError("memory access authority identity is incomplete")
        if not isinstance(self.volatile, bool) or self.complete is not True:
            raise ValueError("memory access authority flags are invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "fragmentId": self.fragment_id, "accessKind": self.access_kind,
            "objectIdentity": self.object_identity,
            "addressValueNode": self.address_value_node,
            "baseOperandIdentity": self.base_operand_identity,
            "offsetBytes": self.offset_bytes,
            "accessWidthBytes": self.access_width_bytes,
            "requiredAlignmentBytes": self.required_alignment_bytes,
            "provenAlignmentBytes": self.proven_alignment_bytes,
            "objectSizeBytes": self.object_size_bytes,
            "boundsRelation": self.bounds_relation,
            "aliasDomainIdentity": self.alias_domain_identity,
            "addressSpaceIdentity": self.address_space_identity,
            "valueOperandIdentity": self.value_operand_identity,
            "volatile": self.volatile, "complete": self.complete,
        }


@dataclass(frozen=True)
class AuthorityMaterializationDecision:
    fragment_id: str
    materializable: bool
    reason_codes: tuple[str, ...]
    authority: MemoryAccessAuthority | None = None
    schema_version: str = L2_MEMORY_MATERIALIZATION_DECISION_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != L2_MEMORY_MATERIALIZATION_DECISION_SCHEMA
                or not self.fragment_id
                or self.reason_codes != tuple(sorted(set(self.reason_codes)))
                or self.materializable != (self.authority is not None)
                or (self.materializable and self.reason_codes)):
            raise ValueError("memory authority decision is inconsistent")

    @property
    def decision_identity(self) -> str:
        return _identity(self.to_dict(include_identity=False))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value = {"schemaVersion": self.schema_version,
                 "fragmentId": self.fragment_id,
                 "materializable": self.materializable,
                 "reasonCodes": list(self.reason_codes),
                 "authority": None if self.authority is None else self.authority.to_dict()}
        if include_identity:
            value["decisionIdentity"] = self.decision_identity
        return value


def assess_memory_authority_materializability(
    translation_proof: Mapping[str, object],
    memory_facts: L2MemoryProofFacts | Mapping[str, object] | None,
    operand_boundary: Mapping[str, object] | None,
    fragment: Mapping[str, object],
) -> AuthorityMaterializationDecision:
    """Make the single fail-closed decision used by planning and execution."""
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    if (isinstance(memory_facts, Mapping)
            and memory_facts.get("schemaVersion")
            == L2_MEMORY_MATERIALIZATION_DECISION_SCHEMA):
        payload = dict(memory_facts)
        claimed = payload.pop("decisionIdentity", None)
        raw_authority = payload.get("authority")
        try:
            if claimed != _identity(payload) or payload.get("fragmentId") != fragment_id:
                raise ValueError
            reasons = payload.get("reasonCodes")
            if (not isinstance(reasons, list)
                    or not all(isinstance(item, str) and item for item in reasons)):
                raise ValueError
            authority = None
            if isinstance(raw_authority, Mapping):
                authority = MemoryAccessAuthority(
                    str(raw_authority.get("fragmentId") or ""),
                    str(raw_authority.get("accessKind") or ""),
                    str(raw_authority.get("objectIdentity") or ""),
                    str(raw_authority.get("addressValueNode") or ""),
                    str(raw_authority.get("baseOperandIdentity") or ""),
                    raw_authority.get("offsetBytes"), raw_authority.get("accessWidthBytes"),
                    raw_authority.get("requiredAlignmentBytes"),
                    raw_authority.get("provenAlignmentBytes"),
                    raw_authority.get("objectSizeBytes"),
                    str(raw_authority.get("boundsRelation") or ""),
                    str(raw_authority.get("aliasDomainIdentity") or ""),
                    str(raw_authority.get("addressSpaceIdentity") or ""),
                    str(raw_authority.get("valueOperandIdentity") or ""),
                    raw_authority.get("volatile"), raw_authority.get("complete"))
            return AuthorityMaterializationDecision(
                fragment_id, payload.get("materializable") is True,
                tuple(reasons), authority)
        except (TypeError, ValueError):
            return AuthorityMaterializationDecision(
                fragment_id or "missing-fragment", False,
                ("L2_MEMORY_AUTHORITY_DECISION_INVALID",))
    reasons: set[str] = set()
    if not fragment_id:
        fragment_id = "missing-fragment"
        reasons.add("L2_FRAGMENT_IDENTITY_MISMATCH")
    if (translation_proof.get("proofStatus") != "approved"
            or translation_proof.get("architectureSemanticsPreserved") is False
            or translation_proof.get("shellSemanticsPreserved") is not True):
        reasons.add("L2_MEMORY_TRANSLATION_PROOF_UNAPPROVED")
    try:
        facts = (memory_facts if isinstance(memory_facts, L2MemoryProofFacts)
                 else memory_proof_facts_from_dict(memory_facts)
                 if isinstance(memory_facts, Mapping) else None)
    except ValueError:
        facts = None
    if facts is None:
        reasons.add("L2_MEMORY_ADDRESS_BINDING_MISSING")
        return AuthorityMaterializationDecision(fragment_id, False,
                                                tuple(sorted(reasons)))
    if facts.fragment_id != fragment_id:
        reasons.add("L2_FRAGMENT_IDENTITY_MISMATCH")
    boundary = operand_boundary if isinstance(operand_boundary, Mapping) else {}
    asm_ids = boundary.get("asmOperandDeclarationIds")
    declarations = boundary.get("declarations")
    bindings = boundary.get("memoryObjectBindings")
    if (boundary.get("complete") is not True or not isinstance(asm_ids, list)
            or not isinstance(declarations, Mapping)
            or max(facts.address_operand_index,
                   facts.value_operand_index) >= len(asm_ids)):
        reasons.add("L2_MEMORY_ADDRESS_BINDING_MISSING")
        return AuthorityMaterializationDecision(fragment_id, False,
                                                tuple(sorted(reasons)))
    address_id = str(asm_ids[facts.address_operand_index])
    value_id = str(asm_ids[facts.value_operand_index])
    address_declaration = declarations.get(address_id)
    if (not isinstance(address_declaration, Mapping)
            or "*" not in str(address_declaration.get("type", ""))):
        reasons.add("L2_MEMORY_ADDRESS_BINDING_MISSING")
    object_binding = bindings.get(address_id) if isinstance(bindings, Mapping) else None
    if not isinstance(object_binding, Mapping):
        reasons.add("L2_MEMORY_OBJECT_IDENTITY_MISSING")
        object_binding = {}
    object_identity = object_binding.get("objectIdentity")
    binding_origin = object_binding.get("bindingOrigin")
    if (not isinstance(object_identity, str) or not object_identity
            or binding_origin not in {
                "compiler-object-v1", "parameter-object-contract-v1",
                "automatic-aligned-memory-object-harness-v1",
                "explicit-harness-object-contract-v1"}):
        reasons.add("L2_MEMORY_OBJECT_IDENTITY_MISSING")
    size = object_binding.get("objectSizeBytes")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        reasons.add("L2_MEMORY_BOUNDS_UNPROVED")
        size = None
    end = facts.byte_offset + facts.width_bytes
    if not facts.bounds_proven or size is None or end > size:
        reasons.add("L2_MEMORY_BOUNDS_UNPROVED")
    proven_alignment = object_binding.get("provenAlignmentBytes")
    if (isinstance(proven_alignment, bool) or not isinstance(proven_alignment, int)
            or proven_alignment < facts.required_alignment
            or facts.byte_offset % facts.required_alignment
            or not facts.alignment_proven):
        reasons.add("L2_MEMORY_ALIGNMENT_UNPROVED")
        proven_alignment = 0
    value_declaration = declarations.get(value_id)
    if (not value_id or not isinstance(value_declaration, Mapping)
            or _c_scalar_width_bytes(value_declaration.get("type")) != facts.width_bytes
            or facts.value_operand_index == facts.address_operand_index):
        reasons.add("L2_MEMORY_VALUE_FLOW_UNPROVED")
    alias_domain = object_binding.get("aliasDomainIdentity")
    address_space = object_binding.get("addressSpaceIdentity")
    if (not isinstance(alias_domain, str) or not alias_domain
            or not isinstance(address_space, str) or not address_space):
        reasons.add("L2_MEMORY_ADDRESS_BINDING_MISSING")
    if not facts.complete or not facts.alias_complete or not facts.unique_object:
        reasons.add("L2_MEMORY_OBJECT_IDENTITY_MISSING")
    if reasons:
        return AuthorityMaterializationDecision(fragment_id, False,
                                                tuple(sorted(reasons)))
    authority = MemoryAccessAuthority(
        fragment_id, facts.access_kind, str(object_identity), address_id,
        address_id, facts.byte_offset, facts.width_bytes,
        facts.required_alignment, int(proven_alignment), size,
        f"0<={facts.byte_offset} && {end}<={size}",
        str(alias_domain), str(address_space),
        value_id, bool(object_binding.get("volatile", False)), True,
    )
    return AuthorityMaterializationDecision(fragment_id, True, (), authority)


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


@dataclass(frozen=True)
class L2MemoryProofFacts:
    fragment_id: str
    access_kind: str
    address_operand_index: int
    value_operand_index: int
    byte_offset: int
    width_bytes: int
    required_alignment: int
    object_origin_kind: str
    object_lifetime_scope: str
    alias_class: str
    unique_object: bool
    bounds_proven: bool
    alignment_proven: bool
    alias_complete: bool
    non_atomic: bool
    memory_order: str
    complete: bool
    facts_identity: str = ""
    schema_version: str = L2_MEMORY_PROOF_FACTS_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_MEMORY_PROOF_FACTS_SCHEMA or not self.fragment_id:
            raise ValueError("memory proof facts schema/fragment is invalid")
        if self.access_kind not in {"load", "store"}:
            raise ValueError("memory proof access kind is unsupported")
        if any(isinstance(x, bool) or not isinstance(x, int) or x < 0 for x in
               (self.address_operand_index, self.value_operand_index, self.byte_offset)):
            raise ValueError("memory proof operand index/offset is invalid")
        if self.width_bytes not in {1, 2, 4, 8}:
            raise ValueError("memory proof width is unsupported")
        if (self.required_alignment <= 0
                or self.byte_offset % self.required_alignment != 0):
            raise ValueError("memory proof alignment is invalid")
        if (not self.object_origin_kind or not self.object_lifetime_scope
                or not self.alias_class or self.memory_order != "relaxed"):
            raise ValueError("memory proof object/order facts are incomplete")
        closed = all((self.unique_object, self.bounds_proven, self.alignment_proven,
                      self.alias_complete, self.non_atomic))
        if self.complete != closed:
            raise ValueError("memory proof completeness does not match safety facts")
        expected = _identity(self._payload(False))
        if self.facts_identity and self.facts_identity != expected:
            raise ValueError("memory proof identity does not match content")
        object.__setattr__(self, "facts_identity", expected)

    def _payload(self, include_identity: bool) -> dict[str, object]:
        result = {"schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
          "accessKind": self.access_kind, "addressOperandIndex": self.address_operand_index,
          "valueOperandIndex": self.value_operand_index, "byteOffset": self.byte_offset,
          "widthBytes": self.width_bytes, "requiredAlignment": self.required_alignment,
          "objectOriginKind": self.object_origin_kind,
          "objectLifetimeScope": self.object_lifetime_scope,
          "aliasClass": self.alias_class, "uniqueObject": self.unique_object,
          "boundsProven": self.bounds_proven, "alignmentProven": self.alignment_proven,
          "aliasComplete": self.alias_complete, "nonAtomic": self.non_atomic,
          "memoryOrder": self.memory_order, "complete": self.complete}
        if include_identity:
            result["factsIdentity"] = self.facts_identity
        return result

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


def memory_proof_facts_from_source_model(
    fragment_id: str, source_model: object,
) -> L2MemoryProofFacts | None:
    """Export one normalized load/store access without reading text or mnemonics."""
    operation = getattr(source_model, "operation", None)
    kind = str(getattr(getattr(operation, "kind", None), "value", ""))
    if kind not in {"load", "store"}:
        return None
    model = getattr(source_model, "operands", None)
    operands = tuple(getattr(model, "operands", ()))
    addresses = [item for item in operands
                 if str(getattr(getattr(item, "kind", None), "value", "")) == "address"
                 and getattr(item, "address", None) is not None]
    values = [item for item in operands if item not in addresses and
              str(getattr(getattr(item, "access", None), "value", "")) in
              ({"output", "read_write"} if kind == "load" else {"input", "read_write"})]
    if len(addresses) != 1 or len(values) != 1:
        return None
    address, value = addresses[0].address, values[0]
    width = getattr(value, "width_bits", None)
    offset = getattr(address, "byte_offset", None)
    alignment = getattr(address, "alignment_bytes", None)
    # A typed scalar C pointer supplies its pointee alignment at the compiler
    # boundary.  If Phase 6A has no numeric alignment yet, require natural
    # alignment and let the frontend sidecar binder prove the pointer type.
    required_alignment = alignment if isinstance(alignment, int) else (
        width // 8 if isinstance(width, int) else 0)
    safe = dict(
        unique_object=bool(getattr(address, "provenance_known", False)),
        bounds_proven=isinstance(offset, int) and offset >= 0,
        alignment_proven=(isinstance(offset, int) and required_alignment > 0
                          and offset % required_alignment == 0),
        alias_complete=len(addresses) == 1,
        non_atomic=not bool(getattr(getattr(source_model, "memory", None), "has_atomic", True)),
    )
    if (not isinstance(width, int) or width % 8 or width // 8 not in {1, 2, 4, 8}
            or not isinstance(offset, int) or required_alignment <= 0):
        return None
    return L2MemoryProofFacts(
        fragment_id, kind, addresses[0].source_operand_index,
        value.source_operand_index, offset, width // 8, required_alignment,
        "function_argument", "function_call", "object:0",
        memory_order="relaxed", complete=all(safe.values()), **safe,
    )


def memory_proof_facts_from_dict(value: Mapping[str, object]) -> L2MemoryProofFacts:
    fields = {"schemaVersion", "fragmentId", "accessKind", "addressOperandIndex",
      "valueOperandIndex", "byteOffset", "widthBytes", "requiredAlignment",
      "objectOriginKind", "objectLifetimeScope", "aliasClass", "uniqueObject",
      "boundsProven", "alignmentProven", "aliasComplete", "nonAtomic",
      "memoryOrder", "complete", "factsIdentity"}
    if set(value) != fields:
        raise ValueError("memory proof facts fields are incomplete or unknown")
    def text(key: str) -> str:
        item = value.get(key)
        if not isinstance(item, str) or not item:
            raise ValueError("memory proof " + key + " is invalid")
        return item
    def integer(key: str) -> int:
        item = value.get(key)
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError("memory proof " + key + " is invalid")
        return item
    def flag(key: str) -> bool:
        item = value.get(key)
        if not isinstance(item, bool):
            raise ValueError("memory proof " + key + " must be boolean")
        return item
    return L2MemoryProofFacts(
        text("fragmentId"), text("accessKind"), integer("addressOperandIndex"),
        integer("valueOperandIndex"), integer("byteOffset"), integer("widthBytes"),
        integer("requiredAlignment"), text("objectOriginKind"),
        text("objectLifetimeScope"), text("aliasClass"), flag("uniqueObject"),
        flag("boundsProven"), flag("alignmentProven"), flag("aliasComplete"),
        flag("nonAtomic"), text("memoryOrder"), flag("complete"),
        text("factsIdentity"), text("schemaVersion"),
    )


def bind_memory_object_authority(
    facts: L2MemoryProofFacts, operands: Sequence[L2OperandAuthority],
    access_authority: MemoryAccessAuthority | None = None,
) -> tuple[L2MemoryObjectAuthority, str]:
    by_index = {item.operand_index: item for item in operands}
    address = by_index.get(facts.address_operand_index)
    value = by_index.get(facts.value_operand_index)
    if not facts.complete or address is None or value is None:
        raise ValueError("memory proof operands/safety facts are incomplete")
    if address.parameter_index is None or address.escape_kind != "function_argument":
        raise ValueError("memory address is not bound to one function argument")
    if access_authority is None:
        raise ValueError("memory object requires compiler/harness object authority")
    if (not access_authority.complete
            or access_authority.fragment_id != facts.fragment_id
            or access_authority.base_operand_identity != address.declaration_id
            or access_authority.value_operand_identity != value.declaration_id):
        raise ValueError("memory access authority does not bind selected operands")
    end = facts.byte_offset + facts.width_bytes
    size = access_authority.object_size_bytes
    if size is None or end > size:
        raise ValueError("memory object bounds are not authoritative")
    object_id = access_authority.object_identity
    readable = ((facts.byte_offset, end),) if facts.access_kind == "load" else ()
    writable = ((facts.byte_offset, end),) if facts.access_kind == "store" else ()
    return L2MemoryObjectAuthority(
        object_id, facts.object_origin_kind, size,
        access_authority.proven_alignment_bytes,
        facts.object_lifetime_scope, access_authority.alias_domain_identity,
        readable, writable, True,
    ), object_id


@dataclass(frozen=True)
class L2MemoryObservation:
    event_id: str
    fragment_id: str
    event_kind: str
    logical_subject: str
    payload: Mapping[str, object]
    execution_order: int
    ordering_predecessors: tuple[str, ...] = ()
    schema_version: str = L2_MEMORY_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_MEMORY_OBSERVATION_SCHEMA:
            raise ValueError("memory observation schema is invalid")
        if self.event_kind not in {"ReadMemory", "WriteMemory"}:
            raise ValueError("memory observation event kind is invalid")
        required = {"objectId", "offset", "size", "value", "alignment",
                    "atomicity", "memoryOrder"}
        if set(self.payload) != required or self.payload.get("objectId") != self.logical_subject:
            raise ValueError("memory observation payload is incomplete")
        if "address" in self.payload or "pointer" in self.payload:
            raise ValueError("raw addresses are forbidden in memory observations")
        if (self.payload.get("atomicity") != "none"
                or self.payload.get("memoryOrder") != "relaxed"):
            raise ValueError("automatic scalar memory observation contract is invalid")
        for key in ("offset", "size", "alignment"):
            item = self.payload.get(key)
            if isinstance(item, bool) or not isinstance(item, int) or item < (0 if key == "offset" else 1):
                raise ValueError("memory observation numeric payload is invalid")
        if not isinstance(self.payload.get("value"), str) or not re.fullmatch(
                r"u(?:8|16|32|64):0x[0-9a-f]+", str(self.payload.get("value"))):
            raise ValueError("memory observation canonical value is invalid")

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion": self.schema_version, "eventId": self.event_id,
                "fragmentId": self.fragment_id, "eventKind": self.event_kind,
                "logicalSubject": self.logical_subject, "payload": dict(self.payload),
                "executionOrder": self.execution_order,
                "orderingPredecessors": list(self.ordering_predecessors)}


def exact_memory_observations_match(
    source: Sequence[L2MemoryObservation], target: Sequence[L2MemoryObservation],
    relations: Sequence[ApprovedEffectRelation],
) -> tuple[bool, str]:
    source_by_id = {item.event_id: item for item in source}
    target_by_id = {item.event_id: item for item in target}
    if len(source_by_id) != len(source) or len(target_by_id) != len(target):
        return False, "L2_MEMORY_EVENT_ID_DUPLICATE"
    expected_source = {item.source_effect_id for item in relations}
    expected_target = {target_id for item in relations for target_id in item.target_effect_ids}
    if set(source_by_id) != expected_source or set(target_by_id) != expected_target:
        return False, "L2_MEMORY_APPROVED_EFFECT_SET_MISMATCH"
    for relation in relations:
        if relation.relation_kind != "exact" or len(relation.target_effect_ids) != 1:
            return False, "L2_MEMORY_EXACT_RELATION_REQUIRED"
        left, right = source_by_id[relation.source_effect_id], target_by_id[relation.target_effect_ids[0]]
        if (left.event_kind != right.event_kind or left.logical_subject != right.logical_subject
                or dict(left.payload) != dict(right.payload)
                or left.execution_order != right.execution_order
                or left.ordering_predecessors != right.ordering_predecessors):
            return False, "L2_MEMORY_OBJECT_RELATIVE_TRACE_MISMATCH"
    return True, ""
