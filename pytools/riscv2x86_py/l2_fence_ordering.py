"""Proof-owned fence ordering domains and strict L2 relation comparison."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .effect_relation import ApprovedEffectRelation, EffectOrderingRequirement


L2_FENCE_PROOF_FACTS_SCHEMA = "riscv2x86.l2-fence-proof-facts.v1"
L2_FENCE_OBSERVATION_SCHEMA = "riscv2x86.l2-fence-ordering-observation.v1"
_ORDERINGS = {"relaxed", "consume", "acquire", "release", "acq_rel", "seq_cst"}
_SCOPES = {"compiler", "thread", "system"}
_CONTRACTS = {
    "c.builtin.atomic-signal-fence.compiler-barrier.seq-cst.v1":
        (True, False, "seq_cst", "compiler"),
    "x86.gnu-att.mfence.full-system-seq-cst.v1":
        (True, True, "seq_cst", "system"),
}


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


@dataclass(frozen=True)
class L2FenceProofFacts:
    fragment_id: str
    before_effect_id: str
    fence_effect_id: str
    after_effect_id: str
    source_compiler_ordering: bool
    source_hardware_ordering: bool
    source_ordering: str
    source_scope: str
    target_compiler_ordering: bool
    target_hardware_ordering: bool
    target_ordering: str
    target_scope: str
    relation_kind: str
    target_contract_id: str
    target_contract_version: str
    source_domain_complete: bool
    target_contract_approved: bool
    instruction_visibility: bool
    complete: bool
    facts_identity: str = ""
    schema_version: str = L2_FENCE_PROOF_FACTS_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_FENCE_PROOF_FACTS_SCHEMA or not self.fragment_id:
            raise ValueError("fence proof facts schema/fragment is invalid")
        ids = (self.before_effect_id, self.fence_effect_id, self.after_effect_id)
        if any(not item for item in ids) or len(set(ids)) != 3:
            raise ValueError("fence proof ordering anchors are invalid")
        if self.source_ordering not in _ORDERINGS or self.target_ordering not in _ORDERINGS:
            raise ValueError("fence proof ordering is invalid")
        if self.source_scope not in _SCOPES or self.target_scope not in _SCOPES:
            raise ValueError("fence proof scope is invalid")
        if self.relation_kind not in {"exact", "strengthened"}:
            raise ValueError("fence proof relation kind is invalid")
        if not self.target_contract_id or not self.target_contract_version:
            raise ValueError("fence proof target contract identity/version is missing")
        closed = (self.source_domain_complete and self.target_contract_approved
                  and not self.instruction_visibility
                  and (self.source_compiler_ordering or self.source_hardware_ordering)
                  and (self.target_compiler_ordering or self.target_hardware_ordering))
        if self.complete != closed:
            raise ValueError("fence proof completeness does not match authority facts")
        expected = _identity(self._payload(False))
        if self.facts_identity and self.facts_identity != expected:
            raise ValueError("fence proof identity does not match content")
        object.__setattr__(self, "facts_identity", expected)

    def _payload(self, include_identity: bool) -> dict[str, object]:
        result = {"schemaVersion":self.schema_version, "fragmentId":self.fragment_id,
          "beforeEffectId":self.before_effect_id, "fenceEffectId":self.fence_effect_id,
          "afterEffectId":self.after_effect_id,
          "sourceCompilerOrdering":self.source_compiler_ordering,
          "sourceHardwareOrdering":self.source_hardware_ordering,
          "sourceOrdering":self.source_ordering, "sourceScope":self.source_scope,
          "targetCompilerOrdering":self.target_compiler_ordering,
          "targetHardwareOrdering":self.target_hardware_ordering,
          "targetOrdering":self.target_ordering, "targetScope":self.target_scope,
          "relationKind":self.relation_kind, "targetContractId":self.target_contract_id,
          "targetContractVersion":self.target_contract_version,
          "sourceDomainComplete":self.source_domain_complete,
          "targetContractApproved":self.target_contract_approved,
          "instructionVisibility":self.instruction_visibility, "complete":self.complete}
        if include_identity:
            result["factsIdentity"] = self.facts_identity
        return result

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


def fence_proof_facts_from_source_model(
    fragment_id: str, source_model: object, approval: Mapping[str, object],
) -> L2FenceProofFacts | None:
    """Bind a complete source barrier to a registered proof-selected contract."""
    barrier = getattr(source_model, "barrier", None)
    if (not bool(getattr(barrier, "present", False))
            or not bool(getattr(barrier, "complete", False))
            or bool(getattr(barrier, "instruction_serializing", True))):
        return None
    source_ordering = str(getattr(getattr(barrier, "ordering", None), "value", ""))
    source_scope = str(getattr(getattr(barrier, "scope", None), "value", ""))
    contract_id = str(approval.get("rendererContractId") or "")
    contract_version = str(approval.get("rendererVersion") or "")
    target = _CONTRACTS.get(contract_id)
    if not source_ordering or not source_scope or target is None or not contract_version:
        return None
    target_compiler, target_hardware, target_ordering, target_scope = target
    source_compiler = bool(getattr(barrier, "compiler_barrier", False))
    source_hardware = bool(getattr(barrier, "hardware_memory_barrier", False))
    exact = ((source_compiler, source_hardware, source_ordering, source_scope)
             == target)
    relation_kind = "exact" if exact else "strengthened"
    facts = dict(source_domain_complete=True, target_contract_approved=True,
                 instruction_visibility=False)
    return L2FenceProofFacts(
        fragment_id, "before:read", "fence:0", "after:write",
        source_compiler, source_hardware, source_ordering, source_scope,
        target_compiler, target_hardware, target_ordering, target_scope,
        relation_kind, contract_id, contract_version, complete=True,
        **facts,
    )


def fence_proof_facts_from_dict(value: Mapping[str, object]) -> L2FenceProofFacts:
    fields = {"schemaVersion", "fragmentId", "beforeEffectId", "fenceEffectId",
      "afterEffectId", "sourceCompilerOrdering", "sourceHardwareOrdering",
      "sourceOrdering", "sourceScope", "targetCompilerOrdering",
      "targetHardwareOrdering", "targetOrdering", "targetScope", "relationKind",
      "targetContractId", "targetContractVersion", "sourceDomainComplete",
      "targetContractApproved", "instructionVisibility", "complete", "factsIdentity"}
    if set(value) != fields:
        raise ValueError("fence proof facts fields are incomplete or unknown")
    def text(key: str) -> str:
        item = value.get(key)
        if not isinstance(item, str) or not item:
            raise ValueError("fence proof " + key + " is invalid")
        return item
    def flag(key: str) -> bool:
        item = value.get(key)
        if not isinstance(item, bool):
            raise ValueError("fence proof " + key + " must be boolean")
        return item
    return L2FenceProofFacts(
        text("fragmentId"), text("beforeEffectId"), text("fenceEffectId"),
        text("afterEffectId"), flag("sourceCompilerOrdering"),
        flag("sourceHardwareOrdering"), text("sourceOrdering"), text("sourceScope"),
        flag("targetCompilerOrdering"), flag("targetHardwareOrdering"),
        text("targetOrdering"), text("targetScope"), text("relationKind"),
        text("targetContractId"), text("targetContractVersion"),
        flag("sourceDomainComplete"), flag("targetContractApproved"),
        flag("instructionVisibility"), flag("complete"), text("factsIdentity"),
        text("schemaVersion"),
    )


def approved_fence_relations(facts: L2FenceProofFacts) -> tuple[ApprovedEffectRelation, ...]:
    if not facts.complete:
        raise ValueError("fence proof facts are incomplete")
    edge = (EffectOrderingRequirement(facts.before_effect_id, facts.after_effect_id),)
    return tuple(sorted((
        ApprovedEffectRelation("relation:after", facts.after_effect_id,
            ("target:" + facts.after_effect_id,), "exact", ("kind", "subject", "value"),
            (), "", True),
        ApprovedEffectRelation("relation:before", facts.before_effect_id,
            ("target:" + facts.before_effect_id,), "exact", ("kind", "subject", "value"),
            (), "", True),
        ApprovedEffectRelation("relation:fence", facts.fence_effect_id,
            ("target:" + facts.fence_effect_id,), facts.relation_kind,
            ("compiler_ordering", "hardware_ordering", "kind", "subject"),
            edge, "", True),
    ), key=lambda item: item.relation_id))


@dataclass(frozen=True)
class L2FenceOrderingEvent:
    event_id: str
    fragment_id: str
    event_kind: str
    logical_subject: str
    payload: Mapping[str, object]
    execution_order: int
    ordering_predecessors: tuple[str, ...]
    schema_version: str = L2_FENCE_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_FENCE_OBSERVATION_SCHEMA:
            raise ValueError("fence ordering observation schema is invalid")
        if self.event_kind not in {"ReadMemory", "Fence", "WriteMemory"}:
            raise ValueError("fence ordering event kind is invalid")
        if self.execution_order < 0 or len(set(self.ordering_predecessors)) != len(self.ordering_predecessors):
            raise ValueError("fence ordering event order/predecessors are invalid")
        expected = ({"value"} if self.event_kind != "Fence" else
                    {"compilerOrdering", "hardwareOrdering", "ordering", "scope",
                     "contractId", "contractVersion"})
        if set(self.payload) != expected:
            raise ValueError("fence ordering event payload is incomplete")

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion":self.schema_version, "eventId":self.event_id,
          "fragmentId":self.fragment_id, "eventKind":self.event_kind,
          "logicalSubject":self.logical_subject, "payload":dict(self.payload),
          "executionOrder":self.execution_order,
          "orderingPredecessors":list(self.ordering_predecessors)}


def fence_ordering_events(
    facts: L2FenceProofFacts, relations: Sequence[ApprovedEffectRelation], *, side: str,
) -> tuple[L2FenceOrderingEvent, ...]:
    by_source = {item.source_effect_id:item for item in relations}
    def event_id(source_id: str) -> str:
        relation = by_source.get(source_id)
        if relation is None or len(relation.target_effect_ids) != 1:
            raise ValueError("fence approved relation is missing an ordering anchor")
        return source_id if side == "source" else relation.target_effect_ids[0]
    before, fence, after = (event_id(facts.before_effect_id),
                            event_id(facts.fence_effect_id), event_id(facts.after_effect_id))
    compiler = facts.source_compiler_ordering if side == "source" else facts.target_compiler_ordering
    hardware = facts.source_hardware_ordering if side == "source" else facts.target_hardware_ordering
    ordering = facts.source_ordering if side == "source" else facts.target_ordering
    scope = facts.source_scope if side == "source" else facts.target_scope
    contract_id = "source:fence-domain" if side == "source" else facts.target_contract_id
    contract_version = facts.schema_version if side == "source" else facts.target_contract_version
    return (
        L2FenceOrderingEvent(before, facts.fragment_id, "ReadMemory", "ordering:before",
                             {"value":"u64:0x1122334455667788"}, 0, ()),
        L2FenceOrderingEvent(fence, facts.fragment_id, "Fence", "ordering:fence",
          {"compilerOrdering":compiler, "hardwareOrdering":hardware,
           "ordering":ordering, "scope":scope, "contractId":contract_id,
           "contractVersion":contract_version}, 1, (before,)),
        L2FenceOrderingEvent(after, facts.fragment_id, "WriteMemory", "ordering:after",
                             {"value":"u64:0x8877665544332211"}, 2, (fence,)),
    )


def _reachable(events: Mapping[str, L2FenceOrderingEvent], before: str, after: str) -> bool:
    visiting = [after]; seen = set()
    while visiting:
        current = visiting.pop()
        if current == before:
            return True
        if current in seen or current not in events:
            continue
        seen.add(current); visiting.extend(events[current].ordering_predecessors)
    return False


def _ordering_covers(source: object, target: object) -> bool:
    coverage = {
        "relaxed":{"relaxed", "consume", "acquire", "release", "acq_rel", "seq_cst"},
        "consume":{"consume", "acquire", "acq_rel", "seq_cst"},
        "acquire":{"acquire", "acq_rel", "seq_cst"},
        "release":{"release", "acq_rel", "seq_cst"},
        "acq_rel":{"acq_rel", "seq_cst"}, "seq_cst":{"seq_cst"},
    }
    return isinstance(source, str) and isinstance(target, str) and target in coverage.get(source, set())


def _scope_covers(source: object, target: object) -> bool:
    rank = {"compiler":0, "thread":1, "system":2}
    return source in rank and target in rank and rank[target] >= rank[source]


def fence_ordering_observations_match(
    source: Sequence[L2FenceOrderingEvent], target: Sequence[L2FenceOrderingEvent],
    relations: Sequence[ApprovedEffectRelation],
) -> tuple[bool, str]:
    source_by = {item.event_id:item for item in source}; target_by = {item.event_id:item for item in target}
    if len(source_by) != len(source) or len(target_by) != len(target):
        return False, "L2_FENCE_EVENT_ID_DUPLICATE"
    expected_source = {item.source_effect_id for item in relations}
    expected_target = {target_id for item in relations for target_id in item.target_effect_ids}
    if set(source_by) != expected_source or set(target_by) != expected_target:
        return False, "L2_FENCE_ORDERING_ANCHOR_MISSING"
    for relation in relations:
        if len(relation.target_effect_ids) != 1:
            return False, "L2_FENCE_RELATION_INVALID"
        left, right = source_by[relation.source_effect_id], target_by[relation.target_effect_ids[0]]
        if left.event_kind != right.event_kind or left.logical_subject != right.logical_subject:
            return False, "L2_FENCE_EVENT_MISMATCH"
        if left.event_kind != "Fence" and dict(left.payload) != dict(right.payload):
            return False, "L2_FENCE_ANCHOR_VALUE_MISMATCH"
        if left.event_kind == "Fence":
            lp, rp = left.payload, right.payload
            if relation.relation_kind == "exact" and (
                    lp.get("compilerOrdering"), lp.get("hardwareOrdering"),
                    lp.get("ordering"), lp.get("scope")) != (
                    rp.get("compilerOrdering"), rp.get("hardwareOrdering"),
                    rp.get("ordering"), rp.get("scope")):
                return False, "L2_FENCE_EXACT_RELATION_NOT_SATISFIED"
            if relation.relation_kind == "strengthened" and (
                    bool(lp.get("compilerOrdering")) and not bool(rp.get("compilerOrdering"))
                    or bool(lp.get("hardwareOrdering")) and not bool(rp.get("hardwareOrdering"))
                    or not _ordering_covers(lp.get("ordering"), rp.get("ordering"))
                    or not _scope_covers(lp.get("scope"), rp.get("scope"))):
                return False, "L2_FENCE_STRENGTHENED_RELATION_NOT_SATISFIED"
        for edge in relation.ordering_requirements:
            target_before = next((x.target_effect_ids[0] for x in relations
                                  if x.source_effect_id == edge.before), "")
            target_after = next((x.target_effect_ids[0] for x in relations
                                 if x.source_effect_id == edge.after), "")
            if not _reachable(source_by, edge.before, edge.after):
                return False, "L2_FENCE_SOURCE_ORDERING_EDGE_MISSING"
            if not target_before or not target_after or not _reachable(target_by, target_before, target_after):
                return False, "L2_FENCE_TARGET_ORDERING_EDGE_MISSING"
    return True, ""
