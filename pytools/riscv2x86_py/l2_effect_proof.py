"""Phase-6D produced, sample-independent L2 effect proof facts.

This module deliberately knows structured semantic models and lowering plans,
but never source mnemonics, rendered text, or L2 test samples.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Mapping

from .effect_relation import ApprovedEffectRelation, EffectOrderingRequirement

L2_EFFECT_PROOF_SCHEMA = "riscv2x86.l2-effect-proof-facts.v1"
_KINDS = frozenset({"exact", "strengthened", "runtime_mediated"})


def identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def proof_identity(evidence) -> str:
    return identity({
        "sourceModelId": evidence.source_model_id,
        "preservationDecisionId": evidence.preservation_decision_id,
        "planId": evidence.plan_id,
        "constraintsId": evidence.constraints_id,
        "proofStatus": "approved",
        "targetEnvironmentId": evidence.target_environment_id,
        "targetCatalogVersion": evidence.target_catalog_version,
    })


@dataclass(frozen=True)
class SourceEffectFact:
    effect_id: str
    effect_kind: str
    logical_subject: str
    complete: bool

    def to_dict(self):
        return {"effectId": self.effect_id, "effectKind": self.effect_kind,
                "logicalSubject": self.logical_subject, "complete": self.complete}


@dataclass(frozen=True)
class TargetEffectFact:
    effect_id: str
    effect_kind: str
    logical_subject: str
    complete: bool

    def to_dict(self):
        return {"effectId": self.effect_id, "effectKind": self.effect_kind,
                "logicalSubject": self.logical_subject, "complete": self.complete}


@dataclass(frozen=True)
class EffectRelationFact:
    relation_id: str
    source_effect_id: str
    target_effect_ids: tuple[str, ...]
    relation_kind: str
    preserved_properties: tuple[str, ...]
    not_claimed_properties: tuple[str, ...]
    runtime_contract_id: str
    runtime_contract_identity: str
    complete: bool
    ordering_requirements: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if self.relation_kind not in _KINDS:
            raise ValueError("unsupported L2 effect relation kind")
        if not self.relation_id or not self.source_effect_id or not self.target_effect_ids:
            raise ValueError("L2 effect relation is missing identities")
        if self.target_effect_ids != tuple(sorted(set(self.target_effect_ids))):
            raise ValueError("target effect identities must be unique and sorted")
        if self.preserved_properties != tuple(sorted(set(self.preserved_properties))):
            raise ValueError("preserved properties must be unique and sorted")
        if self.not_claimed_properties != tuple(sorted(set(self.not_claimed_properties))):
            raise ValueError("not-claimed properties must be unique and sorted")
        if self.relation_kind == "runtime_mediated" and not (
                self.runtime_contract_id and self.runtime_contract_identity):
            raise ValueError("runtime-mediated relation requires a bound contract")
        if self.relation_kind != "runtime_mediated" and (
                self.runtime_contract_id or self.runtime_contract_identity):
            raise ValueError("non-runtime relation cannot bind a runtime contract")

    def to_dict(self):
        return {"relationId": self.relation_id,
                "sourceEffectId": self.source_effect_id,
                "targetEffectIds": list(self.target_effect_ids),
                "relationKind": self.relation_kind,
                "preservedProperties": list(self.preserved_properties),
                "notClaimedProperties": list(self.not_claimed_properties),
                "runtimeContractId": self.runtime_contract_id,
                "runtimeContractIdentity": self.runtime_contract_identity,
                "complete": self.complete,
                "orderingRequirements": [list(x) for x in self.ordering_requirements]}

    def approved_relation(self) -> ApprovedEffectRelation:
        return ApprovedEffectRelation(
            self.relation_id, self.source_effect_id, self.target_effect_ids,
            self.relation_kind, self.preserved_properties,
            tuple(EffectOrderingRequirement(*x) for x in self.ordering_requirements),
            self.runtime_contract_id, self.complete)


@dataclass(frozen=True)
class ShellRelationFact:
    operand_modes: tuple[str, ...]
    constraints: tuple[str, ...]
    early_clobbers: tuple[int, ...]
    tied_operands: tuple[str, ...]
    memory_clobber_preserved: bool
    cc_clobber_preserved: bool
    volatile_placement_preserved: bool
    continuation_preserved: bool
    compiler_visibility_preserved: bool
    complete: bool

    def to_dict(self):
        return {"operandModes": list(self.operand_modes),
                "constraints": list(self.constraints),
                "earlyClobbers": list(self.early_clobbers),
                "tiedOperands": list(self.tied_operands),
                "memoryClobberPreserved": self.memory_clobber_preserved,
                "ccClobberPreserved": self.cc_clobber_preserved,
                "volatilePlacementPreserved": self.volatile_placement_preserved,
                "continuationPreserved": self.continuation_preserved,
                "compilerVisibilityPreserved": self.compiler_visibility_preserved,
                "complete": self.complete}


@dataclass(frozen=True)
class L2EffectProofFacts:
    fragment_id: str
    proof_identity: str
    plan_identity: str
    constraint_identity: str
    renderer_contract_identity: str
    source_effects: tuple[SourceEffectFact, ...]
    target_effects: tuple[TargetEffectFact, ...]
    relations: tuple[EffectRelationFact, ...]
    shell_relation: ShellRelationFact
    complete: bool
    schema_version: str = L2_EFFECT_PROOF_SCHEMA

    def __post_init__(self):
        if self.schema_version != L2_EFFECT_PROOF_SCHEMA:
            raise ValueError("unsupported L2 effect proof schema")
        source_ids = {item.effect_id for item in self.source_effects}
        target_ids = {item.effect_id for item in self.target_effects}
        if len(source_ids) != len(self.source_effects) or len(target_ids) != len(self.target_effects):
            raise ValueError("duplicate L2 effect identities")
        if {item.source_effect_id for item in self.relations} != source_ids:
            raise ValueError("relations must cover every source effect exactly")
        if any(not set(item.target_effect_ids).issubset(target_ids) for item in self.relations):
            raise ValueError("relation refers to an unknown target effect")
        if self.complete and (not self.source_effects or not self.shell_relation.complete
                              or not all(x.complete for x in (*self.source_effects,
                                                              *self.target_effects,
                                                              *self.relations))):
            raise ValueError("complete L2 effect proof has incomplete facts")

    def to_dict(self):
        value = {"schemaVersion": self.schema_version,
                 "fragmentId": self.fragment_id,
                 "proofIdentity": self.proof_identity,
                 "planIdentity": self.plan_identity,
                 "constraintIdentity": self.constraint_identity,
                 "rendererContractIdentity": self.renderer_contract_identity,
                 "sourceEffects": [x.to_dict() for x in self.source_effects],
                 "targetEffects": [x.to_dict() for x in self.target_effects],
                 "relations": [x.to_dict() for x in self.relations],
                 "shellRelation": self.shell_relation.to_dict(),
                 "complete": self.complete}
        value["factsIdentity"] = identity(value)
        return value


def _tuple_strings(value, key):
    raw = value.get(key)
    if not isinstance(raw, list) or not all(isinstance(x, str) and x for x in raw):
        raise ValueError(key + " is invalid")
    result = tuple(raw)
    if result != tuple(sorted(set(result))):
        raise ValueError(key + " must be unique and sorted")
    return result


def effect_proof_facts_from_dict(value: Mapping[str, object]) -> L2EffectProofFacts:
    raw = dict(value)
    claimed = raw.pop("factsIdentity", None)
    if set(raw) != {"schemaVersion", "fragmentId", "proofIdentity", "planIdentity",
                    "constraintIdentity", "rendererContractIdentity", "sourceEffects",
                    "targetEffects", "relations", "shellRelation", "complete"}:
        raise ValueError("L2 effect proof fields are incomplete or unknown")
    if claimed != identity(raw):
        raise ValueError("L2 effect proof facts identity mismatch")
    if raw.get("schemaVersion") != L2_EFFECT_PROOF_SCHEMA:
        raise ValueError("unsupported L2 effect proof schema")
    def effects(key, cls):
        items = raw.get(key)
        if not isinstance(items, list): raise ValueError(key + " is invalid")
        if any(not isinstance(x, Mapping) or set(x) != {
                "effectId", "effectKind", "logicalSubject", "complete"} for x in items):
            raise ValueError(key + " fields are incomplete or unknown")
        return tuple(cls(str(x.get("effectId", "")), str(x.get("effectKind", "")),
                         str(x.get("logicalSubject", "")), x.get("complete") is True)
                     for x in items if isinstance(x, Mapping))
    rels = raw.get("relations")
    if not isinstance(rels, list): raise ValueError("relations is invalid")
    relation_fields = {"relationId", "sourceEffectId", "targetEffectIds", "relationKind",
                       "preservedProperties", "notClaimedProperties", "runtimeContractId",
                       "runtimeContractIdentity", "complete", "orderingRequirements"}
    if any(not isinstance(x, Mapping) or set(x) != relation_fields for x in rels):
        raise ValueError("relation fields are incomplete or unknown")
    relations = tuple(EffectRelationFact(
        str(x.get("relationId", "")), str(x.get("sourceEffectId", "")),
        _tuple_strings(x, "targetEffectIds"), str(x.get("relationKind", "")),
        _tuple_strings(x, "preservedProperties"),
        _tuple_strings(x, "notClaimedProperties"),
        str(x.get("runtimeContractId", "")), str(x.get("runtimeContractIdentity", "")),
        x.get("complete") is True,
        tuple(tuple(pair) for pair in x.get("orderingRequirements", ())))
        for x in rels if isinstance(x, Mapping))
    shell = raw.get("shellRelation")
    if not isinstance(shell, Mapping): raise ValueError("shellRelation is invalid")
    if set(shell) != {"operandModes", "constraints", "earlyClobbers", "tiedOperands",
                      "memoryClobberPreserved", "ccClobberPreserved",
                      "volatilePlacementPreserved", "continuationPreserved",
                      "compilerVisibilityPreserved", "complete"}:
        raise ValueError("shell relation fields are incomplete or unknown")
    early = shell.get("earlyClobbers")
    if not isinstance(early, list) or not all(isinstance(x, int) and not isinstance(x, bool) for x in early):
        raise ValueError("earlyClobbers is invalid")
    shell_fact = ShellRelationFact(
        _tuple_strings(shell, "operandModes"), _tuple_strings(shell, "constraints"),
        tuple(early), _tuple_strings(shell, "tiedOperands"),
        shell.get("memoryClobberPreserved") is True,
        shell.get("ccClobberPreserved") is True,
        shell.get("volatilePlacementPreserved") is True,
        shell.get("continuationPreserved") is True,
        shell.get("compilerVisibilityPreserved") is True,
        shell.get("complete") is True)
    return L2EffectProofFacts(
        str(raw.get("fragmentId", "")), str(raw.get("proofIdentity", "")),
        str(raw.get("planIdentity", "")), str(raw.get("constraintIdentity", "")),
        str(raw.get("rendererContractIdentity", "")),
        effects("sourceEffects", SourceEffectFact), effects("targetEffects", TargetEffectFact),
        relations, shell_fact, raw.get("complete") is True)


def build_effect_proof_facts(request, evidence, fragment_id: str) -> L2EffectProofFacts:
    """Produce semantic effects once, after Phase-6D has discharged all gates."""
    source = request.source_model
    plan = request.candidate_plan
    constraints = request.constraints
    semantic_contract = str(plan.metadata.get("renderer_semantic_contract_id", ""))
    renderer_identity = identity({"semanticContractId": semantic_contract,
                                  "planId": plan.plan_id,
                                  "constraintsId": evidence.constraints_id})
    runtime_contract_id = ""
    for candidate in (constraints.privileged_runtime_constraint,
                      constraints.privileged_functional_constraint):
        if candidate is not None:
            contract = getattr(candidate, "runtime_contract", None) or getattr(candidate, "fallback_contract", None)
            runtime_contract_id = str(getattr(contract, "contract_id", ""))
            break
    runtime_identity = (identity({"contractId": runtime_contract_id,
                                  "rendererContractIdentity": renderer_identity})
                        if runtime_contract_id else "")
    relation_kind = "runtime_mediated" if runtime_contract_id else "exact"
    # One relation describes a semantic effect family; observations carry a
    # separate sample identity and all reference this stable relation.
    if source.operation.has_control_flow:
        effects = [("control:continuation", "ControlTransfer", "continuation:proved",
                    ("branch_condition", "branch_continuation", "branch_outcome",
                     "kind", "target", "value"))]
    elif source.barrier.present:
        effects = [
            ("before:read", "ReadMemory", "ordering:before", ("kind", "subject", "value")),
            ("fence:0", "Fence", "ordering:fence",
             ("kind", "subject", "compiler_ordering", "hardware_ordering")),
            ("after:write", "WriteMemory", "ordering:after", ("kind", "subject", "value")),
        ]
    elif source.memory.reads_memory or source.memory.writes_memory:
        effects = [("memory:access", ("ReadMemory" if source.memory.reads_memory
                                      and not source.memory.writes_memory else "WriteMemory"),
                    "memory:proved-object",
                    ("kind", "subject", "value", "memory_coordinates", "memory_order"))]
    elif source.privileged_state is not None:
        effects = [("privileged:operation", "PrivilegedOperation", "privileged:state",
                    ("kind", "subject", "value"))]
    else:
        effects = [("scalar:continuation", "ScalarResult", "continuation:return",
                    ("branch_continuation", "kind", "value"))]
    # IDs are route-semantic and deliberately independent of sample cardinality.
    effects = sorted(set(effects), key=lambda x: x[0])
    source_effects = tuple(SourceEffectFact(a, b, c, True) for a, b, c, _ in effects)
    target_effects = tuple(TargetEffectFact("target:" + a, b, c, True)
                           for a, b, c, _ in effects)
    not_claimed = (("architectural_equivalence",) if relation_kind == "runtime_mediated"
                   and request.preservation_decision.level.value != "architecture_equivalent" else ())
    relations = tuple(EffectRelationFact(
        "relation:" + effect_id, effect_id, ("target:" + effect_id,),
        ("strengthened" if source.barrier.present and effect_id == "fence:0"
         and "microarchitecture_strengthened" in evidence.dimensions else relation_kind),
        tuple(sorted(properties)), tuple(sorted(not_claimed)), runtime_contract_id,
        runtime_identity, True,
        (("before:read", "after:write"),) if effect_id == "fence:0" else ())
        for effect_id, _kind, _subject, properties in effects)
    target_by_index = {x.source_operand_index: x for x in constraints.operand_constraints}
    operand_modes = tuple(sorted(
        f"{x.source_operand_index}:{x.access.value}" for x in source.operands.operands))
    target_constraints = tuple(sorted(
        f"{i}:{','.join(sorted(c.value for c in x.allowed_classes))}:{x.gnu_constraint_body or ''}"
        for i, x in target_by_index.items()))
    early = tuple(sorted(x.source_operand_index for x in source.operands.operands if x.early_clobber))
    tied = tuple(sorted(f"{x.source_operand_index}:{x.tied_to_source_operand_index}"
                        for x in source.operands.operands
                        if x.tied_to_source_operand_index is not None))
    shell = ShellRelationFact(
        operand_modes, target_constraints, early, tied,
        source.memory.writes_memory or source.memory.reads_memory,
        True, True, True, True, True)
    return L2EffectProofFacts(
        fragment_id, proof_identity(evidence), plan.plan_id, evidence.constraints_id,
        renderer_identity, source_effects, target_effects, relations, shell, True)
