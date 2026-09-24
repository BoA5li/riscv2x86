"""One fail-closed decision shared by L2 classification and resolution."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .l2_authority import L2AuthoritySidecar, l2_authority_sidecar_from_dict
from .l2_dimensions import L2Dimension, parse_l2_dimensions
from .l2_effect_proof import effect_proof_facts_from_dict
from .l2_semantic_profile import L2PatternKind, profile_from_finding

FRAGMENT_L2_MATERIALIZATION_DECISION_SCHEMA = \
    "riscv2x86.fragment-l2-materialization-decision.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

_PROFILE_DIMENSIONS = {
    L2PatternKind.SCALAR: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.BRANCH: (L2Dimension.CONTROL_FLOW, L2Dimension.LOGICAL_OPERANDS,
                           L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.JUMP: (L2Dimension.CONTROL_FLOW, L2Dimension.LOGICAL_OPERANDS,
                         L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.MEMORY_LOAD: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.MEMORY_EFFECTS,
                                L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.MEMORY_STORE: (L2Dimension.LOGICAL_OPERANDS, L2Dimension.MEMORY_EFFECTS,
                                 L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.FENCE: (L2Dimension.MEMORY_EFFECTS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.INSTRUCTION_VISIBILITY_FENCE: (
        L2Dimension.MEMORY_EFFECTS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.PRIVILEGED_READ: (L2Dimension.PRIVILEGED_STATE,
                                    L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.PRIVILEGED_WRITE: (L2Dimension.PRIVILEGED_STATE,
                                     L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.ATOMIC: (L2Dimension.ATOMIC_MEMORY_ORDER, L2Dimension.LOGICAL_OPERANDS,
                           L2Dimension.MEMORY_EFFECTS, L2Dimension.SHELL_SEMANTICS),
    L2PatternKind.COMPOSITE: (L2Dimension.LOGICAL_OPERANDS,
                              L2Dimension.SHELL_SEMANTICS),
}


def _identity(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def required_dimensions_for_finding(finding: Mapping[str, object]) -> tuple[L2Dimension, ...]:
    profile = profile_from_finding(finding)
    dimensions = set(_PROFILE_DIMENSIONS.get(profile.pattern_kind, ()))
    if profile.pattern_kind is L2PatternKind.COMPOSITE:
        if profile.memory_shape.reads or profile.memory_shape.writes:
            dimensions.add(L2Dimension.MEMORY_EFFECTS)
        if (profile.control_flow_shape.internal_branch
                or profile.control_flow_shape.direct_jump
                or profile.control_flow_shape.external):
            dimensions.add(L2Dimension.CONTROL_FLOW)
        if profile.privileged_shape.present:
            dimensions.add(L2Dimension.PRIVILEGED_STATE)
    return tuple(sorted(dimensions, key=lambda item: item.value))


@dataclass(frozen=True)
class FragmentL2MaterializationDecision:
    fragment_id: str
    required_dimensions: tuple[L2Dimension, ...]
    boundary_complete: bool
    relation_complete: bool
    shell_complete: bool
    executable: bool
    reason_codes: tuple[str, ...]
    authority_identity: str = ""
    decision_identity: str = ""
    schema_version: str = FRAGMENT_L2_MATERIALIZATION_DECISION_SCHEMA

    def __post_init__(self):
        if self.schema_version != FRAGMENT_L2_MATERIALIZATION_DECISION_SCHEMA:
            raise ValueError("fragment L2 materialization schema is unsupported")
        if not self.fragment_id or not self.required_dimensions:
            raise ValueError("fragment L2 materialization identity/dimensions are missing")
        if self.required_dimensions != tuple(sorted(set(self.required_dimensions),
                                                     key=lambda item: item.value)):
            raise ValueError("fragment L2 dimensions are not canonical")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("fragment L2 reasons are not canonical")
        if self.authority_identity and _SHA256.fullmatch(self.authority_identity) is None:
            raise ValueError("fragment L2 authority identity is invalid")
        closed = (self.boundary_complete and self.relation_complete
                  and self.shell_complete and not self.reason_codes
                  and bool(self.authority_identity))
        if self.executable != closed:
            raise ValueError("fragment L2 executable flag does not match closure")
        expected = _identity(self._payload(False))
        if self.decision_identity and self.decision_identity != expected:
            raise ValueError("fragment L2 decision identity does not match content")
        object.__setattr__(self, "decision_identity", expected)

    def _payload(self, include_identity: bool):
        result = {"schemaVersion": self.schema_version,
                  "fragmentId": self.fragment_id,
                  "requiredDimensions": [item.value for item in self.required_dimensions],
                  "boundaryComplete": self.boundary_complete,
                  "relationComplete": self.relation_complete,
                  "shellComplete": self.shell_complete,
                  "executable": self.executable,
                  "reasonCodes": list(self.reason_codes),
                  "authorityIdentity": self.authority_identity}
        if include_identity:
            result["decisionIdentity"] = self.decision_identity
        return result

    def to_dict(self):
        return self._payload(True)


def fragment_l2_materialization_decision_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
) -> FragmentL2MaterializationDecision:
    fields = {"schemaVersion", "fragmentId", "requiredDimensions", "boundaryComplete",
              "relationComplete", "shellComplete", "executable", "reasonCodes",
              "authorityIdentity", "decisionIdentity"}
    if set(value) != fields:
        raise ValueError("fragment L2 decision fields are incomplete or unknown")
    dimensions = value.get("requiredDimensions")
    reasons = value.get("reasonCodes")
    if (not isinstance(dimensions, list) or not isinstance(reasons, list)
            or reasons != sorted(set(reasons))
            or not all(isinstance(item, str) and item for item in reasons)):
        raise ValueError("fragment L2 decision arrays are invalid")
    fragment_id = value.get("fragmentId")
    if (not isinstance(fragment_id, str) or not fragment_id
            or (expected_fragment_id and fragment_id != expected_fragment_id)):
        raise ValueError("fragment L2 decision fragment does not match")
    flags = tuple(value.get(name) for name in (
        "boundaryComplete", "relationComplete", "shellComplete", "executable"))
    if not all(isinstance(item, bool) for item in flags):
        raise ValueError("fragment L2 decision flags are invalid")
    return FragmentL2MaterializationDecision(
        fragment_id, parse_l2_dimensions(dimensions), *flags, tuple(reasons),
        str(value.get("authorityIdentity") or ""),
        str(value.get("decisionIdentity") or ""), str(value.get("schemaVersion") or ""))


def _sidecar_dimension_reasons(sidecar: L2AuthoritySidecar,
                               dimensions: Sequence[L2Dimension],
                               pattern: L2PatternKind) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if L2Dimension.LOGICAL_OPERANDS in dimensions and not sidecar.operands:
        reasons.append("L2_FRAGMENT_OPERAND_AUTHORITY_MISSING")
    if L2Dimension.CONTROL_FLOW in dimensions and not sidecar.control_flow:
        reasons.append("L2_FRAGMENT_CONTROL_FLOW_AUTHORITY_MISSING")
    if L2Dimension.MEMORY_EFFECTS in dimensions:
        if pattern in {L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE,
                       L2PatternKind.ATOMIC} and not sidecar.memory_objects:
            reasons.append("L2_FRAGMENT_MEMORY_OBJECT_AUTHORITY_MISSING")
        if pattern is L2PatternKind.FENCE and not sidecar.ordering:
            reasons.append("L2_FRAGMENT_ORDERING_AUTHORITY_MISSING")
        if pattern is L2PatternKind.INSTRUCTION_VISIBILITY_FENCE \
                and not sidecar.runtime_contracts:
            reasons.append("L2_FRAGMENT_RUNTIME_AUTHORITY_MISSING")
    if (L2Dimension.PRIVILEGED_STATE in dimensions
            or L2Dimension.TRAP_SEMANTICS in dimensions) and not sidecar.runtime_contracts:
        reasons.append("L2_FRAGMENT_PRIVILEGED_RUNTIME_AUTHORITY_MISSING")
    if L2Dimension.ATOMIC_MEMORY_ORDER in dimensions and not sidecar.memory_objects:
        reasons.append("L2_FRAGMENT_ATOMIC_AUTHORITY_MISSING")
    return not reasons, reasons


def assess_fragment_l2_materializability(
    finding: Mapping[str, object] | None = None,
    required_dimensions: Sequence[L2Dimension] | None = None, *,
    sidecar: L2AuthoritySidecar | None = None,
    materialization_decision: Mapping[str, object] | None = None,
    expected_fragment_id: str = "",
) -> FragmentL2MaterializationDecision:
    """Assess once from facts, or strictly validate the persisted decision."""
    if materialization_decision is not None:
        parsed = fragment_l2_materialization_decision_from_dict(
            materialization_decision, expected_fragment_id=expected_fragment_id)
        if required_dimensions is not None and parsed.required_dimensions != tuple(required_dimensions):
            raise ValueError("fragment L2 decision dimensions do not match requirement")
        return parsed
    if finding is None:
        raise ValueError("fragment L2 assessment requires finding facts")
    fragment = finding.get("fragment")
    fragment_id = (str(fragment.get("id") or fragment.get("fragmentId") or "")
                   if isinstance(fragment, Mapping) else "")
    dimensions = (tuple(required_dimensions) if required_dimensions is not None
                  else required_dimensions_for_finding(finding))
    reasons: list[str] = []
    try:
        profile = profile_from_finding(finding)
    except ValueError:
        profile = None
        reasons.append("L2_FRAGMENT_SEMANTIC_PROFILE_INVALID")
    approval = finding.get("approvalArtifact")
    if not isinstance(approval, Mapping):
        approval = {}
        reasons.append("L2_FRAGMENT_APPROVAL_MISSING")
    if sidecar is None:
        raw_sidecar = approval.get("l2AuthoritySidecar")
        if isinstance(raw_sidecar, Mapping):
            try:
                sidecar = l2_authority_sidecar_from_dict(
                    raw_sidecar, expected_fragment_id=fragment_id)
            except ValueError:
                reasons.append("L2_FRAGMENT_AUTHORITY_SIDECAR_INVALID")
        else:
            reasons.append("L2_FRAGMENT_AUTHORITY_SIDECAR_MISSING")
    boundary_complete = False
    relation_complete = False
    shell_complete = False
    authority_identity = ""
    if sidecar is not None:
        authority_identity = sidecar.authority_identity
        if not sidecar.complete:
            reasons.append("L2_FRAGMENT_AUTHORITY_SIDECAR_INCOMPLETE")
        dimension_complete, dimension_reasons = _sidecar_dimension_reasons(
            sidecar, dimensions,
            L2PatternKind.UNKNOWN if profile is None else profile.pattern_kind)
        boundary_complete = sidecar.complete and dimension_complete
        reasons.extend(dimension_reasons)
        relation_complete = bool(
            sidecar.complete and sidecar.source_effects
            and sidecar.approved_effect_relations
            and {item.effect_id for item in sidecar.source_effects}
                == {item.source_effect_id for item in sidecar.approved_effect_relations})
        if not relation_complete:
            reasons.append("L2_EFFECT_APPROVED_RELATION_MISSING")
    raw_effect = approval.get("l2EffectProofFacts")
    if isinstance(raw_effect, Mapping):
        try:
            facts = effect_proof_facts_from_dict(raw_effect)
            shell_complete = bool(facts.complete and facts.shell_relation.complete
                                  and facts.fragment_id == fragment_id)
        except ValueError:
            reasons.append("L2_FRAGMENT_SHELL_PROOF_INVALID")
    else:
        reasons.append("L2_FRAGMENT_SHELL_PROOF_MISSING")
    if not shell_complete and "L2_FRAGMENT_SHELL_PROOF_INVALID" not in reasons \
            and "L2_FRAGMENT_SHELL_PROOF_MISSING" not in reasons:
        reasons.append("L2_FRAGMENT_SHELL_PROOF_INCOMPLETE")
    canonical_reasons = tuple(sorted(set(reasons)))
    executable = bool(boundary_complete and relation_complete and shell_complete
                      and not canonical_reasons)
    return FragmentL2MaterializationDecision(
        fragment_id, dimensions, boundary_complete, relation_complete,
        shell_complete, executable, canonical_reasons, authority_identity)
