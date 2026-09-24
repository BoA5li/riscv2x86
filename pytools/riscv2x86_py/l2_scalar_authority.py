"""Typed, auditable decision for automatic scalar L2 authority materialization."""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
import re
from typing import Mapping

from .l2_fragment_execution import fragment_boundary_from_dict
from .l2_semantic_profile import (
    L2PatternKind, l2_fragment_semantic_profile_from_dict,
)


SCALAR_AUTHORITY_DECISION_SCHEMA = "riscv2x86.l2-scalar-authority-decision.v1"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_SCALAR_PATTERNS = {
    L2PatternKind.SCALAR, L2PatternKind.BRANCH, L2PatternKind.JUMP,
    L2PatternKind.COMPOSITE,
}


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


@dataclass(frozen=True)
class ScalarAuthorityMaterializationDecision:
    fragment_id: str
    materializable: bool
    boundary_identity: str
    semantic_profile_identity: str
    proof_identity: str
    reason_codes: tuple[str, ...]
    schema_version: str = SCALAR_AUTHORITY_DECISION_SCHEMA

    def __post_init__(self) -> None:
        if (self.schema_version != SCALAR_AUTHORITY_DECISION_SCHEMA
                or not self.fragment_id
                or self.reason_codes != tuple(sorted(set(self.reason_codes)))
                or any(not item for item in self.reason_codes)
                or self.materializable != (not self.reason_codes)):
            raise ValueError("scalar authority decision is inconsistent")
        for value in (self.boundary_identity, self.semantic_profile_identity,
                      self.proof_identity):
            if value and _SHA.fullmatch(value) is None:
                raise ValueError("scalar authority decision identity is invalid")
        if self.materializable and not all((
                self.boundary_identity, self.semantic_profile_identity,
                self.proof_identity)):
            raise ValueError("materializable scalar authority lacks identities")

    @property
    def decision_identity(self) -> str:
        return _identity(self.to_dict(include_identity=False))

    def with_reason(self, reason_code: str) -> "ScalarAuthorityMaterializationDecision":
        return replace(self, materializable=False,
                       reason_codes=tuple(sorted(set(self.reason_codes + (reason_code,)))))

    def to_dict(self, *, include_identity: bool = True) -> dict[str, object]:
        value = {
            "schemaVersion": self.schema_version,
            "fragmentId": self.fragment_id,
            "materializable": self.materializable,
            "boundaryIdentity": self.boundary_identity,
            "semanticProfileIdentity": self.semantic_profile_identity,
            "proofIdentity": self.proof_identity,
            "reasonCodes": list(self.reason_codes),
        }
        if include_identity:
            value["decisionIdentity"] = self.decision_identity
        return value


_BOUNDARY_REASON_MAP = {
    "L2_FRAGMENT_BOUNDARY_BINDING_MISSING":
        "L2_SCALAR_FRAGMENT_CANDIDATE_MISSING",
    "L2_FRAGMENT_BOUNDARY_RANGE_AMBIGUOUS":
        "L2_SCALAR_FRAGMENT_RANGE_AMBIGUOUS",
    "L2_FRAGMENT_OPERAND_ARITY_MISMATCH":
        "L2_SCALAR_OPERAND_ARITY_MISMATCH",
    "L2_FRAGMENT_VALUE_NODE_MISSING":
        "L2_SCALAR_VALUE_NODE_MISSING",
    "L2_FRAGMENT_INPUT_BINDING_MISSING":
        "L2_SCALAR_INPUT_BINDING_MISSING",
    "L2_FRAGMENT_OUTPUT_BINDING_MISSING":
        "L2_SCALAR_OUTPUT_BINDING_MISSING",
    "L2_FRAGMENT_LIVE_OUT_UNPROVED":
        "L2_SCALAR_LIVE_OUT_UNPROVED",
    "L2_FRAGMENT_DOWNSTREAM_USE_AMBIGUOUS":
        "L2_SCALAR_DOWNSTREAM_USE_AMBIGUOUS",
    "L2_FRAGMENT_OBSERVATION_SINK_MISSING":
        "L2_SCALAR_OBSERVATION_SINK_MISSING",
}


def _proof_identity(approval: Mapping[str, object], fragment_id: str) -> tuple[str, str]:
    proof = approval.get("proofIdentity")
    if (approval.get("proofStatus") != "approved"
            or approval.get("sourceFragmentId") not in {None, "", fragment_id}):
        return "", "L2_SCALAR_PROOF_IDENTITY_MISMATCH"
    if _SHA.fullmatch(str(proof)) is None:
        payload = {key: approval.get(key, "") for key in (
            "sourceModelId", "preservationDecisionId", "planId", "constraintsId",
            "proofStatus", "targetEnvironmentId", "targetCatalogVersion",
        )}
        if not all(payload.values()):
            return "", "L2_SCALAR_PROOF_IDENTITY_MISMATCH"
        proof = _identity(payload)
    return str(proof), ""


def assess_scalar_authority_materializability(
    finding: Mapping[str, object], function: Mapping[str, object] | None,
    fragment_boundary: Mapping[str, object] | None,
) -> ScalarAuthorityMaterializationDecision:
    """Assess only structured compiler/proof facts; never inspect asm text."""
    fragment = finding.get("fragment")
    approval = finding.get("approvalArtifact")
    fragment_id = (str(fragment.get("id") or fragment.get("fragmentId") or "")
                   if isinstance(fragment, Mapping) else "")
    if not fragment_id:
        # Decision records require a stable subject.  A malformed finding is
        # rejected by the report parser before it reaches normal production.
        fragment_id = "unbound-fragment"
    reasons: set[str] = set()
    boundary_identity = ""
    profile_identity = ""
    proof_identity = ""

    raw_profile = finding.get("l2SemanticProfile")
    try:
        if not isinstance(raw_profile, Mapping):
            raise ValueError("profile missing")
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
        profile_identity = profile.profile_identity
        if profile.pattern_kind not in _SCALAR_PATTERNS:
            reasons.add("L2_SCALAR_SEMANTIC_PROFILE_UNSUPPORTED")
        if not profile.complete:
            reasons.add("L2_SCALAR_SEMANTIC_PROFILE_INCOMPLETE")
    except ValueError:
        profile = None
        reasons.add("L2_SCALAR_SEMANTIC_PROFILE_INVALID")

    if not isinstance(approval, Mapping):
        reasons.add("L2_SCALAR_PROOF_IDENTITY_MISMATCH")
    else:
        proof_identity, proof_reason = _proof_identity(approval, fragment_id)
        if proof_reason:
            reasons.add(proof_reason)

    parsed_boundary = None
    legacy_boundary = False
    if not isinstance(fragment_boundary, Mapping):
        reasons.add("L2_SCALAR_FRAGMENT_CANDIDATE_MISSING")
    else:
        if "boundaryIdentity" not in fragment_boundary:
            legacy_boundary = True
            boundary_identity = _identity(fragment_boundary)
            outputs = fragment.get("outputs") if isinstance(fragment, Mapping) else None
            inputs = fragment.get("inputs") if isinstance(fragment, Mapping) else None
            asm_ids = fragment_boundary.get("asmOperandDeclarationIds")
            if fragment_boundary.get("complete") is not True:
                reasons.add("L2_SCALAR_FRAGMENT_CANDIDATE_MISSING")
            if (not isinstance(outputs, list) or not isinstance(inputs, list)
                    or not isinstance(asm_ids, list)
                    or len(asm_ids) != len(outputs or ()) + len(inputs or ())):
                reasons.add("L2_SCALAR_OPERAND_ARITY_MISMATCH")
            if not isinstance(outputs, list) or not outputs:
                reasons.add("L2_SCALAR_OUTPUT_BINDING_MISSING")
        else:
            try:
                parsed_boundary = fragment_boundary_from_dict(
                    fragment_boundary, expected_fragment_id=fragment_id)
                boundary_identity = parsed_boundary.boundary_identity
            except (TypeError, ValueError):
                reasons.add("L2_SCALAR_FRAGMENT_CANDIDATE_MISSING")

    if parsed_boundary is not None:
        reasons.update(_BOUNDARY_REASON_MAP.get(item, item)
                       for item in parsed_boundary.reason_codes)
        outputs = parsed_boundary.output_bindings
        inputs = parsed_boundary.input_bindings
        raw_outputs = fragment.get("outputs") if isinstance(fragment, Mapping) else None
        raw_inputs = fragment.get("inputs") if isinstance(fragment, Mapping) else None
        if not isinstance(raw_outputs, list) or len(outputs) != len(raw_outputs):
            reasons.add("L2_SCALAR_OUTPUT_BINDING_MISSING" if not outputs else
                        "L2_SCALAR_OPERAND_ARITY_MISMATCH")
        if not isinstance(raw_inputs, list) or len(inputs) != len(raw_inputs):
            reasons.add("L2_SCALAR_INPUT_BINDING_MISSING" if not inputs else
                        "L2_SCALAR_OPERAND_ARITY_MISMATCH")
        if any(not item.value_node_identity for item in outputs + inputs):
            reasons.add("L2_SCALAR_VALUE_NODE_MISSING")
        if outputs and not parsed_boundary.live_out_nodes:
            reasons.add("L2_SCALAR_LIVE_OUT_UNPROVED")
            reasons.add("L2_SCALAR_OBSERVATION_SINK_MISSING")

    if function is not None:
        arity = function.get("arity")
        if (isinstance(arity, bool) or not isinstance(arity, int)
                or not 1 <= arity <= 4):
            reasons.add("L2_SCALAR_AUTOMATIC_HARNESS_UNSUPPORTED")
        raw_function_boundary = function.get("l2OperandBoundary")
        candidates = (raw_function_boundary.get("fragmentCandidates")
                      if isinstance(raw_function_boundary, Mapping) else None)
        if (not legacy_boundary
                and (not isinstance(candidates, list) or not candidates)):
            reasons.add("L2_SCALAR_FRAGMENT_CANDIDATE_MISSING")

    if profile is not None and isinstance(approval, Mapping):
        if (profile.pattern_kind in {L2PatternKind.BRANCH, L2PatternKind.JUMP}
                and not isinstance(approval.get("l2ControlFlowProofFacts"), Mapping)):
            reasons.add("L2_SCALAR_EFFECT_RELATION_MISSING")
        if (profile.pattern_kind is L2PatternKind.COMPOSITE
                and not isinstance(approval.get("l2InternalValueProofFacts"), Mapping)):
            reasons.add("L2_SCALAR_OBSERVATION_SINK_MISSING")

    return ScalarAuthorityMaterializationDecision(
        fragment_id, not reasons, boundary_identity, profile_identity,
        proof_identity, tuple(sorted(reasons)))


def scalar_authority_decision_from_dict(
    value: Mapping[str, object], *, expected_fragment_id: str = "",
) -> ScalarAuthorityMaterializationDecision:
    payload = dict(value)
    claimed = payload.pop("decisionIdentity", None)
    reasons = value.get("reasonCodes")
    if not isinstance(reasons, list) or not all(
            isinstance(item, str) and item for item in reasons):
        raise ValueError("scalar authority decision reasons are invalid")
    result = ScalarAuthorityMaterializationDecision(
        str(value.get("fragmentId") or ""),
        value.get("materializable") is True,
        str(value.get("boundaryIdentity") or ""),
        str(value.get("semanticProfileIdentity") or ""),
        str(value.get("proofIdentity") or ""), tuple(reasons),
        str(value.get("schemaVersion") or ""))
    if claimed != result.decision_identity:
        raise ValueError("scalar authority decision identity does not match content")
    if expected_fragment_id and result.fragment_id != expected_fragment_id:
        raise ValueError("scalar authority decision fragment mismatch")
    return result


def scalar_authority_decision_matches_assessment(
    stored: ScalarAuthorityMaterializationDecision,
    assessed: ScalarAuthorityMaterializationDecision,
) -> bool:
    """Permit only the materializer-owned relation-absence refinement."""
    same_subject = (
        stored.fragment_id == assessed.fragment_id
        and stored.boundary_identity == assessed.boundary_identity
        and stored.semantic_profile_identity == assessed.semantic_profile_identity
        and stored.proof_identity == assessed.proof_identity
    )
    allowed = set(assessed.reason_codes)
    allowed.add("L2_SCALAR_EFFECT_RELATION_MISSING")
    return (same_subject
            and set(assessed.reason_codes).issubset(stored.reason_codes)
            and set(stored.reason_codes).issubset(allowed)
            and stored.materializable == (not stored.reason_codes))
