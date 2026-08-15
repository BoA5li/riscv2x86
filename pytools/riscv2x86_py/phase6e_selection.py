"""Phase 6E deterministic selection of complete, approved proof chains."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from .phase6c_constraints import TargetConstraintDerivationResult, TargetConstraintModel, TargetEnvironment
from .phase6d_common import PreservationConclusion, SemanticProofResult, constraint_identity
from .plan_types import TargetLoweringKind, TargetLoweringPlan
from .semantic_types import PreservationDecision
from .source_model import SourceSemanticModel

class FinalSelectionKind(str, Enum):
    SELECTED="selected"; NEEDS_ROUTE="needs_route"; KEEP="keep"; UNSUPPORTED="unsupported"; INVARIANT_VIOLATION="invariant_violation"
class SelectionTier(int, Enum):
    PUBLIC_PORTABLE=1; STRUCTURED_C=2; X86_INLINE_ASM=3; STRENGTHENED=4; BEST_EFFORT=5
class SelectionReasonCode(str, Enum):
    CONSTRAINT_NOT_DERIVED="phase6e.constraint_not_derived"; PROOF_REJECTED="phase6e.proof_rejected"; POLICY_EXCLUDED="phase6e.policy_excluded"; ARTIFACT_MISMATCH="phase6e.artifact_mismatch"; NO_APPROVED_PLAN="phase6e.no_approved_plan"

@dataclass(frozen=True)
class ProvenCandidate:
    plan: TargetLoweringPlan
    constraint_result: TargetConstraintDerivationResult
    proof_result: SemanticProofResult

@dataclass(frozen=True)
class Phase6ESelectionPolicy:
    policy_id: str="phase6e.semantic-fidelity"
    policy_version: str="1"
    allow_best_effort: bool=False
    allow_strengthened: bool=False
    allow_needs_route: bool=False
    allow_keep: bool=False
    registered_route_targets: tuple[str,...]=()

@dataclass(frozen=True)
class Phase6ESelectionRequest:
    source_model: SourceSemanticModel
    preservation_decision: PreservationDecision
    target_environment: TargetEnvironment
    candidates: tuple[ProvenCandidate,...]
    generated_plan_ids: frozenset[str]
    target_catalog_version: str=""
    compiler_capability_id: str=""
    helper_registry_version: str | None=None
    selection_policy: Phase6ESelectionPolicy=Phase6ESelectionPolicy()

@dataclass(frozen=True)
class ApprovedTargetLoweringPlan:
    plan: TargetLoweringPlan
    constraints: TargetConstraintModel
    proof: SemanticProofResult
    source_model_id: str
    preservation_decision_id: str
    target_environment_id: str
    selection_policy_id: str
    selection_policy_version: str
    selection_tier: SelectionTier
    def __post_init__(self):
        if not self.proof.approved or self.proof.evidence is None: raise ValueError("approved selection requires approved proof evidence")

@dataclass(frozen=True)
class CandidateRejectionSummary:
    plan_id: str
    reason_codes: tuple[str,...]

@dataclass(frozen=True)
class FinalSelectionResult:
    kind: FinalSelectionKind
    selected_plan: ApprovedTargetLoweringPlan | None=None
    route_target: str | None=None
    primary_reason_code: str | None=None
    secondary_reason_codes: tuple[str,...]=()
    rejected_candidates: tuple[CandidateRejectionSummary,...]=()
    selection_policy_id: str=""
    selection_policy_version: str=""

def _source_id(s):
    stack=s.stack_frame
    stack_id="none" if stack is None else ":".join((stack.kind.value,str(stack.initial_sp_origin),str(stack.frame_size_bytes),str(stack.required_alignment_bytes),str(stack.source_abi_alignment_bytes),str(stack.net_stack_delta_bytes),repr(stack.adjustments),repr(stack.accesses),repr(stack.pointer_uses),repr(stack.rebinding_accesses),str(stack.stack_address_rebinding_eligible),repr(stack.virtual_private_frame),str(stack.virtual_private_frame_eligible),repr(stack.escape_facts),str(stack.pointer_escapes),str(stack.requires_real_stack_identity),str(stack.has_dynamic_adjustment),str(stack.complete),repr(stack.missing_fact_codes)))
    return "|".join((s.operation.kind.value, ",".join(sorted(x.value for x in s.features)), ",".join(sorted(s.reason_codes)), stack_id,repr(s.abi_effects)))
def _environment_id(e): return f"{e.architecture.value}:{e.abi.value}:{e.asm_dialect.value}"
def _preservation_id(p): return p.level.value+":"+",".join(sorted(p.reason_codes))
def _summary(plan, *codes): return CandidateRejectionSummary(plan.plan_id,tuple(sorted(codes)))

def _artifact_error(r,c):
    p,e=c.plan,c.proof_result.evidence
    if p.plan_id not in r.generated_plan_ids:return "candidate_not_generated_by_phase6b"
    if c.constraint_result.plan_id != p.plan_id:return "constraint_plan_id_mismatch"
    if c.constraint_result.success and (c.constraint_result.constraints is None or c.constraint_result.constraints.environment != r.target_environment):return "constraint_environment_mismatch"
    if c.proof_result.approved and e is None:return "approved_proof_without_evidence"
    if e is not None and c.constraint_result.constraints is None:return "proof_without_constraints"
    if e is not None and (e.plan_id != p.plan_id or e.constraints_plan_id != p.plan_id or e.constraints_id != constraint_identity(c.constraint_result.constraints) or e.source_model_id != _source_id(r.source_model) or e.preservation_decision_id != _preservation_id(r.preservation_decision) or e.target_environment_id != _environment_id(r.target_environment) or e.target_catalog_version != r.target_catalog_version or e.compiler_capability_id != r.compiler_capability_id or e.helper_registry_version != r.helper_registry_version):return "proof_binding_mismatch"
    return None

def _policy_allows(r,c):
    proof=c.proof_result
    if not proof.approved or proof.evidence is None:return False
    x=set(proof.conclusions)
    if PreservationConclusion.NOT_PRESERVED in x:return False
    if PreservationConclusion.ARCHITECTURE_EQUIVALENT not in x:return False
    if r.source_model.microarch.explicitly_microarch_sensitive and PreservationConclusion.MICROARCH_INTENT_PRESERVED not in x:return False
    if PreservationConclusion.BEST_EFFORT in x and not r.selection_policy.allow_best_effort:return False
    if PreservationConclusion.MICROARCH_STRENGTHENED in x and not r.selection_policy.allow_strengthened:return False
    return True

def _tier(c):
    x=set(c.proof_result.conclusions); k=c.plan.kind
    if PreservationConclusion.BEST_EFFORT in x:return SelectionTier.BEST_EFFORT
    if PreservationConclusion.MICROARCH_STRENGTHENED in x:return SelectionTier.STRENGTHENED
    if k in {TargetLoweringKind.C_EXPRESSION,TargetLoweringKind.C_BUILTIN}:return SelectionTier.PUBLIC_PORTABLE
    if k in {TargetLoweringKind.C_STRUCTURED,TargetLoweringKind.VIRTUAL_PRIVATE_FRAME,TargetLoweringKind.ABI_WRAPPER_CALL}:return SelectionTier.STRUCTURED_C
    return SelectionTier.X86_INLINE_ASM
def _key(c): return (int(_tier(c)),c.plan.sort_key,c.plan.kind.value)

def select_final_target_lowering_plan(request: Phase6ESelectionRequest)->FinalSelectionResult:
    """Validate artifact identity then select only approved candidates; no proof rerun."""
    if not isinstance(request,Phase6ESelectionRequest) or request.preservation_decision != request.source_model.preservation:
        return FinalSelectionResult(FinalSelectionKind.INVARIANT_VIOLATION,primary_reason_code=SelectionReasonCode.ARTIFACT_MISMATCH.value)
    approved=[]; rejected=[]
    for candidate in sorted(request.candidates,key=lambda c:c.plan.sort_key):
        error=_artifact_error(request,candidate)
        if error:return FinalSelectionResult(FinalSelectionKind.INVARIANT_VIOLATION,primary_reason_code=SelectionReasonCode.ARTIFACT_MISMATCH.value,secondary_reason_codes=(error,))
        if not candidate.constraint_result.success:
            rejected.append(_summary(candidate.plan,SelectionReasonCode.CONSTRAINT_NOT_DERIVED.value,*[x.value for x in candidate.constraint_result.reason_codes]));continue
        if not candidate.proof_result.approved:
            rejected.append(_summary(candidate.plan,SelectionReasonCode.PROOF_REJECTED.value,*[x.value for x in candidate.proof_result.reason_codes]));continue
        if not _policy_allows(request,candidate):
            rejected.append(_summary(candidate.plan,SelectionReasonCode.POLICY_EXCLUDED.value));continue
        approved.append(candidate)
    if approved:
        chosen=sorted(approved,key=_key)[0]; ev=chosen.proof_result.evidence
        selected=ApprovedTargetLoweringPlan(chosen.plan,chosen.constraint_result.constraints,chosen.proof_result,ev.source_model_id,ev.preservation_decision_id,ev.target_environment_id,request.selection_policy.policy_id,request.selection_policy.policy_version,_tier(chosen))
        return FinalSelectionResult(FinalSelectionKind.SELECTED,selected_plan=selected,rejected_candidates=tuple(rejected),selection_policy_id=request.selection_policy.policy_id,selection_policy_version=request.selection_policy.policy_version)
    if request.selection_policy.allow_needs_route and request.selection_policy.registered_route_targets:
        return FinalSelectionResult(FinalSelectionKind.NEEDS_ROUTE,route_target=sorted(request.selection_policy.registered_route_targets)[0],rejected_candidates=tuple(rejected),selection_policy_id=request.selection_policy.policy_id,selection_policy_version=request.selection_policy.policy_version)
    if request.selection_policy.allow_keep:
        return FinalSelectionResult(FinalSelectionKind.KEEP,rejected_candidates=tuple(rejected),selection_policy_id=request.selection_policy.policy_id,selection_policy_version=request.selection_policy.policy_version)
    codes=tuple(sorted({x for item in rejected for x in item.reason_codes}))
    return FinalSelectionResult(FinalSelectionKind.UNSUPPORTED,primary_reason_code=SelectionReasonCode.NO_APPROVED_PLAN.value,secondary_reason_codes=codes,rejected_candidates=tuple(rejected),selection_policy_id=request.selection_policy.policy_id,selection_policy_version=request.selection_policy.policy_version)
