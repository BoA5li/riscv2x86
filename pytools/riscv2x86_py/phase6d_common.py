"""Phase 6D DTOs and common D0-D4 gates; no raw-artifact access."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from .phase6c_constraints import TargetConstraintModel, TargetEnvironment
from .plan_types import PlanRequirement, TargetLoweringKind, TargetLoweringPlan
from .semantic_types import PreservationDecision
from .source_model import SourceSemanticModel

class SemanticProofReasonCode(str, Enum):
    INVALID_REQUEST="phase6d.invalid_request"; SOURCE_INCOMPLETE="phase6d.source_incomplete"
    PRESERVATION_MISMATCH="phase6d.preservation_mismatch"; PLAN_CONSTRAINT_MISMATCH="phase6d.plan_constraint_mismatch"
    TARGET_CAPABILITY_MISSING="phase6d.target_capability_missing"; TARGET_SEMANTICS_MISSING="phase6d.target_semantics_missing"
    SHELL_UNPRESERVED="phase6d.shell_unpreserved"; MEMORY_UNPRESERVED="phase6d.memory_unpreserved"
    ATOMIC_UNPRESERVED="phase6d.atomic_unpreserved"; BARRIER_UNPRESERVED="phase6d.barrier_unpreserved"
    CONTROL_FLOW_UNPRESERVED="phase6d.control_flow_unpreserved"; ABI_UNPRESERVED="phase6d.abi_unpreserved"
    MICROARCH_UNPRESERVED="phase6d.microarch_unpreserved"; PLAN_CONTRACT_MISSING="phase6d.plan_contract_missing"
    UNSUPPORTED_PLAN_KIND="phase6d.unsupported_plan_kind"; INTERNAL_INVARIANT="phase6d.internal_invariant"

class PreservationConclusion(str, Enum):
    ARCHITECTURE_EQUIVALENT="architecture_equivalent"; SHELL_PRESERVED="shell_preserved"
    MICROARCH_INTENT_PRESERVED="microarchitecture_intent_preserved"; MICROARCH_STRENGTHENED="microarchitecture_strengthened"
    BEST_EFFORT="best_effort"; NOT_PRESERVED="not_preserved"

@dataclass(frozen=True)
class TargetSemanticCatalog:
    """Versioned structured target semantic IDs; never instruction text."""
    supported_plan_kinds: frozenset[TargetLoweringKind]
    semantic_contract_ids: frozenset[str]
    version: str

@dataclass(frozen=True)
class CompilerCapabilityModel:
    supports_gnu_inline_asm: bool
    supports_asm_goto: bool
    builtin_capabilities: frozenset[str] = frozenset()

@dataclass(frozen=True)
class HelperSemanticContractRegistry:
    allowed_contract_ids: frozenset[str]
    version: str

@dataclass(frozen=True)
class SemanticProofRequest:
    source_model: SourceSemanticModel
    preservation_decision: PreservationDecision
    candidate_plan: TargetLoweringPlan
    constraints: TargetConstraintModel
    target_environment: TargetEnvironment
    target_semantic_catalog: TargetSemanticCatalog
    compiler_capabilities: CompilerCapabilityModel
    helper_contract_registry: HelperSemanticContractRegistry | None = None

@dataclass(frozen=True)
class SemanticProofResult:
    approved: bool
    plan_id: str | None
    conclusions: tuple[PreservationConclusion,...] = ()
    reason_codes: tuple[SemanticProofReasonCode,...] = ()
    details: Mapping[str,str|int|bool|None] = MappingProxyType({})
    def __post_init__(self):
        if self.approved and self.reason_codes: raise ValueError("approved proof has reason codes")
        if not self.approved and not self.reason_codes: raise ValueError("failed proof needs reason code")
        object.__setattr__(self,"conclusions",tuple(sorted(set(self.conclusions),key=lambda x:x.value)))
        object.__setattr__(self,"reason_codes",tuple(sorted(set(self.reason_codes),key=lambda x:x.value)))
        object.__setattr__(self,"details",MappingProxyType(dict(self.details)))
    @classmethod
    def passed(cls, plan_id, conclusions): return cls(True,plan_id,tuple(conclusions))
    @classmethod
    def failed(cls, plan_id, code, details=None): return cls(False,plan_id,(PreservationConclusion.NOT_PRESERVED,),(code,),{} if details is None else details)

@dataclass(frozen=True)
class ApprovedTargetLoweringPlan:
    plan: TargetLoweringPlan; constraints: TargetConstraintModel; proof: SemanticProofResult
    def __post_init__(self):
        if not self.proof.approved or self.proof.plan_id != self.plan.plan_id or self.constraints.plan_id != self.plan.plan_id: raise ValueError("approved wrapper requires matching proof and constraints")

def reject(request, code, details=None): return SemanticProofResult.failed(getattr(getattr(request,"candidate_plan",None),"plan_id",None),code,details)

def validate_common(request: SemanticProofRequest):
    if not isinstance(request,SemanticProofRequest): return SemanticProofResult.failed(None,SemanticProofReasonCode.INVALID_REQUEST)
    s,p,c,e=request.source_model,request.candidate_plan,request.constraints,request.target_environment
    if not all((isinstance(s,SourceSemanticModel),isinstance(p,TargetLoweringPlan),isinstance(c,TargetConstraintModel),isinstance(e,TargetEnvironment),isinstance(request.preservation_decision,PreservationDecision),isinstance(request.target_semantic_catalog,TargetSemanticCatalog),isinstance(request.compiler_capabilities,CompilerCapabilityModel))): return reject(request,SemanticProofReasonCode.INVALID_REQUEST)
    if request.preservation_decision != s.preservation: return reject(request,SemanticProofReasonCode.PRESERVATION_MISMATCH)
    if c.plan_id != p.plan_id or c.environment != e: return reject(request,SemanticProofReasonCode.PLAN_CONSTRAINT_MISMATCH)
    if not p.supports_features(e.available_features): return reject(request,SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    if p.kind not in request.target_semantic_catalog.supported_plan_kinds: return reject(request,SemanticProofReasonCode.TARGET_SEMANTICS_MISSING)
    if not s.operation.complete or not s.operands.complete or not s.implicit_state.complete: return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    return None

def finalize(request, conclusions):
    from .phase6d_microarchitecture import preserve_microarchitecture
    result=preserve_microarchitecture(request)
    if result is not None:return result
    extra=() if not request.source_model.microarch.explicitly_microarch_sensitive else (PreservationConclusion.MICROARCH_INTENT_PRESERVED,)
    return SemanticProofResult.passed(request.candidate_plan.plan_id,tuple(conclusions)+extra)

def run_semantic_proof_gate(*, source_model, preservation_decision=None, candidate_plan, constraints, target_environment, target_semantic_catalog=None, compiler_capabilities=None, helper_contract_registry=None):
    """D0-D4 then exactly one plan-specific proof; unknowns reject."""
    if preservation_decision is None and isinstance(source_model,SourceSemanticModel): preservation_decision=source_model.preservation
    if target_semantic_catalog is None or compiler_capabilities is None: return SemanticProofResult.failed(getattr(candidate_plan,"plan_id",None),SemanticProofReasonCode.INVALID_REQUEST)
    request=SemanticProofRequest(source_model,preservation_decision,candidate_plan,constraints,target_environment,target_semantic_catalog,compiler_capabilities,helper_contract_registry)
    common=validate_common(request)
    if common is not None:return common
    from . import phase6d_c_expression as ce, phase6d_c_builtin as cb, phase6d_x86_inline_asm as xa, phase6d_atomic as ab, phase6d_control_flow as cf, phase6d_helper_abi as ha
    dispatch={TargetLoweringKind.C_EXPRESSION:ce.prove,TargetLoweringKind.C_BUILTIN:cb.prove,TargetLoweringKind.X86_GNU_INLINE_ASM:xa.prove,TargetLoweringKind.X86_ATOMIC:ab.prove_atomic,TargetLoweringKind.X86_BARRIER:ab.prove_barrier,TargetLoweringKind.STRUCTURED_CONTROL_FLOW:cf.prove,TargetLoweringKind.HELPER_CALL:ha.prove}
    fn=dispatch.get(candidate_plan.kind)
    if fn is None:return reject(request,SemanticProofReasonCode.UNSUPPORTED_PLAN_KIND)
    try:return fn(request)
    except (AttributeError,TypeError,ValueError):return reject(request,SemanticProofReasonCode.INTERNAL_INVARIANT)
