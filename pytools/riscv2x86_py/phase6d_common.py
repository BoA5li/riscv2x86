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
    REQUIREMENT_UNPROVEN="phase6d.requirement_unproven"; BINDING_UNSAFE="phase6d.binding_unsafe"

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
    contracts: Mapping[str, object] = MappingProxyType({})

    def contract(self, contract_id: str) -> object | None:
        return self.contracts.get(contract_id)

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
class ProofEvidence:
    """Stable, renderer-independent identity and per-dimension proof record."""
    source_model_id: str; preservation_level: str; preservation_decision_id: str; plan_id: str
    constraints_plan_id: str; constraints_id: str; target_environment_id: str
    target_catalog_version: str; compiler_capability_id: str
    helper_registry_version: str | None
    dimensions: tuple[str,...]; proved_requirements: tuple[str,...]

@dataclass(frozen=True)
class SemanticProofResult:
    approved: bool
    plan_id: str | None
    conclusions: tuple[PreservationConclusion,...] = ()
    reason_codes: tuple[SemanticProofReasonCode,...] = ()
    details: Mapping[str,str|int|bool|None] = MappingProxyType({})
    evidence: ProofEvidence | None = None
    def __post_init__(self):
        if self.approved and (self.reason_codes or self.evidence is None): raise ValueError("approved proof requires evidence and no reason codes")
        if not self.approved and not self.reason_codes: raise ValueError("failed proof needs reason code")
        object.__setattr__(self,"conclusions",tuple(sorted(set(self.conclusions),key=lambda x:x.value)))
        object.__setattr__(self,"reason_codes",tuple(sorted(set(self.reason_codes),key=lambda x:x.value)))
        object.__setattr__(self,"details",MappingProxyType(dict(self.details)))
    @classmethod
    def passed(cls, plan_id, conclusions, evidence): return cls(True,plan_id,tuple(conclusions),(),{},evidence)
    @classmethod
    def failed(cls, plan_id, code, details=None): return cls(False,plan_id,(PreservationConclusion.NOT_PRESERVED,),(code,),{} if details is None else details)

@dataclass(frozen=True)
class ApprovedTargetLoweringPlan:
    plan: TargetLoweringPlan; constraints: TargetConstraintModel; proof: SemanticProofResult
    def __post_init__(self):
        if not self.proof.approved or self.proof.plan_id != self.plan.plan_id or self.constraints.plan_id != self.plan.plan_id: raise ValueError("approved wrapper requires matching proof and constraints")

def reject(request, code, details=None): return SemanticProofResult.failed(getattr(getattr(request,"candidate_plan",None),"plan_id",None),code,details)

def constraint_identity(c):
    """Deterministic Phase-6C constraint identity; no renderer data involved."""
    operands=",".join(f"{x.source_operand_index}:{x.role.value}:{','.join(sorted(y.value for y in x.allowed_classes))}:{x.required_width_bits}:{x.required_signedness}:{x.tied_to_source_operand_index}:{x.early_clobber}:{x.fixed_register_name}" for x in c.operand_constraints)
    memory=c.memory_constraint
    control=c.control_flow_constraint
    contracts = tuple(
        item for item in (
            c.c_expression_constraint, c.c_builtin_constraint,
            c.x86_gnu_inline_asm_contract, c.x86_memory_inline_asm_contract,
            c.x86_atomic_contract, c.x86_barrier_contract,
            c.structured_control_flow_contract, c.helper_abi_contract,
        ) if item is not None
    )
    # Contract payload is part of the proof binding.  Type names alone would
    # permit a changed xadd/xchg or ordering contract to reuse stale evidence.
    contract_identity = ",".join(
        f"{type(item).__name__}:{repr(item)}" for item in contracts
    )
    return "|".join((c.plan_id, str(c.environment.architecture.value), str(c.environment.abi.value), operands, str((memory.requires_memory_clobber,memory.requires_atomic_ordering,memory.requires_compiler_barrier,memory.requires_hardware_barrier,memory.atomic_success_ordering,memory.atomic_failure_ordering,memory.required_atomic_width_bits,memory.required_alignment_bytes,memory.barrier_scope)), str((control.preserve_control_flow,control.preserve_asm_goto,control.preserve_retry_loop,control.requires_helper_abi_contract,control.preserve_stack_pointer,control.preserve_frame_pointer)), contract_identity))

def _evidence(request, conclusions, requirements):
    e=request.target_environment
    return ProofEvidence(
        source_model_id="|".join((request.source_model.operation.kind.value, ",".join(sorted(x.value for x in request.source_model.features)), ",".join(sorted(request.source_model.reason_codes)))),
        preservation_level=request.preservation_decision.level.value,
        preservation_decision_id=request.preservation_decision.level.value+":"+",".join(sorted(request.preservation_decision.reason_codes)),
        plan_id=request.candidate_plan.plan_id, constraints_plan_id=request.constraints.plan_id, constraints_id=constraint_identity(request.constraints),
        target_environment_id=f"{e.architecture.value}:{e.abi.value}:{e.asm_dialect.value}",
        target_catalog_version=request.target_semantic_catalog.version+":"+",".join(sorted(request.target_semantic_catalog.semantic_contract_ids)),
        compiler_capability_id=f"asm={request.compiler_capabilities.supports_gnu_inline_asm};goto={request.compiler_capabilities.supports_asm_goto}",
        helper_registry_version=None if request.helper_contract_registry is None else request.helper_contract_registry.version,
        dimensions=tuple(sorted(x.value for x in conclusions)),
        proved_requirements=tuple(sorted(x.value for x in requirements)),
    )

def validate_common(request: SemanticProofRequest):
    if not isinstance(request,SemanticProofRequest): return SemanticProofResult.failed(None,SemanticProofReasonCode.INVALID_REQUEST)
    s,p,c,e=request.source_model,request.candidate_plan,request.constraints,request.target_environment
    if not all((isinstance(s,SourceSemanticModel),isinstance(p,TargetLoweringPlan),isinstance(c,TargetConstraintModel),isinstance(e,TargetEnvironment),isinstance(request.preservation_decision,PreservationDecision),isinstance(request.target_semantic_catalog,TargetSemanticCatalog),isinstance(request.compiler_capabilities,CompilerCapabilityModel))): return reject(request,SemanticProofReasonCode.INVALID_REQUEST)
    if request.preservation_decision != s.preservation: return reject(request,SemanticProofReasonCode.PRESERVATION_MISMATCH)
    if c.plan_id != p.plan_id or c.environment != e: return reject(request,SemanticProofReasonCode.PLAN_CONSTRAINT_MISMATCH)
    if not p.supports_features(e.available_features): return reject(request,SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    if p.kind not in request.target_semantic_catalog.supported_plan_kinds: return reject(request,SemanticProofReasonCode.TARGET_SEMANTICS_MISSING)
    # A GNU-asm candidate is proof-eligible only when its *specific*,
    # versioned renderer semantic contract is present in the target catalog.
    # This checks structured plan metadata only; it does not inspect asm text.
    if p.kind in {TargetLoweringKind.X86_GNU_INLINE_ASM, TargetLoweringKind.X86_ATOMIC, TargetLoweringKind.X86_BARRIER, TargetLoweringKind.STRUCTURED_CONTROL_FLOW, TargetLoweringKind.HELPER_CALL}:
        semantic_contract_id = p.metadata.get("renderer_semantic_contract_id")
        if semantic_contract_id is None and p.kind is TargetLoweringKind.STRUCTURED_CONTROL_FLOW:
            flow = c.structured_control_flow_contract
            semantic_contract_id = None if flow is None else flow.semantic_contract_id
        if semantic_contract_id is None and p.kind is TargetLoweringKind.HELPER_CALL:
            helper = c.helper_abi_contract
            semantic_contract_id = None if helper is None else "helper." + helper.runtime_contract_id
        if (not isinstance(semantic_contract_id, str) or
                semantic_contract_id not in request.target_semantic_catalog.semantic_contract_ids):
            return reject(request, SemanticProofReasonCode.TARGET_SEMANTICS_MISSING, {
                "renderer_semantic_contract_id": (
                    semantic_contract_id if isinstance(semantic_contract_id, str) else None
                ),
            })
    if not all((s.operation.complete,s.operands.complete,s.implicit_state.complete,s.control_flow.cfg_ok,not s.control_flow.has_unknown_target,s.control_flow.has_indirect_control_flow is not None,not s.registers.has_unresolved_register_identity,s.completeness.runtime_facts_structurally_valid)) : return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    if (s.atomic.present and not s.atomic.complete) or (s.barrier.present and not s.barrier.complete) or (s.helper_abi.present and not s.helper_abi.complete): return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    if s.microarch.explicitly_microarch_sensitive and any(value is None for value in (s.microarch.has_timing_source,s.microarch.has_cache_operation,s.microarch.has_speculation_control)): return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    return None

def _validate_requirements(request):
    s,p,c=request.source_model,request.candidate_plan,request.constraints
    checks={
        PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS: s.operands.complete,
        PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS: all(x.width_bits is not None for x in s.operands.operands),
        PlanRequirement.PRESERVE_VOLATILE: (not s.shell.is_volatile or c.preserve_volatile),
        PlanRequirement.PRESERVE_CC_CLOBBER: (not s.shell.has_cc_clobber or c.preserve_cc_clobber),
        PlanRequirement.PRESERVE_MEMORY_CLOBBER: (not s.shell.has_memory_clobber or c.memory_constraint.requires_memory_clobber),
        PlanRequirement.PRESERVE_MEMORY_ORDERING: (not s.barrier.present or c.memory_constraint.requires_compiler_barrier or c.memory_constraint.requires_hardware_barrier),
        PlanRequirement.PRESERVE_ATOMIC_ORDERING: (not s.atomic.present or c.memory_constraint.requires_atomic_ordering),
        PlanRequirement.PRESERVE_CONTROL_FLOW: (not s.operation.has_control_flow or c.control_flow_constraint.preserve_control_flow),
        PlanRequirement.PRESERVE_ASM_GOTO: (not s.control_flow.has_asm_goto or c.control_flow_constraint.preserve_asm_goto),
        PlanRequirement.PRESERVE_STACK_FRAME: (not (s.registers.reads_or_writes_stack_pointer or s.registers.reads_or_writes_frame_pointer) or (c.control_flow_constraint.preserve_stack_pointer and c.control_flow_constraint.preserve_frame_pointer)),
        PlanRequirement.PRESERVE_MICROARCH_INTENT: (not s.microarch.explicitly_microarch_sensitive or s.microarch.has_structured_microarch_intent),
        PlanRequirement.PROVE_HELPER_ABI_CONTRACT: (p.kind is not TargetLoweringKind.HELPER_CALL or c.helper_abi_contract is not None),
        PlanRequirement.PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY: all(x.width_bits is not None for x in s.operands.operands),
        PlanRequirement.PROVE_DEFINED_C_SEMANTICS: (p.kind is not TargetLoweringKind.C_EXPRESSION or (s.value_operation is not None and s.value_operation.complete)),
    }
    for requirement in p.requirements:
        if requirement in checks and not checks[requirement]: return reject(request,SemanticProofReasonCode.REQUIREMENT_UNPROVEN,{"requirement":requirement.value})
    return None

def _validate_operand_bindings(request):
    available={x.source_operand_index:x for x in request.source_model.operands.operands}
    for target in request.constraints.operand_constraints:
        source=available.get(target.source_operand_index)
        if source is None or (target.required_width_bits is not None and target.required_width_bits != source.width_bits): return reject(request,SemanticProofReasonCode.BINDING_UNSAFE)
        early_clobber_strengthening = (
            request.candidate_plan.metadata.get("renderer_semantic_contract_id")
            == "x86.gnu-att.gpr.out-gpr-gpr-binary.v1"
            and target.role.value == "output"
            and source.access.value == "output"
            and target.early_clobber
            and not source.early_clobber
        )
        if (target.tied_to_source_operand_index != source.tied_to_source_operand_index or
                (target.early_clobber != source.early_clobber and
                 not early_clobber_strengthening)):
            return reject(request,SemanticProofReasonCode.BINDING_UNSAFE)
        # A proven X86_ATOMIC memory operand is the only permitted target
        # read-write/location adaptation for a source ADDRESS binding.  The
        # atomic proof additionally checks it is the contract's object index.
        atomic_memory_address = (
            request.candidate_plan.kind is TargetLoweringKind.X86_ATOMIC and
            target.role.value == "read_write" and
            any(item.value == "memory" for item in target.allowed_classes) and
            source.access.value == "address"
        )
        if target.role.value != source.access.value and not atomic_memory_address:
            return reject(request,SemanticProofReasonCode.BINDING_UNSAFE)
    return None

def finalize(request, conclusions):
    required=_validate_requirements(request)
    if required is not None:return required
    bindings=_validate_operand_bindings(request)
    if bindings is not None:return bindings
    from .phase6d_microarchitecture import preserve_microarchitecture
    result=preserve_microarchitecture(request)
    if result is not None:return result
    extra=() if not request.source_model.microarch.explicitly_microarch_sensitive else (PreservationConclusion.MICROARCH_INTENT_PRESERVED,)
    final=tuple(conclusions)+extra
    return SemanticProofResult.passed(request.candidate_plan.plan_id,final,_evidence(request,final,request.candidate_plan.requirements))

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
