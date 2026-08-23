"""Phase 6D DTOs and common D0-D4 gates; no raw-artifact access."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from .phase6c_constraints import TargetConstraintModel, TargetEnvironment
from .plan_types import PlanRequirement, TargetLoweringKind, TargetLoweringPlan
from .semantic_types import PreservationDecision
from .source_model import SourceSemanticModel
from .target_register_policy import POLICY_VERSION, is_forbidden_host_stack_frame_register

_STRICT_PRIVILEGED_KINDS = frozenset({
    TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER,
    TargetLoweringKind.SYSCALL_OR_SERVICE_ABI_ADAPTER,
    TargetLoweringKind.PRIVILEGED_EVENT_ADAPTER,
    TargetLoweringKind.MMU_RUNTIME_ADAPTER,
    TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER,
})


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
    TARGET_FIXED_REGISTER_POLICY_VIOLATION="phase6d.target_fixed_register_policy_violation"
    FUNCTIONAL_FALLBACK_UNPROVEN="phase6d.privileged_functional_fallback_unproven"
    IGNORED_STATE_UNPROVEN="phase6d.privileged_ignored_state_unproven"
    PRIVILEGED_CSR_MAPPING_UNPROVEN="phase6d.privileged.csr-mapping-unproven"
    PRIVILEGED_TRAP_MAPPING_UNPROVEN="phase6d.privileged.trap-mapping-unproven"
    PRIVILEGED_RETURN_CONTINUATION_UNPROVEN="phase6d.privileged.return-continuation-unproven"
    PRIVILEGED_INTERRUPT_MAPPING_UNPROVEN="phase6d.privileged.interrupt-mapping-unproven"
    PRIVILEGED_MMU_MAPPING_UNPROVEN="phase6d.privileged.mmu-mapping-unproven"
    PRIVILEGED_TLB_SCOPE_UNPROVEN="phase6d.privileged.tlb-scope-unproven"
    PRIVILEGED_VIRTUALIZATION_MAPPING_UNPROVEN="phase6d.privileged.virtualization-mapping-unproven"
    PRIVILEGED_IGNORED_STATE_ESCAPE="phase6d.privileged.ignored-state-escape"
    PRIVILEGED_TARGET_SIDE_EFFECT_UNPROVEN="phase6d.privileged.target-side-effect-unproven"

class PreservationConclusion(str, Enum):
    ARCHITECTURE_EQUIVALENT="architecture_equivalent"; SHELL_PRESERVED="shell_preserved"
    FUNCTIONAL_EQUIVALENT="functional_equivalent"
    MICROARCH_INTENT_PRESERVED="microarchitecture_intent_preserved"; MICROARCH_STRENGTHENED="microarchitecture_strengthened"
    BEST_EFFORT="best_effort"; NOT_PRESERVED="not_preserved"
    ARCHITECTURE_STATE_NOT_PRESERVED="architecture_state_not_preserved"
    MICROARCHITECTURE_NOT_PRESERVED="microarchitecture_not_preserved"

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
    privileged_runtime_registry: object | None = None
    privileged_functional_registry: object | None = None
    privileged_functional_policy: object | None = None

@dataclass(frozen=True)
class ProofEvidence:
    """Stable, renderer-independent identity and per-dimension proof record."""
    source_model_id: str; preservation_level: str; preservation_decision_id: str; plan_id: str
    constraints_plan_id: str; constraints_id: str; target_environment_id: str
    target_catalog_version: str; compiler_capability_id: str
    helper_registry_version: str | None
    privileged_registry_version: str | None
    privileged_mapping_registry_version: str | None
    privileged_functional_registry_version: str | None
    privileged_functional_policy_identity: str | None
    dimensions: tuple[str,...]; proved_requirements: tuple[str,...]
    privileged_effect_evidence: tuple["PrivilegedEffectProofEvidence", ...] = ()
    privileged_effect_proof_identity: str | None = None


@dataclass(frozen=True)
class PrivilegedEffectProofEvidence:
    source_effect_id: str
    target_mapping_id: str
    contract_id: str
    contract_version: str
    obligation_ids: tuple[str, ...]
    conclusion: str

    def __post_init__(self):
        for name in ("source_effect_id", "target_mapping_id", "contract_id", "contract_version", "conclusion"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise TypeError(f"{name} must be non-empty")
        if tuple(sorted(set(self.obligation_ids))) != self.obligation_ids:
            raise ValueError("effect proof obligations must be unique and sorted")

    @property
    def proof_id(self) -> str:
        return "sha256:" + sha256(repr((
            self.source_effect_id, self.target_mapping_id, self.contract_id,
            self.contract_version, self.obligation_ids, self.conclusion,
        )).encode("utf-8")).hexdigest()


def privileged_effect_proof_identity(evidence):
    values = tuple(evidence)
    if tuple(sorted(values, key=lambda item: item.source_effect_id)) != values:
        raise ValueError("privileged effect evidence must use stable sorting")
    return "sha256:" + sha256(repr(values).encode("utf-8")).hexdigest()

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
    operands=",".join(f"{x.source_operand_index}:{x.role.value}:{','.join(sorted(y.value for y in x.allowed_classes))}:{x.required_width_bits}:{x.required_signedness}:{x.tied_to_source_operand_index}:{x.early_clobber}:{x.fixed_register_name}:{x.gnu_constraint_body}" for x in c.operand_constraints)
    memory=c.memory_constraint
    control=c.control_flow_constraint
    contracts = tuple(
        item for item in (
            c.c_expression_constraint, c.c_builtin_constraint,
            c.x86_gnu_inline_asm_contract, c.x86_memory_inline_asm_contract,
            c.x86_atomic_contract, c.x86_barrier_contract,
            c.structured_control_flow_contract, c.helper_abi_contract,
            c.stack_rebinding_constraint,
            c.virtual_private_frame_constraint,
            c.abi_wrapper_constraint,
            c.privileged_runtime_constraint,
            c.privileged_functional_constraint,
        ) if item is not None
    )
    # Contract payload is part of the proof binding.  Type names alone would
    # permit a changed xadd/xchg or ordering contract to reuse stale evidence.
    contract_identity = ",".join(
        f"{type(item).__name__}:{repr(item)}" for item in contracts
    )
    return "|".join((c.plan_id, str(c.environment.architecture.value), str(c.environment.abi.value), c.target_register_policy_version, operands, str((memory.requires_memory_clobber,memory.requires_atomic_ordering,memory.requires_compiler_barrier,memory.requires_hardware_barrier,memory.atomic_success_ordering,memory.atomic_failure_ordering,memory.required_atomic_width_bits,memory.required_alignment_bytes,memory.barrier_scope)), str((control.preserve_control_flow,control.preserve_asm_goto,control.preserve_retry_loop,control.requires_helper_abi_contract,control.preserve_stack_pointer,control.preserve_frame_pointer)), contract_identity))

def _evidence(request, conclusions, requirements, privileged_effect_evidence=()):
    e=request.target_environment
    stack=request.source_model.stack_frame
    stack_id="none" if stack is None else ":".join((stack.kind.value,str(stack.initial_sp_origin),str(stack.frame_size_bytes),str(stack.required_alignment_bytes),str(stack.source_abi_alignment_bytes),str(stack.net_stack_delta_bytes),repr(stack.adjustments),repr(stack.accesses),repr(stack.pointer_uses),repr(stack.rebinding_accesses),str(stack.stack_address_rebinding_eligible),repr(stack.virtual_private_frame),str(stack.virtual_private_frame_eligible),repr(stack.escape_facts),str(stack.pointer_escapes),str(stack.requires_real_stack_identity),str(stack.has_dynamic_adjustment),str(stack.complete),repr(stack.missing_fact_codes)))
    effect_evidence = tuple(sorted(privileged_effect_evidence, key=lambda item: item.source_effect_id))
    return ProofEvidence(
        source_model_id="|".join((request.source_model.operation.kind.value, ",".join(sorted(x.value for x in request.source_model.features)), ",".join(sorted(request.source_model.reason_codes)), stack_id,repr(request.source_model.abi_effects),repr(request.source_model.privileged_state))),
        preservation_level=request.preservation_decision.level.value,
        preservation_decision_id=request.preservation_decision.level.value+":"+",".join(sorted(request.preservation_decision.reason_codes)),
        plan_id=request.candidate_plan.plan_id, constraints_plan_id=request.constraints.plan_id, constraints_id=constraint_identity(request.constraints),
        target_environment_id=f"{e.architecture.value}:{e.abi.value}:{e.asm_dialect.value}",
        target_catalog_version=request.target_semantic_catalog.version+":"+",".join(sorted(request.target_semantic_catalog.semantic_contract_ids)),
        compiler_capability_id=f"asm={request.compiler_capabilities.supports_gnu_inline_asm};goto={request.compiler_capabilities.supports_asm_goto}",
        helper_registry_version=None if request.helper_contract_registry is None else request.helper_contract_registry.version,
        privileged_registry_version=(None if request.privileged_runtime_registry is None
                                     else getattr(request.privileged_runtime_registry,"version",None)),
        privileged_mapping_registry_version=(
            None if request.privileged_runtime_registry is None
            else getattr(getattr(request.privileged_runtime_registry, "mapping_registries", None), "version", None)
        ),
        privileged_functional_registry_version=(
            None if request.privileged_functional_registry is None
            else getattr(request.privileged_functional_registry, "version", None)
        ),
        privileged_functional_policy_identity=(
            None if request.privileged_functional_policy is None
            else getattr(request.privileged_functional_policy, "identity", None)
        ),
        dimensions=tuple(sorted(x.value for x in conclusions)),
        proved_requirements=tuple(sorted(x.value for x in requirements)),
        privileged_effect_evidence=effect_evidence,
        privileged_effect_proof_identity=(
            None if not effect_evidence else privileged_effect_proof_identity(effect_evidence)
        ),
    )

def validate_common(request: SemanticProofRequest):
    if not isinstance(request,SemanticProofRequest): return SemanticProofResult.failed(None,SemanticProofReasonCode.INVALID_REQUEST)
    s,p,c,e=request.source_model,request.candidate_plan,request.constraints,request.target_environment
    if not all((isinstance(s,SourceSemanticModel),isinstance(p,TargetLoweringPlan),isinstance(c,TargetConstraintModel),isinstance(e,TargetEnvironment),isinstance(request.preservation_decision,PreservationDecision),isinstance(request.target_semantic_catalog,TargetSemanticCatalog),isinstance(request.compiler_capabilities,CompilerCapabilityModel))): return reject(request,SemanticProofReasonCode.INVALID_REQUEST)
    if request.preservation_decision != s.preservation: return reject(request,SemanticProofReasonCode.PRESERVATION_MISMATCH)
    if c.plan_id != p.plan_id or c.environment != e: return reject(request,SemanticProofReasonCode.PLAN_CONSTRAINT_MISMATCH)
    if c.target_register_policy_version != POLICY_VERSION or any(
        operand.requires_fixed_register and is_forbidden_host_stack_frame_register(operand.fixed_register_name)
        for operand in c.operand_constraints
    ):
        return reject(request, SemanticProofReasonCode.TARGET_FIXED_REGISTER_POLICY_VIOLATION)
    if not p.supports_features(e.available_features): return reject(request,SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    if p.kind not in request.target_semantic_catalog.supported_plan_kinds: return reject(request,SemanticProofReasonCode.TARGET_SEMANTICS_MISSING)
    # A GNU-asm candidate is proof-eligible only when its *specific*,
    # versioned renderer semantic contract is present in the target catalog.
    # This checks structured plan metadata only; it does not inspect asm text.
    if p.kind in {TargetLoweringKind.X86_GNU_INLINE_ASM, TargetLoweringKind.X86_ATOMIC, TargetLoweringKind.X86_BARRIER, TargetLoweringKind.STRUCTURED_CONTROL_FLOW, TargetLoweringKind.HELPER_CALL, TargetLoweringKind.STACK_ADDRESS_REBINDING, TargetLoweringKind.VIRTUAL_PRIVATE_FRAME, TargetLoweringKind.ABI_WRAPPER_CALL, *_STRICT_PRIVILEGED_KINDS, TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK}:
        semantic_contract_id = p.metadata.get("renderer_semantic_contract_id")
        if semantic_contract_id is None and p.kind is TargetLoweringKind.STRUCTURED_CONTROL_FLOW:
            flow = c.structured_control_flow_contract
            semantic_contract_id = None if flow is None else flow.semantic_contract_id
        if semantic_contract_id is None and p.kind is TargetLoweringKind.HELPER_CALL:
            helper = c.helper_abi_contract
            semantic_contract_id = None if helper is None else "helper." + helper.runtime_contract_id
        if semantic_contract_id is None and p.kind in _STRICT_PRIVILEGED_KINDS:
            privileged = c.privileged_runtime_constraint
            semantic_contract_id = (None if privileged is None else
                                    privileged.runtime_contract.semantic_contract_id)
        if semantic_contract_id is None and p.kind is TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK:
            privileged = c.privileged_functional_constraint
            semantic_contract_id = (None if privileged is None else
                                    privileged.fallback_contract.semantic_contract_id)
        if (not isinstance(semantic_contract_id, str) or
                semantic_contract_id not in request.target_semantic_catalog.semantic_contract_ids):
            return reject(request, SemanticProofReasonCode.TARGET_SEMANTICS_MISSING, {
                "renderer_semantic_contract_id": (
                    semantic_contract_id if isinstance(semantic_contract_id, str) else None
                ),
            })
    rebinding_complete = p.kind in {TargetLoweringKind.STACK_ADDRESS_REBINDING,TargetLoweringKind.VIRTUAL_PRIVATE_FRAME} and s.stack_frame is not None and (s.stack_frame.stack_address_rebinding_eligible or s.stack_frame.virtual_private_frame_eligible)
    operand_complete = s.operands.complete or rebinding_complete
    implicit_complete = s.implicit_state.complete or rebinding_complete
    operation_complete=s.operation.complete or (p.kind is TargetLoweringKind.VIRTUAL_PRIVATE_FRAME and s.stack_frame is not None and s.stack_frame.virtual_private_frame_eligible) or (p.kind is TargetLoweringKind.ABI_WRAPPER_CALL and s.abi_effects is not None and s.abi_effects.complete) or (p.kind in (_STRICT_PRIVILEGED_KINDS | {TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK}) and s.privileged_state is not None and s.privileged_state.complete)
    control_complete=(s.control_flow.has_indirect_control_flow is not None or (p.kind is TargetLoweringKind.VIRTUAL_PRIVATE_FRAME and s.stack_frame is not None and s.stack_frame.virtual_private_frame_eligible) or (p.kind is TargetLoweringKind.ABI_WRAPPER_CALL and s.abi_effects is not None and s.abi_effects.complete))
    if not all((operation_complete,operand_complete,implicit_complete,s.control_flow.cfg_ok,not s.control_flow.has_unknown_target,control_complete,not s.registers.has_unresolved_register_identity,s.completeness.runtime_facts_structurally_valid)) : return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    stack_sensitive = s.registers.reads_or_writes_stack_pointer or s.registers.reads_or_writes_frame_pointer
    if stack_sensitive and (s.stack_frame is None or not s.stack_frame.complete): return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    if (s.atomic.present and not s.atomic.complete) or (s.barrier.present and not s.barrier.complete) or (s.helper_abi.present and not s.helper_abi.complete and p.kind not in {TargetLoweringKind.STACK_ADDRESS_REBINDING,TargetLoweringKind.VIRTUAL_PRIVATE_FRAME}): return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    if s.microarch.explicitly_microarch_sensitive and any(value is None for value in (s.microarch.has_timing_source,s.microarch.has_cache_operation,s.microarch.has_speculation_control)): return reject(request,SemanticProofReasonCode.SOURCE_INCOMPLETE)
    return None

def _validate_requirements(request):
    s,p,c=request.source_model,request.candidate_plan,request.constraints
    checks={
        PlanRequirement.AUTHORITATIVE_OPERAND_BINDINGS: s.operands.complete or (p.kind is TargetLoweringKind.STACK_ADDRESS_REBINDING and s.stack_frame is not None and s.stack_frame.stack_address_rebinding_eligible),
        PlanRequirement.AUTHORITATIVE_OPERAND_WIDTHS: all(x.width_bits is not None for x in s.operands.operands),
        PlanRequirement.PRESERVE_VOLATILE: (not s.shell.is_volatile or c.preserve_volatile),
        PlanRequirement.PRESERVE_CC_CLOBBER: (not s.shell.has_cc_clobber or c.preserve_cc_clobber),
        PlanRequirement.PRESERVE_MEMORY_CLOBBER: (not s.shell.has_memory_clobber or c.memory_constraint.requires_memory_clobber),
        PlanRequirement.PRESERVE_MEMORY_ORDERING: (not s.barrier.present or c.memory_constraint.requires_compiler_barrier or c.memory_constraint.requires_hardware_barrier),
        PlanRequirement.PRESERVE_ATOMIC_ORDERING: (not s.atomic.present or c.memory_constraint.requires_atomic_ordering),
        PlanRequirement.PRESERVE_CONTROL_FLOW: (not s.operation.has_control_flow or c.control_flow_constraint.preserve_control_flow),
        PlanRequirement.PRESERVE_ASM_GOTO: (not s.control_flow.has_asm_goto or c.control_flow_constraint.preserve_asm_goto),
        PlanRequirement.PRESERVE_STACK_FRAME: (not (s.registers.reads_or_writes_stack_pointer or s.registers.reads_or_writes_frame_pointer) or (s.stack_frame is not None and s.stack_frame.complete and not s.stack_frame.requires_whole_function_lowering and c.control_flow_constraint.preserve_stack_pointer and c.control_flow_constraint.preserve_frame_pointer)),
        PlanRequirement.AUTHORITATIVE_STACK_ACCESS_BINDINGS: (s.stack_frame is not None and s.stack_frame.stack_address_rebinding_eligible),
        PlanRequirement.PRESERVE_STACK_LAYOUT: (c.stack_rebinding_constraint is not None),
        PlanRequirement.PRESERVE_STACK_ALIGNMENT: (s.stack_frame is not None and all(x.guaranteed_alignment_bytes is not None and x.required_alignment_bytes is not None and x.guaranteed_alignment_bytes >= x.required_alignment_bytes for x in s.stack_frame.rebinding_accesses)),
        PlanRequirement.PROVE_NO_STACK_ADDRESS_ESCAPE: (s.stack_frame is not None and not s.stack_frame.pointer_escapes and not s.stack_frame.requires_real_stack_identity and getattr(s.stack_frame.escape_facts,"analysis_complete",False) and not getattr(s.stack_frame.escape_facts,"unknown_use_present",True)),
        PlanRequirement.PROVE_NO_HOST_STACK_POINTER_MUTATION: (c.stack_rebinding_constraint is not None and c.stack_rebinding_constraint.forbids_host_stack_pointer_mutation),
        PlanRequirement.PROVE_STACK_OBJECT_BOUNDS: (s.stack_frame is not None and all(x.object_size_bytes is not None and x.target_object_offset_bytes + x.width_bits // 8 <= x.object_size_bytes for x in s.stack_frame.rebinding_accesses)),
        PlanRequirement.PROVE_STATIC_BALANCED_PRIVATE_FRAME: (s.stack_frame is not None and s.stack_frame.virtual_private_frame_eligible and s.stack_frame.net_stack_delta_bytes == 0),
        PlanRequirement.PROVE_FRAME_LAYOUT_COMPLETE: (s.stack_frame is not None and s.stack_frame.virtual_private_frame is not None and s.stack_frame.virtual_private_frame.layout_complete),
        PlanRequirement.PROVE_FRAME_ACCESS_BOUNDS: (s.stack_frame is not None and s.stack_frame.virtual_private_frame is not None and all(x.complete for x in s.stack_frame.virtual_private_frame.accesses)),
        PlanRequirement.PROVE_PRIVATE_FRAME_INITIALIZATION: (s.stack_frame is not None and s.stack_frame.virtual_private_frame is not None and s.stack_frame.virtual_private_frame.initialization_complete),
        PlanRequirement.PROVE_NO_REAL_STACK_IDENTITY: (s.stack_frame is not None and not s.stack_frame.requires_real_stack_identity),
        PlanRequirement.PROVE_NO_EXPLICIT_HOST_STACK_POINTER_MUTATION: (c.virtual_private_frame_constraint is not None and c.virtual_private_frame_constraint.forbids_explicit_host_stack_pointer_mutation),
        PlanRequirement.PROVE_PRIVATE_FRAME_VALUE_FLOW: (s.stack_frame is not None and s.stack_frame.virtual_private_frame is not None and all(x.value_operand_index is not None for x in s.stack_frame.virtual_private_frame.accesses)),
        PlanRequirement.PRESERVE_PRIVATE_FRAME_ALIGNMENT: (s.stack_frame is not None and s.stack_frame.virtual_private_frame is not None and c.virtual_private_frame_constraint is not None and c.virtual_private_frame_constraint.required_alignment_bytes >= s.stack_frame.virtual_private_frame.required_alignment_bytes),
        PlanRequirement.PRESERVE_MICROARCH_INTENT: (not s.microarch.explicitly_microarch_sensitive or s.microarch.has_structured_microarch_intent),
        PlanRequirement.PROVE_HELPER_ABI_CONTRACT: (p.kind is not TargetLoweringKind.HELPER_CALL or c.helper_abi_contract is not None),
        PlanRequirement.PROVE_EXACT_ABI_WRAPPER_CONTRACT: c.abi_wrapper_constraint is not None,
        PlanRequirement.PROVE_DIRECT_CALLEE_IDENTITY: s.abi_effects is not None and s.abi_effects.complete,
        PlanRequirement.PROVE_ARGUMENT_LOCATION_MAPPING: c.abi_wrapper_constraint is not None,
        PlanRequirement.PROVE_RETURN_LOCATION_MAPPING: c.abi_wrapper_constraint is not None,
        PlanRequirement.PROVE_CALLER_SAVED_EFFECTS: s.abi_effects is not None and s.abi_effects.caller_saved_effects_complete,
        PlanRequirement.PROVE_CALLEE_SAVED_PRESERVATION: s.abi_effects is not None and s.abi_effects.callee_saved_effects_complete,
        PlanRequirement.PROVE_CALL_STACK_ALIGNMENT: c.abi_wrapper_constraint is not None and c.abi_wrapper_constraint.target_call_stack_alignment_bytes > 0,
        PlanRequirement.PROVE_CALL_MEMORY_EFFECTS: c.abi_wrapper_constraint is not None,
        PlanRequirement.PROVE_NO_UNWIND_OR_NONLOCAL_TRANSFER: c.abi_wrapper_constraint is not None and c.abi_wrapper_constraint.forbids_unwind,
        PlanRequirement.PROVE_PIC_PLT_TLS_COMPATIBILITY: s.abi_effects is not None and s.abi_effects.pic_plt_tls_effects_complete,
        PlanRequirement.PROVE_NO_OBSERVABLE_RA_STATE: s.abi_effects is not None and not s.abi_effects.reads_ra and not s.abi_effects.writes_ra,
        PlanRequirement.PROVE_EXACT_PRIVILEGED_RUNTIME_CONTRACT: c.privileged_runtime_constraint is not None,
        PlanRequirement.PROVE_PRIVILEGED_STATE_COMPLETE: s.privileged_state is not None and s.privileged_state.complete,
        PlanRequirement.PROVE_PRIVILEGED_EFFECT_COVERAGE: c.privileged_runtime_constraint is not None and c.privileged_runtime_constraint.runtime_contract.preserves_architectural_state,
        PlanRequirement.PROVE_TARGET_EXECUTION_PROFILE: c.privileged_runtime_constraint is not None and c.privileged_runtime_constraint.target_environment_id == f"{c.environment.architecture.value}:{c.environment.abi.value}:{c.environment.asm_dialect.value}",
        PlanRequirement.PRESERVE_PRIVILEGED_TRAPS: c.privileged_runtime_constraint is not None and c.privileged_runtime_constraint.runtime_contract.preserves_trap_behavior,
        PlanRequirement.PRESERVE_PRIVILEGED_CONTROL_FLOW: c.privileged_runtime_constraint is not None and c.privileged_runtime_constraint.runtime_contract.preserves_control_flow,
        PlanRequirement.PRESERVE_PRIVILEGED_MEMORY_EFFECTS: c.privileged_runtime_constraint is not None and c.privileged_runtime_constraint.runtime_contract.preserves_memory_effects,
        PlanRequirement.PRESERVE_PRIVILEGED_SHELL: (
            (c.privileged_runtime_constraint is not None
             and c.privileged_runtime_constraint.runtime_contract.preserves_shell)
            or
            (c.privileged_functional_constraint is not None
             and c.privileged_functional_constraint.fallback_contract.preserves_shell)
        ),
        PlanRequirement.PROVE_NO_GENERIC_HELPER_FALLBACK: (
            (p.kind in _STRICT_PRIVILEGED_KINDS
             and c.privileged_runtime_constraint is not None
             and c.privileged_runtime_constraint.forbids_generic_helper_fallback)
            or
            (p.kind is TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK
             and c.privileged_functional_constraint is not None
             and c.privileged_functional_constraint.forbids_generic_helper_fallback)
        ),
        PlanRequirement.PROVE_FUNCTIONAL_FALLBACK_POLICY_ENABLED: c.privileged_functional_constraint is not None and request.privileged_functional_policy is not None and getattr(request.privileged_functional_policy,"enabled",False),
        PlanRequirement.PROVE_FUNCTIONAL_OBSERVABILITY_COMPLETE: s.privileged_state is not None and s.privileged_state.observability is not None and s.privileged_state.observability.complete,
        PlanRequirement.PROVE_EXACT_PRIVILEGED_FUNCTIONAL_CONTRACT: c.privileged_functional_constraint is not None,
        PlanRequirement.PRESERVE_FUNCTIONAL_OUTPUTS: c.privileged_functional_constraint is not None and c.privileged_functional_constraint.fallback_contract.preserves_outputs,
        PlanRequirement.PRESERVE_FUNCTIONAL_MEMORY: c.privileged_functional_constraint is not None and c.privileged_functional_constraint.fallback_contract.preserves_memory,
        PlanRequirement.PRESERVE_FUNCTIONAL_ERROR: c.privileged_functional_constraint is not None and c.privileged_functional_constraint.fallback_contract.preserves_errors,
        PlanRequirement.PRESERVE_FUNCTIONAL_TERMINATION: c.privileged_functional_constraint is not None and c.privileged_functional_constraint.fallback_contract.preserves_termination,
        PlanRequirement.PRESERVE_FUNCTIONAL_TRAPS: c.privileged_functional_constraint is not None and c.privileged_functional_constraint.fallback_contract.preserves_traps,
        PlanRequirement.PROVE_IGNORED_PRIVILEGED_STATE_AUTHORITY: c.privileged_functional_constraint is not None and s.privileged_state is not None and s.privileged_state.observability is not None and c.privileged_functional_constraint.fallback_contract.ignored_state_ids == tuple(x.state_id for x in s.privileged_state.observability.ignored_states),
        PlanRequirement.PROVE_NO_UNKNOWN_PRIVILEGED_STATE: s.privileged_state is not None and s.privileged_state.complete and not s.privileged_state.reason_codes and s.privileged_state.state is not None and s.privileged_state.state.complete and not s.privileged_state.state.missing_fact_codes,
        PlanRequirement.PROVE_SOURCE_TARGET_WIDTH_COMPATIBILITY: all(x.width_bits is not None for x in s.operands.operands),
        PlanRequirement.PROVE_DEFINED_C_SEMANTICS: (p.kind is not TargetLoweringKind.C_EXPRESSION or (s.value_operation is not None and s.value_operation.complete)) and (p.kind is not TargetLoweringKind.STACK_ADDRESS_REBINDING or (s.stack_frame is not None and s.stack_frame.stack_address_rebinding_eligible)) and (p.kind is not TargetLoweringKind.VIRTUAL_PRIVATE_FRAME or (s.stack_frame is not None and s.stack_frame.virtual_private_frame_eligible)),
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
            in {
                "x86.gnu-att.gpr.out-gpr-gpr-binary.v1",
                "x86.gnu-att.gpr.out-gpr-immediate-binary.v1",
                "x86.gnu-att.gpr.out-gpr-variable-shift.u32-u64.v1",
                "x86.gnu-att.gpr.out-gpr-immediate-shift.u32-u64.v1",
            }
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
        direct_memory_address = (
            request.candidate_plan.kind is TargetLoweringKind.X86_GNU_INLINE_ASM and
            request.constraints.x86_memory_inline_asm_contract is not None and
            target.role.value == "input" and
            any(item.value == "general_register" for item in target.allowed_classes) and
            source.access.value == "address"
        )
        if target.role.value != source.access.value and not atomic_memory_address and not direct_memory_address:
            return reject(request,SemanticProofReasonCode.BINDING_UNSAFE)
    return None

def finalize(request, conclusions, privileged_effect_evidence=()):
    required=_validate_requirements(request)
    if required is not None:return required
    bindings=_validate_operand_bindings(request)
    if bindings is not None:return bindings
    from .phase6d_microarchitecture import preserve_microarchitecture
    result=preserve_microarchitecture(request)
    if result is not None:return result
    extra=() if not request.source_model.microarch.explicitly_microarch_sensitive else (PreservationConclusion.MICROARCH_INTENT_PRESERVED,)
    final=tuple(conclusions)+extra
    return SemanticProofResult.passed(request.candidate_plan.plan_id,final,_evidence(request,final,request.candidate_plan.requirements,privileged_effect_evidence))

def run_semantic_proof_gate(*, source_model, preservation_decision=None, candidate_plan, constraints, target_environment, target_semantic_catalog=None, compiler_capabilities=None, helper_contract_registry=None, privileged_runtime_registry=None, privileged_functional_registry=None, privileged_functional_policy=None):
    """D0-D4 then exactly one plan-specific proof; unknowns reject."""
    if preservation_decision is None and isinstance(source_model,SourceSemanticModel): preservation_decision=source_model.preservation
    if target_semantic_catalog is None or compiler_capabilities is None: return SemanticProofResult.failed(getattr(candidate_plan,"plan_id",None),SemanticProofReasonCode.INVALID_REQUEST)
    request=SemanticProofRequest(source_model,preservation_decision,candidate_plan,constraints,target_environment,target_semantic_catalog,compiler_capabilities,helper_contract_registry,privileged_runtime_registry,privileged_functional_registry,privileged_functional_policy)
    common=validate_common(request)
    if common is not None:return common
    from . import phase6d_c_expression as ce, phase6d_c_builtin as cb, phase6d_x86_inline_asm as xa, phase6d_atomic as ab, phase6d_control_flow as cf, phase6d_helper_abi as ha
    from . import phase6d_stack_rebinding as sr, phase6d_virtual_private_frame as vp, phase6d_abi_wrapper as aw, phase6d_privileged_runtime as pr, phase6d_privileged_functional as pf
    dispatch={TargetLoweringKind.C_EXPRESSION:ce.prove,TargetLoweringKind.C_BUILTIN:cb.prove,TargetLoweringKind.X86_GNU_INLINE_ASM:xa.prove,TargetLoweringKind.X86_ATOMIC:ab.prove_atomic,TargetLoweringKind.X86_BARRIER:ab.prove_barrier,TargetLoweringKind.STRUCTURED_CONTROL_FLOW:cf.prove,TargetLoweringKind.HELPER_CALL:ha.prove,TargetLoweringKind.STACK_ADDRESS_REBINDING:sr.prove,TargetLoweringKind.VIRTUAL_PRIVATE_FRAME:vp.prove,TargetLoweringKind.ABI_WRAPPER_CALL:aw.prove,TargetLoweringKind.COUNTER_OBSERVATION_ADAPTER:pr.prove,TargetLoweringKind.SYSCALL_OR_SERVICE_ABI_ADAPTER:pr.prove,TargetLoweringKind.PRIVILEGED_EVENT_ADAPTER:pr.prove,TargetLoweringKind.MMU_RUNTIME_ADAPTER:pr.prove,TargetLoweringKind.PRIVILEGED_RUNTIME_ADAPTER:pr.prove,TargetLoweringKind.PRIVILEGED_FUNCTIONAL_FALLBACK:pf.prove}
    fn=dispatch.get(candidate_plan.kind)
    if fn is None:return reject(request,SemanticProofReasonCode.UNSUPPORTED_PLAN_KIND)
    try:return fn(request)
    except (AttributeError,TypeError,ValueError):return reject(request,SemanticProofReasonCode.INTERNAL_INVARIANT)
