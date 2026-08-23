"""Strict Phase-6D proof for one registered privileged runtime adapter."""
from .phase6d_common import (
    PreservationConclusion,
    SemanticProofReasonCode,
    finalize,
    reject,
)
from .privileged_runtime_contracts import (
    PrivilegedRuntimeContract,
    privileged_source_identity,
    target_environment_identity,
)


def prove(request):
    source = request.source_model.privileged_state
    constraint = request.constraints.privileged_runtime_constraint
    registry = request.privileged_runtime_registry
    if (
        source is None or not source.strict_translation_eligible
        or source.state is None or not source.state.present
        or constraint is None
        or registry is None
    ):
        return reject(request, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    contract = constraint.runtime_contract
    registered = registry.resolve(source, request.target_environment)
    if not isinstance(contract, PrivilegedRuntimeContract) or registered != contract:
        return reject(request, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if (
        constraint.registry_version != registry.version
        or constraint.source_privileged_identity != privileged_source_identity(source)
        or contract.target_environment_id
        != target_environment_identity(request.target_environment)
        or contract.required_target_capability
        not in request.target_environment.helper_contract_capabilities
    ):
        return reject(request, SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)
    if source.requires_whole_function_lowering:
        return reject(request, SemanticProofReasonCode.CONTROL_FLOW_UNPRESERVED)
    if not all((
        contract.complete,
        contract.preserves_architectural_state,
        contract.preserves_shell,
        contract.preserves_memory_effects,
        contract.preserves_trap_behavior,
        contract.preserves_control_flow,
        contract.abi_isolated,
        contract.may_return,
        not contract.may_unwind,
    )):
        return reject(request, SemanticProofReasonCode.ABI_UNPRESERVED)
    shell = request.source_model.shell
    if (
        (shell.is_volatile and not contract.preserves_volatile_execution)
        or (shell.has_memory_clobber
            and not contract.preserves_compiler_memory_ordering)
        or (shell.has_cc_clobber and not contract.preserves_cc_clobber)
    ):
        return reject(request, SemanticProofReasonCode.SHELL_UNPRESERVED)
    if (
        request.source_model.microarch.explicitly_microarch_sensitive
        and not contract.preserves_microarchitecture_intent
    ):
        return reject(request, SemanticProofReasonCode.MICROARCH_UNPRESERVED)
    return finalize(request, (
        PreservationConclusion.ARCHITECTURE_EQUIVALENT,
        PreservationConclusion.SHELL_PRESERVED,
    ))
