"""Phase-6D proof for one explicitly permitted privileged fallback."""
from .functional_observability import FunctionalFallbackPossibility
from .phase6d_common import (
    PreservationConclusion,
    SemanticProofReasonCode,
    finalize,
    reject,
)
from .privileged_functional_contracts import (
    PrivilegedFunctionalFallbackContract,
    functional_observability_identity,
)
from .privileged_runtime_contracts import (
    privileged_source_identity,
    target_environment_identity,
)


def prove(request):
    source = request.source_model.privileged_state
    constraint = request.constraints.privileged_functional_constraint
    registry = request.privileged_functional_registry
    policy = request.privileged_functional_policy
    if (
        source is None or not source.complete or source.reason_codes
        or source.state is None or not source.state.present
        or not source.state.complete or source.state.missing_fact_codes
        or source.observability is None or not source.observability.complete
        or source.observability.missing_fact_codes
        or source.observability.fallback_possibility is not
            FunctionalFallbackPossibility.POSSIBLE_WITH_EXACT_TARGET_CONTRACT
        or not source.functional_fallback_possible
        or constraint is None or registry is None or policy is None
        or not getattr(policy, "enabled", False)
    ):
        return reject(request, SemanticProofReasonCode.FUNCTIONAL_FALLBACK_UNPROVEN)
    contract = constraint.fallback_contract
    registered = registry.resolve(source, request.target_environment)
    if (
        not isinstance(contract, PrivilegedFunctionalFallbackContract)
        or registered != contract
        or constraint.registry_version != registry.version
        or constraint.policy_identity != policy.identity
        or constraint.source_privileged_identity
            != privileged_source_identity(source)
        or constraint.source_observability_identity
            != functional_observability_identity(source.observability)
        or constraint.target_environment_id
            != target_environment_identity(request.target_environment)
    ):
        return reject(request, SemanticProofReasonCode.PLAN_CONTRACT_MISSING)
    if (
        source.requires_whole_function_lowering
        or contract.required_target_capability
            not in request.target_environment.helper_contract_capabilities
    ):
        return reject(request, SemanticProofReasonCode.TARGET_CAPABILITY_MISSING)

    observability = source.observability
    ignored = tuple(item.state_id for item in observability.ignored_states)
    if (
        contract.ignored_state_ids != ignored
        or contract.required_value_source_ids
            != observability.required_privileged_value_sources
        or observability.unignored_privileged_state_ids
    ):
        return reject(request, SemanticProofReasonCode.IGNORED_STATE_UNPROVEN)
    if not all((
        contract.complete,
        contract.functional_equivalence_only,
        contract.preserves_outputs,
        contract.preserves_memory,
        contract.preserves_errors,
        contract.preserves_termination,
        contract.preserves_traps,
        contract.preserves_shell,
        contract.may_return,
        not contract.may_unwind,
    )):
        return reject(request, SemanticProofReasonCode.FUNCTIONAL_FALLBACK_UNPROVEN)
    shell = request.source_model.shell
    if (
        (shell.is_volatile and not contract.preserves_volatile_execution)
        or (shell.has_memory_clobber
            and not contract.preserves_compiler_memory_ordering)
        or (shell.has_cc_clobber and not contract.preserves_cc_clobber)
    ):
        return reject(request, SemanticProofReasonCode.SHELL_UNPRESERVED)
    # Functional fallback is never allowed to inherit or imply a
    # microarchitecture-preservation claim.
    if request.source_model.microarch.explicitly_microarch_sensitive:
        return reject(request, SemanticProofReasonCode.MICROARCH_UNPRESERVED)
    return finalize(request, (
        PreservationConclusion.FUNCTIONAL_EQUIVALENT,
        PreservationConclusion.SHELL_PRESERVED,
    ))
