"""One production target profile shared by pipeline and contract preparation."""
from .phase6c_constraints import TargetEnvironment
from .helper_runtime_manifest import RV64_MULHU_U64, MONOTONIC_TIME_NS_V1, TSC_TICKS_V1


def production_target_environment(*, allow_functional_fallbacks=False,
                                  runtime_registry=None,functional_registry=None, deployment=None):
    features={'x86:gpr_inline_asm','x86:atomic','x86:hardware_fence',
        'compiler:atomic-builtin','compiler:barrier-builtin','runtime:'+RV64_MULHU_U64.runtime_contract_id}
    helpers={RV64_MULHU_U64.runtime_contract_id,RV64_MULHU_U64.required_environment_capability}
    if allow_functional_fallbacks:
        for counter in (MONOTONIC_TIME_NS_V1,TSC_TICKS_V1):
            features.add('runtime:'+counter.runtime_contract_id)
            helpers.update((counter.runtime_contract_id,counter.required_environment_capability))
    for registry in (runtime_registry,functional_registry):
        if registry is not None:features.update(registry.required_target_capabilities)
    if deployment is not None:
        features.update(deployment.capabilities)
        helpers.update(deployment.capabilities)
    return TargetEnvironment.fixed_sysv_amd64_gnu_att(available_features=features,
        builtin_capabilities={'c_builtin:atomic','c_builtin:compiler_barrier'},
        supports_gnu_asm_goto=True,helper_contract_capabilities=helpers)
