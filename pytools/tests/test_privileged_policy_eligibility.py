from types import SimpleNamespace

from riscv2x86_py.functional_observability import FunctionalFallbackPossibility
from riscv2x86_py.privileged_policy import PrivilegedPreservationPolicy
from riscv2x86_py.privileged_state_adapter import build_privileged_state_adapter
from riscv2x86_py.privileged_state_analysis import PrivilegedSemanticClass
from riscv2x86_py.semantic_types import SemanticFeature


def _state():
    return SimpleNamespace(
        present=True,
        complete=True,
        missing_fact_codes=(),
        semantic_classes=(PrivilegedSemanticClass.PRIVILEGED_CSR_STATE,),
        classification_complete=True,
        return_effects=(),
        trap_effects=(),
        csr_effects=(),
    )


def _shell():
    return SimpleNamespace(
        output_count=0,
        has_memory_clobber=False,
        is_volatile=False,
    )


def _memory():
    return SimpleNamespace(reads_memory=False, writes_memory=False)


def _control():
    return SimpleNamespace(has_return=False)


def _observability():
    return SimpleNamespace(
        fragment_id="frag",
        complete=True,
        missing_fact_codes=(),
        outputs=(),
        memory=SimpleNamespace(
            compiler_memory_order_observable=False,
            volatile_execution_observable=False,
            reads_memory=False,
            writes_memory=False,
        ),
        trap=SimpleNamespace(present=False),
        fallback_possibility=(
            FunctionalFallbackPossibility.POSSIBLE_WITH_EXACT_TARGET_CONTRACT
        ),
        ignored_states=(),
        unignored_privileged_state_ids=(),
    )


def _build(policy, observability=None):
    return build_privileged_state_adapter(
        fragment_id="frag",
        phase5_state=_state(),
        observability=observability,
        read_only_counter_candidate=None,
        shell=_shell(),
        memory=_memory(),
        control_flow=_control(),
        abi_effects=None,
        whole_function_route=None,
        preservation_policy=policy,
    )


def test_strict_eligibility_does_not_require_functional_observability():
    model = _build(PrivilegedPreservationPolicy.STRICT_ARCHITECTURAL)

    assert model.complete
    assert model.strict_translation_eligible
    assert not model.functional_fallback_eligible
    assert model.functional_observability is None
    assert (
        "phase6a.privileged-observability-missing"
        in model.functional_fallback_reason_codes
    )
    assert "phase6a.privileged-observability-missing" not in model.reason_codes


def test_fallback_requires_policy_and_complete_observability_authority():
    disabled = _build(
        PrivilegedPreservationPolicy.STRICT_ARCHITECTURAL,
        _observability(),
    )
    enabled = _build(
        PrivilegedPreservationPolicy.FUNCTIONAL_FALLBACK_ALLOWED,
        _observability(),
    )

    assert disabled.strict_translation_eligible
    assert not disabled.functional_fallback_eligible
    assert enabled.strict_translation_eligible
    assert enabled.functional_fallback_eligible
    assert enabled.functional_fallback_possible


def test_cli_policy_mapping_and_semantic_feature_vocabulary():
    assert (
        PrivilegedPreservationPolicy.from_allow_functional_fallbacks(False)
        is PrivilegedPreservationPolicy.STRICT_ARCHITECTURAL
    )
    assert (
        PrivilegedPreservationPolicy.from_allow_functional_fallbacks(True)
        is PrivilegedPreservationPolicy.FUNCTIONAL_FALLBACK_ALLOWED
    )
    expected = {
        "counter_observation",
        "fpu_architectural_state",
        "privileged_csr_state",
        "tlb_maintenance",
        "trap_service",
        "pmp_state",
        "functional_fallback_requested",
        "functional_architecture_state_not_preserved",
        "functional_microarchitecture_not_preserved",
    }
    assert expected <= {item.value for item in SemanticFeature}
