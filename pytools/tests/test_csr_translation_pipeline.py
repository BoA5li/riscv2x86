from types import SimpleNamespace

from riscv2x86_py.csr_effect_constraints import CsrTargetMapping
from riscv2x86_py.csr_structured_renderer import CsrRuntimeRecipe
from riscv2x86_py.csr_translation_pipeline import (
    CsrRendererRegistry,
    CsrRuntimeRegistry,
    CsrTranslationFallbackPolicy,
    run_csr_translation_pipeline,
)
from riscv2x86_py.csr_runtime_registry import CounterObservationContract


def _counter_contract(relation="architectural-equivalence"):
    exact = relation == "architectural-equivalence"
    return CounterObservationContract(
        "counter-contract-v1", relation, "riscv-time-epoch",
        "riscv-time-epoch" if exact else "posix-monotonic-epoch",
        10_000_000, 1, 1 if exact else 10, "monotonic", 64, "hart",
        "migration-preserves-source-hart" if exact else "thread-monotonic",
        "source-defined", "registered-runtime-call", 0 if exact else 100,
        "runtime-checked", "reported-by-runtime", True,
    )


def _complete_counter_model():
    field = SimpleNamespace(field_id="riscv.csr.cycle.all", complete=True)
    effect = SimpleNamespace(
        csr_id="riscv.csr.cycle",
        csr_class=SimpleNamespace(value="user_counter_observation"),
        operation=SimpleNamespace(value="read"),
        may_trap=False,
        complete=True,
        access_allowed=True,
        affected_fields=(field,),
    )
    binding = SimpleNamespace(
        source_effect_id="e:riscv.csr.cycle", complete=True,
        immediate_value=None, reason_codes=(),
    )
    return SimpleNamespace(
        effects=(effect,), operand_bindings=(binding,),
        semantic_classes=("user_counter_observation",), strict_eligible=True,
        fallback_eligible=True, requires_whole_function=False, complete=True,
        reason_codes=(),
    )


def test_pipeline_emits_only_after_6d_and_6f_approval():
    model = _complete_counter_model()
    mapping = CsrTargetMapping(
        "e:riscv.csr.cycle", "riscv.csr.cycle", "counter-context",
        "read-counter", "v1", "user", "per-thread", read_result_mapping="out",
        field_mappings=("riscv.csr.cycle.all",), old_new_state_relation_id="same",
        access_policy_mapping_id="counter-gate", ordering_relation_id="ordered",
        counter_contract_identity="counter-contract-v1",
        counter_relation_kind="architectural-equivalence",
        counter_contract=_counter_contract(),
    )
    runtime = CsrRuntimeRegistry("registry-v1", "v1", "user", (mapping,), True, True)
    recipe = CsrRuntimeRecipe(
        "counter-read-v1", "rv2x86_csr_read", "RV2X86_CSR_CYCLE", "ctx",
        None, "out", "rv2x86_csr_runtime.h", "rv2x86_csr_runtime", "v1",
        "no-trap-observation", True,
    )
    renderer = CsrRendererRegistry(
        "renderer-v1", {"read-counter": recipe}, {"counter-read-v1": "v1"},
    )
    result = run_csr_translation_pipeline(
        model, None, SimpleNamespace(execution_profile="user"), runtime, renderer,
        CsrTranslationFallbackPolicy(shell_preserved=True),
    )
    assert result.status == "approved"
    assert result.proof_invoked and result.proof is not None and result.proof.approved
    assert result.render is not None
    assert result.suggested_replacement == "out = rv2x86_csr_read(ctx, RV2X86_CSR_CYCLE);"


def test_no_6d_proof_means_no_csr_replacement():
    model = _complete_counter_model()
    result = run_csr_translation_pipeline(
        model, None, SimpleNamespace(execution_profile="user"), None, None,
        CsrTranslationFallbackPolicy(shell_preserved=True),
    )
    assert result.status == "needs_route"
    assert result.proof_invoked is False
    assert result.proof is None
    assert result.suggested_replacement is None


def test_functional_counter_relation_uses_registered_pipeline_without_arch_claim():
    model = _complete_counter_model()
    contract = _counter_contract("functional-monotonic-observation")
    mapping = CsrTargetMapping(
        "e:riscv.csr.cycle", "riscv.csr.cycle", "counter-context",
        "read-counter", "v1", "user", "per-thread", read_result_mapping="out",
        field_mappings=("riscv.csr.cycle.all",), old_new_state_relation_id="same",
        access_policy_mapping_id="counter-gate", ordering_relation_id="ordered",
        counter_contract_identity=contract.contract_id,
        counter_relation_kind=contract.relation_kind, counter_contract=contract,
    )
    recipe = CsrRuntimeRecipe(
        "counter-functional-v1", "rv2x86_csr_read", "RV2X86_CSR_TIME",
        "ctx", None, "out", "rv2x86_csr_runtime.h", "rv2x86_csr_runtime",
        "v1", "no-trap-observation", True,
    )
    renderer = CsrRendererRegistry(
        "renderer-v1", {"read-counter": recipe}, {"counter-functional-v1": "v1"},
    )
    result = run_csr_translation_pipeline(
        model, None, SimpleNamespace(execution_profile="user"),
        CsrRuntimeRegistry("registry-v1", "v1", "user", (mapping,), True, True),
        renderer, CsrTranslationFallbackPolicy(
            allow_functional_fallbacks=True, shell_preserved=True,
        ),
    )
    assert result.status == "approved"
    assert result.route == "csr_functional_fallback"
    assert result.proof_invoked
    assert {item.conclusion for item in result.proof.evidence} == {"functional_relation"}
    assert result.suggested_replacement == (
        "out = rv2x86_csr_read(ctx, RV2X86_CSR_TIME);"
    )
