from types import SimpleNamespace
from riscv2x86_py.source_csr_semantic_model import adapt_source_csr_semantic_model

def test_6a_only_adapts_complete_phase5_facts():
    effect=SimpleNamespace(csr_id="riscv.csr.cycle",csr_class=SimpleNamespace(value="user_counter_observation"),complete=True,access_allowed=True,may_trap=False)
    binding=SimpleNamespace(complete=True,source_effect_id="e",reason_codes=())
    flow=SimpleNamespace(complete=True,entry_state="in",exit_states=((1,"out"),))
    model=adapt_source_csr_semantic_model(SimpleNamespace(csr_effects=(effect,),csr_operand_bindings=(binding,),csr_state_dataflow=flow))
    assert model.complete and model.strict_eligible and not model.fallback_eligible
    assert model.model_identity.startswith("csr-6a:")

def test_6a_rejects_missing_join_or_trap_relation():
    effect=SimpleNamespace(csr_id="riscv.csr.mstatus",csr_class=SimpleNamespace(value="privileged_status"),complete=True,access_allowed=True,may_trap=True)
    model=adapt_source_csr_semantic_model(SimpleNamespace(csr_effects=(effect,),csr_operand_bindings=(),csr_state_dataflow=SimpleNamespace(complete=False)))
    assert not model.complete and model.requires_whole_function
