from riscv2x86_py.csr_functional_fallback import evaluate_csr_functional_fallback
def _d(**kw):
 base=dict(enabled=True,semantic_classes=("user_counter_observation",),is_write=False,observability_complete=True,read_result_complete=True,c_output_complete=True,memory_complete=True,error_complete=True,termination_complete=True,trap_to_result_complete=True,ignored_state_ids=("cycle-rate",),ignored_state_non_escaping=True,address_value_non_escaping=True,runtime_no_extra_effects=True,shell_preserved=True);base.update(kw);return evaluate_csr_functional_fallback(**base)
def test_counter_fallback_needs_every_explicit_fact(): assert _d().approved and not _d(shell_preserved=False).approved
def test_csr_writes_and_mmu_are_never_fallbacks():
 assert not _d(is_write=True).approved
 assert not _d(semantic_classes=("address_translation",)).approved
