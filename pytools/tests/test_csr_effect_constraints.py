from types import SimpleNamespace
from riscv2x86_py.csr_effect_constraints import CsrTargetMapping,derive_csr_effect_constraints
def test_6c_requires_exact_complete_versioned_mapping():
 e=SimpleNamespace(csr_id="riscv.csr.cycle",operation=SimpleNamespace(value="read"),may_trap=False)
 b=SimpleNamespace(source_effect_id="e:riscv.csr.cycle",complete=True,immediate_value=None)
 s=SimpleNamespace(effects=(e,),operand_bindings=(b,))
 m=CsrTargetMapping("e:riscv.csr.cycle","riscv.csr.cycle","ctx","read","v1","user","life",read_result_mapping="out",field_mappings=("all",),old_new_state_relation_id="same",access_policy_mapping_id="gate")
 assert derive_csr_effect_constraints(source_model=s,mappings=(m,),runtime_version="v1",execution_profile="user",shell_transportable=True)[0].complete
def test_6c_rejects_missing_or_ambiguous_mapping():
 s=SimpleNamespace(effects=(SimpleNamespace(csr_id="riscv.csr.cycle",operation=SimpleNamespace(value="read"),may_trap=False),),operand_bindings=())
 assert not derive_csr_effect_constraints(source_model=s,mappings=(),runtime_version="v",execution_profile="p",shell_transportable=False)[0].complete
