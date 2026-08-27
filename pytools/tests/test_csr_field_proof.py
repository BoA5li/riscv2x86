from types import SimpleNamespace
from riscv2x86_py.csr_field_proof import prove_csr_fields
def test_field_proof_requires_relation_policy_and_shell():
 f=SimpleNamespace(field_id="riscv.csr.mstatus.mie",complete=True,warl_or_wlrl_policy_id="p")
 e=SimpleNamespace(csr_id="riscv.csr.mstatus",may_trap=False,affected_fields=(f,))
 b=SimpleNamespace(source_effect_id="e:riscv.csr.mstatus",complete=True)
 c=SimpleNamespace(source_effect_id="e:riscv.csr.mstatus",complete=True,access_policy_mapping_id="a",ordering_relation_id="o",field_mappings=("f",),old_new_state_relation_id="r",target_operation_id="target",denied_access_trap_mapping_id=None)
 s=SimpleNamespace(effects=(e,),operand_bindings=(b,),requires_whole_function=False)
 r=prove_csr_fields(source_model=s,constraints=(c,),execution_profile="p",shell_preserved=True,external_state_complete=True)
 assert r.approved and r.evidence[0].conclusion=="field_equivalent"
def test_field_proof_fails_closed_for_missing_warl_or_shell():
 s=SimpleNamespace(effects=(),operand_bindings=(),requires_whole_function=False)
 assert not prove_csr_fields(source_model=s,constraints=(),execution_profile="p",shell_preserved=False,external_state_complete=True).approved
