from types import SimpleNamespace
from riscv2x86_py.csr_plan_families import CsrPlanFamily,derive_csr_plan_candidates
def _m(classes,ids=("riscv.csr.cycle",),whole=False):
 return SimpleNamespace(complete=True,effects=tuple(SimpleNamespace(csr_id=i) for i in ids),semantic_classes=classes,requires_whole_function=whole,strict_eligible=True,fallback_eligible=True)
def test_families_are_disjoint_and_mmu_is_not_generic_runtime():
 assert derive_csr_plan_candidates(_m(("fpu_state",)))[0].family is CsrPlanFamily.CSR_FPU_STATE_ADAPTER
 assert derive_csr_plan_candidates(_m(("vector_state",)))[0].family is CsrPlanFamily.CSR_VECTOR_STATE_ADAPTER
 assert derive_csr_plan_candidates(_m(("address_translation",),("riscv.csr.satp",),True))[0].family is CsrPlanFamily.CSR_MMU_STATE_RUNTIME
def test_multi_effect_route_is_state_machine_and_fallback_limited():
 assert derive_csr_plan_candidates(_m(("interrupt_state","privileged_status"),("riscv.csr.mie","riscv.csr.mstatus"),True))[0].family is CsrPlanFamily.CSR_STATE_MACHINE
 cs=derive_csr_plan_candidates(_m(("user_counter_observation",)),allow_functional_fallbacks=True)
 assert cs[-1].family is CsrPlanFamily.CSR_FUNCTIONAL_FALLBACK
