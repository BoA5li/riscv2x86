from riscv2x86_py.csr_runtime_registry import *
def _e(f=CsrRuntimeRegistryFamily.LOGICAL_CSR_STATE,mode="logical-runtime"):
 return CsrRuntimeRegistryEntry("c","v1","riscv-privileged-1.12","machine","%s"%mode,("riscv.csr.mstatus",),("read_write",),("f",),"a","t","o","life","rv2x86_csr_write","r","h","l",True,f)
def test_registry_is_unique_profile_bound_and_system_safe():
 r=CsrRuntimeRegistry((_e(),));m=r.mapping_for(source_effect_id="e",csr_id="riscv.csr.mstatus",operation="read_write",source_spec_version="riscv-privileged-1.12",source_execution_profile="machine",target_execution_mode="logical-runtime");assert m and m.runtime_version=="v1"
 assert r.mapping_for(source_effect_id="e",csr_id="riscv.csr.mstatus",operation="read_write",source_spec_version="bad",source_execution_profile="machine",target_execution_mode="logical-runtime") is None
 s=CsrRuntimeRegistry((_e(CsrRuntimeRegistryFamily.SYSTEM_VMM_ADAPTER,"ordinary-user-process"),));assert s.resolve(csr_id="riscv.csr.mstatus",operation="read_write",source_spec_version="riscv-privileged-1.12",source_execution_profile="machine",target_execution_mode="ordinary-user-process") is None
