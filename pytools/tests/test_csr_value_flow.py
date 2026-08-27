from types import SimpleNamespace
from riscv2x86_py.csr_value_flow import CsrOperandAuthority, join_csr_operand_bindings
from riscv2x86_py.pcode_ir import CanonicalPrivilegedOperation, CanonicalPrivilegedOperationKind, CanonicalCsrOperationKind

def test_csr_join_uses_value_node_authority_not_operand_order():
    op=CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,csr_id="riscv.csr.mstatus",csr_operation=CanonicalCsrOperationKind.READ_WRITE,read_value_node_id="old",write_value_node_id="new",read_modify_write=True,state_complete=True)
    insn=SimpleNamespace(addr=0x1000,privileged_operations=(op,))
    auth=CsrOperandAuthority({"old":7,"new":3},{7:64,3:64},{7:"unsigned",3:"unsigned"},{7:False},volatile_preserved=True,memory_clobber_preserved=True,cc_clobber_preserved=True)
    binding=join_csr_operand_bindings(lifted_insns=(insn,),authority=auth,fragment_shell=SimpleNamespace(isVolatile=False,clobbers=[]))[0]
    assert binding.complete and (binding.read_result_operand_index,binding.write_value_operand_index)==(7,3)

def test_csr_join_rejects_missing_type_and_shell_or_escape_proof():
    op=CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,csr_id="riscv.csr.mstatus",csr_operation=CanonicalCsrOperationKind.READ,read_value_node_id="old",state_complete=True)
    auth=CsrOperandAuthority({"old":0},{},{},{0:True})
    binding=join_csr_operand_bindings(lifted_insns=(SimpleNamespace(addr=1,privileged_operations=(op,)),),authority=auth,fragment_shell=SimpleNamespace(isVolatile=True,clobbers=["memory","cc"]))[0]
    assert not binding.complete
    assert "csr-join.output-escape-unproven" in binding.reason_codes
    assert "csr-join.volatile-shell-unproven" in binding.reason_codes
