from types import SimpleNamespace
from riscv2x86_py.csr_value_flow import CsrOperandAuthorityFacts,join_csr_operand_bindings
from riscv2x86_py.pcode_ir import CanonicalPrivilegedOperation,CanonicalPrivilegedOperationKind,CanonicalCsrOperationKind
def _auth(**kw):
 d=dict(fragment_id="f",value_node_to_operand_index={"old":0,"new":1},operand_width_bits={0:64,1:64},operand_signedness={0:"unsigned",1:"unsigned"},operand_access={0:"output",1:"input"},tied_operand_pairs=(),early_clobber_outputs=(),fixed_register_constraints={0:"",1:""},output_escape_facts={0:False},shell_facts={"volatile":True,"memory":False,"cc":False},complete=True);d.update(kw);return CsrOperandAuthorityFacts(**d)
def _join(op,a):return join_csr_operand_bindings(lifted_insns=(SimpleNamespace(addr=1,privileged_operations=(op,)),),authority=a)[0]
def test_csrrw_uses_only_explicit_frontend_authority():
 op=CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,csr_id="riscv.csr.mstatus",csr_operation=CanonicalCsrOperationKind.READ_WRITE,read_value_node_id="old",write_value_node_id="new")
 b=_join(op,_auth());assert b.complete and (b.read_result_operand_index,b.write_value_operand_index)==(0,1)
def test_suppressed_operands_need_no_binding():
 op=CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,csr_id="riscv.csr.mstatus",csr_operation=CanonicalCsrOperationKind.WRITE,read_result_suppressed=True,write_value_node_id="new")
 assert _join(op,_auth(value_node_to_operand_index={"new":1})).complete
 op=CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,csr_id="riscv.csr.mstatus",csr_operation=CanonicalCsrOperationKind.READ,read_value_node_id="old",write_value_suppressed=True)
 assert _join(op,_auth(value_node_to_operand_index={"old":0})).complete
def test_missing_strict_facts_and_escape_fail_closed():
 op=CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,csr_id="riscv.csr.mstatus",csr_operation=CanonicalCsrOperationKind.READ,read_value_node_id="old")
 b=_join(op,_auth(output_escape_facts={0:True},fixed_register_constraints={}));assert not b.complete and "csr-join.output-escape-unproven" in b.reason_codes and "csr-join.fixed-register-fact-missing" in b.reason_codes
