from types import SimpleNamespace
from riscv2x86_py.csr_state_dataflow import analyze_csr_state_dataflow, UNKNOWN
from riscv2x86_py.pcode_ir import CanonicalPrivilegedOperation,CanonicalPrivilegedOperationKind,CanonicalCsrOperationKind,CanonicalCsrFieldEffect

def _op(kind,imm=1): return CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,csr_id="riscv.csr.mstatus",csr_operation=kind,immediate_mask=imm,affected_csr_fields=(CanonicalCsrFieldEffect("mie",writable_mask=1,complete=True),),state_complete=True,may_trap=False)
def test_dataflow_write_read_and_branch_conflict_merge_unknown():
    a=SimpleNamespace(addr=1,successors=[2,3],instructions=[SimpleNamespace(privileged_operations=(_op(CanonicalCsrOperationKind.WRITE),))])
    b=SimpleNamespace(addr=2,successors=[4],instructions=[SimpleNamespace(privileged_operations=(_op(CanonicalCsrOperationKind.WRITE,2),))])
    c=SimpleNamespace(addr=3,successors=[4],instructions=[SimpleNamespace(privileged_operations=(_op(CanonicalCsrOperationKind.WRITE,3),))])
    d=SimpleNamespace(addr=4,successors=[],instructions=[])
    r=analyze_csr_state_dataflow(blocks=(a,b,c,d),cfg=SimpleNamespace(entry=1))
    assert dict(r.block_in_states)[4].value_map()["riscv.csr.mstatus.mie"]==UNKNOWN
def test_dataflow_rejects_incomplete_effect_and_unmodelled_trap():
    op=_op(CanonicalCsrOperationKind.WRITE); op=op.__class__(**{**op.__dict__,"state_complete":False,"may_trap":True})
    b=SimpleNamespace(addr=1,successors=[],instructions=[SimpleNamespace(privileged_operations=(op,))])
    r=analyze_csr_state_dataflow(blocks=(b,),cfg=SimpleNamespace(entry=1))
    assert not r.complete and "csr-dataflow.trap-edge-requires-route" in r.reason_codes
