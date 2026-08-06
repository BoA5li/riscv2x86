from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import lift
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.translate import translate
from riscv2x86_py.verify import verify

def _all(frag):
    a = assemble(frag)
    assert a.ok, a.error

    l = lift(a.machine_code)
    assert l.ok, l.error

    _, s = from_lifted(l.insns)
    t = translate(frag, l, s)
    return verify(frag, l, s, t), t

def test_verify_amoadd_functional_rmw_only():
    frag = AsmFragment(
        rawAsmText="amoadd.w %0, %2, %1",
        outputs=[AsmOperand(constraint="=r", exprText="old", isOutput=True),
                 AsmOperand(constraint="+A", exprText="*p", isOutput=True)],
        inputs=[AsmOperand(constraint="r", exprText="v")])
    vr, t = _all(frag)
    assert "__ATOMIC_RELAXED" in t.replacement
    # verified 仅表示 RMW 功能语义成立，不表示 memory-order 已建模证明
    assert vr.status == "verified", vr.detail
    assert "functional RMW equivalence" in vr.detail
    assert "memory-order equivalence not modeled" in vr.detail

def test_verify_fence_full():
    frag = AsmFragment(rawAsmText="fence rw,rw")
    vr, _ = _all(frag)
    assert vr.status == "verified"

def test_verify_fence_weak():
    frag = AsmFragment(rawAsmText="fence r,w")
    vr, _ = _all(frag)
    # 我们故意把弱屏障升格为 SEQ_CST，这是保守翻译，Phase 8 标 build_only
    assert vr.status == "build_only"