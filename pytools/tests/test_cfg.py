from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import lift
from riscv2x86_py.cfg import build_cfg_any

def _cas_retry_frag():
    return AsmFragment(
        rawAsmText=(
            "1: lr.w %0, %1\n"
            "   bne  %0, %3, 2f\n"
            "   sc.w %2, %4, %1\n"
            "   bnez %2, 1b\n"
            "2:"
        ),
        outputs=[
            AsmOperand(constraint="=&r", exprText="old", isOutput=True),
            AsmOperand(constraint="+A",  exprText="*p",  isOutput=True),
            AsmOperand(constraint="=&r", exprText="sc",  isOutput=True),
        ],
        inputs=[
            AsmOperand(constraint="r", exprText="expected"),
            AsmOperand(constraint="r", exprText="desired"),
        ],
        clobbers=["memory"], isVolatile=True)

def test_cfg_has_backedge_for_retry():
    f = _cas_retry_frag()
    a = assemble(f); assert a.ok, a.error
    l = lift(a.machine_code); assert l.ok
    c = build_cfg_any(a.machine_code, l.insns, xlen=64)
    assert c.ok
    # 至少存在一条跨越 bnez -> lr 的回边
    lr_addr = next(i.addr for i in l.insns
                   if i.asm_mnem.lower().startswith("lr."))
    bnez_addr = next(i.addr for i in l.insns
                   if i.asm_mnem.lower().startswith(("bnez", "bne", "c.bnez")))
    src_node = next(n for n in c.nodes.values() if bnez_addr in n.instr_addrs)
    assert any(lr_addr in c.nodes[s].instr_addrs
               for s in src_node.successors)
    for ins in l.insns:
        print({
            "addr": hex(ins.addr),
            "mnem": getattr(ins, "asm_mnem", None),
            "asm": getattr(ins, "asm", None),
            "asm_text": getattr(ins, "asm_text", None),
            "text": getattr(ins, "text", None),
            "disasm": getattr(ins, "disasm", None),
            "ops": getattr(ins, "asm_operands", None),
        })