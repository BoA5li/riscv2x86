from types import SimpleNamespace

from .test_phase7_conftest import import_from_env


lrsc_mod = import_from_env("R2X_LRSC_MODULE", "riscv2x86_py.patterns.lrsc")
lrsc_rmw_mod = import_from_env("R2X_LRSC_RMW_MODULE", "riscv2x86_py.patterns.lrsc_rmw")


def insn(addr, mnem, body):
    return SimpleNamespace(addr=addr, asm_mnem=mnem, asm_body=body)


def _cfg_with_edge(src_block_addr, dst_block_addr, src_insns, dst_insns):
    src = SimpleNamespace(addr=src_block_addr, instr_addrs=src_insns, successors=[dst_block_addr])
    dst = SimpleNamespace(addr=dst_block_addr, instr_addrs=dst_insns, successors=[])
    return SimpleNamespace(ok=True, nodes={src_block_addr: src, dst_block_addr: dst})


def test_detect_cas_weak_one_shot():
    insns = [
        insn(0x100, "lr.w.aq", "a0, (a1)"),
        insn(0x104, "bne", "a0, a2, 0x120"),
        insn(0x108, "sc.w.rl", "a3, a4, (a1)"),
    ]
    cfg = SimpleNamespace(ok=False, nodes={})
    operand_index_map = {"x11": 0, "x12": 1, "x14": 2, "x10": 0, "x13": 3}
    m = lrsc_mod.detect_cas(insns, cfg, operand_index_map, output_count=4)
    assert m is not None
    assert m.width == 32
    assert m.is_weak is True
    assert m.success_order == "__ATOMIC_ACQ_REL"
    assert m.failure_order == "__ATOMIC_ACQUIRE"


def test_detect_cas_strong_retry_loop():
    insns = [
        insn(0x100, "lr.d", "a0, (a1)"),
        insn(0x104, "bne", "a0, a2, 0x120"),
        insn(0x108, "sc.d", "a3, a4, (a1)"),
        insn(0x10C, "bnez", "a3, 0x100"),
    ]
    cfg = _cfg_with_edge(0x10C, 0x100, [0x10C], [0x100, 0x104, 0x108])
    operand_index_map = {"x11": 0, "x12": 1, "x14": 2, "x10": 0, "x13": 3}
    m = lrsc_mod.detect_cas(insns, cfg, operand_index_map, output_count=4)
    assert m is not None
    assert m.width == 64
    assert m.is_weak is False


def test_detect_lrsc_rmw_addi():
    insns = [
        insn(0x100, "lr.w.aq", "a0, (a1)"),
        insn(0x104, "addi", "a2, a0, 5"),
        insn(0x108, "sc.w.rl", "a3, a2, (a1)"),
        insn(0x10C, "bnez", "a3, 0x100"),
    ]
    cfg = _cfg_with_edge(0x10C, 0x100, [0x10C], [0x100, 0x104, 0x108])
    m = lrsc_rmw_mod.detect(insns, cfg=cfg)
    assert m is not None
    assert m.op_kind == "add"
    assert m.val_kind == "imm"
    assert m.val_imm == 5
    assert m.aq is True
    assert m.rl is True


def test_emit_c_for_lrsc_rmw_addi():
    frag = SimpleNamespace(
        outputs=[SimpleNamespace(exprText="old_v")],
        inputs=[SimpleNamespace(exprText="addr"), SimpleNamespace(exprText="val")],
    )
    m = SimpleNamespace(
        op_kind="add", is_w_width=True, addr_reg="a1",
        val_kind="imm", val_reg=None, val_imm=7, aq=True, rl=True,
    )
    body, notes = lrsc_rmw_mod.emit_c(frag, m)
    assert "__atomic_fetch_add" in body
    assert "__ATOMIC_ACQ_REL" in body
    assert "old_v" in body
    assert any("LR/SC RMW" in n for n in notes)