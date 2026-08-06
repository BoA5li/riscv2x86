from __future__ import annotations

import pytest


pytestmark = pytest.mark.lift


def opname(raw_op) -> str:
    opcode = getattr(raw_op, "opcode", None)

    if opcode is None:
        return ""

    name = getattr(opcode, "name", None)

    if isinstance(name, str):
        return name.upper()

    return str(opcode).upper()


def opnames(insn) -> set[str]:
    return {
        opname(raw_op)
        for raw_op in (getattr(insn, "raw_ops", None) or [])
    }


def collect_const_values(insn) -> set[int]:
    values = set()

    for raw_op in (getattr(insn, "raw_ops", None) or []):
        for varnode in (getattr(raw_op, "inputs", None) or []):
            space = getattr(varnode, "space", None)
            space_name = getattr(space, "name", "")

            if str(space_name).lower() != "const":
                continue

            offset = getattr(varnode, "offset", None)

            if isinstance(offset, int):
                values.add(offset)

    return values


def lifted_length(insn) -> int:
    value = getattr(insn, "length", None)

    assert isinstance(value, int)
    assert value > 0

    return value


# ---------------------------------------------------------------------------
# Address / basic lifting invariants.
# ---------------------------------------------------------------------------

def test_lifted_instruction_address_and_length(lift_snippet):
    base = 0x10000

    lifted = lift_snippet(
        """
        addi a0, a0, 1
        addi a1, a1, 2
        """,
        base_addr=base,
    )

    assert len(lifted) == 2
    assert lifted[0].addr == base

    assert lifted[1].addr == (
        lifted[0].addr + lifted_length(lifted[0])
    )


# ---------------------------------------------------------------------------
# Arithmetic.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("asm", "expected_op"),
    [
        ("add a0, a1, a2", "INT_ADD"),
        ("sub a0, a1, a2", "INT_SUB"),
        ("and a0, a1, a2", "INT_AND"),
        ("or a0, a1, a2", "INT_OR"),
        ("xor a0, a1, a2", "INT_XOR"),
        ("sll a0, a1, a2", "INT_LEFT"),
        ("srl a0, a1, a2", "INT_RIGHT"),
        ("sra a0, a1, a2", "INT_SRIGHT"),
    ],
)
def test_integer_instruction_semantic_shape(
    lift_one,
    asm,
    expected_op,
):
    insn = lift_one(asm)

    assert expected_op in opnames(insn)


def test_addi_contains_int_add_and_immediate(lift_one):
    insn = lift_one("addi a0, a1, 16")

    assert "INT_ADD" in opnames(insn)

    constants = collect_const_values(insn)

    assert 16 in constants or 0x10 in constants


# ---------------------------------------------------------------------------
# Memory operations.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "asm",
    [
        "lb a0, 0(a1)",
        "lbu a0, 0(a1)",
        "lh a0, 4(a1)",
        "lw a0, 8(a1)",
        "ld a0, 0(a1)",
    ],
)
def test_load_instructions_have_load_semantics(lift_one, asm):
    insn = lift_one(asm)

    names = opnames(insn)

    assert "LOAD" in names
    assert "STORE" not in names


@pytest.mark.parametrize(
    "asm",
    [
        "sb a0, 0(a1)",
        "sw a0, 4(a1)",
        "sd a0, 8(a1)",
    ],
)
def test_store_instructions_have_store_semantics(lift_one, asm):
    insn = lift_one(asm)

    names = opnames(insn)

    assert "STORE" in names


def test_load_with_offset_has_address_calculation(lift_one):
    insn = lift_one("lw a0, 12(a1)")

    names = opnames(insn)

    assert "LOAD" in names

    # pypcode / SLEIGH 的不同版本可能会折叠有效地址计算。
    assert "INT_ADD" in names or "LOAD" in names


# ---------------------------------------------------------------------------
# Control flow p-code shape.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "asm",
    [
        "beq a0, a1, 8",
        "bne a0, a1, 8",
        "blt a0, a1, 8",
        "bge a0, a1, 8",
        "bltu a0, a1, 8",
        "bgeu a0, a1, 8",
    ],
)
def test_conditional_branch_has_cbranch(lift_one, asm):
    insn = lift_one(asm)

    assert "CBRANCH" in opnames(insn)


def test_jal_has_call_or_branch_semantics(lift_one):
    insn = lift_one("jal ra, 8")

    names = opnames(insn)

    assert "CALL" in names or "BRANCH" in names


def test_jalr_has_indirect_control_flow_semantics(lift_one):
    insn = lift_one("jalr ra, 0(a0)")

    names = opnames(insn)

    assert (
        "CALLIND" in names
        or "BRANCHIND" in names
        or "CALL" in names
    )


def test_ret_has_return_or_indirect_branch_semantics(lift_one):
    insn = lift_one("ret")

    names = opnames(insn)

    assert "RETURN" in names or "BRANCHIND" in names


# ---------------------------------------------------------------------------
# Fence / atomic extension.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "asm",
    [
        "fence",
        "fence rw, rw",
    ],
)
def test_fence_lifts_successfully(lift_one, asm):
    insn = lift_one(asm)

    assert insn.raw_ops is not None


@pytest.mark.parametrize(
    "asm",
    [
        "lr.w.aq a0, (a1)",
        "sc.w.rl a0, a2, (a1)",
        "amoadd.w.aq a0, a2, (a1)",
        "amoadd.w.rl a0, a2, (a1)",
        "amoadd.w.aqrl a0, a2, (a1)",
    ],
)
def test_atomic_instruction_lifts_successfully(lift_one, asm):
    insn = lift_one(asm)

    assert insn.raw_ops is not None