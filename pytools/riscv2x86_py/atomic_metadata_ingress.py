"""Decoder-owned RISC-V atomic metadata ingress.

This module is deliberately below canonical IR.  It decodes the architectural
instruction word and emits typed facts; Phase 6 never inspects mnemonics or
recognises a LOAD/ALU/STORE p-code shape as atomic.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DecodedAtomicOperation:
    operation_kind: str
    width_bits: int
    address_register: str
    input_value_register: str
    result_register: str | None
    result_semantics: str
    ordering_before: str
    ordering_after: str
    atomicity_scope: str
    address_space_identity: str
    complete: bool = True


_RMW_KIND = {
    0b00001: "exchange",
    0b00000: "fetch_add",
    0b00100: "fetch_xor",
    0b01100: "fetch_and",
    0b01000: "fetch_or",
}

_ABI_REGISTERS = (
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
)


def decode_atomic_operation(machine_bytes: bytes, *, xlen_bits: int) -> DecodedAtomicOperation | None:
    """Decode the finite AMO RMW family from one RISC-V instruction word."""
    if len(machine_bytes) < 4:
        return None
    word = int.from_bytes(machine_bytes[:4], "little")
    if word & 0x7f != 0x2f:
        return None
    width_bits = {0b010: 32, 0b011: 64}.get((word >> 12) & 0x7)
    if width_bits is None or width_bits > xlen_bits:
        return None
    operation_kind = _RMW_KIND.get((word >> 27) & 0x1f)
    if operation_kind is None:
        # LR/SC, min/max and CAS-like sequences need their own typed contract.
        return None
    rd, rs1, rs2 = (word >> 7) & 0x1f, (word >> 15) & 0x1f, (word >> 20) & 0x1f
    aq, rl = bool(word & (1 << 26)), bool(word & (1 << 25))
    return DecodedAtomicOperation(
        operation_kind=operation_kind,
        width_bits=width_bits,
        address_register=_ABI_REGISTERS[rs1],
        input_value_register=_ABI_REGISTERS[rs2],
        result_register=None if rd == 0 else _ABI_REGISTERS[rd],
        result_semantics="none" if rd == 0 else "old_value",
        ordering_before="release" if rl else "relaxed",
        ordering_after="acquire" if aq else "relaxed",
        atomicity_scope="system",
        address_space_identity="riscv.default-data-address-space",
    )
