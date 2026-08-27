"""Phase-4 CSR metadata ingress from decoded machine-code fields."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .csr_spec_catalog import CsrCatalogProfile, CsrSpecificationCatalog, DEFAULT_CSR_SPECIFICATION_CATALOG

CSR_DECODER_VERSION = "riscv-csr-bitfield-decoder.v1"


class DecodedCsrOpcodeKind(str, Enum):
    CSRRW = "csrrw"; CSRRS = "csrrs"; CSRRC = "csrrc"
    CSRRWI = "csrrwi"; CSRRSI = "csrrsi"; CSRRCI = "csrrci"
    UNKNOWN = "unknown"


_FUNCT3_TO_KIND = {
    0b001: DecodedCsrOpcodeKind.CSRRW, 0b010: DecodedCsrOpcodeKind.CSRRS,
    0b011: DecodedCsrOpcodeKind.CSRRC, 0b101: DecodedCsrOpcodeKind.CSRRWI,
    0b110: DecodedCsrOpcodeKind.CSRRSI, 0b111: DecodedCsrOpcodeKind.CSRRCI,
}
_IMMEDIATE = {DecodedCsrOpcodeKind.CSRRWI, DecodedCsrOpcodeKind.CSRRSI, DecodedCsrOpcodeKind.CSRRCI}
_HIGH_COUNTERS = {0xC80, 0xC81, 0xC82}


@dataclass(frozen=True)
class DecodedCsrInstruction:
    """Decoder-owned CSR identity and decoded operands, never disassembly text."""
    opcode_kind: DecodedCsrOpcodeKind
    csr_numeric_address: int | None
    rd_register_id: str | None
    rs1_register_id: str | None
    zimm5: int | None
    instruction_width_bits: int
    decoder_version: str
    complete: bool

    def __post_init__(self) -> None:
        if self.instruction_width_bits != 32:
            raise ValueError("CSR instruction encoding must be 32 bits")
        if self.zimm5 is not None and not 0 <= self.zimm5 <= 31:
            raise ValueError("zimm5 must be unsigned five-bit")

    @property
    def immediate_form(self) -> bool:
        return self.opcode_kind in _IMMEDIATE


@dataclass(frozen=True)
class CsrDecoderProfile:
    privilege_spec_version: str
    xlen_bits: int
    extensions: tuple[str, ...]

    def catalog_profile(self) -> CsrCatalogProfile:
        version = self.privilege_spec_version.strip().lower()
        if not version.startswith("riscv-privileged-"):
            version = "riscv-privileged-" + version
        return CsrCatalogProfile(version, self.xlen_bits, tuple(sorted(set(
            item.strip().lower() for item in self.extensions if item.strip()))))


def profile_from_execution_facts(facts: Any, *, xlen_bits: int) -> CsrDecoderProfile | None:
    version = getattr(facts, "source_privilege_spec_version", None)
    extensions = getattr(facts, "source_isa_extensions", None)
    if not isinstance(version, str) or not version.strip() or not isinstance(extensions, tuple):
        return None
    return CsrDecoderProfile(version, xlen_bits, extensions)


def decode_csr_instruction(machine_bytes: bytes) -> DecodedCsrInstruction | None:
    """Decode RISC-V SYSTEM CSR bitfields from bytes, or return non-CSR None."""
    if not isinstance(machine_bytes, (bytes, bytearray)) or len(machine_bytes) < 4:
        return None
    word = int.from_bytes(machine_bytes[:4], "little")
    if (word & 0x7F) != 0x73:
        return None
    funct3 = (word >> 12) & 0x7
    if funct3 == 0:
        return None  # Other SYSTEM instructions use their own privileged ingress.
    kind = _FUNCT3_TO_KIND.get(funct3, DecodedCsrOpcodeKind.UNKNOWN)
    value = (word >> 15) & 0x1F
    return DecodedCsrInstruction(
        opcode_kind=kind, csr_numeric_address=(word >> 20) & 0xFFF,
        rd_register_id=f"x{(word >> 7) & 0x1F}",
        rs1_register_id=None if kind in _IMMEDIATE else f"x{value}",
        zimm5=value if kind in _IMMEDIATE else None,
        instruction_width_bits=32, decoder_version=CSR_DECODER_VERSION,
        complete=kind is not DecodedCsrOpcodeKind.UNKNOWN,
    )


def _node(addr: int, role: str, register: str) -> str:
    return f"decoder-csr:{addr:#x}:{role}:{register}"


def canonical_csr_operations_from_decoded(*, addr: int, decoded: DecodedCsrInstruction,
        xlen_bits: int, profile: CsrDecoderProfile | None,
        catalog: CsrSpecificationCatalog = DEFAULT_CSR_SPECIFICATION_CATALOG) -> tuple[Any, ...]:
    """Canonicalize only a decoded instruction and the versioned catalog entry."""
    from .pcode_ir import CanonicalCsrFieldEffect, CanonicalCsrOperationKind, CanonicalPrivilegedOperation, CanonicalPrivilegedOperationKind
    entry = None if profile is None or decoded.csr_numeric_address is None else catalog.resolve(
        numeric_address=decoded.csr_numeric_address, profile=profile.catalog_profile())
    immediate = decoded.immediate_form
    base = decoded.opcode_kind.value[:-1] if immediate else decoded.opcode_kind.value
    rd_x0 = decoded.rd_register_id == "x0"
    source_x0 = decoded.zimm5 == 0 if immediate else decoded.rs1_register_id == "x0"
    # Only CSRRW[I] suppresses a CSR read for rd=x0.  CSRRS/CSRRC still read
    # the CSR, but rd=x0 discards its result.
    reads = base != "csrrw" or not rd_x0
    writes = base == "csrrw" or not source_x0
    if base == "csrrw":
        operation = CanonicalCsrOperationKind.READ_WRITE if reads else CanonicalCsrOperationKind.WRITE
    elif base == "csrrs":
        operation = CanonicalCsrOperationKind.SET_BITS if writes else CanonicalCsrOperationKind.READ
    elif base == "csrrc":
        operation = CanonicalCsrOperationKind.CLEAR_BITS if writes else CanonicalCsrOperationKind.READ
    else:
        operation = CanonicalCsrOperationKind.UNKNOWN
    fields = () if entry is None else tuple(CanonicalCsrFieldEffect(
        field_id=f"{entry.csr_id}.{field.field_id}", writable_mask=field.writable_mask,
        warl_or_wlrl_policy_id=field.policy_id, side_effect_ids=field.side_effect_ids,
        complete=field.behavior.value != "wpri") for field in entry.fields)
    profile_has_zicsr = profile is not None and "zicsr" in {
        item.strip().lower() for item in profile.extensions
    }
    complete = bool(decoded.complete and entry is not None and profile is not None and
                    profile.xlen_bits == xlen_bits and profile_has_zicsr and
                    (decoded.csr_numeric_address not in _HIGH_COUNTERS or xlen_bits == 32))
    return (CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
        csr_id=None if entry is None else entry.csr_id,
        csr_numeric_address=decoded.csr_numeric_address,
        decoder_opcode_kind=decoded.opcode_kind.value,
        csr_semantic_class="unknown" if entry is None else entry.semantic_class,
        csr_operation=operation,
        read_value_node_id=(_node(addr, "rd", decoded.rd_register_id) if reads and not rd_x0 else None),
        write_value_node_id=(_node(addr, "rs1", decoded.rs1_register_id) if writes and not immediate and decoded.rs1_register_id else None),
        immediate_mask=decoded.zimm5 if immediate and writes else None,
        read_result_suppressed=reads and rd_x0, write_value_suppressed=not writes,
        read_modify_write=operation in {CanonicalCsrOperationKind.READ_WRITE, CanonicalCsrOperationKind.SET_BITS, CanonicalCsrOperationKind.CLEAR_BITS},
        affected_csr_fields=fields, xlen_bits=xlen_bits, required_extension_id="zicsr",
        access_gate_ids=() if entry is None else entry.access_gates,
        access_gate_evaluation_complete=False,
        required_privilege_mode=None if entry is None else entry.minimum_privilege_mode,
        may_trap=True, state_complete=complete),)


def decode_csr_privileged_operations(*, addr: int, machine_bytes: bytes, xlen_bits: int,
        profile: CsrDecoderProfile | None,
        catalog: CsrSpecificationCatalog = DEFAULT_CSR_SPECIFICATION_CATALOG) -> tuple[Any, ...]:
    """Production machine-byte decoder entry used by :func:`lift`."""
    decoded = decode_csr_instruction(machine_bytes)
    if decoded is None:
        return ()
    return canonical_csr_operations_from_decoded(addr=addr, decoded=decoded,
        xlen_bits=xlen_bits, profile=profile, catalog=catalog)
