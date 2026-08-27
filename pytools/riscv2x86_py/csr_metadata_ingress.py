"""Phase-4 CSR metadata ingress from decoder identities.

The adapter runs beside lifting, before canonical IR exists.  It may consume a
decoder's structured mnemonic/operand fields, but no later phase may inspect
those fields again.  The result is a typed ``CanonicalPrivilegedOperation``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .csr_spec_catalog import (
    CsrCatalogProfile,
    CsrSpecificationCatalog,
    DEFAULT_CSR_SPECIFICATION_CATALOG,
)

_CSR_FORMS = {"csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci"}
_COUNTER_PSEUDOS = {
    "rdcycle": ("cycle", False), "rdtime": ("time", False),
    "rdinstret": ("instret", False), "rdcycleh": ("cycle", True),
    "rdtimeh": ("time", True), "rdinstreth": ("instret", True),
}


@dataclass(frozen=True)
class CsrDecoderProfile:
    privilege_spec_version: str
    xlen_bits: int
    extensions: tuple[str, ...]

    def catalog_profile(self) -> CsrCatalogProfile:
        version = self.privilege_spec_version.strip().lower()
        if not version.startswith("riscv-privileged-"):
            version = "riscv-privileged-" + version
        return CsrCatalogProfile(version, self.xlen_bits,
            tuple(sorted(set(item.strip().lower() for item in self.extensions if item.strip()))))


def profile_from_execution_facts(facts: Any, *, xlen_bits: int) -> CsrDecoderProfile | None:
    version = getattr(facts, "source_privilege_spec_version", None)
    extensions = getattr(facts, "source_isa_extensions", None)
    if not isinstance(version, str) or not version.strip() or not isinstance(extensions, tuple):
        return None
    return CsrDecoderProfile(version, xlen_bits, extensions)


def _tokens(body: str) -> tuple[str, ...]:
    if not isinstance(body, str):
        return ()
    return tuple(token.strip().lower() for token in body.replace("\t", " ").split(",") if token.strip())


def _csr_address(token: str) -> int | None:
    try:
        value = int(token, 0)
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= 0xfff else None


def _is_zero_register(token: str) -> bool:
    return token.strip().lower() in {"x0", "zero"}


def _node(addr: int, role: str, operand: str) -> str:
    return f"decoder-csr:{addr:#x}:{role}:{operand}"


def decode_csr_privileged_operations(*, addr: int, decoder_mnemonic: str,
        decoder_operands: str, xlen_bits: int, profile: CsrDecoderProfile | None,
        catalog: CsrSpecificationCatalog = DEFAULT_CSR_SPECIFICATION_CATALOG) -> tuple[Any, ...]:
    """Return typed CSR metadata, or ``()`` for non-CSR decoder identities.

    A CSR-shaped instruction with a missing/invalid profile still returns one
    incomplete typed operation.  This prevents an illegal CSR from silently
    becoming ordinary integer code while preserving the fail-closed boundary.
    """
    mnem = (decoder_mnemonic or "").strip().lower()
    operands = _tokens(decoder_operands)
    if mnem not in _CSR_FORMS and mnem not in _COUNTER_PSEUDOS:
        return ()
    from .pcode_ir import CanonicalCsrFieldEffect, CanonicalCsrOperationKind, CanonicalPrivilegedOperation, CanonicalPrivilegedOperationKind
    if mnem in _COUNTER_PSEUDOS:
        name, high_half = _COUNTER_PSEUDOS[mnem]
        # high-half counter aliases exist only for RV32; RV64 must reject them.
        entry = None if profile is None else catalog.resolve_id(csr_id_or_alias=name, profile=profile.catalog_profile())
        valid = len(operands) == 1 and (not high_half or xlen_bits == 32) and entry is not None
        return (CanonicalPrivilegedOperation(
            kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
            csr_id=("riscv.csr." + name if entry is None else entry.csr_id),
            csr_semantic_class=("user_counter_observation" if entry is None else entry.semantic_class),
            csr_operation=CanonicalCsrOperationKind.READ,
            read_value_node_id=(_node(addr, "rd", operands[0]) if len(operands) == 1 else None),
            read_modify_write=False, xlen_bits=xlen_bits,
            required_extension_id="zicsr", access_gate_ids=(() if entry is None else entry.access_gates),
            access_gate_evaluation_complete=False,
            required_privilege_mode=(None if entry is None else entry.minimum_privilege_mode),
            may_trap=True, state_complete=valid,
        ),)
    immediate = mnem.endswith("i")
    if len(operands) != 3:
        return (CanonicalPrivilegedOperation(CanonicalPrivilegedOperationKind.CSR_ACCESS,
            csr_id="", csr_operation=CanonicalCsrOperationKind.UNKNOWN,
            xlen_bits=xlen_bits, state_complete=False),)
    rd, csr_token, source = operands
    csr_address = _csr_address(csr_token)
    entry = None
    if profile is not None:
        cp = profile.catalog_profile()
        entry = (catalog.resolve(numeric_address=csr_address, profile=cp) if csr_address is not None
                 else catalog.resolve_id(csr_id_or_alias=csr_token, profile=cp))
    source_zero = _is_zero_register(source)
    zimm = None
    if immediate:
        try: zimm = int(source, 0)
        except ValueError: zimm = None
        source_zero = zimm == 0
    base = mnem[:-1] if immediate else mnem
    reads = not (base == "csrrw" and _is_zero_register(rd))
    writes = not ((base in {"csrrs", "csrrc"}) and source_zero)
    operation = (CanonicalCsrOperationKind.READ_WRITE if reads and writes else
                 CanonicalCsrOperationKind.READ if reads else CanonicalCsrOperationKind.WRITE)
    if base == "csrrs" and writes: operation = CanonicalCsrOperationKind.SET_BITS
    if base == "csrrc" and writes: operation = CanonicalCsrOperationKind.CLEAR_BITS
    fields = () if entry is None else tuple(CanonicalCsrFieldEffect(
        field_id=f"{entry.csr_id}.{field.field_id}", writable_mask=field.writable_mask,
        warl_or_wlrl_policy_id=field.policy_id, side_effect_ids=field.side_effect_ids,
        complete=field.behavior.value not in {"wpri"},
    ) for field in entry.fields)
    complete = entry is not None and (not immediate or zimm is not None and 0 <= zimm < 32)
    return (CanonicalPrivilegedOperation(
        kind=CanonicalPrivilegedOperationKind.CSR_ACCESS,
        csr_id="" if entry is None else entry.csr_id,
        csr_semantic_class="unknown" if entry is None else entry.semantic_class,
        csr_operation=operation,
        read_value_node_id=(_node(addr, "rd", rd) if reads else None),
        write_value_node_id=(_node(addr, "rs1", source) if writes and not immediate else None),
        immediate_mask=(zimm if immediate and writes else None),
        read_modify_write=operation in {CanonicalCsrOperationKind.READ_WRITE, CanonicalCsrOperationKind.SET_BITS, CanonicalCsrOperationKind.CLEAR_BITS},
        affected_csr_fields=fields, xlen_bits=xlen_bits, required_extension_id="zicsr",
        access_gate_ids=(() if entry is None else entry.access_gates), access_gate_evaluation_complete=False,
        required_privilege_mode=(None if entry is None else entry.minimum_privilege_mode), may_trap=True,
        state_complete=complete,
    ),)
