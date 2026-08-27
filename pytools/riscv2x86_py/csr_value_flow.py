"""Phase-5 authoritative CSR effect <-> GNU operand join.

The join is deliberately one-way: Phase 4 creates decoder value-node ids and
assembler/frontend facts bind those ids to GNU operands.  Renderers receive
only ``SourceCsrOperandBinding`` and may not recover a binding from registers,
instruction text, or operand order.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping
from .runtime_facts import canonicalize_riscv_register_name

@dataclass(frozen=True)
class SourceCsrOperandBinding:
    source_effect_id: str
    read_result_operand_index: int | None
    write_value_operand_index: int | None
    immediate_value: int | None
    source_value_width_bits: int | None
    source_signedness: str | None
    complete: bool
    reason_codes: tuple[str, ...] = ()

@dataclass(frozen=True)
class CsrOperandAuthority:
    value_node_to_operand_index: Mapping[str, int]
    operand_width_bits: Mapping[int, int]
    operand_signedness: Mapping[int, str]
    output_escapes: Mapping[int, bool]
    tied_operand_pairs: tuple[tuple[int, int], ...] = ()
    early_clobber_outputs: tuple[int, ...] = ()
    volatile_preserved: bool | None = None
    memory_clobber_preserved: bool | None = None
    cc_clobber_preserved: bool | None = None
    fixed_register_operands: Mapping[int, str] = None

def authority_from_phase4_facts(*, lifted_insns: tuple[Any, ...] | list[Any], runtime_facts: Any) -> CsrOperandAuthority:
    """Adapt Phase-4 materialization facts; never inspect asm text or p-code."""
    registers = getattr(runtime_facts, "rv_to_operand_index", {}) or {}
    node_map={}
    for insn in lifted_insns:
        for op in tuple(getattr(insn, "privileged_operations", ()) or ()):
            for node in (getattr(op,"read_value_node_id",None),getattr(op,"write_value_node_id",None)):
                if not isinstance(node,str) or not node.startswith("decoder-csr:"): continue
                register=canonicalize_riscv_register_name(node.rsplit(":",1)[-1])
                if register and register in registers: node_map[node]=registers[register]
    # Signedness/escape remain explicitly unknown until the frontend supplies
    # them; the join will therefore reject approval rather than invent facts.
    return CsrOperandAuthority(node_map,getattr(runtime_facts,"operand_width_bits",{}) or {},{}, {},fixed_register_operands={})

def _effect_id(addr: int, ordinal: int, op: Any) -> str:
    return f"csr-effect:{addr:#x}:{ordinal}:{getattr(op, 'csr_id', '') or 'unknown'}"

def _as_index(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

def _joined_index(node_id: str | None, authority: CsrOperandAuthority) -> int | None:
    if not isinstance(node_id, str) or not node_id:
        return None
    return _as_index(authority.value_node_to_operand_index.get(node_id))

def join_csr_operand_bindings(*, lifted_insns: tuple[Any, ...] | list[Any], authority: CsrOperandAuthority,
                              fragment_shell: Any) -> tuple[SourceCsrOperandBinding, ...]:
    """Join every typed CSR operation using already-materialized node facts."""
    result=[]
    ordinal=0
    volatile=bool(getattr(fragment_shell, "isVolatile", False))
    clobbers={str(x).strip('"').lower() for x in getattr(fragment_shell, "clobbers", ())}
    for insn in lifted_insns:
        for op in tuple(getattr(insn, "privileged_operations", ()) or ()):
            if getattr(getattr(op, "kind", None), "value", None) != "csr_access":
                continue
            ordinal += 1; reasons=[]
            effect_id=_effect_id(getattr(insn,"addr",0), ordinal, op)
            read=_joined_index(getattr(op,"read_value_node_id",None), authority)
            write=_joined_index(getattr(op,"write_value_node_id",None), authority)
            immediate=getattr(op,"immediate_mask",None)
            reads=getattr(op,"read_value_node_id",None) is not None
            writes=getattr(op,"write_value_node_id",None) is not None or immediate is not None
            if reads and read is None: reasons.append("csr-join.read-result-binding-missing")
            if writes and immediate is None and write is None: reasons.append("csr-join.write-value-binding-missing")
            if immediate is not None and (not isinstance(immediate,int) or isinstance(immediate,bool) or not 0 <= immediate < 32): reasons.append("csr-join.zimm-invalid")
            if not reads and read is not None: reasons.append("csr-join.read-suppression-violated")
            if not writes and (write is not None or immediate is not None): reasons.append("csr-join.write-suppression-violated")
            used=tuple(i for i in (read,write) if i is not None)
            widths={authority.operand_width_bits.get(i) for i in used}
            signed={authority.operand_signedness.get(i) for i in used}
            if used and (None in widths or any(not isinstance(v,int) or v <= 0 for v in widths)): reasons.append("csr-join.c-type-width-missing")
            if used and (None in signed or any(v not in {"signed","unsigned"} for v in signed)): reasons.append("csr-join.c-type-signedness-missing")
            if read is not None and authority.output_escapes.get(read) is not False: reasons.append("csr-join.output-escape-unproven")
            if read is not None and write is not None and read == write and (read,write) not in authority.tied_operand_pairs: reasons.append("csr-join.tied-operand-unproven")
            if read is not None and read in authority.early_clobber_outputs: reasons.append("csr-join.early-clobber-requires-contract")
            if volatile and authority.volatile_preserved is not True: reasons.append("csr-join.volatile-shell-unproven")
            if "memory" in clobbers and authority.memory_clobber_preserved is not True: reasons.append("csr-join.memory-shell-unproven")
            if "cc" in clobbers and authority.cc_clobber_preserved is not True: reasons.append("csr-join.cc-shell-unproven")
            for index in used:
                if index in (authority.fixed_register_operands or {}) and not (authority.fixed_register_operands or {}).get(index): reasons.append("csr-join.fixed-register-contract-missing")
            result.append(SourceCsrOperandBinding(effect_id,read,write,immediate,
                next(iter(widths)) if len(widths)==1 else None,
                next(iter(signed)) if len(signed)==1 else None,not reasons,tuple(sorted(set(reasons)))))
    return tuple(result)
