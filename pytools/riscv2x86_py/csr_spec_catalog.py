"""Versioned RISC-V privileged CSR specification catalog.

This module is an authoritative Phase-4 input, not a lowering table.  A
caller must select an exact Privileged Architecture version and ISA profile;
the catalog intentionally has no global, version-less ``csr_id -> spec`` API.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


PRIV_SPEC_1_12 = "riscv-privileged-1.12"


class CsrFieldBehavior(str, Enum):
    RW = "rw"; RO = "ro"; WARL = "warl"; WLRL = "wlrl"; WPRI = "wpri"


class CsrReadPolicy(str, Enum):
    READABLE = "readable"; TRAP = "trap"


class CsrWritePolicy(str, Enum):
    READ_ONLY = "read_only"; WRITABLE = "writable"; TRAP = "trap"


@dataclass(frozen=True)
class CsrFieldSpecification:
    field_id: str
    bit_offset: int
    bit_width: int
    writable_mask: int
    behavior: CsrFieldBehavior
    policy_id: str | None = None
    side_effect_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.field_id or self.bit_offset < 0 or self.bit_width <= 0:
            raise ValueError("CSR field requires a non-empty id and valid bit range")
        if self.writable_mask < 0 or self.writable_mask >= (1 << self.bit_width):
            raise ValueError("CSR field writable mask exceeds its field width")
        if tuple(sorted(set(self.side_effect_ids))) != self.side_effect_ids:
            raise ValueError("CSR field side effects must be unique and sorted")


@dataclass(frozen=True)
class CsrSpecificationEntry:
    csr_id: str
    numeric_address: int
    privilege_spec_version: str
    xlen_profiles: tuple[int, ...]
    required_extensions: tuple[str, ...]
    semantic_class: str
    minimum_privilege_mode: str
    read_policy: CsrReadPolicy
    write_policy: CsrWritePolicy
    fields: tuple[CsrFieldSpecification, ...]
    aliases: tuple[str, ...] = ()
    access_gates: tuple[str, ...] = ()
    read_side_effect_ids: tuple[str, ...] = ()
    write_side_effect_ids: tuple[str, ...] = ()
    trap_policy_id: str | None = None
    complete: bool = True

    def __post_init__(self) -> None:
        if not self.csr_id.startswith("riscv.csr.") or not 0 <= self.numeric_address <= 0xfff:
            raise ValueError("CSR id/address is invalid")
        if not self.privilege_spec_version or not set(self.xlen_profiles) <= {32, 64}:
            raise ValueError("CSR must declare supported XLEN profiles")
        if tuple(sorted(set(self.xlen_profiles))) != self.xlen_profiles:
            raise ValueError("XLEN profiles must be unique and sorted")
        for values in (self.required_extensions, self.aliases, self.access_gates,
                       self.read_side_effect_ids, self.write_side_effect_ids):
            if tuple(sorted(set(values))) != values:
                raise ValueError("CSR catalog tuple values must be unique and sorted")
        if len({field.field_id for field in self.fields}) != len(self.fields):
            raise ValueError("CSR field ids must be unique")
        occupied = 0
        for field in self.fields:
            mask = ((1 << field.bit_width) - 1) << field.bit_offset
            if occupied & mask:
                raise ValueError("CSR fields must not overlap")
            occupied |= mask


@dataclass(frozen=True)
class CsrCatalogProfile:
    privilege_spec_version: str
    xlen_bits: int
    extensions: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.xlen_bits not in {32, 64} or not self.privilege_spec_version:
            raise ValueError("catalog profile needs an exact spec version and XLEN")
        if tuple(sorted(set(self.extensions))) != self.extensions:
            raise ValueError("extensions must be unique and sorted")


def _f(name: str, offset: int, width: int, behavior: CsrFieldBehavior,
       mask: int | None = None, policy: str | None = None,
       effects: tuple[str, ...] = ()) -> CsrFieldSpecification:
    return CsrFieldSpecification(name, offset, width,
        ((1 << width) - 1) if mask is None else mask, behavior, policy, effects)


def _entry(name: str, addr: int, klass: str, mode: str, *,
           xlen: tuple[int, ...] = (32, 64), extensions: tuple[str, ...] = (),
           read: CsrReadPolicy = CsrReadPolicy.READABLE,
           write: CsrWritePolicy = CsrWritePolicy.WRITABLE,
           fields: tuple[CsrFieldSpecification, ...] = (), aliases: tuple[str, ...] = (),
           gates: tuple[str, ...] = (), read_fx: tuple[str, ...] = (),
           write_fx: tuple[str, ...] = (), trap: str | None = "riscv.csr.access-illegal.v1") -> CsrSpecificationEntry:
    return CsrSpecificationEntry("riscv.csr." + name, addr, PRIV_SPEC_1_12, xlen,
        extensions, klass, mode, read, write, fields, aliases, gates, read_fx,
        write_fx, trap, True)


# The catalog deliberately contains only entries whose field/access semantics
# are represented here.  Unknown, draft, custom, or another spec version must
# remain unresolved for the next phase to reject or route explicitly.
_V1_12_ENTRIES = (
    _entry("cycle", 0xC00, "user_counter_observation", "u", write=CsrWritePolicy.READ_ONLY,
           gates=("riscv.counteren.cycle",), aliases=("cycle",)),
    _entry("time", 0xC01, "user_counter_observation", "u", write=CsrWritePolicy.READ_ONLY,
           gates=("riscv.counteren.time",), aliases=("time",)),
    _entry("instret", 0xC02, "user_counter_observation", "u", write=CsrWritePolicy.READ_ONLY,
           gates=("riscv.counteren.instret",), aliases=("instret",)),
    _entry("fflags", 0x001, "fpu_state", "u", extensions=("f",),
           fields=(_f("fflags", 0, 5, CsrFieldBehavior.RW),), aliases=("fflags",)),
    _entry("frm", 0x002, "fpu_state", "u", extensions=("f",),
           fields=(_f("frm", 0, 3, CsrFieldBehavior.WARL, policy="riscv.frm.warl.v1"),), aliases=("frm",)),
    _entry("fcsr", 0x003, "fpu_state", "u", extensions=("f",),
           fields=(_f("fflags", 0, 5, CsrFieldBehavior.RW), _f("frm", 5, 3, CsrFieldBehavior.WARL, policy="riscv.frm.warl.v1")), aliases=("fcsr",)),
    _entry("sstatus", 0x100, "privileged_status", "s", fields=(_f("sie", 1, 1, CsrFieldBehavior.RW), _f("spie", 5, 1, CsrFieldBehavior.RW), _f("spp", 8, 1, CsrFieldBehavior.RW), _f("fs", 13, 2, CsrFieldBehavior.WARL, policy="riscv.fs.warl.v1")), aliases=("sstatus",)),
    _entry("mstatus", 0x300, "privileged_status", "m", fields=(_f("mie", 3, 1, CsrFieldBehavior.RW), _f("mpie", 7, 1, CsrFieldBehavior.RW), _f("mpp", 11, 2, CsrFieldBehavior.WARL, policy="riscv.mpp.warl.v1"), _f("fs", 13, 2, CsrFieldBehavior.WARL, policy="riscv.fs.warl.v1")), aliases=("mstatus",)),
    _entry("sie", 0x104, "interrupt_state", "s", fields=(_f("ssie", 1, 1, CsrFieldBehavior.RW), _f("stie", 5, 1, CsrFieldBehavior.RW), _f("seie", 9, 1, CsrFieldBehavior.RW)), aliases=("sie",)),
    _entry("mie", 0x304, "interrupt_state", "m", fields=(_f("msie", 3, 1, CsrFieldBehavior.RW), _f("mtie", 7, 1, CsrFieldBehavior.RW), _f("meie", 11, 1, CsrFieldBehavior.RW)), aliases=("mie",)),
    _entry("sip", 0x144, "interrupt_state", "s", fields=(_f("ssip", 1, 1, CsrFieldBehavior.RW), _f("stip", 5, 1, CsrFieldBehavior.RO, 0), _f("seip", 9, 1, CsrFieldBehavior.RO, 0)), aliases=("sip",)),
    _entry("mip", 0x344, "interrupt_state", "m", fields=(_f("msip", 3, 1, CsrFieldBehavior.RW), _f("mtip", 7, 1, CsrFieldBehavior.RO, 0), _f("meip", 11, 1, CsrFieldBehavior.RO, 0)), aliases=("mip",)),
    _entry("stvec", 0x105, "trap_vector", "s", xlen=(64,), fields=(_f("mode", 0, 2, CsrFieldBehavior.WARL, policy="riscv.tvec.mode.warl.v1"), _f("base", 2, 62, CsrFieldBehavior.WARL, policy="riscv.tvec.base.warl.v1")), aliases=("stvec",)),
    _entry("mtvec", 0x305, "trap_vector", "m", xlen=(64,), fields=(_f("mode", 0, 2, CsrFieldBehavior.WARL, policy="riscv.tvec.mode.warl.v1"), _f("base", 2, 62, CsrFieldBehavior.WARL, policy="riscv.tvec.base.warl.v1")), aliases=("mtvec",)),
    _entry("sepc", 0x141, "trap_state", "s", xlen=(64,), fields=(_f("pc", 0, 64, CsrFieldBehavior.WARL, policy="riscv.epc.warl.v1"),), aliases=("sepc",)),
    _entry("mepc", 0x341, "trap_state", "m", xlen=(64,), fields=(_f("pc", 0, 64, CsrFieldBehavior.WARL, policy="riscv.epc.warl.v1"),), aliases=("mepc",)),
    _entry("scause", 0x142, "trap_state", "s", xlen=(64,), fields=(_f("cause", 0, 64, CsrFieldBehavior.WLRL, policy="riscv.cause.wlrl.v1"),), aliases=("scause",)),
    _entry("mcause", 0x342, "trap_state", "m", xlen=(64,), fields=(_f("cause", 0, 64, CsrFieldBehavior.WLRL, policy="riscv.cause.wlrl.v1"),), aliases=("mcause",)),
    _entry("stval", 0x143, "trap_state", "s", xlen=(64,), fields=(_f("tval", 0, 64, CsrFieldBehavior.WARL, policy="riscv.tval.warl.v1"),), aliases=("stval",)),
    _entry("mtval", 0x343, "trap_state", "m", xlen=(64,), fields=(_f("tval", 0, 64, CsrFieldBehavior.WARL, policy="riscv.tval.warl.v1"),), aliases=("mtval",)),
    _entry("medeleg", 0x302, "delegation", "m", xlen=(64,), fields=(_f("exceptions", 0, 64, CsrFieldBehavior.WARL, policy="riscv.medeleg.warl.v1"),), aliases=("medeleg",)),
    _entry("mideleg", 0x303, "delegation", "m", xlen=(64,), fields=(_f("interrupts", 0, 64, CsrFieldBehavior.WARL, policy="riscv.mideleg.warl.v1"),), aliases=("mideleg",)),
    _entry("scounteren", 0x106, "counter_control", "s", fields=(_f("counter_enable", 0, 32, CsrFieldBehavior.RW),), aliases=("scounteren",)),
    _entry("mcounteren", 0x306, "counter_control", "m", fields=(_f("counter_enable", 0, 32, CsrFieldBehavior.RW),), aliases=("mcounteren",)),
    _entry("satp", 0x180, "address_translation", "s", xlen=(64,), fields=(_f("ppn", 0, 44, CsrFieldBehavior.WARL, policy="riscv.satp.ppn.warl.v1", effects=("riscv.mmu.root-change",)), _f("asid", 44, 16, CsrFieldBehavior.WARL, policy="riscv.satp.asid.warl.v1"), _f("mode", 60, 4, CsrFieldBehavior.WARL, policy="riscv.satp.mode.warl.v1")), aliases=("satp",), write_fx=("riscv.mmu.root-change",)),
)


class CsrSpecificationCatalog:
    def __init__(self, entries: Iterable[CsrSpecificationEntry] = _V1_12_ENTRIES):
        self._entries = tuple(entries)
        keys = [(entry.privilege_spec_version, entry.numeric_address) for entry in self._entries]
        if len(set(keys)) != len(keys):
            raise ValueError("catalog has duplicate version/address entries")

    def resolve(self, *, numeric_address: int, profile: CsrCatalogProfile) -> CsrSpecificationEntry | None:
        for entry in self._entries:
            if (entry.privilege_spec_version == profile.privilege_spec_version and
                    entry.numeric_address == numeric_address and profile.xlen_bits in entry.xlen_profiles and
                    set(entry.required_extensions).issubset(profile.extensions)):
                return entry
        return None

    def resolve_id(self, *, csr_id_or_alias: str, profile: CsrCatalogProfile) -> CsrSpecificationEntry | None:
        key = csr_id_or_alias.strip().lower()
        for entry in self._entries:
            if entry.privilege_spec_version != profile.privilege_spec_version:
                continue
            if key in (entry.csr_id, *entry.aliases) and profile.xlen_bits in entry.xlen_profiles and set(entry.required_extensions).issubset(profile.extensions):
                return entry
        return None

    def entries_for_profile(self, profile: CsrCatalogProfile) -> tuple[CsrSpecificationEntry, ...]:
        return tuple(entry for entry in self._entries if entry.privilege_spec_version == profile.privilege_spec_version and profile.xlen_bits in entry.xlen_profiles and set(entry.required_extensions).issubset(profile.extensions))


DEFAULT_CSR_SPECIFICATION_CATALOG = CsrSpecificationCatalog()
