"""Versioned, profile-selectable RISC-V CSR specification database.

The JSON documents under ``catalog/riscv-privileged-*/rv*.json`` are the
authoritative source.  This module validates and indexes them; it is not a
mnemonic lowering table and intentionally has no version-less lookup.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping


PRIV_SPEC_1_12 = "riscv-privileged-1.12"
PRIV_SPEC_1_13 = "riscv-privileged-1.13"


class CsrFieldBehavior(str, Enum):
    RW = "rw"; RO = "ro"; WARL = "warl"; WLRL = "wlrl"; WPRI = "wpri"


class CsrReadPolicy(str, Enum):
    READABLE = "readable"; TRAP = "trap"


class CsrWritePolicy(str, Enum):
    READ_ONLY = "read_only"; WRITABLE = "writable"; TRAP = "trap"


@dataclass(frozen=True)
class CsrFieldSpecification:
    field_id: str
    canonical_field_id: str
    bit_offset: int
    bit_width: int
    writable_mask: int
    behavior: CsrFieldBehavior
    policy_id: str | None = None
    side_effect_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.field_id or not self.canonical_field_id or self.bit_offset < 0 or self.bit_width <= 0:
            raise ValueError("CSR field needs ids and a valid bit range")
        if self.writable_mask < 0 or self.writable_mask >= (1 << self.bit_width):
            raise ValueError("CSR field writable mask exceeds its width")


@dataclass(frozen=True)
class CsrAliasAndView:
    alias_id: str
    target_csr_id: str
    field_identities: tuple[tuple[str, str], ...] = ()
    view_kind: str = "alias"


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
    aliases_and_views: tuple[CsrAliasAndView, ...] = ()
    access_gates: tuple[str, ...] = ()
    read_side_effect_ids: tuple[str, ...] = ()
    write_side_effect_ids: tuple[str, ...] = ()
    trap_policy_id: str | None = None
    complete: bool = True
    route_required: bool = False

    @property
    def aliases(self) -> tuple[str, ...]:
        """Compatibility view for callers that only need textual aliases."""
        return tuple(item.alias_id for item in self.aliases_and_views)

    def __post_init__(self) -> None:
        if not self.csr_id.startswith("riscv.csr.") or not 0 <= self.numeric_address <= 0xfff:
            raise ValueError("CSR id/address is invalid")
        if not self.privilege_spec_version or not self.xlen_profiles or not set(self.xlen_profiles) <= {32, 64}:
            raise ValueError("CSR must declare RV32 and/or RV64 profile")
        if not self.complete and not self.route_required:
            raise ValueError("incomplete catalog entry must explicitly require a route")
        if len({field.field_id for field in self.fields}) != len(self.fields):
            raise ValueError("CSR field ids must be unique")
        occupied = 0
        for field in self.fields:
            mask = ((1 << field.bit_width) - 1) << field.bit_offset
            if occupied & mask:
                raise ValueError("CSR fields overlap")
            occupied |= mask


@dataclass(frozen=True)
class CsrCatalogProfile:
    privilege_spec_version: str
    xlen_bits: int
    extensions: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.xlen_bits not in {32, 64} or not self.privilege_spec_version:
            raise ValueError("catalog profile needs exact version and XLEN")
        if tuple(sorted(set(self.extensions))) != self.extensions:
            raise ValueError("extensions must be normalized/unique/sorted")


def _tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("catalog string-list field is invalid")
    return tuple(value)


def _field(raw: Mapping[str, object]) -> CsrFieldSpecification:
    return CsrFieldSpecification(
        field_id=str(raw["field_id"]), canonical_field_id=str(raw["canonical_field_id"]),
        bit_offset=int(raw["bit_offset"]), bit_width=int(raw["bit_width"]),
        writable_mask=int(raw["writable_mask"]), behavior=CsrFieldBehavior(str(raw["behavior"])),
        policy_id=raw.get("policy_id") if isinstance(raw.get("policy_id"), str) else None,
        side_effect_ids=_tuple(raw.get("side_effect_ids", [])),
    )


def _entry(raw: Mapping[str, object], *, document_version: str, document_xlen: int) -> CsrSpecificationEntry:
    if raw.get("privilege_spec_version") != document_version:
        raise ValueError("entry privilege version does not match its document")
    xlen = tuple(int(item) for item in raw["xlen_profiles"])
    if document_xlen not in xlen:
        raise ValueError("profile document contains incompatible entry")
    views = []
    for item in raw.get("aliases_and_views", []):
        if not isinstance(item, dict): raise ValueError("invalid CSR view")
        identities = tuple((str(pair[0]), str(pair[1])) for pair in item.get("field_identities", []) if isinstance(pair, list) and len(pair) == 2)
        views.append(CsrAliasAndView(str(item["alias_id"]), str(item["target_csr_id"]), identities, str(item.get("view_kind", "alias"))))
    return CsrSpecificationEntry(
        csr_id=str(raw["csr_id"]), numeric_address=int(raw["numeric_address"]),
        privilege_spec_version=document_version, xlen_profiles=xlen,
        required_extensions=_tuple(raw.get("required_extensions", [])),
        semantic_class=str(raw["semantic_class"]), minimum_privilege_mode=str(raw["minimum_privilege_mode"]),
        read_policy=CsrReadPolicy(str(raw["read_policy"])), write_policy=CsrWritePolicy(str(raw["write_policy"])),
        fields=tuple(_field(item) for item in raw.get("fields", [])), aliases_and_views=tuple(views),
        access_gates=_tuple(raw.get("access_gates", [])), read_side_effect_ids=_tuple(raw.get("read_side_effect_ids", [])),
        write_side_effect_ids=_tuple(raw.get("write_side_effect_ids", [])),
        trap_policy_id=raw.get("trap_policy_id") if isinstance(raw.get("trap_policy_id"), str) else None,
        complete=bool(raw.get("complete", False)), route_required=bool(raw.get("route_required", False)),
    )


class CsrSpecificationCatalog:
    def __init__(self, entries: Iterable[CsrSpecificationEntry] | None = None, *, catalog_root: Path | None = None):
        self._catalog_root = catalog_root or Path(__file__).resolve().parents[2] / "catalog"
        self._entries = tuple(entries) if entries is not None else self._load_documents()
        keys = [(entry.privilege_spec_version, entry.numeric_address, xlen) for entry in self._entries for xlen in entry.xlen_profiles]
        if len(set(keys)) != len(keys): raise ValueError("duplicate version/profile/address CSR entry")

    def _load_documents(self) -> tuple[CsrSpecificationEntry, ...]:
        entries = []
        for path in sorted(self._catalog_root.glob("riscv-privileged-*/rv*.json")):
            raw = json.loads(path.read_text(encoding="utf-8"))
            version, xlen = raw.get("privilege_spec_version"), raw.get("xlen_bits")
            if not isinstance(version, str) or xlen not in {32, 64}: raise ValueError(f"invalid catalog document {path}")
            entries.extend(_entry(item, document_version=version, document_xlen=xlen) for item in raw.get("entries", []))
        if not entries: raise ValueError("no CSR specification documents found")
        return tuple(entries)

    @staticmethod
    def _matches(entry: CsrSpecificationEntry, profile: CsrCatalogProfile) -> bool:
        return (entry.privilege_spec_version == profile.privilege_spec_version and profile.xlen_bits in entry.xlen_profiles and
                set(entry.required_extensions).issubset(profile.extensions))

    def resolve(self, *, numeric_address: int, profile: CsrCatalogProfile) -> CsrSpecificationEntry | None:
        return next((entry for entry in self._entries if entry.numeric_address == numeric_address and self._matches(entry, profile)), None)

    def resolve_id(self, *, csr_id_or_alias: str, profile: CsrCatalogProfile) -> CsrSpecificationEntry | None:
        key = csr_id_or_alias.strip().lower()
        return next((entry for entry in self._entries if self._matches(entry, profile) and key in (entry.csr_id, *entry.aliases)), None)

    def entries_for_profile(self, profile: CsrCatalogProfile) -> tuple[CsrSpecificationEntry, ...]:
        return tuple(entry for entry in self._entries if self._matches(entry, profile))


DEFAULT_CSR_SPECIFICATION_CATALOG = CsrSpecificationCatalog()
