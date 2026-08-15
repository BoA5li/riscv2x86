"""Versioned Phase-4 ABI-call and target-wrapper sidecar ingress.

Neither source symbols nor operand order are used as an ABI authority here.
The sidecar is produced by a frontend/compiler plugin or a verified corpus
annotation and is joined later with canonical CALL identities.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path
from .abi_effects import (
    AbiCallBindingFacts, AbiValueLocationKind, SourceAbiCallBinding,
    SourceAbiProfile, SourceAbiValueLocation, TargetAbiWrapperContract,
    TargetAbiWrapperRegistry,
)

ABI_CALL_SIDECAR_SCHEMA = "riscv2x86.abi-call-sidecar.v1"
ABI_WRAPPER_REGISTRY_SCHEMA = "riscv2x86.abi-wrapper-registry.v1"

@dataclass(frozen=True)
class AbiCallSidecar:
    schema_version: str
    facts_by_fragment_id: tuple[AbiCallBindingFacts, ...]
    provenance: str
    def __post_init__(self):
        ids = tuple(x.fragment_id for x in self.facts_by_fragment_id)
        if len(ids) != len(set(ids)): raise ValueError("ABI sidecar fragment ids must be unique")
    def bindings_for(self, fragment_id: str) -> tuple[SourceAbiCallBinding, ...]:
        matches = [x for x in self.facts_by_fragment_id if x.fragment_id == fragment_id]
        return () if not matches else matches[0].bindings
    def facts_for(self, fragment_id: str) -> AbiCallBindingFacts | None:
        return next((x for x in self.facts_by_fragment_id if x.fragment_id == fragment_id), None)

def _require_dict(value, what):
    if not isinstance(value, dict): raise ValueError(f"{what} must be an object")
    return value
def _tuple_strings(value, what):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value): raise ValueError(f"{what} must be a string array")
    return tuple(value)
def _optional_bool(value, what):
    if value is not None and not isinstance(value, bool): raise ValueError(f"{what} must be bool or null")
    return value
def _location(value):
    d = _require_dict(value, "ABI value location")
    try: kind = AbiValueLocationKind(d["kind"])
    except (KeyError, ValueError) as exc: raise ValueError("ABI value location has invalid kind") from exc
    return SourceAbiValueLocation(kind, d.get("register"), d.get("stackOffsetBytes"), d.get("widthBits"), d.get("signedness"), d.get("valueKind", ""), bool(d.get("complete", False)))
def _binding(value, fragment_id):
    d = _require_dict(value, "ABI call binding")
    if d.get("fragmentId") != fragment_id: raise ValueError("ABI binding fragmentId does not match enclosing facts")
    try: profile = SourceAbiProfile(d["sourceAbiProfile"])
    except (KeyError, ValueError) as exc: raise ValueError("ABI binding has invalid sourceAbiProfile") from exc
    return SourceAbiCallBinding(
        fragment_id, d["blockAddress"], d["operationIndex"], profile,
        d["directTargetId"], d["sourceSemanticContractId"], d["sourceSemanticVersion"],
        tuple(d["argumentOperandIndexes"]), tuple(d["returnOperandIndexes"]),
        _tuple_strings(d["argumentTypes"], "argumentTypes"), _tuple_strings(d["returnTypes"], "returnTypes"),
        tuple(_location(x) for x in d["sourceArgumentLocations"]), tuple(_location(x) for x in d["sourceReturnLocations"]),
        d.get("stackAlignmentBytes"), d.get("picPltMode"), d.get("tlsModel"),
        _optional_bool(d.get("mayReturn"), "mayReturn"), _optional_bool(d.get("mayUnwind"), "mayUnwind"),
        d.get("memoryEffect", ""), bool(d.get("bindingComplete", False)), d.get("provenance", ""),
        d.get("sourceSymbolId"), _tuple_strings(d.get("callerSavedClobbers", []), "callerSavedClobbers"),
        _tuple_strings(d.get("calleeSavedPreserved", []), "calleeSavedPreserved"),
        d.get("sourceCallFrameSizeBytes"), _optional_bool(d.get("mayTrap"), "mayTrap"), d.get("canonicalTargetIdentity"),
    )

def abi_call_sidecar_from_dict(value) -> AbiCallSidecar:
    d = _require_dict(value, "ABI call sidecar")
    if d.get("schemaVersion") != ABI_CALL_SIDECAR_SCHEMA: raise ValueError("unsupported ABI call sidecar schemaVersion")
    provenance = d.get("provenance")
    if not isinstance(provenance, str) or not provenance: raise ValueError("ABI call sidecar requires provenance")
    entries = d.get("fragments")
    if not isinstance(entries, list): raise ValueError("ABI call sidecar fragments must be an array")
    facts=[]
    for item in entries:
        item=_require_dict(item, "ABI fragment facts"); fid=item.get("fragmentId")
        if not isinstance(fid, str) or not fid: raise ValueError("ABI fragment facts require fragmentId")
        bindings=tuple(_binding(x, fid) for x in item.get("bindings", []))
        facts.append(AbiCallBindingFacts(fid, bindings, bool(item.get("complete", False)), _tuple_strings(item.get("missingFactCodes", []), "missingFactCodes"), item.get("provenance", provenance)))
    return AbiCallSidecar(ABI_CALL_SIDECAR_SCHEMA, tuple(sorted(facts, key=lambda x:x.fragment_id)), provenance)

def target_abi_wrapper_registry_from_dict(value) -> TargetAbiWrapperRegistry:
    d=_require_dict(value, "ABI wrapper registry")
    if d.get("schemaVersion") != ABI_WRAPPER_REGISTRY_SCHEMA: raise ValueError("unsupported ABI wrapper registry schemaVersion")
    version=d.get("version")
    if not isinstance(version, str) or not version: raise ValueError("ABI wrapper registry requires version")
    contracts=[]
    for value in d.get("contracts", []):
        x=_require_dict(value, "ABI wrapper contract")
        try: profile=SourceAbiProfile(x["sourceAbiProfile"])
        except (KeyError, ValueError) as exc: raise ValueError("ABI wrapper contract has invalid sourceAbiProfile") from exc
        contracts.append(TargetAbiWrapperContract(
            x["contractId"], x["semanticVersion"], profile, x["targetAbi"], x["sourceTargetId"], x["targetWrapperSymbol"],
            _tuple_strings(x["argumentTypes"], "argumentTypes"), _tuple_strings(x["returnTypes"], "returnTypes"),
            tuple(x["argumentOperandIndexes"]), tuple(x["returnOperandIndexes"]), x["memoryEffect"],
            bool(x["mayReturn"]), bool(x["mayUnwind"]), _tuple_strings(x.get("requiredHeaders", []), "requiredHeaders"),
            x.get("requiredLibrary"), bool(x["picPltCompatible"]), bool(x["tlsCompatible"]), x["exactSemanticContractId"],
        ))
    return TargetAbiWrapperRegistry(tuple(contracts), version)

def load_abi_call_sidecar(path: str | Path) -> AbiCallSidecar:
    return abi_call_sidecar_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
def load_target_abi_wrapper_registry(path: str | Path) -> TargetAbiWrapperRegistry:
    return target_abi_wrapper_registry_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
