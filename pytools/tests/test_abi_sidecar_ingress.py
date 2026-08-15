from riscv2x86_py.abi_sidecar import (
    ABI_CALL_SIDECAR_SCHEMA, ABI_WRAPPER_REGISTRY_SCHEMA,
    abi_call_sidecar_from_dict, target_abi_wrapper_registry_from_dict,
)
from riscv2x86_py.abi_effects import (
    CanonicalCallSite, build_abi_effects,
)


def _location(register):
    return {"kind": "gpr", "register": register, "stackOffsetBytes": None,
            "widthBits": 64, "signedness": "unsigned", "valueKind": "scalar",
            "complete": True}


def _binding():
    return {
        "fragmentId": "frag:call", "blockAddress": 4096, "operationIndex": 0,
        "sourceAbiProfile": "rv64-lp64", "directTargetId": "crc.u64",
        "sourceSemanticContractId": "crc.semantic", "sourceSemanticVersion": "1",
        "argumentOperandIndexes": [1], "returnOperandIndexes": [0],
        "argumentTypes": ["uint64_t"], "returnTypes": ["uint64_t"],
        "sourceArgumentLocations": [_location("a1")],
        "sourceReturnLocations": [_location("a0")],
        "stackAlignmentBytes": 16, "picPltMode": "direct", "tlsModel": "none",
        "mayReturn": True, "mayUnwind": False, "mayTrap": False,
        "memoryEffect": "none", "bindingComplete": True, "provenance": "frontend.v1",
        "canonicalTargetIdentity": "8192",
    }


def test_sidecar_fragment_join_builds_real_abi_effects():
    sidecar = abi_call_sidecar_from_dict({
        "schemaVersion": ABI_CALL_SIDECAR_SCHEMA, "provenance": "frontend.v1",
        "fragments": [{"fragmentId": "frag:call", "complete": True,
                       "bindings": [_binding()]}],
    })
    bindings = sidecar.bindings_for("frag:call")
    effects = build_abi_effects(
        has_call=True, bindings=bindings,
        call_sites=(CanonicalCallSite(4096, 0, True, "8192", ("a1",), ("a0",), False, True, True, True),),
    )
    assert effects is not None and effects.complete
    assert effects.calls[0].target.target_id == "crc.u64"


def test_versioned_registry_resolves_the_ingressed_call():
    registry = target_abi_wrapper_registry_from_dict({
        "schemaVersion": ABI_WRAPPER_REGISTRY_SCHEMA, "version": "registry.v1",
        "contracts": [{
            "contractId": "abi.crc.v1", "semanticVersion": "1",
            "sourceAbiProfile": "rv64-lp64", "targetAbi": "sysv_amd64",
            "sourceTargetId": "crc.u64", "targetWrapperSymbol": "rv2x86_crc",
            "argumentTypes": ["uint64_t"], "returnTypes": ["uint64_t"],
            "argumentOperandIndexes": [1], "returnOperandIndexes": [0],
            "memoryEffect": "none", "mayReturn": True, "mayUnwind": False,
            "requiredHeaders": ["crc.h"], "requiredLibrary": None,
            "picPltCompatible": True, "tlsCompatible": True,
            "exactSemanticContractId": "crc.semantic",
        }],
    })
    sidecar = abi_call_sidecar_from_dict({
        "schemaVersion": ABI_CALL_SIDECAR_SCHEMA, "provenance": "frontend.v1",
        "fragments": [{"fragmentId": "frag:call", "complete": True, "bindings": [_binding()]}],
    })
    effects = build_abi_effects(
        has_call=True, bindings=sidecar.bindings_for("frag:call"),
        call_sites=(CanonicalCallSite(4096, 0, True, "8192", ("a1",), ("a0",), False, True, True, True),),
    )
    assert registry.resolve(effects, "sysv_amd64").target_wrapper_symbol == "rv2x86_crc"


def test_sidecar_rejects_fragment_identity_mismatch():
    value = _binding(); value["fragmentId"] = "other"
    try:
        abi_call_sidecar_from_dict({
            "schemaVersion": ABI_CALL_SIDECAR_SCHEMA, "provenance": "frontend.v1",
            "fragments": [{"fragmentId": "frag:call", "complete": True, "bindings": [value]}],
        })
    except ValueError as exc:
        assert "fragmentId" in str(exc)
    else:
        raise AssertionError("fragment mismatch must fail closed")


def test_launcher_exposes_both_abi_sidecar_options(monkeypatch=None):
    import sys
    from riscv2x86_py.riscv2x86_translate import parse_args
    old = sys.argv
    try:
        sys.argv = ["riscv2x86-translate", "--input", "in.c", "--output-dir", "out",
                   "--abi-call-sidecar", "calls.json", "--abi-wrapper-registry", "wrappers.json"]
        args = parse_args()
        assert str(args.abi_call_sidecar) == "calls.json"
        assert str(args.abi_wrapper_registry) == "wrappers.json"
    finally:
        sys.argv = old
