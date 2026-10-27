"""Content-bound LR/SC diagnostics. No decoder candidate grants approval."""
from dataclasses import asdict
from collections.abc import Mapping

from .lrsc_sequence import candidate, SequenceError
from .route_authority import RouteAuthorityDecision, content_identity


def decision(fragment, machine_bytes, *, base_address=0, xlen_bits=64,
             runtime_facts=None, source_digest=""):
    if not isinstance(machine_bytes, bytes) or len(machine_bytes) < 4:
        return None
    first = int.from_bytes(machine_bytes[:4], "little")
    if first & 127 != 0x2f or first >> 27 != 2:
        return None
    raw = dict(fragment) if isinstance(fragment, Mapping) else asdict(fragment)
    authority = raw.get("compilerFragmentAuthority") or {}
    compiler_candidate = authority.get("candidate") or {}
    outputs, inputs = raw.get("outputs", []), raw.get("inputs", [])
    payload = {
        "machineBytes": machine_bytes.hex(), "baseAddress": base_address,
        "xlenBits": xlen_bits,
        "frontendOperands": {"outputs": outputs, "inputs": inputs},
        "frontendOutputCount": len(outputs), "frontendInputCount": len(inputs),
        "frontendReadWriteCount": sum(str(o.get("constraint", "")).startswith("+") for o in outputs),
        "compilerFragmentJoin": raw.get("compilerFragmentJoin") or {},
        "compilerAuthorityIdentity": authority.get("authorityIdentity", ""),
        "compilerOperandBindings": compiler_candidate.get("operandBindings", []),
        "compilerOperandSlots": compiler_candidate.get("operandSlotFacts", {}),
        "semanticApproval": False,
    }
    try:
        payload["sequenceCandidate"] = candidate(
            machine_bytes, base_address=base_address, xlen_bits=xlen_bits)
        code = "LRSC_SEQUENCE_MACHINE_CONTRACT_ONLY"
        detail = "Machine sequence decoded; compiler closure and full semantic proof still required"
        if runtime_facts is not None:
            from .lrsc_compiler_binding import bind
            try:
                payload["compilerBinding"] = bind(payload["sequenceCandidate"], authority,
                    fragment_id=str(raw.get("fragmentId") or raw.get("id")),
                    source_digest=source_digest, begin_offset=raw.get("beginOffset"),
                    end_offset=raw.get("endOffset"), runtime_facts=runtime_facts,
                    frontend_fragment=raw)
                code = "LRSC_COMPILER_BINDING_COMPLETE_SEMANTIC_PROOF_REQUIRED"
                detail = "Compiler operands/object bound; sequence semantic and execution proof still required"
            except (ValueError, KeyError, TypeError, IndexError) as exc:
                payload["compilerBindingFailure"] = {
                    "reasonCode": getattr(exc, "reason_code", "LRSC_COMPILER_BINDING_INVALID"),
                    "detail": str(exc), "exceptionType": type(exc).__name__}
                code = payload["compilerBindingFailure"]["reasonCode"]
                detail = "Compiler/object binding rejected; no semantic approval"

    except SequenceError as exc:
        code, detail = exc.reason_code, "LR/SC machine region is outside the closed sequence domain"
    return RouteAuthorityDecision(
        "atomic", str(raw.get("fragmentId") or raw.get("id")),
        "lrsc_sequence_ingress", code, detail, content_identity(payload),
        accepted=False, inputs_payload=payload,
    ).to_dict()
