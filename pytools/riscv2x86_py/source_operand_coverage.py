"""Report declared slots versus semantic bindings without inventing authority."""
from .route_authority import RouteAuthorityDecision, content_identity


def snapshot(fragment_id, model):
    operands = model.operands
    bound = {item.source_operand_index: item for item in operands.operands}
    slots = []
    for index, item in enumerate(model.shell.all_operands):
        semantic = bound.get(index)
        slots.append({
            "operandIndex": index, "constraint": item.constraint,
            "declaredPartition": "output" if item.is_output else "input",
            "declaredReadWrite": item.is_output and item.constraint.startswith("+"),
            "modeled": semantic is not None,
            "modeledAccess": semantic.access.value if semantic is not None else "",
            "modeledKind": semantic.kind.value if semantic is not None else "",
            "widthBits": semantic.width_bits if semantic is not None else None,
        })
    expected = set(range(len(slots)))
    body = {
        "schemaVersion": "riscv2x86.source-operand-coverage.v1",
        "fragmentId": fragment_id, "slots": slots,
        "declaredOperandCount": len(slots), "modeledOperandCount": len(bound),
        "unmodeledIndexes": sorted(expected - set(bound)),
        "unexpectedIndexes": sorted(set(bound) - expected),
        "missingFactCodes": list(operands.missing_fact_codes),
        "complete": operands.complete and set(bound) == expected,
        "semanticApproval": False,
    }
    return dict(body, coverageIdentity=content_identity(body))


def decision(fragment_id, model):
    payload = snapshot(fragment_id, model)
    if payload["complete"]:
        return None
    return RouteAuthorityDecision(
        "source-operands", fragment_id, "source_operand_coverage",
        "SOURCE_OPERAND_COVERAGE_INCOMPLETE",
        "Declared GNU slots or their semantic bindings remain incomplete; no authority inferred",
        content_identity(payload), accepted=False, inputs_payload=payload,
    ).to_dict()
