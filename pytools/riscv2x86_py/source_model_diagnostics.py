"""Diagnostic-only projection of the actual Phase-6A models."""
def missing(model):
    reasons=[]
    if not model.operands.complete:
        reasons.extend('operands:'+c for c in model.operands.missing_fact_codes)
    if not model.operation.complete:reasons.append('operation:incomplete')
    if not model.implicit_state.complete:reasons.append('implicit-state:incomplete')
    if model.value_operation is None and model.value_program is None:
        reasons.append('value:canonical-dataflow-not-modeled')
    if model.operand_relation_error:reasons.append('gnu-relation:'+model.operand_relation_error)
    return {'missingSourceFacts':sorted(set(reasons)),
        'operandModelComplete':model.operands.complete,
        'compilerIntegerTypesComplete':model.operands.complete and all(o.compiler_integer_type_complete for o in model.operands.operands),
        'operandRelationIdentity':model.operand_relation_identity,
        'valueOperationKind':None if model.value_operation is None else model.value_operation.kind.value,
        'operationModelComplete':model.operation.complete,
        'implicitStateComplete':model.implicit_state.complete,
        'valueOperationPresent':model.value_operation is not None,
        'valueProgramPresent':model.value_program is not None}
