"""Finite straight-line predicate-region closure over typed canonical ops."""
from .compiler_value_flow import identity
from .pcode_ir import VarKind


class AsmGotoRegionError(ValueError):
    failure_stage = 'asm_goto_region_closure'
    def __init__(self, code, detail):
        super().__init__(detail)
        self.reason_code = code


def close_predicate_region(blocks, branch):
    """Prove the supported region has no effects outside the predicate slice.

    Cross-block dominance and output definedness need independent contracts;
    a flattened list must never stand in for either of those proofs.
    """
    def reject(code, detail):
        raise AsmGotoRegionError('ASM_GOTO_REGION_' + code, detail)
    if len(blocks) != 1:
        reject('DOMINANCE_AUTHORITY_REQUIRED', 'Only one straight-line predicate block is closed')
    ops = [o for o in blocks[0].ops if o.opcode.upper() != 'IMARK']
    if not ops or ops[-1] is not branch or sum(o.opcode.upper() == 'CBRANCH' for o in ops) != 1:
        reject('EXIT_NOT_FINAL', 'The conditional exit must be unique and final')
    producers, positions = {}, {}
    allowed = {'COPY', 'INT_ZEXT', 'INT_SEXT', 'BOOL_NEGATE', 'INT_EQUAL', 'INT_NOTEQUAL'}
    for position, op in enumerate(ops[:-1]):
        if op.opcode.upper() not in allowed or op.output is None:
            reject('EFFECT_UNSUPPORTED', 'Region contains an operation outside the pure predicate vocabulary')
        if op.output.kind is not VarKind.UNIQUE:
            reject('LIVE_WRITE_UNPROVEN', 'Writes outside compiler-independent temporary values need live-out authority')
        if op.output in producers:
            reject('MULTIPLE_DEFINITIONS', 'Temporary has multiple definitions')
        producers[op.output] = op
        positions[id(op)] = position
    positions[id(branch)] = len(ops)-1
    from .pcode_ir import conditional_transfer_from_op
    try:
        transfer = conditional_transfer_from_op(branch)
    except ValueError as exc:
        reject('CONDITIONAL_TRANSFER_INVALID', str(exc))
    visited = set()
    def visit(value, consumer):
        producer = producers.get(value)
        if producer is None:
            if value.kind not in {VarKind.REG, VarKind.CONST}:
                reject('VALUE_UNBOUND', 'Predicate uses an undefined temporary')
            return
        if positions[id(producer)] >= positions[id(consumer)]:
            reject('USE_BEFORE_DEFINITION', 'Predicate definition does not precede use')
        if id(producer) in visited:
            return
        visited.add(id(producer))
        for input_value in producer.inputs:
            visit(input_value, producer)
    visit(transfer.condition, branch)
    if visited != {id(o) for o in ops[:-1]}:
        reject('UNCOVERED_OPERATION', 'Region contains effects outside the proven predicate dependency slice')
    def var(v):
        return {'kind':v.kind.value, 'space':v.space,'offset':v.offset,'size':v.size,'name':v.name}
    payload = {'schemaVersion':'riscv2x86.asm-goto-predicate-region.v1',
        'operations':[{'opcode':o.opcode.upper(),'output':None if o.output is None else var(o.output),
                       'inputs':[var(v) for v in o.inputs]} for o in ops],
        'complete':True,'scope':'single_straight_line_predicate_block'}
    return {**payload,'regionIdentity':identity(payload)}
