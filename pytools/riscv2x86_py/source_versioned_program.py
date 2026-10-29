"""Temporal canonical-p-code adapter for finite operand-backed GPR programs.

No source text or instruction mnemonic is consulted. Each COPY captures the
current value; arithmetic results must reach one output storage slot before
the next arithmetic operation. Old values whose storage was overwritten are
rejected, rather than silently read as the new value. Unbound scratch storage,
memory, control flow and mixed-width operations remain outside this contract.
"""
from .pcode_ir import VarKind


def build(*, blocks, runtime_status, operands, operation):
    from .source_model import (SourceOperationKind, SourceOperandAccess,
        SourceOperandKind, SourceStraightLineValueOpcode as Code,
        SourceStraightLineValueInstruction as Instruction,
        SourceStraightLineValueProgram as Program, canonicalize_riscv_register_name)
    if (operation.kind is not SourceOperationKind.REGISTER_ONLY or
            operation.may_trap is not False or not operands.complete or
            len(blocks) != 1 or not runtime_status.structurally_valid):
        return None
    bindings = {o.source_operand_index: o for o in operands.operands}
    if any(o.kind is not SourceOperandKind.REGISTER or o.width_bits not in {32, 64}
           or o.signedness.value == 'unknown' or o.tied_to_source_operand_index is not None
           or o.fixed_register_name is not None or o.access not in {SourceOperandAccess.INPUT, SourceOperandAccess.OUTPUT}
           for o in bindings.values()):
        return None
    widths = {o.width_bits for o in bindings.values()}
    if len(widths) != 1:
        return None
    width = next(iter(widths))
    registers = {}
    for reg, index in runtime_status.rv_to_operand_index.items():
        name = canonicalize_riscv_register_name(reg)
        if not name or name in registers or index not in bindings:
            return None
        registers[name] = index
    def slot(v):
        return registers.get(canonicalize_riscv_register_name(v.name)) if v.kind is VarKind.REG else None
    inputs = tuple(i for i, o in bindings.items() if o.access is SourceOperandAccess.INPUT)
    outputs = tuple(i for i, o in bindings.items() if o.access is SourceOperandAccess.OUTPUT)
    if not inputs or not outputs:
        return None
    current = {i: 'input:'+str(i) for i in inputs}
    values = {}
    def read(v):
        if v in values:
            return values[v]
        i = slot(v)
        return current.get(i) if i in inputs else None
    codes = {'INT_ADD': Code.UNSIGNED_ADD, 'INT_SUB': Code.UNSIGNED_SUB,
             'INT_AND': Code.BIT_AND, 'INT_OR': Code.BIT_OR, 'INT_XOR': Code.BIT_XOR}
    items = [o for o in blocks[0].ops if o.opcode.upper() != 'IMARK']
    instructions = []; history = []; pending = None
    def finish():
        if pending is None:
            return True
        token, code, sources = pending
        destinations = [i for i in outputs if current.get(i) == token]
        if len(destinations) != 1:
            return False
        instructions.append(Instruction(code, destinations[0], sources))
        return True
    for op in items:
        code = op.opcode.upper(); out = op.output
        if out is None or out.kind is VarKind.CONST or out.size * 8 != width:
            return None
        if code == 'COPY':
            if len(op.inputs) != 1 or op.inputs[0].size != out.size:
                return None
            token = read(op.inputs[0])
            if token is None:
                return None
            i = slot(out)
            # Cross-slot copies need an explicit storage/liveness contract.
            if i is not None and (i not in outputs or pending is None or token != pending[0]):
                return None
            values[out] = token
            if i is not None:
                current[i] = token
            continue
        if code not in codes or len(op.inputs) != 2 or not finish():
            return None
        if any(v.size * 8 != width for v in op.inputs):
            return None
        source_tokens = tuple(read(v) for v in op.inputs)
        indexes = []
        for token in source_tokens:
            matches = [i for i, value in current.items() if value == token]
            if token is None or len(matches) != 1:
                return None
            indexes.append(matches[0])
        token = 'definition:'+str(len(history))
        history.append((token, *source_tokens))
        values[out] = token
        i = slot(out)
        if i is not None:
            if i not in outputs:
                return None
            current[i] = token
        pending = (token, codes[code], tuple(indexes))
    if not finish() or len(instructions) < 2:
        return None
    try:
        return Program(width, tuple(instructions), outputs, inputs,
                       value_schema_version=2, definition_history=tuple(history))
    except (ValueError, TypeError):
        return None
