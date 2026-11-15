"""Phase-6A unsigned product projection, derived only from typed canonical IR.

Every semantic definition must belong to the closed result DAG. COPY is
temporal aliasing, not a license to invent a value or ignore a register write.
"""
def build(*, blocks, runtime_status, operands, operation):
    from .pcode_ir import VarKind
    from .source_model import (SourceOperationKind, SourceOperandKind,
        SourceOperandAccess, SourceValueOperationKind, SourceValueOperationModel,
        canonicalize_riscv_register_name)
    if (not operands.complete or not runtime_status.structurally_valid or len(blocks)!=1
            or operation.kind is not SourceOperationKind.REGISTER_ONLY
            or operation.may_trap is not False):return None
    slots={o.source_operand_index:o for o in operands.operands}
    outputs=[i for i,o in slots.items() if o.access is SourceOperandAccess.OUTPUT]
    inputs=[i for i,o in slots.items() if o.access is SourceOperandAccess.INPUT]
    widths={o.width_bits for o in slots.values()}
    if (len(outputs)!=1 or len(inputs)!=2 or len(slots)!=3 or len(widths)!=1
            or next(iter(widths)) not in (32,64)
            or any(not o.compiler_integer_type_complete or o.kind is not SourceOperandKind.REGISTER or o.fixed_register_name
                   or o.tied_to_source_operand_index is not None for o in slots.values())):return None
    width=next(iter(widths));registers={}
    for name,index in runtime_status.rv_to_operand_index.items():
        key=canonicalize_riscv_register_name(name)
        if not key or key in registers or index not in slots:return None
        registers[key]=index
    def slot(v):
        return registers.get(canonicalize_riscv_register_name(v.name)) if v.kind is VarKind.REG else None
    values={};definitions={};semantic=set();register_writes=[]
    def read(v):
        if v in values:return values[v]
        i=slot(v)
        return ('input',i) if i in inputs and v.size*8==width else None
    for serial,op in enumerate(blocks[0].ops):
        code=op.opcode.upper()
        if code=='IMARK':continue
        out=op.output;args=op.inputs
        if out is None or out.kind not in (VarKind.REG,VarKind.UNIQUE):return None
        token=('definition',serial)
        if code=='COPY':
            if len(args)!=1 or args[0].size!=out.size:return None
            token=read(args[0])
            if token is None:return None
        elif code=='INT_ZEXT':
            if len(args)!=1 or args[0].size*8!=width or out.size*8!=2*width:return None
            source=read(args[0])
            if source is None or source[0]!='input':return None
            definitions[token]=('zext',source);semantic.add(token)
        elif code=='INT_MULT':
            if len(args)!=2 or out.size*8!=2*width or any(v.size!=out.size for v in args):return None
            left,right=map(read,args)
            if left is None or right is None:return None
            definitions[token]=('multiply',left,right);semantic.add(token)
        elif code=='SUBPIECE':
            if (len(args)!=2 or args[0].size*8!=2*width or out.size*8!=width
                    or args[1].kind is not VarKind.CONST or type(args[1].offset) is not int
                    or args[1].offset!=width//8):return None
            source=read(args[0])
            if source is None:return None
            definitions[token]=('high',source);semantic.add(token)
        else:return None
        values[out]=token
        if out.kind is VarKind.REG:
            if slot(out)!=outputs[0] or out.size*8!=width:return None
            register_writes.append(token)
    if len(register_writes)!=1:return None
    result=register_writes[0];high=definitions.get(result)
    if not high or high[0]!='high':return None
    product=definitions.get(high[1])
    if not product or product[0]!='multiply':return None
    a,b=(definitions.get(t) for t in product[1:])
    if not a or not b or a[0]!='zext' or b[0]!='zext':return None
    indexes=(a[1][1],b[1][1])
    if set(indexes)!=set(inputs) or semantic!={result,high[1],*product[1:]}:return None
    return SourceValueOperationModel(SourceValueOperationKind.UNSIGNED_MULTIPLY_HIGH,
        indexes,outputs[0],True)
