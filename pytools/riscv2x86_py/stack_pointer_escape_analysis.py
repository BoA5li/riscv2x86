"""Phase-5 def/use classification for affine stack-derived pointers."""
from __future__ import annotations
from .pcode_ir import (StackAddressBase, StackEscapeFacts, StackDerivedPointerUse,
    StackPointerUseKind, StackAccessKind, VarKind)

_SP={"sp","x2"}; _FP={"fp","s0","x8"}
_COMPARE={"INT_EQUAL","INT_NOTEQUAL","INT_LESS","INT_LESSEQUAL","INT_SLESS","INT_SLESSEQUAL"}
_PTR_TO_INT={"CAST","INT_ZEXT","INT_SEXT","SUBPIECE"}

def _reg(v): return "" if v is None or v.kind is not VarKind.REG else (v.name or "").strip().lower()
def _key(v): return None if v is None else (v.kind.value,v.space,v.offset,v.size,v.name)
def _id(v):
    key=_key(v); return "none" if key is None else ":".join(str(x) for x in key)
def _const(v): return v.offset if v is not None and v.kind is VarKind.CONST else None

def analyze_stack_pointer_escapes(*, blocks, states, frame_start:int|None, frame_end:int=0):
    """Classify every known derived-pointer use from stabilized CFG states.

    ``states`` is the affine-analysis block-entry state.  Unknown provenance is
    deliberately recorded as UNKNOWN_USE rather than being treated as a safe
    non-pointer value.
    """
    uses=[]; passed=returned=stored=compared=unknown=out_of_frame=False
    for addr in sorted(states):
        sp,fp,values=states[addr]
        for index,op in enumerate(next(b for b in blocks if b.addr==addr).ops):
            code=op.opcode.upper()
            def affine(v):
                if _reg(v) in _SP:return sp
                if _reg(v) in _FP:return fp
                return values.get(_key(v))
            ins=[affine(v) for v in op.inputs]
            def add(operand,kind,target=None,complete=True):
                nonlocal passed,returned,stored,compared,unknown,out_of_frame
                use=StackDerivedPointerUse(_id(op.inputs[operand]),addr,index,operand,kind,target,complete); uses.append(use)
                passed |= kind in {StackPointerUseKind.PASSED_TO_DIRECT_CALL,StackPointerUseKind.PASSED_TO_INDIRECT_CALL}
                returned |= kind is StackPointerUseKind.RETURNED_TO_C
                stored |= kind is StackPointerUseKind.STORED_TO_EXTERNAL_MEMORY
                compared |= kind in {StackPointerUseKind.POINTER_COMPARISON,StackPointerUseKind.POINTER_TO_INTEGER,StackPointerUseKind.OUT_OF_FRAME_MEMORY_ACCESS}
                unknown |= kind is StackPointerUseKind.UNKNOWN_USE
                out_of_frame |= kind is StackPointerUseKind.OUT_OF_FRAME_MEMORY_ACCESS
            # First classify all inputs whose provenance is known.
            for operand,value in enumerate(ins):
                if value is None: continue
                if code=="COPY": kind=StackPointerUseKind.COPY
                elif code in {"INT_ADD","INT_SUB"} and operand==0 and len(op.inputs)>=2 and _const(op.inputs[1]) is not None: kind=StackPointerUseKind.AFFINE_OFFSET
                elif code in _COMPARE: kind=StackPointerUseKind.POINTER_COMPARISON
                elif code in _PTR_TO_INT: kind=StackPointerUseKind.POINTER_TO_INTEGER
                elif code in {"CALL","CALLIND"}: kind=StackPointerUseKind.PASSED_TO_INDIRECT_CALL if code=="CALLIND" else StackPointerUseKind.PASSED_TO_DIRECT_CALL
                elif code=="RETURN": kind=StackPointerUseKind.RETURNED_TO_C
                elif code=="LOAD":
                    address_index=len(op.inputs)-1
                    in_frame=frame_start is None or frame_start<=value[1]<frame_end
                    kind=StackPointerUseKind.FRAME_LOAD_ADDRESS if operand==address_index and in_frame else StackPointerUseKind.OUT_OF_FRAME_MEMORY_ACCESS if operand==address_index else StackPointerUseKind.UNKNOWN_USE
                elif code=="STORE":
                    address_index=len(op.inputs)-2 if len(op.inputs)>=3 else len(op.inputs)-1
                    if operand==address_index:
                        in_frame=frame_start is None or frame_start<=value[1]<frame_end
                        kind=StackPointerUseKind.FRAME_STORE_ADDRESS if in_frame else StackPointerUseKind.OUT_OF_FRAME_MEMORY_ACCESS
                    elif operand==len(op.inputs)-1: kind=StackPointerUseKind.STORED_TO_EXTERNAL_MEMORY
                    else: kind=StackPointerUseKind.UNKNOWN_USE
                else: kind=StackPointerUseKind.UNKNOWN_USE
                add(operand,kind,_id(op.output) if op.output is not None else None,kind is not StackPointerUseKind.UNKNOWN_USE)
            # Propagate canonical affine provenance for subsequent uses.
            result=None
            if code=="COPY" and ins: result=ins[0]
            elif code in {"INT_ADD","INT_SUB"} and len(op.inputs)>=2 and ins[0] is not None and _const(op.inputs[1]) is not None:
                result=(ins[0][0],ins[0][1]+(_const(op.inputs[1]) if code=="INT_ADD" else -_const(op.inputs[1])))
            if op.output is not None: values=dict(values); values[_key(op.output)]=result
            if _reg(op.output) in _SP: sp=result
            elif _reg(op.output) in _FP: fp=result
    uses=tuple(sorted(uses,key=lambda x:(x.block_address,x.operation_index,-1 if x.operand_index is None else x.operand_index,x.pointer_value_id)))
    escapes=passed or returned or stored or compared or unknown or out_of_frame
    return StackEscapeFacts(escapes,passed,returned,stored,compared,escapes,not unknown,unknown),uses
