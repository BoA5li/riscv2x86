"""Phase-5 typed, fail-closed stack-frame semantic analysis.

This module consumes canonical ``Block`` / ``Op`` objects only.  It never
inspects assembly spelling, p-code text, or renderer output.
"""
from __future__ import annotations
from .pcode_ir import (Block, IRSummary, Op, Var, VarKind,
    StackFrameSemantics, StackFrameClassification, StackAddressBase,
    StackAccessKind, StackAdjustment, StackMemoryAccess, StackEscapeFacts)
from .pcode_ir import PrivateFrameRange, PrivateFrameSlotAccess, PrivateFrameLayoutFacts

_SP={"sp","x2"}; _FP={"fp","s0","x8"}

def _reg(v:Var|None)->str:
    return "" if v is None or v.kind is not VarKind.REG else (v.name or "").strip().lower()
def _key(v:Var|None):
    return None if v is None else (v.kind.value,v.space,v.offset,v.size,v.name)
def _const(v:Var|None): return v.offset if v is not None and v.kind is VarKind.CONST else None
def _node(v:Var|None):
    return None if v is None else ("reg:" + _reg(v) if _reg(v) else None)
def _alignment(width_bits:int|None):
    if not width_bits or width_bits % 8: return None
    # A conservative target storage requirement; never inferred from XLEN.
    return min(width_bits // 8, 16)

def analyze_stack_frame_semantics(*, blocks:tuple[Block,...]|list[Block], summary:IRSummary) -> StackFrameSemantics:
    """Compute the first safe subset of affine SP/FP and access facts.

    Multi-block, calls, returns and any unrecognised SP/FP producer are not
    guessed: they produce a typed incomplete/whole-function result.
    """
    sensitive=bool(set(summary.reads_regs)|set(summary.writes_regs)) and bool((set(summary.reads_regs)|set(summary.writes_regs)) & (_SP|_FP))
    empty_escape=StackEscapeFacts(False,False,False,False,False,False)
    if not sensitive:
        return StackFrameSemantics(StackFrameClassification.NONE,StackAddressBase.ENTRY_SP,None,0,0,(),(),empty_escape,False,False,False,False,True)
    if summary.has_call_or_return:
        return StackFrameSemantics(StackFrameClassification.WHOLE_FUNCTION,StackAddressBase.ENTRY_SP,None,None,None,(),(),empty_escape,False,True,summary.has_return,True,True)
    if len(blocks)!=1 or summary.has_branch:
        return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.UNKNOWN,None,None,None,(),(),empty_escape,True,False,summary.has_return,None,False,("stack-frame-cfg-not-straight-line",))
    env:dict[tuple,tuple[StackAddressBase,int]|None]={}
    sp=(StackAddressBase.ENTRY_SP,0); fp=None
    adjustments=[]; accesses=[]; private_raw=[]; dynamic=False; exposed=False
    block=blocks[0]
    for index,op in enumerate(block.ops):
        code=op.opcode.upper(); out=_key(op.output)
        def affine(v):
            name=_reg(v)
            if name in _SP: return sp
            if name in _FP: return fp
            return env.get(_key(v))
        values=[affine(v) for v in op.inputs]
        result=None
        if code=="COPY" and values: result=values[0]
        elif code in {"INT_ADD","INT_SUB"} and len(op.inputs)>=2:
            left=values[0]; right=_const(op.inputs[1])
            if left is not None and right is not None: result=(left[0],left[1]+(right if code=="INT_ADD" else -right))
        if out is not None: env[out]=result
        outreg=_reg(op.output)
        if outreg in _SP|_FP:
            before=sp[1] if outreg in _SP else (None if fp is None else fp[1])
            value=result
            if outreg in _SP: sp=value
            else: fp=value
            after=None if value is None else value[1]
            delta=None if before is None or after is None else after-before
            adjustments.append(StackAdjustment(block.addr,index,outreg,delta,before,after))
            if value is None: dynamic=True
        if code in {"LOAD","STORE"}:
            address=op.inputs[-1] if code=="LOAD" else (op.inputs[-2] if len(op.inputs)>=2 else None)
            address_affine=affine(address)
            if address_affine is not None and address_affine[0] in {StackAddressBase.ENTRY_SP,StackAddressBase.FRAME_POINTER}:
                width=(op.output.size if code=="LOAD" and op.output is not None else (op.inputs[-1].size if code=="STORE" else 0))*8
                kind=StackAccessKind.LOAD if code=="LOAD" else StackAccessKind.STORE
                accesses.append(StackMemoryAccess(block.addr,index,address_affine[0],None,address_affine[1],width or None,_alignment(width),kind,False if code=="LOAD" else None,True,False))
                private_raw.append((block.addr,index,address_affine[1],width or None,kind,_node(op.output if code=="LOAD" else op.inputs[-1])))
        # A stack-derived address used anywhere except a recognised memory
        # address is conservatively observable/escaping.
        for value in values:
            if value is not None and value[0] in {StackAddressBase.ENTRY_SP,StackAddressBase.FRAME_POINTER} and code not in {"COPY","INT_ADD","INT_SUB","LOAD","STORE"}:
                exposed=True
    esc=StackEscapeFacts(exposed,False,False,False,exposed,exposed)
    if dynamic or sp is None:
        return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.UNKNOWN,None,None,None,tuple(adjustments),tuple(accesses),esc,True,False,summary.has_return,None,False,("stack-frame-non-affine-adjustment",))
    if not adjustments:
        complete=not exposed
        return StackFrameSemantics(StackFrameClassification.ADDRESS_ONLY,StackAddressBase.ENTRY_SP,None,None,0,tuple(adjustments),tuple(accesses),esc,False,False,False,False,complete,() if complete else ("stack-address-escapes",))
    min_sp=min((x.after_affine_offset for x in adjustments if x.register in _SP and x.after_affine_offset is not None),default=0)
    frame_size=-min_sp
    # A virtual frame is valid only if it is a non-empty down-growing range,
    # exits at EntrySP, and every access is private to that range.
    ranges=[]; slots=[]; initialized=[]; reasons=[]
    if frame_size <= 0 or sp[1] != 0:
        reasons.append("private-frame-unbalanced")
    for address,op_index,offset,width,kind,value in private_raw:
        if width is None or width % 8 or value is None:
            reasons.append("private-frame-value-flow-incomplete"); continue
        size=width//8; in_range=(-frame_size <= offset and offset+size <= 0)
        init = kind is StackAccessKind.STORE or all(any(a <= byte < b for a,b in initialized) for byte in range(offset,offset+size))
        if kind is StackAccessKind.LOAD and not init: reasons.append("private-frame-initial-content-observable")
        if not in_range: reasons.append("private-frame-access-out-of-range")
        if kind is StackAccessKind.STORE: initialized.append((offset,offset+size))
        slots.append(PrivateFrameSlotAccess(address,op_index,offset,offset+frame_size,width,_alignment(width) or 1,kind,False if kind is StackAccessKind.LOAD else None,value,False,init,in_range and init))
        ranges.append((offset,offset+size))
    # Byte-range representation makes overlap explicit.  Overlap is allowed
    # only because every exact access is kept as a byte-range memcpy recipe.
    layout_complete=bool(slots) and not reasons and not exposed
    if exposed: reasons.append("private-frame-address-escape")
    required=max((x.required_alignment_bytes for x in slots),default=1)
    layout=PrivateFrameLayoutFacts(
        PrivateFrameRange(-frame_size,0,frame_size,required) if frame_size>0 else None,
        tuple(slots),True,not any("initial-content" in x for x in reasons),
        not any("out-of-range" in x for x in reasons),layout_complete,tuple(sorted(set(reasons))))
    if layout_complete:
        return StackFrameSemantics(StackFrameClassification.PRIVATE_BALANCED,StackAddressBase.ENTRY_SP,required,frame_size,0,tuple(adjustments),tuple(accesses),esc,False,False,False,False,True,(),layout)
    esc=StackEscapeFacts(exposed,False,False,False,exposed,exposed or any("initial-content" in x for x in reasons))
    return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.ENTRY_SP,None,frame_size or None,sp[1],tuple(adjustments),tuple(accesses),esc,False,False,False,False,False,tuple(sorted(set(reasons or ["private-frame-layout-incomplete"]))),layout)
