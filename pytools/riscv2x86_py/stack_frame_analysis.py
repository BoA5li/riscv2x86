"""Phase-5 CFG affine stack-frame analysis; unknowns always fail closed."""
from __future__ import annotations
from collections import deque
from .pcode_ir import (Block, IRSummary, Var, VarKind, StackFrameSemantics, StackFrameClassification, StackAddressBase, StackAccessKind, StackAdjustment, StackMemoryAccess, StackEscapeFacts, PrivateFrameRange, PrivateFrameSlotAccess, PrivateFrameLayoutFacts)
from .cfg import CFGResult, build_cfg_from_blocks

_SP={"sp","x2"}; _FP={"fp","s0","x8"}
def _reg(v): return "" if v is None or v.kind is not VarKind.REG else (v.name or "").strip().lower()
def _key(v): return None if v is None else (v.kind.value,v.space,v.offset,v.size,v.name)
def _const(v): return v.offset if v is not None and v.kind is VarKind.CONST else None
def _node(v): return None if not _reg(v) else "reg:"+_reg(v)
def _align(bits): return None if not bits or bits%8 else min(bits//8,16)
def _join(a,b): return a if a==b else None

def _join_state(old,new):
    if old is None:return new,True
    merged=(_join(old[0],new[0]),_join(old[1],new[1]),{k:v for k,v in old[2].items() if new[2].get(k)==v})
    return merged,merged!=old

def _transfer(block,state):
    sp,fp,values=state; adjustments=[]; accesses=[]; dynamic=False; exposed=False
    for index,op in enumerate(block.ops):
        code=op.opcode.upper(); out=_key(op.output)
        def affine(v):
            if _reg(v) in _SP:return sp
            if _reg(v) in _FP:return fp
            return values.get(_key(v))
        ins=[affine(v) for v in op.inputs]; result=None
        if code=="COPY" and ins: result=ins[0]
        elif code in {"INT_ADD","INT_SUB"} and len(op.inputs)>=2 and ins[0] is not None and _const(op.inputs[1]) is not None:
            result=(ins[0][0],ins[0][1]+(_const(op.inputs[1]) if code=="INT_ADD" else -_const(op.inputs[1])))
        if out is not None: values=dict(values); values[out]=result
        target=_reg(op.output)
        if target in _SP|_FP:
            before=(sp if target in _SP else fp); after=result
            if target in _SP:sp=after
            else:fp=after
            adjustments.append(StackAdjustment(block.addr,index,target,None if before is None or after is None else after[1]-before[1],None if before is None else before[1],None if after is None else after[1]))
            dynamic|=after is None
        if code in {"LOAD","STORE"}:
            # Canonical STORE is normally (space, address, value); compact
            # unit-test IR may use (value, address).
            address=op.inputs[-2] if code=="STORE" and len(op.inputs)>=3 else (op.inputs[-1] if op.inputs else None); addr=affine(address)
            if addr is not None and addr[0] in {StackAddressBase.ENTRY_SP,StackAddressBase.FRAME_POINTER}:
                bits=(op.output.size if code=="LOAD" and op.output else (op.inputs[-1].size if code=="STORE" else 0))*8; kind=StackAccessKind.LOAD if code=="LOAD" else StackAccessKind.STORE
                accesses.append((StackMemoryAccess(block.addr,index,addr[0],None,addr[1],bits or None,_align(bits),kind,False if code=="LOAD" else None,True,False),_node(op.output if code=="LOAD" else op.inputs[-1])))
        for value in ins:
            if value is not None and value[0] in {StackAddressBase.ENTRY_SP,StackAddressBase.FRAME_POINTER} and code not in {"COPY","INT_ADD","INT_SUB","LOAD","STORE"}: exposed=True
    return (sp,fp,values),adjustments,accesses,dynamic,exposed

def _has_cycle(nodes):
    active=set(); done=set()
    def visit(addr):
        if addr in active:return True
        if addr in done:return False
        active.add(addr); hit=any(s in nodes and visit(s) for s in nodes[addr].successors); active.remove(addr); done.add(addr); return hit
    return any(visit(a) for a in nodes)

def analyze_stack_frame_semantics(*, blocks:tuple[Block,...]|list[Block], summary:IRSummary, cfg:CFGResult|None=None) -> StackFrameSemantics:
    sensitive=bool((set(summary.reads_regs)|set(summary.writes_regs)) & (_SP|_FP)); empty=StackEscapeFacts(False,False,False,False,False,False)
    if not sensitive:return StackFrameSemantics(StackFrameClassification.NONE,StackAddressBase.ENTRY_SP,None,0,0,(),(),empty,False,False,False,False,True)
    if summary.has_call_or_return:return StackFrameSemantics(StackFrameClassification.WHOLE_FUNCTION,StackAddressBase.ENTRY_SP,None,None,None,(),(),empty,False,True,summary.has_return,True,True)
    cfg=build_cfg_from_blocks(blocks) if cfg is None else cfg; by_addr={b.addr:b for b in blocks}
    if not cfg.ok or cfg.entry not in by_addr or any(n.has_unknown_target or any(s not in by_addr for s in n.successors) for n in cfg.nodes.values()):
        return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.UNKNOWN,None,None,None,(),(),empty,True,False,summary.has_return,None,False,("stack-frame-cfg-incomplete",))
    states={cfg.entry:((StackAddressBase.ENTRY_SP,0),None,{})}; queue=deque([cfg.entry]); conflict=False
    while queue:
        addr=queue.popleft(); out,_,_,dynamic,_=_transfer(by_addr[addr],states[addr])
        for successor in cfg.nodes[addr].successors:
            merged,changed=_join_state(states.get(successor),out)
            if states.get(successor) is not None and merged[0] is None and states[successor][0] is not None:conflict=True
            if dynamic:conflict=True
            if changed:states[successor]=merged; queue.append(successor)
    final_transfers={addr:_transfer(by_addr[addr],state) for addr,state in states.items()}
    out_states={addr:item[0] for addr,item in final_transfers.items()}
    exits=tuple(sorted(a for a,n in cfg.nodes.items() if not n.successors))
    if not exits or any(a not in states for a in exits):return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.UNKNOWN,None,None,None,(),(),empty,True,False,summary.has_return,None,False,("stack-frame-cfg-exit-incomplete",))
    if any(item[3] for item in final_transfers.values()):
        return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.UNKNOWN,None,None,None,(),(),empty,True,False,summary.has_return,None,False,("stack-frame-non-affine-adjustment",))
    if conflict or any(out_states[a][0] is None for a in exits):
        reason="stack-frame-non-convergent-affine-state" if _has_cycle(cfg.nodes) else "stack-frame-affine-merge-conflict"
        return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.UNKNOWN,None,None,None,(),(),empty,True,False,summary.has_return,None,False,(reason,))
    adjustments=[]; items=[]; exposed=False
    for addr in sorted(states):
        _,a,x,_,e=_transfer(by_addr[addr],states[addr]); adjustments.extend(a); items.extend(x); exposed|=e
    adjustments=tuple(sorted(adjustments,key=lambda x:(x.block_address,x.operation_index))); items=tuple(sorted(items,key=lambda x:(x[0].block_address,x[0].operation_index))); accesses=tuple(x[0] for x in items); escape=StackEscapeFacts(exposed,False,False,False,exposed,exposed)
    if not adjustments:
        return StackFrameSemantics(StackFrameClassification.ADDRESS_ONLY,StackAddressBase.ENTRY_SP,None,None,0,adjustments,accesses,escape,False,False,False,False,not exposed,() if not exposed else ("stack-address-escapes",))
    unbalanced_exit=any(out_states[a][0][1]!=0 for a in exits)
    min_sp=min([0]+[x.after_affine_offset for x in adjustments if x.register in _SP and x.after_affine_offset is not None]); size=-min_sp; reasons=[]; by_block={}
    for access,value in items:by_block.setdefault(access.block_address,[]).append((access,value))
    init={cfg.entry:frozenset()}; queue=deque([cfg.entry]); slots=[]
    while queue:
        addr=queue.popleft(); current=set(init[addr])
        for access,value in by_block.get(addr,[]):
            if access.offset_bytes is None or access.width_bits is None or value is None:reasons.append("private-frame-value-flow-incomplete");continue
            width=access.width_bits//8; byte_range=set(range(access.offset_bytes,access.offset_bytes+width)); in_range=size>0 and -size<=access.offset_bytes and access.offset_bytes+width<=0; initialized=access.access is StackAccessKind.STORE or byte_range.issubset(current)
            if access.access is StackAccessKind.LOAD and not initialized:reasons.append("private-frame-initial-content-observable")
            if not in_range:reasons.append("private-frame-access-out-of-range")
            slots.append(PrivateFrameSlotAccess(access.block_address,access.operation_index,access.offset_bytes,access.offset_bytes+size,access.width_bits,access.required_alignment_bytes or 1,access.access,access.signed_load,value,False,initialized,in_range and initialized))
            if access.access is StackAccessKind.STORE:current.update(byte_range)
        out=frozenset(current)
        for successor in cfg.nodes[addr].successors:
            old=init.get(successor); merged=out if old is None else old & out
            if old!=merged:init[successor]=merged;queue.append(successor)
    if exposed:reasons.append("private-frame-address-escape")
    if unbalanced_exit:reasons.append("private-frame-unbalanced-exit")
    complete=bool(slots) and not reasons; required=max((x.required_alignment_bytes for x in slots),default=1); layout=PrivateFrameLayoutFacts(PrivateFrameRange(-size,0,size,required) if size>0 else None,tuple(sorted(slots,key=lambda x:(x.source_block_address,x.source_operation_index))),True,not any("initial-content" in x for x in reasons),not any("out-of-range" in x for x in reasons),complete,tuple(sorted(set(reasons))))
    if complete:return StackFrameSemantics(StackFrameClassification.PRIVATE_BALANCED,StackAddressBase.ENTRY_SP,required,size,0,adjustments,accesses,escape,False,False,False,False,True,(),layout)
    return StackFrameSemantics(StackFrameClassification.UNKNOWN,StackAddressBase.ENTRY_SP,None,size or None,None,adjustments,accesses,escape,False,False,False,False,False,tuple(sorted(set(reasons or ["private-frame-layout-incomplete"]))),layout)
