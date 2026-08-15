from riscv2x86_py.pcode_ir import Block, Op, Var, VarKind, StackAddressBase, StackPointerUseKind
from riscv2x86_py.stack_pointer_escape_analysis import analyze_stack_pointer_escapes

def _reg(name, offset): return Var(VarKind.REG,"register",offset,8,name)
def _state(): return {0x1000:((StackAddressBase.ENTRY_SP,0),None,{})}

def test_stack_pointer_written_to_external_memory_is_distinguished():
    sp=_reg("sp",2); t0=_reg("t0",5); a1=_reg("a1",11); mem=Var(VarKind.OTHER,"ram",0,0)
    block=Block(0x1000,ops=[Op(0x1000,"COPY",t0,[sp]),Op(0x1000,"STORE",None,[mem,a1,t0])])
    facts,uses=analyze_stack_pointer_escapes(blocks=[block],states=_state(),frame_start=None)
    assert facts.pointer_escapes and facts.stored_to_external_memory
    assert any(x.use_kind is StackPointerUseKind.STORED_TO_EXTERNAL_MEMORY for x in uses)

def test_pointer_comparison_and_unknown_use_are_distinguished():
    sp=_reg("sp",2); t0=_reg("t0",5); a0=_reg("a0",10); out=_reg("a1",11)
    block=Block(0x1000,ops=[Op(0x1000,"COPY",t0,[sp]),Op(0x1000,"INT_EQUAL",out,[t0,a0]),Op(0x1000,"INT_AND",out,[t0,a0])])
    facts,uses=analyze_stack_pointer_escapes(blocks=[block],states=_state(),frame_start=None)
    assert facts.compared_or_exposed and facts.unknown_use_present and not facts.analysis_complete
    assert StackPointerUseKind.POINTER_COMPARISON in {x.use_kind for x in uses}
    assert StackPointerUseKind.UNKNOWN_USE in {x.use_kind for x in uses}

def test_private_frame_access_is_not_an_escape():
    sp=_reg("sp",2); out=_reg("a0",10); mem=Var(VarKind.OTHER,"ram",0,0)
    block=Block(0x1000,ops=[Op(0x1000,"LOAD",out,[mem,sp])])
    facts,uses=analyze_stack_pointer_escapes(blocks=[block],states={0x1000:((StackAddressBase.ENTRY_SP,-8),None,{})},frame_start=-16)
    assert not facts.pointer_escapes
    assert uses[0].use_kind is StackPointerUseKind.FRAME_LOAD_ADDRESS
