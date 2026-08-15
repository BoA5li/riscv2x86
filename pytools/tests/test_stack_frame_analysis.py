from riscv2x86_py.pcode_ir import Block, IRSummary, Op, Var, VarKind, StackFrameClassification
from riscv2x86_py.stack_frame_analysis import analyze_stack_frame_semantics


def _summary(*, reads=(), writes=(), branch=False, callret=False):
    return IRSummary(True, branch, callret, False, False, set(reads), set(writes), False, False)


def test_stack_address_only_access_is_typed_and_complete() -> None:
    sp=Var(VarKind.REG,"register",2,8,"sp")
    out=Var(VarKind.REG,"register",10,8,"a0")
    load=Op(0x1000,"LOAD",out,[Var(VarKind.OTHER,"ram",0,0),sp])
    model=analyze_stack_frame_semantics(blocks=[Block(0x1000,ops=[load])],summary=_summary(reads={"sp"},writes={"a0"}))
    assert model.classification is StackFrameClassification.ADDRESS_ONLY
    assert model.complete
    assert model.accesses[0].offset_bytes == 0


def test_non_affine_stack_write_fails_closed() -> None:
    sp=Var(VarKind.REG,"register",2,8,"sp")
    a0=Var(VarKind.REG,"register",10,8,"a0")
    write=Op(0x1000,"COPY",sp,[a0])
    model=analyze_stack_frame_semantics(blocks=[Block(0x1000,ops=[write])],summary=_summary(reads={"a0"},writes={"sp"}))
    assert model.classification is StackFrameClassification.UNKNOWN
    assert not model.complete
    assert "stack-frame-non-affine-adjustment" in model.missing_fact_codes


def test_call_or_return_requires_whole_function_route() -> None:
    model=analyze_stack_frame_semantics(blocks=[Block(0x1000)],summary=_summary(reads={"sp"},callret=True))
    assert model.classification is StackFrameClassification.WHOLE_FUNCTION
    assert model.complete

def _adjust(addr, delta):
    sp=Var(VarKind.REG,"register",2,8,"sp")
    return Op(addr,"INT_ADD",sp,[sp,Var(VarKind.CONST,"const",delta,8)])

def test_cfg_paths_with_balanced_frame_are_analyzed_not_rejected():
    value=Var(VarKind.REG,"register",10,8,"a0")
    sp=Var(VarKind.REG,"register",2,8,"sp")
    blocks=[
        Block(0x1000,ops=[_adjust(0x1000,-8)],successors=[0x1010]),
        Block(0x1010,ops=[Op(0x1010,"STORE",None,[value,sp]), _adjust(0x1010,8)],successors=[]),
    ]
    model=analyze_stack_frame_semantics(blocks=blocks,summary=_summary(reads={"sp","a0"},writes={"sp"},branch=True))
    assert model.classification is StackFrameClassification.PRIVATE_BALANCED
    assert model.complete

def test_cfg_unbalanced_exit_fails_closed():
    blocks=[
        Block(0x1000,ops=[],successors=[0x1010,0x1020]),
        Block(0x1010,ops=[_adjust(0x1010,-8)],successors=[]),
        Block(0x1020,ops=[],successors=[]),
    ]
    model=analyze_stack_frame_semantics(blocks=blocks,summary=_summary(reads={"sp"},writes={"sp"},branch=True))
    assert model.classification is StackFrameClassification.UNKNOWN
    assert "private-frame-unbalanced-exit" in model.missing_fact_codes

def test_cfg_loop_that_changes_sp_is_non_convergent():
    blocks=[Block(0x1000,ops=[_adjust(0x1000,-8)],successors=[0x1000])]
    model=analyze_stack_frame_semantics(blocks=blocks,summary=_summary(reads={"sp"},writes={"sp"},branch=True))
    assert model.classification is StackFrameClassification.UNKNOWN
    assert "stack-frame-cfg-exit-incomplete" in model.missing_fact_codes or "stack-frame-non-convergent-affine-state" in model.missing_fact_codes

def test_cfg_conditional_store_does_not_prove_private_initialization():
    sp=Var(VarKind.REG,"register",2,8,"sp"); value=Var(VarKind.REG,"register",10,8,"a0"); out=Var(VarKind.REG,"register",11,8,"a1")
    blocks=[
        Block(0x1000,ops=[_adjust(0x1000,-8)],successors=[0x1010,0x1020]),
        Block(0x1010,ops=[Op(0x1010,"STORE",None,[value,sp])],successors=[0x1030]),
        Block(0x1020,ops=[],successors=[0x1030]),
        Block(0x1030,ops=[Op(0x1030,"LOAD",out,[Var(VarKind.OTHER,"ram",0,0),sp]),_adjust(0x1030,8)],successors=[]),
    ]
    model=analyze_stack_frame_semantics(blocks=blocks,summary=_summary(reads={"sp","a0"},writes={"sp","a1"},branch=True))
    assert model.classification is StackFrameClassification.UNKNOWN
    assert "private-frame-initial-content-observable" in model.missing_fact_codes
