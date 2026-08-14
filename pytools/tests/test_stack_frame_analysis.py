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
