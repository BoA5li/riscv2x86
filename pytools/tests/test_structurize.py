from .helpers import build_and_diff   # 自己抽出来的 Unicorn + 译文差分

def test_if_then():
    asm = (
        "    li   %0, 0\n"
        "    bne  %1, %2, 1f\n"
        "    addi %0, %1, 1\n"
        "1:  nop\n"
    )
    build_and_diff(
        asm,
        outs=["out"], ins=["a","b"],
        cases=[(5, 5), (5, 6), (-1 & 0xffffffffffffffff, 0)],
        out_index=0)

def test_if_else():
    asm = (
        "    bne  %1, %2, 1f\n"
        "    li   %0, 100\n"
        "    j    2f\n"
        "1:  li   %0, 200\n"
        "2:  nop\n"
    )
    build_and_diff(
        asm, outs=["out"], ins=["a","b"],
        cases=[(1,1),(1,2),(0,0)], out_index=0)

def test_nested_if():
    asm = (
        "    beq  %1, %2, 3f\n"   # 外层 if
        "    bge  %1, %2, 1f\n"   # 内层 if-else
        "    li   %0, 1\n"
        "    j    2f\n"
        "1:  li   %0, 2\n"
        "2:  j    4f\n"
        "3:  li   %0, 3\n"
        "4:  nop\n"
    )
    build_and_diff(
        asm, outs=["out"], ins=["a","b"],
        cases=[(1,1),(2,1),(1,2)], out_index=0)