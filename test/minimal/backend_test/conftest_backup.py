from __future__ import annotations

import textwrap
from typing import Callable

import pytest

from riscv2x86_py.assemble import assemble
from riscv2x86_py.lift import LiftedInsn, lift
from riscv2x86_py.schema import AsmFragment


DEFAULT_BASE_ADDR = 0x10000

class RealAssemblyError(RuntimeError):
    """真实 RISC-V 汇编失败。"""


def _assemble_and_lift(
    asm: str,
    *,
    xlen: int = 64,
    base_addr: int = DEFAULT_BASE_ADDR,
) -> list[LiftedInsn]:
    """
    使用真实的项目实现完成：

        RISC-V asm source
          -> schema.AsmFragment(rawAsmText=...)
          -> riscv2x86_py.assemble.assemble()
          -> LLVM llvm-mc / ELF relocation 解析
          -> riscv2x86_py.lift.lift()
          -> pypcode
          -> LiftedInsn[]

    不使用 fake pypcode、mock assemble、pytest.skip 或 sys.path 修改。
    """
    source = textwrap.dedent(asm).strip()

    if not source:
        pytest.fail("test supplied an empty assembly snippet")

    # AsmFragment 的真实文本字段是 rawAsmText，而非 template。
    frag = AsmFragment(
        rawAsmText=source,
    )

    assembled = assemble(
        frag,
        xlen=xlen,
    )

    if not assembled.ok:
        raise RealAssemblyError(
            "real assembly failed\n"
            f"xlen: {xlen}\n"
            f"base_addr: 0x{base_addr:x}\n\n"
            f"error:\n{assembled.error}\n\n"
            f"source assembly:\n{source}\n\n"
            f"rendered assembly:\n{assembled.rendered_asm}"
        )

    if not assembled.machine_code:
        pytest.fail(
            "assembly succeeded but produced empty machine code\n\n"
            f"source assembly:\n{source}\n\n"
            f"rendered assembly:\n{assembled.rendered_asm}"
        )

    lifted_result = lift(
        assembled.machine_code,
        xlen=xlen,
        base_addr=base_addr,
        relocations=assembled.relocations,
        strict_disassembly=True,
    )

    if not lifted_result.ok:
        pytest.fail(
            "real pypcode lifting failed\n"
            f"error:\n{lifted_result.error}\n\n"
            f"source assembly:\n{source}\n\n"
            f"rendered assembly:\n{assembled.rendered_asm}\n\n"
            f"machine code:\n{assembled.machine_code.hex()}"
        )

    if not lifted_result.insns:
        pytest.fail(
            "lifting succeeded but produced no lifted instructions\n\n"
            f"source assembly:\n{source}\n\n"
            f"rendered assembly:\n{assembled.rendered_asm}\n\n"
            f"machine code:\n{assembled.machine_code.hex()}"
        )

    return lifted_result.insns


@pytest.fixture
def lift_snippet() -> Callable[..., list[LiftedInsn]]:
    """
    将一段真实 RISC-V 汇编经真实 assemble() 与 lift() 转换为
    LiftedInsn 列表。
    """

    def _lift_snippet(
        asm: str,
        *,
        xlen: int = 64,
        base_addr: int = DEFAULT_BASE_ADDR,
    ) -> list[LiftedInsn]:
        return _assemble_and_lift(
            asm,
            xlen=xlen,
            base_addr=base_addr,
        )

    return _lift_snippet


@pytest.fixture
def lift_one(
    lift_snippet: Callable[..., list[LiftedInsn]],
) -> Callable[..., LiftedInsn]:
    """
    汇编并 lift 恰好一条机器指令。

    若输入汇编因伪指令展开、标签布局或其他原因产生多条指令，
    fixture 会明确失败，而不会选取或伪造其中某一条。
    """

    def _lift_one(
        asm: str,
        *,
        xlen: int = 64,
        base_addr: int = DEFAULT_BASE_ADDR,
    ) -> LiftedInsn:
        insns = lift_snippet(
            asm,
            xlen=xlen,
            base_addr=base_addr,
        )

        if len(insns) != 1:
            pytest.fail(
                "lift_one expected exactly one lifted instruction, "
                f"but got {len(insns)}\n\n"
                f"source assembly:\n{asm}\n\n"
                f"lifted addresses:\n"
                f"{[hex(insn.addr) for insn in insns]}"
            )

        return insns[0]

    return _lift_one