"""
进程内运行 assemble() 产出的 RISC-V 机器码，
作为 QEMU 的替代参考执行器。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from unicorn import (
    Uc, UC_ARCH_RISCV, UC_MODE_RISCV64, UcError,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
)
from unicorn import riscv_const as RV

# 占位寄存器名 -> Unicorn 寄存器 ID
_REG_ID = {f"x{i}": getattr(RV, f"UC_RISCV_REG_X{i}") for i in range(32)}
# RISC-V ABI 别名也接受
_ALIAS = {"a0":"x10","a1":"x11","a2":"x12","a3":"x13","a4":"x14",
          "a5":"x15","a6":"x16","a7":"x17",
          "t0":"x5","t1":"x6","t2":"x7","t3":"x28","t4":"x29",
          "t5":"x30","t6":"x31","zero":"x0"}

def _rid(name: str) -> int:
    return _REG_ID[_ALIAS.get(name, name)]

@dataclass
class RvRunResult:
    regs_out: Dict[str, int]
    mem_out: Dict[int, bytes]
    error: Optional[str] = None

    fault_pc: Optional[int] = None
    fault_addr: Optional[int] = None
    fault_size: Optional[int] = None
    fault_access: Optional[str] = None

    trace: List[int] = field(default_factory=list)

# 内存布局：
#   CODE  : 0x00010000 ~ +64KB
#   STACK : 0x00020000 ~ +64KB (sp 指向中间)
#   DATA  : 0x00030000 ~ +64KB (供 "m"/"A" 操作数指针落地)
_CODE_BASE, _STACK_BASE, _DATA_BASE = 0x10000, 0x20000, 0x30000
_PAGE = 0x10000

def run_rv64(machine_code: bytes,
             reg_inputs: Dict[str, int],
             reg_outputs: List[str],
             mem_inputs: Optional[Dict[int, bytes]] = None,
             mem_outputs: Optional[Dict[int, int]] = None,
             ) -> RvRunResult:
    """
    把 machine_code 加载到 0x10000 执行，直到 PC 越过末尾。
    reg_inputs : 起始寄存器值，键用 x0..x31 或 a0..a7/t0..t6/zero
    reg_outputs: 结束时要读回哪些寄存器
    mem_inputs : 起始内存内容（addr -> bytes），地址须落在 DATA 区
    mem_outputs: addr -> 读回字节数
    """
    mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
    for base in (_CODE_BASE, _STACK_BASE, _DATA_BASE):
        mu.mem_map(base, _PAGE)

    mu.mem_write(_CODE_BASE, machine_code)

    # sp 给一个合法值，避免栈访存落到未映射区
    mu.reg_write(_rid("x2"), _STACK_BASE + _PAGE // 2)

    for r, v in reg_inputs.items():
        mu.reg_write(_rid(r), v & ((1 << 64) - 1))
    for addr, data in (mem_inputs or {}).items():
        mu.mem_write(addr, data)

    trace: List[int] = []
    fault_pc: Optional[int] = None
    fault_addr: Optional[int] = None
    fault_size: Optional[int] = None
    fault_access: Optional[str] = None

    def _on_code(mu, address, size, user_data):
        # 保留前 32 条指令地址，足够定位
        if len(trace) < 32:
            trace.append(address)

    def _on_unmapped(mu, access, address, size, value, user_data):
        nonlocal fault_pc, fault_addr, fault_size, fault_access
        fault_pc = mu.reg_read(RV.UC_RISCV_REG_PC)
        fault_addr = address
        fault_size = size
        fault_access = {
            19: "read_unmapped",
            20: "write_unmapped",
            21: "fetch_unmapped",
        }.get(access, str(access))
        return False  # 让 Unicorn 抛 UcError

    mu.hook_add(UC_HOOK_CODE, _on_code)
    mu.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED |
        UC_HOOK_MEM_WRITE_UNMAPPED |
        UC_HOOK_MEM_FETCH_UNMAPPED,
        _on_unmapped
    )

    err = None
    try:
        mu.emu_start(
            _CODE_BASE,
            _CODE_BASE + len(machine_code),
            timeout=2_000_000,
            count=10_000
        )
    except UcError as e:
        err = (
            f"unicorn: {e}; "
            f"pc={hex(fault_pc) if fault_pc is not None else 'None'}; "
            f"addr={hex(fault_addr) if fault_addr is not None else 'None'}; "
            f"size={fault_size}; access={fault_access}; "
            f"trace={[hex(x) for x in trace]}"
        )

    regs = {r: mu.reg_read(_rid(r)) for r in reg_outputs}
    mems = {a: bytes(mu.mem_read(a, n)) for a, n in (mem_outputs or {}).items()}

    return RvRunResult(
        regs_out=regs,
        mem_out=mems,
        error=err,
        fault_pc=fault_pc,
        fault_addr=fault_addr,
        fault_size=fault_size,
        fault_access=fault_access,
        trace=trace,
    )