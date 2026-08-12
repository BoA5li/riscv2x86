"""
规范化 p-code IR（hybrid 版）：

- 以 p-code opcode 为主，抽取控制流 / 寄存器 / 内存副作用；
- 必要时使用 asm mnemonic / asm body 兜底；
- 按机器码绝对地址拆分 basic block；
- CFG successor 仅保留当前 fragment 内部边；
- direct external jump / call 不应被误认为 unknown target；
- 支持 RISC-V branch / call / return / compressed instruction / atomic summary；
- 同时返回全局 IRSummary，并在每个 Block 上提供局部 summary。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
from typing import Any, List, Optional, Set, FrozenSet, Iterable
import re
from .runtime_facts import _PROVEN_PURE_INTEGER_OPCODES, _NON_SEMANTIC_CANONICAL_OPCODES

_ATOMIC_MNEMONIC_RE = re.compile(
    r"^(?P<op>"
    r"lr|sc|"
    r"amoswap|amoadd|amoxor|amoand|amoor|"
    r"amomin|amomax|amominu|amomaxu"
    r")\.(?P<width>w|d)"
    r"(?:\.(?P<ordering>aqrl|aq|rl))?$",
    re.IGNORECASE,
)

def canonicalize_lifted_instruction(
    ins: Any,
    *,
    addr: Optional[int] = None,
    index: int = 0,
) -> CanonicalInsn:
    """
    将单条 LiftedInsn 一次性规范化为 CanonicalInsn。

    后续 Block 构造、CFG、局部 summary 和 fragment summary 都必须消费
    CanonicalInsn，而不是重新遍历 LiftedInsn.raw_ops。

    重要安全约束：

    - register identity 只能由 lifting adapter 显式提供到 raw varnode.name；
    - 本函数及 _to_var() 不得从 register offset、size、str(v)、repr(v)
      或 raw p-code text 重建寄存器名；
    - 若 adapter 没有提供 name，则 Canonical Var.name 保持为空，后续
      lowerer 应 fail closed。
    """
    if addr is None:
        addr = _ins_addr(ins, index)

    size = _ins_size(ins)

    asm_mnem = (getattr(ins, "asm_mnem", "") or "").strip().lower()
    asm_body = (getattr(ins, "asm_body", "") or "").strip()
    semantic_tags = _structured_semantic_tags_from_instruction(ins)

    terminator_kind = _terminator_kind(ins)
    direct_target = _direct_target(ins, terminator_kind)

    barrier_info = _barrier_info_from_instruction(ins)

    atomic_mnemonic, atomic_orderings = _atomic_info_from_asm(ins)

    # 保留旧 decoder 兼容路径。
    if atomic_mnemonic is None and _is_atomic_mnem(asm_mnem):
        atomic_mnemonic = asm_mnem

        ordering = _atomic_ordering_from_mnem(asm_mnem)
        atomic_orderings.update(_atomic_ordering_flags(ordering))

    ops: List[Op] = []

    has_branch_op = False
    has_call_or_return_op = False
    raw_has_barrier = False
    raw_has_atomic = False

    for raw_op in _raw_ops(ins):
        opname = (_opname(raw_op) or "").upper()

        if opname in _BRANCH_OPS:
            has_branch_op = True

        if opname in _CALLRET_OPS:
            has_call_or_return_op = True

        if opname in _BARRIER_OPS:
            raw_has_barrier = True

        if opname in _ATOMIC_OPS:
            raw_has_atomic = True

        inputs = [
            _to_var(raw_var)
            for raw_var in (getattr(raw_op, "inputs", None) or [])
        ]

        output_raw = getattr(raw_op, "output", None)
        output = _to_var(output_raw) if output_raw is not None else None

        ops.append(
            Op(
                addr=addr,
                opcode=opname,
                output=output,
                inputs=inputs,
            )
        )

    # raw p-code 有 barrier opcode，但 asm / decoder 无法恢复具体 RISC-V
    # barrier 类型时，必须保守地保留 unknown barrier。
    has_unknown_barrier = raw_has_barrier and barrier_info is None

    has_atomic = raw_has_atomic or atomic_mnemonic is not None

    atomic_reads_mem = False
    atomic_writes_mem = False

    if atomic_mnemonic is not None:
        atomic_reads_mem, atomic_writes_mem = _atomic_memory_effects(
            atomic_mnemonic
        )

    return CanonicalInsn(
        addr=addr,
        size=size,
        ops=ops,
        terminator_kind=terminator_kind,
        direct_target=direct_target,
        has_branch_op=has_branch_op,
        has_call_or_return_op=has_call_or_return_op,
        barrier_info=barrier_info,
        has_unknown_barrier=has_unknown_barrier,
        has_atomic=has_atomic,
        atomic_mnemonic=atomic_mnemonic,
        atomic_orderings=set(atomic_orderings),
        atomic_reads_mem=atomic_reads_mem,
        atomic_writes_mem=atomic_writes_mem,
        semantic_tags=semantic_tags,
        asm_mnem=asm_mnem,
        asm_body=asm_body,
    )

def _atomic_ordering_flags(ordering: Optional[str]) -> set[str]:
    """
    Convert an atomic mnemonic ordering suffix into canonical independent
    ordering flags.

    Canonical output may contain only:

        "aq"
        "rl"

    In particular:

        "aqrl" -> {"aq", "rl"}
    """
    if ordering == "aq":
        return {"aq"}

    if ordering == "rl":
        return {"rl"}

    if ordering == "aqrl":
        return {"aq", "rl"}

    return set()


def _atomic_info_from_asm(ins: Any) -> tuple[Optional[str], set[str]]:
    """
    从 LiftedInsn.asm_mnem / asm_body 中识别 RISC-V 原子指令及 ordering。

    返回：

        (atomic_mnemonic, {"aq", "rl"})

    例如：

        asm_mnem = "amoadd.d.aqrl"
        asm_body = "a0, a1, (a2)"

    或旧 lift 实现：

        asm_mnem = ""
        asm_body = "amoadd.d.aqrl a0, a1, (a2)"

    注意：atomic_orderings 的 canonical 表示只允许 "aq" 和 "rl"；
    不允许将 "aqrl" 作为单个集合元素保存。
    """
    candidates: list[str] = []

    asm_mnem = (getattr(ins, "asm_mnem", "") or "").strip().lower()
    if asm_mnem:
        candidates.append(asm_mnem)

    asm_body = (getattr(ins, "asm_body", "") or "").strip().lower()
    if asm_body:
        candidates.append(asm_body.split(None, 1)[0])

    for mnemonic in candidates:
        match = _ATOMIC_MNEMONIC_RE.fullmatch(mnemonic)

        if match is None:
            continue

        ordering_text = match.group("ordering") or ""

        return mnemonic, _atomic_ordering_flags(ordering_text)

    return None, set()

class FenceSet(IntFlag):
    """
    RISC-V FENCE predecessor/successor set。

    I: instruction-fetch / instruction stream
    O: device output / MMIO output
    R: memory read
    W: memory write
    """
    NONE = 0
    I = 1 << 0
    O = 1 << 1
    R = 1 << 2
    W = 1 << 3


class BarrierKind(str, Enum):
    """
    不同 barrier 不能被压扁为单一 has_memory_barrier bool。
    """
    MEMORY_FENCE = "memory_fence"
    TSO_FENCE = "tso_fence"
    INSTRUCTION_FENCE = "instruction_fence"
    UNKNOWN_BARRIER = "unknown_barrier"

class StructuredSemanticTag(str, Enum):
    """
    由 decoder / canonicalizer 明确恢复的架构语义类别。

    这些 tag 是 Phase 6 strategy 可使用的 structured semantic evidence。
    不允许 Phase 6 通过 asm_mnem、asm_body、raw p-code text 自行推断。
    """

    ARCHITECTURAL_NOP = "architectural_nop"
    SPIN_WAIT_HINT = "spin_wait_hint"


_FENCE_TEXT_TO_BIT = {
    "i": FenceSet.I,
    "o": FenceSet.O,
    "r": FenceSet.R,
    "w": FenceSet.W,
}


def _fence_set_to_text(value: FenceSet) -> str:
    """
    输出稳定的 canonical 顺序：iorw。
    """
    return "".join(
        letter
        for letter, bit in (
            ("i", FenceSet.I),
            ("o", FenceSet.O),
            ("r", FenceSet.R),
            ("w", FenceSet.W),
        )
        if value & bit
    )


def _parse_fence_set(text: str) -> Optional[FenceSet]:
    """
    解析 RISC-V FENCE 的 pred/succ token。

    允许：
        r
        rw
        iorw
        wor   # 输入顺序不 canonical，但仍可解析

    拒绝：
        rr
        rx
        ""
    """
    text = (text or "").strip().lower()

    if not text:
        return None

    result = FenceSet.NONE

    for char in text:
        bit = _FENCE_TEXT_TO_BIT.get(char)

        if bit is None:
            return None

        if result & bit:
            return None

        result |= bit

    return result

def _structured_semantic_tags_from_instruction(
    ins: Any,
) -> FrozenSet[StructuredSemanticTag]:
    """
    从 decoder 提供的 typed semantic_tags 读取结构化语义标签。

    安全规则：

      * 不读取 asm_mnem；
      * 不读取 asm_body；
      * 不解析 raw p-code text；
      * 不根据 mnemonic 猜测 NOP / PAUSE；
      * decoder 没有提供 typed tag 时，返回空集合；
      * Phase 6 因而 fail closed，而不是猜测匹配。
    """
    raw_tags = getattr(ins, "semantic_tags", None)

    if raw_tags is None:
        return frozenset()

    if isinstance(raw_tags, StructuredSemanticTag):
        return frozenset({raw_tags})

    if not isinstance(raw_tags, Iterable) or isinstance(
        raw_tags,
        (str, bytes),
    ):
        return frozenset()

    tags: set[StructuredSemanticTag] = set()

    for tag in raw_tags:
        if isinstance(tag, StructuredSemanticTag):
            tags.add(tag)

    return frozenset(tags)

@dataclass(frozen=True)
class BarrierInfo:
    """
    单条 RISC-V barrier 的规范化语义。

    对普通 fence：
        kind = MEMORY_FENCE
        pred_mask / succ_mask 保存真实 pred/succ。

    对 fence.tso：
        kind = TSO_FENCE
        pred/succ 仍可保存编码层面的 rw/rw，
        但绝不能因此被当作普通 fence rw,rw。

    对 fence.i：
        kind = INSTRUCTION_FENCE
        它不是普通 memory ordering fence。

    对 p-code 只告诉我们“有 barrier”，但 decoder/lifter 没保留 operand
    的场景：
        kind = UNKNOWN_BARRIER
        semantics_complete = False
    """
    kind: BarrierKind
    pred_mask: FenceSet = FenceSet.NONE
    succ_mask: FenceSet = FenceSet.NONE
    raw_mnemonic: str = ""
    semantics_complete: bool = True

    @property
    def pred(self) -> str:
        return _fence_set_to_text(self.pred_mask)

    @property
    def succ(self) -> str:
        return _fence_set_to_text(self.succ_mask)

    @property
    def is_instruction_fence(self) -> bool:
        return self.kind is BarrierKind.INSTRUCTION_FENCE

    @property
    def is_tso_hint(self) -> bool:
        return self.kind is BarrierKind.TSO_FENCE

    @property
    def is_memory_fence(self) -> bool:
        return self.kind in {
            BarrierKind.MEMORY_FENCE,
            BarrierKind.TSO_FENCE,
        }

    @property
    def is_unknown(self) -> bool:
        return (
            self.kind is BarrierKind.UNKNOWN_BARRIER
            or not self.semantics_complete
        )

class VarKind(Enum):
    REG = "reg"
    MEM = "mem"
    CONST = "const"
    UNIQUE = "unique"
    OTHER = "other"


@dataclass(frozen=True)
class Var:
    kind: VarKind
    space: str
    offset: int
    size: int
    name: str = ""

    def __str__(self) -> str:
        if self.kind == VarKind.CONST:
            return f"#{hex(self.offset)}:{self.size}"
        return f"{self.space}[{hex(self.offset)}]:{self.size}"


@dataclass
class Op:
    addr: int
    opcode: str
    output: Optional[Var]
    inputs: List[Var]

@dataclass
class CanonicalInsn:
    """
    单条机器指令的规范化 p-code / 汇编语义。
    """

    addr: int
    size: int

    ops: List[Op] = field(default_factory=list)

    terminator_kind: Optional[str] = None
    direct_target: Optional[int] = None

    has_branch_op: bool = False
    has_call_or_return_op: bool = False

    barrier_info: Optional[BarrierInfo] = None
    has_unknown_barrier: bool = False

    has_atomic: bool = False
    atomic_mnemonic: Optional[str] = None
    atomic_orderings: Set[str] = field(default_factory=set)
    atomic_reads_mem: bool = False
    atomic_writes_mem: bool = False

    # 新增：供 Phase 6 使用的 structured semantic evidence。
    #
    # 必须由 decoder / canonicalization 的 typed metadata 生成。
    # 不允许 Phase 6 根据 asm_mnem / asm_body 推断。
    semantic_tags: FrozenSet[StructuredSemanticTag] = field(
        default_factory=frozenset
    )

    # 仅用于 debug / display / compatibility。
    asm_mnem: str = ""
    asm_body: str = ""

@dataclass
class IRSummary:
    is_single_block: bool
    has_branch: bool
    has_call_or_return: bool
    has_memory_barrier: bool
    has_atomic: bool
    reads_regs: Set[str]
    writes_regs: Set[str]
    reads_mem: bool
    writes_mem: bool

    has_unresolved_register_identity: bool = False

    atomic_orderings: Set[str] = field(default_factory=set)
    atomic_mnemonics: Set[str] = field(default_factory=set)
    barrier_infos: List[BarrierInfo] = field(default_factory=list)

    has_instruction_barrier: bool = False
    has_unknown_barrier: bool = False

    has_return: Optional[bool] = None
    has_tail_call: Optional[bool] = None
    has_indirect_control_flow: Optional[bool] = None

    has_timing_source: Optional[bool] = None
    has_cache_operation: Optional[bool] = None
    has_speculation_control: Optional[bool] = None

    @property
    def barrier_info(self) -> Optional[BarrierInfo]:
        if len(self.barrier_infos) == 1:
            return self.barrier_infos[0]

        return None

@dataclass
class Block:
    # Basic-block 的绝对机器码地址；也是 CFG node ID。
    addr: int

    # 已规范化的 p-code ops。
    ops: List[Op] = field(default_factory=list)

    # 当前 fragment 内部 successor 地址。
    successors: List[int] = field(default_factory=list)

    # 展示 / 调试元数据。
    size: int = 0
    instr_addrs: List[int] = field(default_factory=list)

    # successor 地址 -> edge kind。
    successor_kinds: dict[int, str] = field(default_factory=dict)

    # direct CALL 的 callee 地址；callee 不等于 CFG successor。
    call_targets: List[int] = field(default_factory=list)

    # "", branch, cbranch, call, callind, branchind, return。
    terminator_kind: str = ""

    # CFG 辅助语义。
    has_branch: bool = False
    is_call_or_return: bool = False
    is_indirect: bool = False
    has_unknown_target: bool = False

    # 当前 block 的局部 IR summary。
    #
    # 保留 from_lifted() 的全局 summary 返回方式，
    # 同时兼容通过 block.summary 读取分析结果的调用方。
    summary: Optional[IRSummary] = None

    instructions: List[CanonicalInsn] = field(default_factory=list)

    @property
    def is_branch(self) -> bool:
        """
        兼容部分 CFG 调用方使用的 is_branch 字段。

        authoritative 语义仍存储于 has_branch；该 property 仅作为
        不改变数据模型的兼容层。
        """
        return self.has_branch


_BRANCH_OPS = {"BRANCH", "CBRANCH", "BRANCHIND"}
_CALLRET_OPS = {"CALL", "CALLIND", "RETURN"}
_TERM_OPS = _BRANCH_OPS | _CALLRET_OPS
_DIRECT_TARGET_OPS = {"BRANCH", "CBRANCH", "CALL"}

# 旧 lifting 中可能出现的 atomic / barrier opcode 兜底。
_ATOMIC_OPS: set[str] = set()

# raw p-code barrier opcode 的保守识别。
_BARRIER_OPS = {"FENCE", "MEMORYBARRIER"}

# Canonical atomic ordering flags。
#
# aqrl 必须展开为 {"aq", "rl"}，不得作为单独元素保存。
_ATOMIC_ORDERINGS = {"aq", "rl"}

_TARGET_TOKEN_RE = re.compile(r"[-+]?(?:0x[0-9a-fA-F]+|\d+)")
_PC_REL_TARGET_RE = re.compile(
    r"""
    ^
    \.
    \s*
    (?P<op>[+-])
    \s*
    (?P<imm>0x[0-9a-fA-F]+|\d+)
    $
    """,
    re.VERBOSE,
)

def _raw_ops(ins: Any) -> list[Any]:
    """
    从 LiftedInsn 中读取结构化 p-code operation。

    authoritative production field:
        - raw_ops

    legacy structured compatibility fields:
        - pcode
        - ops

    注意：
      - pcode_ops 是展示/诊断用文本，不得用于 canonicalization；
      - 不解析 str(op)、repr(op) 或 raw p-code text；
      - 不合并多个字段，避免重复计算；
      - 若 raw_ops 字段存在，则即使为空，也视为 authoritative empty op list。
    """

    def _as_structured_ops(value: Any) -> Optional[list[Any]]:
        if value is None:
            return None

        if isinstance(value, (str, bytes, bytearray)):
            return None

        try:
            ops = list(value)
        except (TypeError, ValueError):
            return None

        # 禁止 List[str] 之类的 p-code display 文本进入语义恢复路径。
        if any(isinstance(op, (str, bytes, bytearray)) for op in ops):
            return None

        return ops

    # raw_ops 是新 lifting adapter 的 authoritative 字段。
    if hasattr(ins, "raw_ops"):
        ops = _as_structured_ops(getattr(ins, "raw_ops", None))
        return ops if ops is not None else []

    # 仅保留旧版本的结构化对象兼容字段。
    for field_name in ("pcode", "ops"):
        ops = _as_structured_ops(getattr(ins, field_name, None))
        if ops is not None:
            return ops

    return []

def _opname(op: Any) -> str:
    """
    从结构化 opcode 字段读取并规范化 p-code opcode。

    不解析 str(op)、repr(op) 或 raw p-code text。
    """
    for attr in (
        "opcode_name",
        "opcode",
        "mnemonic",
        "op",
        "name",
        "operation",
    ):
        opcode = getattr(op, attr, None)

        if isinstance(opcode, str):
            text = opcode
        else:
            enum_name = getattr(opcode, "name", None)
            text = enum_name if isinstance(enum_name, str) else ""

        text = text.strip().upper().replace("CPUI_", "")

        if not text:
            continue

        for known in (
            "CBRANCH",
            "BRANCHIND",
            "BRANCH",
            "CALLIND",
            "CALL",
            "RETURN",
            "LOAD",
            "STORE",
            "FENCE",
            "MEMORYBARRIER",
            "CPOOLREF",
            "SEGMENTOP",
        ):
            if (
                text == known
                or text.endswith("." + known)
                or text.endswith("_" + known)
            ):
                return known

        return text

    return ""

def _ins_addr(ins: Any, index: int = -1) -> int:
    """
    从 lifted instruction 读取绝对机器码地址。

    兼容常见字段：
      - addr
      - address
      - pc

    仅接受非负 Python int。

    不接受：
      - None；
      - bool；
      - str；
      - float；
      - 负数；
      - fragment-relative offset。

    如果 lift 层没有保存 absolute machine-code address，
    CFG 无法正确构建；pcode_ir 不得使用 index、0 或其他猜测值代替。
    """
    for attr in ("addr", "address", "pc"):
        value = getattr(ins, attr, None)

        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        ):
            return value

    where = (
        f"lifted instruction[{index}]"
        if index >= 0
        else "lifted instruction"
    )

    observed = {
        attr: getattr(ins, attr, None)
        for attr in ("addr", "address", "pc")
        if hasattr(ins, attr)
    }

    raise AssertionError(
        f"{where} has no valid non-negative absolute machine-code address; "
        f"observed={observed!r}; "
        "expected ins.addr, ins.address, or ins.pc to contain a non-negative "
        "Python int absolute address"
    )


def _ins_size(ins: Any) -> int:
    """
    尽量读取 machine instruction size。

    RISC-V:
      - compressed instruction: 2 bytes
      - normal instruction: 4 bytes
    """
    for attr in ("length", "size", "insn_size"):
        value = getattr(ins, attr, None)

        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value > 0
        ):
            return value

    for attr in ("bytes_", "inst_bytes", "bytes", "machine_code"):
        raw = getattr(ins, attr, None)

        if isinstance(raw, (bytes, bytearray)) and len(raw) > 0:
            return len(raw)

        try:
            if raw is not None and len(raw) > 0:
                return len(raw)
        except Exception:
            pass

    return 0

def _raw_space_name(v: Any) -> Optional[str]:
    """
    Read a lifting-layer varnode address-space name without parsing str(v).

    Compatible forms:

        v.space.name == "register"
        v.space == "register"

    This helper intentionally does not inspect str(v), repr(v), raw p-code
    text, register offsets, or varnode widths.
    """
    raw_space = getattr(v, "space", None)

    if raw_space is None:
        return None

    named_space = getattr(raw_space, "name", None)

    if isinstance(named_space, str) and named_space.strip():
        return named_space.strip()

    if isinstance(raw_space, str) and raw_space.strip():
        return raw_space.strip()

    return None

def _to_var(v: Any) -> Var:
    """
    Convert a lifting-layer varnode into canonical structured Var.

    Important Phase-6 contract:

      * Canonical Var preserves register identity in Var.name only when the
        lifting adapter explicitly provides that name.
      * This function must not reconstruct register identity from offset,
        size, str(v), repr(v), or raw p-code text.
      * If a register name is unavailable, the Var remains structurally
        valid but Var.name is empty. Register-name-dependent lowerers must
        reject it rather than guessing.
    """
    if v is None:
        return Var(VarKind.OTHER, "?", 0, 0)

    space = _raw_space_name(v)

    try:
        off = int(getattr(v, "offset"))
        size = int(getattr(v, "size"))
    except (AttributeError, TypeError, ValueError):
        return Var(VarKind.OTHER, "?", 0, 0)

    if not space:
        return Var(VarKind.OTHER, "?", 0, 0)

    raw_name = getattr(v, "name", "")

    # Register names must come from an explicit adapter field.  Do not
    # stringify arbitrary non-string values because that can accidentally
    # turn an opaque object representation into semantic register identity.
    name = raw_name.strip() if isinstance(raw_name, str) else ""

    space_lower = space.lower()

    if space_lower == "const":
        kind = VarKind.CONST
    elif space_lower == "register":
        kind = VarKind.REG
    elif space_lower == "unique":
        kind = VarKind.UNIQUE
    elif space_lower in {"ram", "mem"}:
        kind = VarKind.MEM
    else:
        kind = VarKind.OTHER

    return Var(
        kind=kind,
        space=space,
        offset=off,
        size=size,
        name=name,
    )

def _candidate_target_addr(v: Any) -> Optional[int]:
    """
    从结构化 p-code branch/call 输入中恢复 direct target。

    仅接受明确的非负绝对地址：

        * Python int；
        * const-space varnode 的 integer offset；
        * ram-space varnode 的 integer offset；
        * mem-space varnode 的 integer offset。

    不接受：

        * None；
        * bool；
        * str；
        * float；
        * fragment-relative offset；
        * register-space varnode；
        * unique-space varnode；
        * 通过寄存器 offset 推测出的地址。
    """
    if v is None or isinstance(v, bool):
        return None

    if isinstance(v, int):
        return v if v >= 0 else None

    space = _raw_space_name(v)

    raw_offset = getattr(v, "offset", None)

    if (
        raw_offset is None
        or isinstance(raw_offset, bool)
        or not isinstance(raw_offset, int)
    ):
        return None

    if raw_offset < 0:
        return None

    if (space or "").lower() in {"const", "ram", "mem"}:
        return raw_offset

    return None

def _asm_operands(ins: Any) -> List[str]:
    """
    返回规范化后的汇编 operand 列表。

    通常 asm_body 不包含 mnemonic，例如：

        asm_mnem = "jal"
        asm_body = "ra, 0x10080"

    但兼容旧实现可能出现：

        asm_mnem = "jal"
        asm_body = "jal ra, 0x10080"
    """
    body = (getattr(ins, "asm_body", "") or "").strip()
    mnem = (getattr(ins, "asm_mnem", "") or "").strip().lower()

    if not body:
        return []

    parts = [
        part.strip().lower()
        for part in body.split(",")
        if part.strip()
    ]

    if parts and mnem:
        first = parts[0]

        if first == mnem:
            parts = parts[1:]
        elif first.startswith(mnem + " "):
            remaining = first[len(mnem):].strip()

            if remaining:
                parts[0] = remaining
            else:
                parts = parts[1:]

    return parts

def _normalized_instruction_mnemonic(ins: Any) -> str:
    """
    优先读取 decoder/lifter 给出的 machine-code-derived mnemonic。

    推荐 lifting adapter 未来保存：
        decoded_mnemonic
        decoded_asm_mnem
        machine_mnemonic

    asm_mnem 仅作为兼容 fallback。
    """
    for attr in (
        "decoded_mnemonic",
        "decoded_asm_mnem",
        "machine_mnemonic",
        "asm_mnem",
    ):
        value = getattr(ins, attr, None)

        if isinstance(value, str) and value.strip():
            return value.strip().lower()

    return ""


def _fence_operands_from_structured_metadata(
    ins: Any,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    尝试从 lifting / decoder 的结构化 metadata 获取 fence 信息。

    返回：
        (kind_text, pred_text, succ_text)

    可接受字段示例：

        ins.fence_kind = "tso"
        ins.fence_pred = "rw"
        ins.fence_succ = "rw"

    或：

        ins.decoded_metadata = {
            "fence_kind": "tso",
            "fence_pred": "rw",
            "fence_succ": "rw",
        }

    这里不要求所有 adapter 都实现这些字段；
    没有时由 asm fallback 继续处理。
    """
    metadata = getattr(ins, "decoded_metadata", None)

    if not isinstance(metadata, dict):
        metadata = {}

    def get_text(*names: str) -> Optional[str]:
        for name in names:
            value = getattr(ins, name, None)

            if value is None:
                value = metadata.get(name)

            if isinstance(value, str) and value.strip():
                return value.strip().lower()

        return None

    kind = get_text(
        "fence_kind",
        "decoded_fence_kind",
        "barrier_kind",
    )

    pred = get_text(
        "fence_pred",
        "decoded_fence_pred",
        "barrier_pred",
    )

    succ = get_text(
        "fence_succ",
        "decoded_fence_succ",
        "barrier_succ",
    )

    return kind, pred, succ


def _barrier_info_from_instruction(ins: Any) -> Optional[BarrierInfo]:
    """
    从单条 LiftedInsn 提取 RISC-V barrier 语义。

    优先级：

        1. decoder/lifter 的 structured metadata；
        2. machine-code-derived mnemonic；
        3. asm_mnem / asm_body fallback；
        4. 若 p-code 告知 barrier 但语义已丢失，则返回 UNKNOWN_BARRIER。

    支持：
        fence r, w
        fence rw, rw
        fence iorw, iorw
        fence.tso
        fence.i
    """
    mnem = _normalized_instruction_mnemonic(ins)

    structured_kind, structured_pred, structured_succ = (
        _fence_operands_from_structured_metadata(ins)
    )

    normalized_kind = (structured_kind or "").strip().lower()

    # 显式结构化的 fence.i。
    if normalized_kind in {
        "i",
        "fence.i",
        "instruction",
        "instruction_fence",
    }:
        return BarrierInfo(
            kind=BarrierKind.INSTRUCTION_FENCE,
            raw_mnemonic=mnem or "fence.i",
            semantics_complete=True,
        )

       # 显式结构化的 fence.tso。
    #
    # RISC-V fence.tso 语义固定为 pred=rw, succ=rw；
    # metadata 未显式提供 pred/succ 时可以使用该规范默认值。
    #
    # 但如果 metadata 显式提供了非法 fence set，则不能伪造 rw 继续
    # 当作完整 TSO barrier，必须保守降级为 UNKNOWN_BARRIER。
    if normalized_kind in {
        "tso",
        "fence.tso",
        "tso_fence",
    }:
        expected = FenceSet.R | FenceSet.W

        if structured_pred is None:
            pred = expected
        else:
            pred = _parse_fence_set(structured_pred)

        if structured_succ is None:
            succ = expected
        else:
            succ = _parse_fence_set(structured_succ)

        if (
            pred is None
            or succ is None
            or pred != expected
            or succ != expected
        ):
            return BarrierInfo(
                kind=BarrierKind.UNKNOWN_BARRIER,
                raw_mnemonic=mnem or "fence.tso",
                semantics_complete=False,
            )

        return BarrierInfo(
            kind=BarrierKind.TSO_FENCE,
            pred_mask=expected,
            succ_mask=expected,
            raw_mnemonic=mnem or "fence.tso",
            semantics_complete=True,
        )

    # 结构化普通 FENCE pred/succ。
        # 结构化普通 FENCE pred/succ。
    #
    # 普通 fence 的 pred 和 succ 必须同时可恢复。只恢复到一侧、或任意
    # 一侧包含非法字符时，不能继续把它表示为带 NONE mask 的普通 fence；
    # 否则 summary 会错误地将其当作语义完整的 memory fence。
    if structured_pred is not None or structured_succ is not None:
        # 普通 fence 的两侧必须同时由 structured metadata 提供。
        if structured_pred is None or structured_succ is None:
            return BarrierInfo(
                kind=BarrierKind.UNKNOWN_BARRIER,
                raw_mnemonic=mnem or "fence",
                semantics_complete=False,
            )

        pred = _parse_fence_set(structured_pred)
        succ = _parse_fence_set(structured_succ)

        if pred is None or succ is None:
            return BarrierInfo(
                kind=BarrierKind.UNKNOWN_BARRIER,
                raw_mnemonic=mnem or "fence",
                semantics_complete=False,
            )

        return BarrierInfo(
            kind=BarrierKind.MEMORY_FENCE,
            pred_mask=pred,
            succ_mask=succ,
            raw_mnemonic=mnem or "fence",
            semantics_complete=True,
        )

    # fence.i 必须先于 startswith("fence") 判断。
    if mnem == "fence.i":
        return BarrierInfo(
            kind=BarrierKind.INSTRUCTION_FENCE,
            raw_mnemonic="fence.i",
            semantics_complete=True,
        )

    if mnem == "fence.tso":
        # 注意：
        # fence.tso 的编码层面通常可表现为 pred=rw, succ=rw，
        # 但其语义不能被折叠成普通 fence rw,rw。
        return BarrierInfo(
            kind=BarrierKind.TSO_FENCE,
            pred_mask=FenceSet.R | FenceSet.W,
            succ_mask=FenceSet.R | FenceSet.W,
            raw_mnemonic="fence.tso",
            semantics_complete=True,
        )

    if mnem == "fence":
        operands = _asm_operands(ins)

        # GNU/LLVM assembler 中 `fence` 无 operand 通常表示默认 iorw,iorw。
        if not operands:
            return BarrierInfo(
                kind=BarrierKind.MEMORY_FENCE,
                pred_mask=(
                    FenceSet.I
                    | FenceSet.O
                    | FenceSet.R
                    | FenceSet.W
                ),
                succ_mask=(
                    FenceSet.I
                    | FenceSet.O
                    | FenceSet.R
                    | FenceSet.W
                ),
                raw_mnemonic="fence",
                semantics_complete=True,
            )

        if len(operands) != 2:
            return BarrierInfo(
                kind=BarrierKind.UNKNOWN_BARRIER,
                raw_mnemonic="fence",
                semantics_complete=False,
            )

        pred = _parse_fence_set(operands[0])
        succ = _parse_fence_set(operands[1])

        if pred is None or succ is None:
            return BarrierInfo(
                kind=BarrierKind.UNKNOWN_BARRIER,
                raw_mnemonic="fence",
                semantics_complete=False,
            )

        return BarrierInfo(
            kind=BarrierKind.MEMORY_FENCE,
            pred_mask=pred,
            succ_mask=succ,
            raw_mnemonic="fence",
            semantics_complete=True,
        )

    # p-code 可能只保留 barrier opcode，不保留 RISC-V operand。
    raw_opnames = {_opname(op) for op in _raw_ops(ins)}

    if raw_opnames & _BARRIER_OPS:
        return BarrierInfo(
            kind=BarrierKind.UNKNOWN_BARRIER,
            raw_mnemonic=mnem,
            semantics_complete=False,
        )

    return None


def _parse_target_from_asm(ins: Any) -> Optional[int]:
    """
    从 asm_body 最后一个操作数恢复 direct target。

    支持：
      beq a0, a1, 0x10008
      jal ra, 0x10008
      beq a0, a1, .+8
      beq a0, a1, .-4

    对 label-only 情况，通常 assembler / disassembler 应已经将 label
    解析为绝对地址；如果仍为纯 label，无法在此层恢复。
    """
    body = (getattr(ins, "asm_body", "") or "").strip()

    if not body:
        return None

    parts = [part.strip() for part in body.split(",") if part.strip()]

    if not parts:
        return None

    last = parts[-1]

    # 支持 .+8 / .-4 形式的 PC-relative target。
    pc_rel = _PC_REL_TARGET_RE.match(last)

    if pc_rel is not None:
        try:
            base = _ins_addr(ins)
            imm = int(pc_rel.group("imm"), 0)
        except Exception:
            return None

        if pc_rel.group("op") == "-":
            imm = -imm

        return base + imm

    # 常规绝对数字地址。
    token = _TARGET_TOKEN_RE.search(last)

    if token is None:
        return None

    try:
        return int(token.group(0), 0)
    except ValueError:
        return None


def _atomic_ordering_from_mnem(mnem: str) -> Optional[str]:
    """
    从 RISC-V atomic mnemonic 中提取 ordering suffix。

    返回原始 suffix：

        "aq"
        "rl"
        "aqrl"

    调用方必须通过 _atomic_ordering_flags() 将其转换为 canonical
    independent flags：

        "aq"   -> {"aq"}
        "rl"   -> {"rl"}
        "aqrl" -> {"aq", "rl"}
    """
    parts = (mnem or "").strip().lower().split(".")

    for part in reversed(parts):
        if part in {"aq", "rl", "aqrl"}:
            return part

    return None

def _is_atomic_mnem(mnem: str) -> bool:
    """
    严格识别合法的 RISC-V A extension atomic mnemonic。

    覆盖：

        lr.w / lr.d
        sc.w / sc.d
        amoswap.*
        amoadd.*
        amoxor.*
        amoand.*
        amoor.*
        amomin.*
        amomax.*
        amominu.*
        amomaxu.*

    以及可选 ordering suffix：

        .aq
        .rl
        .aqrl

    不接受仅以 "amo"、"lr."、"sc." 开头的任意字符串，
    避免将非 atomic 或损坏的 decoder 输出误判为 atomic。
    """
    normalized = (mnem or "").strip().lower()

    return _ATOMIC_MNEMONIC_RE.fullmatch(normalized) is not None

def _atomic_memory_effects(mnem: str) -> tuple[bool, bool]:
    """
    返回 (reads_mem, writes_mem)。

    lr.*:
      load-reserved，只读内存。

    sc.*:
      store-conditional，写内存。

    amo*:
      read-modify-write，同时读写内存。
    """
    mnem = (mnem or "").strip().lower()

    if mnem.startswith("lr."):
        return True, False

    if mnem.startswith("sc."):
        return False, True

    if mnem.startswith("amo"):
        return True, True

    return False, False


def _asm_terminator_kind(ins: Any) -> Optional[str]:
    """
    当 p-code 不足以稳定识别 terminator 时使用 RISC-V mnemonic 兜底。
    """
    mnem = (getattr(ins, "asm_mnem", "") or "").strip().lower()
    ops = _asm_operands(ins)

    if not mnem:
        return None

    if mnem in {"ret", "c.ret"}:
        return "RETURN"

    if mnem in {
        "beq",
        "bne",
        "beqz",
        "bnez",
        "blt",
        "bge",
        "bltu",
        "bgeu",
        "blez",
        "bgez",
        "bltz",
        "bgtz",
        "c.beqz",
        "c.bnez",
    }:
        return "CBRANCH"

    # tail 是 direct jump / tail-call，而不是 indirect jump。
    #
    # 即使目标是 unresolved external symbol，也不能将其视为
    # BRANCHIND 或 has_unknown_target=True。
    if mnem in {"j", "c.j", "b", "tail"}:
        return "BRANCH"

    if mnem in {"jr", "c.jr"}:
        return "BRANCHIND"

    # call symbol / call 0x... 是 direct CALL。
    #
    # unresolved symbol 时 _direct_target() 可能返回 None，但 CALL
    # 语义和 call-return fallthrough edge 必须保留。
    if mnem == "call":
        return "CALL"

    if mnem == "c.jal":
        return "CALL"

    if mnem == "c.jalr":
        return "CALLIND"

    # jal x0, target => direct jump
    # jal ra, target => direct call
    # jal target => assembler 常见简写，默认 rd=ra，可视为 call
    if mnem == "jal":
        if ops and ops[0] in {"x0", "zero"}:
            return "BRANCH"
        return "CALL"

    # jalr x0, ... => indirect jump
    # jalr ra, ... => indirect call
    if mnem == "jalr":
        if ops and ops[0] in {"x0", "zero"}:
            return "BRANCHIND"
        return "CALLIND"

    return None


def _raw_terminator_kind(ins: Any) -> Optional[str]:
    opnames = {_opname(op) for op in _raw_ops(ins)}

    if "RETURN" in opnames:
        return "RETURN"

    if "CBRANCH" in opnames:
        return "CBRANCH"

    if "CALLIND" in opnames:
        return "CALLIND"

    if "CALL" in opnames:
        return "CALL"

    if "BRANCHIND" in opnames:
        return "BRANCHIND"

    if "BRANCH" in opnames:
        return "BRANCH"

    return None


def _terminator_kind(ins: Any) -> Optional[str]:
    """
    p-code 优先，但 return alias 优先保留。

    某些 lift 会把 ret 表示为 BRANCHIND；
    对 CFG 和 summary 来说，ret 应保留 RETURN 语义。
    """
    asm_term = _asm_terminator_kind(ins)

    if asm_term == "RETURN":
        return "RETURN"

    raw_term = _raw_terminator_kind(ins)

    if raw_term is not None:
        return raw_term

    return asm_term


def _direct_target(ins: Any, term: Optional[str]) -> Optional[int]:
    """
    恢复 direct BRANCH / CBRANCH / CALL target。

    注意：
      - target 可以位于 fragment 外；
      - fragment 内过滤在 CFG 构建阶段执行；
      - external direct branch/call 不是 unknown target。
    """
    if term not in _DIRECT_TARGET_OPS:
        return None

    for op in _raw_ops(ins):
        if _opname(op) != term:
            continue

        inputs = getattr(op, "inputs", None) or []

        if not inputs:
            continue

        target = _candidate_target_addr(inputs[0])

        if target is not None:
            return target

        # 部分 p-code object 将 direct target 单独保存在属性中，
        # 而不是放入 inputs[0]。
        for attr in ("target", "input0", "destination"):
            candidate = getattr(op, attr, None)
            target = _candidate_target_addr(candidate)

            if target is not None:
                return target

    return _parse_target_from_asm(ins)


def _dedup_ints(values: List[int]) -> List[int]:
    out: List[int] = []
    seen: set[int] = set()

    for value in values:
        if value in seen:
            continue

        seen.add(value)
        out.append(value)

    return out

def _summary_register_key(var: Var) -> str:
    """
    为 IRSummary 生成 register identity key。

    具名寄存器使用 lifting adapter 明确提供的 canonical name。
    无名字寄存器仅保留 opaque identity，不得依据 offset 推断 ABI 名。
    """
    name = var.name.strip() if isinstance(var.name, str) else ""

    if name:
        return name

    return f"reg@{var.space}:{hex(var.offset)}:{var.size}"

def _is_proven_pure_integer_straight_line_fragment(
    insns: list[CanonicalInsn],
) -> bool:
    """
    判断 fragment 是否可仅从 CanonicalInsn / Op 严格证明为：

      * 无 branch / call / return；
      * 无 indirect control flow；
      * 无 atomic；
      * 无 barrier；
      * 无 load/store；
      * 仅包含：
          - 已知的非语义 canonical marker；
          - 已知的普通整数数据流 operation。

    返回 False 不代表 fragment 一定不安全，而只代表当前 summary
    producer 不能完成可靠证明；调用方必须继续 fail closed。
    """
    if not insns:
        return False

    saw_semantic_integer_op = False

    for ins in insns:
        if ins.terminator_kind:
            return False

        if ins.has_branch_op:
            return False

        if ins.has_call_or_return_op:
            return False

        if ins.has_atomic:
            return False

        if ins.barrier_info is not None:
            return False

        if ins.has_unknown_barrier:
            return False

        for op in ins.ops:
            opcode = (op.opcode or "").upper()

            # instruction marker 不是可执行数据流语义。
            if opcode in _NON_SEMANTIC_CANONICAL_OPCODES:
                continue

            # 当前 generic integer lowering 不接受 memory semantic。
            if opcode in {"LOAD", "STORE"}:
                return False

            # 所有未知 structured opcode 必须保持 fail closed。
            if opcode not in _PROVEN_PURE_INTEGER_OPCODES:
                return False

            saw_semantic_integer_op = True

    # 仅 IMARK 的 fragment 也不能被当成“已证明的普通整数 fragment”。
    return saw_semantic_integer_op


def _is_proven_straight_line_barrier_fragment(
    insns: list[CanonicalInsn],
) -> bool:
    """Prove the narrow no-control-flow barrier shape used by Phase 6A.

    A barrier does not itself imply a return, indirect branch, timing source
    or cache operation.  The canonical summary must be able to state those
    facts as absent for a standalone, fully decoded fence; otherwise Phase 6D
    correctly rejects the plan as incomplete.  This predicate intentionally
    does *not* admit unknown barriers, atomics, instruction fences, or a
    mixed instruction sequence.
    """
    if len(insns) != 1:
        return False

    ins = insns[0]
    if (
        ins.terminator_kind
        or ins.has_branch_op
        or ins.has_call_or_return_op
        or ins.has_atomic
        or ins.has_unknown_barrier
        or ins.barrier_info is None
        or ins.barrier_info.is_unknown
        or ins.barrier_info.is_instruction_fence
    ):
        return False

    # A standalone barrier route must not hide data-flow, memory access or
    # another unmodelled instruction behind the fence metadata.
    for op in ins.ops:
        opcode = (op.opcode or "").upper()
        if opcode not in _NON_SEMANTIC_CANONICAL_OPCODES:
            return False

    return True

def _summarize_instructions(
    insns: list[CanonicalInsn],
    *,
    is_single_block: bool,
) -> IRSummary:
    """
    汇总 CanonicalInsn 的语义。

    重要约束：

      - 不重新读取 LiftedInsn；
      - 不重新扫描 raw p-code；
      - 不重新通过 asm 文本判断 barrier / atomic；
      - Block summary 与 fragment summary 必须仅从 CanonicalInsn 派生。
    """
    has_branch = False
    has_callret = False
    has_atomic = False

    # 仅指普通 memory fence / fence.tso。
    has_fence = False

    # fence.i 单独记录。
    has_instruction_barrier = False

    # raw p-code 存在 barrier，但具体 RISC-V barrier 语义未恢复。
    has_unknown_barrier = False

    reads_regs: Set[str] = set()
    writes_regs: Set[str] = set()

    reads_mem = False
    writes_mem = False

    atomic_orderings: Set[str] = set()
    atomic_mnemonics: Set[str] = set()

    barrier_infos: List[BarrierInfo] = []

    for ins in insns:
        term = ins.terminator_kind

        if term in _BRANCH_OPS or ins.has_branch_op:
            has_branch = True

        if term in _CALLRET_OPS or ins.has_call_or_return_op:
            has_callret = True

        barrier_info = ins.barrier_info

        if barrier_info is not None:
            barrier_infos.append(barrier_info)

            if barrier_info.is_memory_fence:
                has_fence = True

            if barrier_info.is_instruction_fence:
                has_instruction_barrier = True

            if barrier_info.is_unknown:
                has_unknown_barrier = True

        if ins.has_unknown_barrier:
            has_unknown_barrier = True

        if ins.has_atomic:
            has_atomic = True

        if ins.atomic_mnemonic is not None:
            atomic_mnemonics.add(ins.atomic_mnemonic)

        atomic_orderings.update(ins.atomic_orderings)

        reads_mem = reads_mem or ins.atomic_reads_mem
        writes_mem = writes_mem or ins.atomic_writes_mem

        for op in ins.ops:
            if op.opcode == "LOAD":
                reads_mem = True

            if op.opcode == "STORE":
                writes_mem = True
            has_unresolved_register_identity = False
            for var in op.inputs:
                if var.kind == VarKind.REG:
                    if not (var.name or "").strip():
                        has_unresolved_register_identity = True
                    reads_regs.add(_summary_register_key(var))

            if op.output is not None and op.output.kind == VarKind.REG:
                if not (op.output.name or "").strip():
                    has_unresolved_register_identity = True
                writes_regs.add(_summary_register_key(op.output))

    # 对普通、直线、纯整数 canonical p-code fragment，
    # 可以严格证明以下“特殊语义不存在”。
    #
    # 对其他 fragment 维持 None。
    #
    # None 的语义不是 False，而是“当前 producer 不能可靠证明”；
    # generic lowering 必须继续 fail closed。
    proven_pure_integer = (
        _is_proven_pure_integer_straight_line_fragment(insns)
    )

    proven_false: Optional[bool] = (
        False
        if (
            proven_pure_integer
            or _is_proven_straight_line_barrier_fragment(insns)
        )
        else None
    )

    return IRSummary(
        is_single_block=is_single_block,
        has_branch=has_branch,
        has_call_or_return=has_callret,
        has_memory_barrier=has_fence,
        has_atomic=has_atomic,
        reads_regs=reads_regs,
        writes_regs=writes_regs,
        reads_mem=reads_mem,
        writes_mem=writes_mem,
        atomic_orderings=atomic_orderings,
        atomic_mnemonics=atomic_mnemonics,
        barrier_infos=barrier_infos,
        has_instruction_barrier=has_instruction_barrier,
        has_unknown_barrier=has_unknown_barrier,

        # ===== Phase 6 fail-closed semantic proof fields =====
        #
        # 仅在 canonical IR 被证明是纯整数直线代码时填写 False。
        # 其他情况保留 None，禁止将未知语义错误降级为安全语义。
        has_return=proven_false,
        has_tail_call=proven_false,
        has_indirect_control_flow=proven_false,
        has_timing_source=proven_false,
        has_cache_operation=proven_false,
        has_speculation_control=proven_false,
    )

def summarize_lifted_instruction(ins: Any) -> IRSummary:
    """
    返回单条 LiftedInsn 的 IR 分析摘要。

    即使调用方只持有 LiftedInsn，也必须先构造 CanonicalInsn，
    以确保该公共入口和 from_lifted() 使用完全相同的语义恢复规则。
    """
    canonical = canonicalize_lifted_instruction(ins)

    return _summarize_instructions(
        [canonical],
        is_single_block=True,
    )

def canonicalize_lifted_instructions(
    lifted_instructions: Iterable[Any],
) -> list[CanonicalInsn]:
    """
    将 lifting 层指令序列转换为 authoritative CanonicalInsn 序列。

    处理顺序：

        LiftedInsn
          -> address validation
          -> canonicalize_lifted_instruction()
          -> CanonicalInsn

    安全约束：

    - 每条 LiftedInsn 只 canonicalize 一次；
    - CanonicalInsn.addr 必须是唯一、非负的绝对机器码地址；
    - 下游 Block、CFG、summary、lowering 前分析只允许消费返回的
      CanonicalInsn，禁止重新读取 LiftedInsn.raw_ops / pcode_ops / pcode。
    """
    lifted_list = list(lifted_instructions or [])

    if not lifted_list:
        return []

    indexed_lifted: list[tuple[int, Any]] = []
    seen_addrs: set[int] = set()

    # 第一阶段：读取并校验 authoritative machine-code address。
    for index, ins in enumerate(lifted_list):
        addr = _ins_addr(ins, index)

        if addr < 0:
            raise AssertionError(
                f"lifted instruction[{index}] has negative address {addr}; "
                "CanonicalInsn.addr must be an absolute machine-code address"
            )

        if addr in seen_addrs:
            raise AssertionError(
                f"duplicate lifted instruction address 0x{addr:x}; "
                "each machine instruction must have a unique absolute address"
            )

        seen_addrs.add(addr)
        indexed_lifted.append((addr, ins))

    # 第二阶段：每条 LiftedInsn 仅在这里 canonicalize 一次。
    canonical_insns: list[CanonicalInsn] = []

    for index, (addr, ins) in enumerate(indexed_lifted):
        canonical_insns.append(
            canonicalize_lifted_instruction(
                ins,
                addr=addr,
                index=index,
            )
        )

    return canonical_insns


def from_lifted(
    lifted_insns: Iterable[Any],
) -> tuple[list[Block], IRSummary]:
    """
    将 lifting 结果转换为 fragment 内 BasicBlock 列表和全局 IRSummary。

    authoritative data flow：

        LiftedInsn
          -> canonicalize_lifted_instructions()
          -> CanonicalInsn
          -> Block.instructions / Block.ops / Block.summary / CFG / IRSummary

    注意：

    - 本函数在 canonicalization 后不得重新读取 LiftedInsn；
    - CFG、Block summary、fragment summary 均只从 CanonicalInsn 派生；
    - Block.ops 只是 CanonicalInsn.ops 的兼容性扁平视图，不是独立来源。

    CFG 规则：

    1. 第一条指令是 leader；
    2. fragment 内 direct target 是 leader；
    3. 任意 terminator 后的下一条指令也是 leader；
    4. successor 仅包含当前 fragment 内地址；
    5. direct external jump/call 不是 unknown target；
    6. indirect jump/call/return 才是 unknown target。
    """
    # 从此处开始，后续逻辑只消费 CanonicalInsn。
    canonical_insns = canonicalize_lifted_instructions(lifted_insns)

    if not canonical_insns:
        return [], IRSummary(
            is_single_block=False,
            has_branch=False,
            has_call_or_return=False,
            has_memory_barrier=False,
            has_atomic=False,
            reads_regs=set(),
            writes_regs=set(),
            reads_mem=False,
            writes_mem=False,
            atomic_orderings=set(),
            atomic_mnemonics=set(),
            barrier_infos=[],
            has_instruction_barrier=False,
            has_unknown_barrier=False,
        )

    addr_set = {ins.addr for ins in canonical_insns}
    leaders: set[int] = {canonical_insns[0].addr}

    # addr -> terminator kind / direct target。
    #
    # 这些数据仅来自 CanonicalInsn。
    term_by_addr: dict[int, Optional[str]] = {}
    direct_target_by_addr: dict[int, Optional[int]] = {}

    # 第一阶段：从 canonical instructions 分析 terminator 和 leader。
    for index, ins in enumerate(canonical_insns):
        addr = ins.addr
        term = ins.terminator_kind
        direct_target = ins.direct_target

        term_by_addr[addr] = term
        direct_target_by_addr[addr] = direct_target

        # fragment 内 direct branch/call target 必须拆 block。
        if direct_target in addr_set:
            leaders.add(direct_target)

        # 所有 terminator 后面必须切 block。
        if term is not None and index + 1 < len(canonical_insns):
            leaders.add(canonical_insns[index + 1].addr)

    # 第二阶段：按 leader 分组，并构造 Block 的 canonical instruction
    # stream 与兼容性扁平 op stream。
    blocks: list[Block] = []
    block_insns: list[list[CanonicalInsn]] = []

    current_block: Optional[Block] = None
    current_group: Optional[list[CanonicalInsn]] = None

    for ins in canonical_insns:
        addr = ins.addr

        if current_block is None or (
            addr in leaders and addr != current_block.addr
        ):
            current_block = Block(addr=addr)
            blocks.append(current_block)

            current_group = []
            block_insns.append(current_group)

        assert current_group is not None

        current_group.append(ins)

        # Block.instructions 是 authoritative instruction-level IR。
        current_block.instructions.append(ins)

        current_block.instr_addrs.append(addr)
        current_block.size += ins.size

        # Block.ops 是兼容性扁平视图，严格从 CanonicalInsn.ops 派生。
        current_block.ops.extend(ins.ops)

    block_by_addr = {block.addr: block for block in blocks}

    # 第三阶段：每个 block 的局部 summary 只从 canonical group 派生。
    for block, group in zip(blocks, block_insns):
        block.summary = _summarize_instructions(
            group,
            is_single_block=True,
        )

    # 第四阶段：建立 CFG edge。
    for index, group in enumerate(block_insns):
        block = blocks[index]
        last_ins = group[-1]
        last_addr = last_ins.addr

        term = term_by_addr.get(last_addr)
        direct_target = direct_target_by_addr.get(last_addr)

        next_addr = (
            blocks[index + 1].addr
            if index + 1 < len(blocks)
            else None
        )

        successors: list[int] = []
        successor_kinds: dict[int, str] = {}

        block.successors = []
        block.successor_kinds = {}
        block.call_targets = []

        block.terminator_kind = (term or "").lower()

        block.has_branch = term in _BRANCH_OPS
        block.is_call_or_return = term in _CALLRET_OPS

        block.is_indirect = term in {
            "BRANCHIND",
            "CALLIND",
            "RETURN",
        }

        # 仅 indirect control flow / return 属于 unknown target。
        #
        # direct external jump/call，以及 unresolved direct symbol，
        # 都不能被错误标为 unknown indirect target。
        block.has_unknown_target = term in {
            "BRANCHIND",
            "CALLIND",
            "RETURN",
        }

        def add_successor(target: Optional[int], kind: str) -> None:
            if target is None or target not in block_by_addr:
                return

            if target not in successors:
                successors.append(target)
                successor_kinds[target] = kind
                return

            old_kind = successor_kinds.get(target, "")

            if old_kind and kind not in old_kind.split("|"):
                successor_kinds[target] = f"{old_kind}|{kind}"

        if term == "CBRANCH":
            # direct taken edge + fallthrough edge。
            add_successor(direct_target, "taken")
            add_successor(next_addr, "fallthrough")

        elif term == "BRANCH":
            # direct jump / tail-call：
            #
            # internal target:
            #   successors=[target]
            #
            # external direct target:
            #   successors=[]
            #   has_unknown_target=False
            add_successor(direct_target, "taken")

        elif term == "CALL":
            # direct call target 不作为 fragment 内 CFG successor。
            #
            # CALL 的 continuation 通过 call_return edge 表示。
            # 即使 direct target 是 fragment 外地址，也不是 unknown target。
            if direct_target is not None:
                block.call_targets = [direct_target]

            add_successor(next_addr, "call_return")

        elif term == "CALLIND":
            # 间接调用 target unknown，但在 fragment 中可能顺序返回。
            add_successor(next_addr, "call_return")

        elif term in {"BRANCHIND", "RETURN"}:
            # 无法静态得出 fragment 内 successor。
            pass

        else:
            # 非 terminator block 的线性 fallthrough。
            add_successor(next_addr, "linear")

        block.successors = _dedup_ints(successors)

        block.successor_kinds = {
            target: successor_kinds[target]
            for target in block.successors
            if target in successor_kinds
        }

    # 第五阶段：fragment summary 仅从 canonical instructions 派生。
    summary = _summarize_instructions(
        canonical_insns,
        is_single_block=(len(blocks) == 1),
    )

    return blocks, summary
