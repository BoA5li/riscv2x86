from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, List, Optional, Protocol, Tuple

import pypcode

from .csr_metadata_ingress import CsrDecoderProfile, decode_csr_privileged_operations


if TYPE_CHECKING:
    from .pcode_ir import IRSummary


class RegisterNameResolver(Protocol):
    """
    lifting adapter 使用的 authoritative register-name resolver。

    resolver 必须来自当前架构 / language backend 的权威寄存器数据库，
    例如：

    - Ghidra Language.getRegister(...)
    - translator.getRegister(...)
    - 已加载 language specification 中的 register database
    - 测试 fake language 中明确声明的 register table

    禁止在 pcode_ir.py、x86 lowerer 或 lift.py 中根据 register offset /
    size 猜测 ABI register name。

    例如，以下行为禁止出现在 canonicalization 或 lowering 层：

        0x2050 -> a0
        0x2058 -> a1
        0x2060 -> a2
    """

    def register_name_for_varnode(
        self,
        *,
        space: str,
        offset: int,
        size: int,
    ) -> Optional[str]:
        """
        返回 authoritative register name。

        无法解析时必须返回 None，而不是猜测名称。
        """
        ...


@dataclass(frozen=True)
class AdaptedVarnode:
    """
    pypcode raw varnode 的结构化 adapter。

    pcode_ir.py 应消费此对象，而不是直接依赖 pypcode varnode 的具体实现。

    name 规则：

    - backend raw varnode 已显式暴露 name 时可保留；
    - 否则仅允许通过 RegisterNameResolver / language resolver 查询；
    - 查询失败时保持空字符串；
    - 不允许根据 offset / size 推断 ABI register name。
    """

    raw: Any
    space: str
    offset: int
    size: int
    name: str = ""

class AuthoritativeRegisterNameUnavailableError(ValueError):
    """
    register varnode 没有可用的 authoritative register name。

    这是安全边界错误，不允许 canonical IR / lowerer 根据 offset、
    xN 编号或 p-code 操作数顺序猜测 ABI register identity。
    """
    pass

@dataclass(frozen=True)
class AdaptedPcodeOp:
    """
    pypcode raw PcodeOp 的结构化 adapter。

    pcode_ir.canonicalize_lifted_instruction() 应只读取：

    - opcode
    - inputs
    - output

    raw 仅用于调试；canonical IR 不应依赖 raw 的字符串表现形式。
    """

    raw: Any
    opcode: Any
    inputs: List[AdaptedVarnode]
    output: Optional[AdaptedVarnode]


@dataclass
class LiftedInsn:
    """
    一条已经完成 p-code lifting 的机器指令。

    addr 必须始终是绝对机器码地址：

        addr == base_addr + instruction_offset

    注意：

    - summary 是可选的单条指令粒度 IR 分析摘要；
    - lift() 本身只负责生成结构化 raw_ops；
    - summary 应由 canonicalization / IR analysis 层在 raw_ops 已被
      转换为 canonical IR 后生成；
    - Block.summary 是 BasicBlock 局部摘要；
    - pcode_ops 仅用于诊断、展示和 Finding.pcodeText；
    - raw_ops 是结构化、authoritative adapter 后的 p-code op，
      应由 pcode_ir.canonicalize_lifted_instruction() 消费。
    """

    addr: int
    length: int
    asm_mnem: str
    asm_body: str
    pcode_ops: List[str]

    # 保存 AdaptedPcodeOp，而不是原始 pypcode PcodeOp。
    raw_ops: List[AdaptedPcodeOp] = field(default_factory=list)

    # Phase-4 decoder/catalog ingress; Phase 5+ consumes this typed fact only.
    privileged_operations: tuple[Any, ...] = ()

    sym_ref: Optional[Tuple[int, str]] = None
    summary: Optional["IRSummary"] = None

    @property
    def address(self) -> int:
        """兼容使用 address 命名的调用方。"""
        return self.addr

    @property
    def pc(self) -> int:
        """兼容使用 pc 命名的调用方。"""
        return self.addr

    @property
    def size(self) -> int:
        """兼容使用 size 命名的调用方。"""
        return self.length


@dataclass
class LiftResult:
    ok: bool
    insns: List[LiftedInsn]
    error: str = ""
    language_id: str = ""

    # 供 pipeline 进行稳定分流，避免依赖 error 文本匹配。
    #
    # 例如：
    #   ""
    #   "register_name_unavailable"
    #   "pcode_adaptation_failed"
    #   "translate_failed"
    error_code: str = ""


@dataclass
class GhidraLanguageRegisterResolver:
    """
    基于真实 Ghidra Language 的 authoritative register-name resolver。

    真实 Ghidra API 常见调用链为：

        language
            -> language.getAddressFactory()
            -> address_factory.getAddressSpace("register")
            -> register_space.getAddress(offset)
            -> language.getRegister(address, size)

    即 Ghidra Language.getRegister(...) 通常接收 Address，而不是
    Python int offset。

    同时兼容项目中可能存在的 adapter：

        language.get_register(offset, size)
        language.getRegister(offset, size)
        language.getRegister(address, size)

    所有查询均为 authoritative backend lookup；不包含任何根据
    offset / size 推断 xN、aN、sp、ra 等名称的逻辑。
    """

    language: Any

    @staticmethod
    def _normalise_register_name(value: Any) -> Optional[str]:
        """从 Ghidra Register / adapter 返回值中读取非空名称。"""
        if isinstance(value, str):
            text = value.strip()
            return text or None

        if value is None:
            return None

        name = getattr(value, "name", None)

        if isinstance(name, str):
            text = name.strip()
            if text:
                return text

        get_name = getattr(value, "getName", None)

        if callable(get_name):
            try:
                resolved = get_name()
            except Exception:
                return None

            if isinstance(resolved, str):
                text = resolved.strip()
                if text:
                    return text

        return None

    @staticmethod
    def _get_callable(obj: Any, *names: str) -> Optional[Any]:
        """返回对象上第一个可调用属性。"""
        for name in names:
            method = getattr(obj, name, None)
            if callable(method):
                return method

        return None

    def _register_address_for_offset(self, offset: int):
        get_address_factory = self._get_callable(
            self.language,
            "getAddressFactory",
            "get_address_factory",
        )

        if get_address_factory is None:
            return None

        try:
            address_factory = get_address_factory()
        except Exception:
            return None

        if address_factory is None:
            return None

        register_space = None

        # 真实 Ghidra API 的优先路径。
        get_register_space = self._get_callable(
            address_factory,
            "getRegisterSpace",
            "get_register_space",
        )

        if get_register_space is not None:
            try:
                register_space = get_register_space()
            except Exception:
                register_space = None

        # 为测试 adapter / 旧实现保留 fallback。
        if register_space is None:
            get_address_space = self._get_callable(
                address_factory,
                "getAddressSpace",
                "get_address_space",
            )

            if get_address_space is None:
                return None

            try:
                register_space = get_address_space("register")
            except Exception:
                return None

        if register_space is None:
            return None

        get_address = self._get_callable(
            register_space,
            "getAddress",
            "get_address",
        )

        if get_address is None:
            return None

        try:
            return get_address(offset)
        except Exception:
            return None
    def _lookup_via_ghidra_address(
            self,
            *,
            offset: int,
            size: int,
        ) -> Optional[str]:
            """
            使用真实 Ghidra Language.getRegister(Address, size) 查询。

            这是生产环境优先路径。
            """
            address = self._register_address_for_offset(offset)

            if address is None:
                return None

            get_register = self._get_callable(
                self.language,
                "getRegister",
                "get_register",
            )

            if get_register is None:
                return None

            try:
                register = get_register(address, size)
            except Exception:
                return None

            return self._normalise_register_name(register)

    def _lookup_via_adapter_offset(
        self,
        *,
        offset: int,
        size: int,
    ) -> Optional[str]:
        """
        兼容非 Java Ghidra adapter。

        某些项目 wrapper 可能提供：

            get_register(offset, size)

        或：

            getRegister(offset, size)

        该分支仅作为 adapter compatibility fallback。

        对真实 Ghidra Language，应优先走：

            getRegister(Address, size)
        """
        get_register = self._get_callable(
            self.language,
            "get_register",
        )

        if get_register is not None:
            try:
                register = get_register(offset, size)
            except Exception:
                register = None

            name = self._normalise_register_name(register)

            if name:
                return name

        # 某些非 Java wrapper 使用 camelCase，但接受 int offset。
        #
        # 对真实 Ghidra Language，此调用通常会失败；失败后安全返回 None。
        get_register = self._get_callable(
            self.language,
            "getRegister",
        )

        if get_register is None:
            return None

        try:
            register = get_register(offset, size)
        except Exception:
            return None

        return self._normalise_register_name(register)

    def register_name_for_varnode(
        self,
        *,
        space: str,
        offset: int,
        size: int,
    ) -> Optional[str]:
        """
        返回 authoritative register name。

        对真实 Ghidra Language：

            register offset
              -> register AddressSpace
              -> Address
              -> Language.getRegister(Address, size)
              -> Register.getName()

        查询失败必须返回 None，不允许根据 offset 推断 x10 / a0 等名称。
        """
        if not isinstance(space, str):
            return None

        if space.strip().lower() != "register":
            return None

        if isinstance(offset, bool) or not isinstance(offset, int):
            return None

        if isinstance(size, bool) or not isinstance(size, int):
            return None

        if offset < 0 or size <= 0:
            return None

        # 真实 Ghidra Language 的 authoritative 正确路径。
        resolved = self._lookup_via_ghidra_address(
            offset=offset,
            size=size,
        )

        if resolved:
            return resolved

        # adapter compatibility fallback；仍然是明确 API lookup，
        # 不包含 offset-to-register-name 猜测。
        return self._lookup_via_adapter_offset(
            offset=offset,
            size=size,
        )

def _lang_id(xlen: int) -> str:
    if isinstance(xlen, bool) or not isinstance(xlen, int):
        raise ValueError(f"unsupported xlen: {xlen!r}")

    if xlen == 32:
        return "RISCV:LE:32:default"

    if xlen == 64:
        return "RISCV:LE:64:default"

    raise ValueError(f"unsupported xlen: {xlen}")


def _format_pcode_op(op: Any) -> str:
    """
    将 pypcode 的 PcodeOp 格式化为可读文本。

    该函数只用于 diagnostics / Finding.pcodeText / 测试展示。

    绝不能让 pcode_ir 或 lowerer 通过该文本重新解析操作数、
    register offset 或 register name。
    """
    try:
        return str(op)
    except Exception:
        opcode = getattr(op, "opcode", None)

        opcode_name = getattr(opcode, "name", None)
        if opcode_name:
            return str(opcode_name)

        if opcode is not None:
            return str(opcode)

        return repr(op)


def _raw_varnode_space_name(raw_varnode: Any) -> str:
    """
    从 backend 暴露的结构化属性中取得 address-space 名称。

    不解析 str(raw_varnode)、repr(raw_varnode) 或 p-code 文本。
    """
    for attr in ("space", "space_name", "address_space"):
        value = getattr(raw_varnode, attr, None)

        if value is None:
            continue

        if isinstance(value, str):
            text = value.strip()
            if text:
                return text

        nested_name = getattr(value, "name", None)

        if isinstance(nested_name, str):
            text = nested_name.strip()
            if text:
                return text

    return ""


def _raw_varnode_int(raw_varnode: Any, attr: str) -> int:
    """
    严格读取 raw varnode 的整数 offset / size 字段。

    不接受：

    - None；
    - bool；
    - str；
    - float；
    - 能被 int(...) 截断或转换的任意对象。

    不能把非法字段静默转换为 0，因为这样可能将 malformed varnode
    误解释为某个合法的 offset=0 寄存器或 constant。
    """
    value = getattr(raw_varnode, attr, None)

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"raw varnode has invalid {attr}: {value!r}; "
            "expected a Python int"
        )

    return value


def _normalise_register_name(value: Any) -> str:
    """只接受非空字符串作为 authoritative register name。"""
    if not isinstance(value, str):
        return ""

    return value.strip()


def _call_register_name_resolver(
    resolver: Any,
    *,
    space: str,
    offset: int,
    size: int,
) -> Optional[str]:
    """
    调用明确提供的 authoritative resolver。

    支持两种显式 resolver 接口：

    1. register_name_for_varnode(...)
    2. register_name_for(...)

    第二种接口用于兼容项目已有 language adapter 或测试 fake language：

        class FakeLanguage:
            def register_name_for(self, *, space, offset, size):
                ...

    这里仅调用调用方显式提供的 resolver 方法；不包含任何 offset-to-ABI
    register 猜测逻辑。
    """
    if resolver is None:
        return None

    method = getattr(resolver, "register_name_for_varnode", None)

    if not callable(method):
        method = getattr(resolver, "register_name_for", None)

    if not callable(method):
        return None

    try:
        resolved = method(
            space=space,
            offset=offset,
            size=size,
        )
    except Exception:
        return None

    name = _normalise_register_name(resolved)
    return name or None


def _select_register_name_resolver(
    *,
    register_name_resolver: Optional[RegisterNameResolver],
    language: Any,
) -> Optional[Any]:
    """
    统一处理显式 resolver 与 language 参数。

    language 参数是一种便利写法：

        adapt_varnode(raw, language=my_language)
        lift(..., language=my_language)

    选择规则：

    1. 显式传入 register_name_resolver 时直接使用；
    2. language 自身实现 register_name_for_varnode(...) 或
       register_name_for(...) 时，将 language 直接作为 resolver；
    3. 否则使用 GhidraLanguageRegisterResolver(language)，通过
       authoritative Ghidra API 查询：

           language.getAddressFactory()
               .getAddressSpace("register")
               .getAddress(offset)

           language.getRegister(address, size)

    不允许同时传入 register_name_resolver 和 language，因为两者的优先级
    模糊可能导致测试与生产环境行为不一致。

    本函数及其 resolver 不允许根据 register offset / size 猜测 RISC-V
    ABI register name。
    """
    if register_name_resolver is not None and language is not None:
        raise ValueError(
            "pass either register_name_resolver or language, not both"
        )

    if register_name_resolver is not None:
        return register_name_resolver

    if language is None:
        return None

    if callable(getattr(language, "register_name_for_varnode", None)):
        return language

    if callable(getattr(language, "register_name_for", None)):
        return language

    return GhidraLanguageRegisterResolver(language=language)

def adapt_raw_varnode(
    raw_varnode: Any,
    *,
    register_name_resolver: Optional[RegisterNameResolver] = None,
) -> AdaptedVarnode:
    """
    将 pypcode raw varnode 转换为结构化 AdaptedVarnode。

    register name 的优先级：

    1. backend 已在 raw_varnode.name 中明确提供的名称；
    2. 外部注入的 authoritative RegisterNameResolver；
    3. 保持 name == ""，由后续 lowerer fail-closed。

    该函数不包含、不调用、不间接依赖任何 RISC-V offset-to-name 猜测表。

    对 malformed raw varnode，函数抛出 ValueError。lift() 会将其转换为
    LiftResult(ok=False, ...)；不会静默使用 offset=0 或 size=0 继续。
    """
    if raw_varnode is None:
        raise ValueError("cannot adapt None raw varnode")

    space = _raw_varnode_space_name(raw_varnode)
    offset = _raw_varnode_int(raw_varnode, "offset")
    size = _raw_varnode_int(raw_varnode, "size")

    if offset < 0:
        raise ValueError(
            f"raw varnode has negative offset: {offset}"
        )

    if size <= 0:
        raise ValueError(
            f"raw varnode has non-positive size: {size}"
        )

    raw_name = getattr(raw_varnode, "name", "")
    name = _normalise_register_name(raw_name)

    if (
        not name
        and space.strip().lower() == "register"
        and register_name_resolver is not None
    ):
        resolved = _call_register_name_resolver(
            register_name_resolver,
            space=space,
            offset=offset,
            size=size,
        )

        if resolved:
            name = resolved

    return AdaptedVarnode(
        raw=raw_varnode,
        space=space,
        offset=offset,
        size=size,
        name=name,
    )


def adapt_varnode(
    raw_varnode: Any,
    *,
    language: Any = None,
    register_name_resolver: Optional[RegisterNameResolver] = None,
) -> AdaptedVarnode:
    """
    adapt_raw_varnode() 的公共便利包装。

    支持以下两种安全调用方式：

        adapt_varnode(raw, register_name_resolver=resolver)

    或：

        adapt_varnode(raw, language=language)

    language 必须是 authoritative backend language / translator / register
    database，或者是显式提供 register_name_for(...) 的测试 fake language。
    """
    resolver = _select_register_name_resolver(
        register_name_resolver=register_name_resolver,
        language=language,
    )

    return adapt_raw_varnode(
        raw_varnode,
        register_name_resolver=resolver,
    )


def adapt_raw_pcode_op(
    raw_op: Any,
    *,
    register_name_resolver: Optional[RegisterNameResolver] = None,
) -> AdaptedPcodeOp:
    """
    将 pypcode raw PcodeOp 转换为结构化 AdaptedPcodeOp。

    pcode_ir 层后续只能消费 adapter 后的 opcode / inputs / output，
    不应重新检查 raw_op 的字符串表示。
    """
    if raw_op is None:
        raise ValueError("cannot adapt None raw p-code op")

    raw_inputs = getattr(raw_op, "inputs", None)

    if raw_inputs is None:
        raw_input_list: List[Any] = []
    else:
        try:
            raw_input_list = list(raw_inputs)
        except TypeError as e:
            raise ValueError(
                "raw p-code op inputs are not iterable"
            ) from e

    inputs = [
        adapt_raw_varnode(
            raw_varnode,
            register_name_resolver=register_name_resolver,
        )
        for raw_varnode in raw_input_list
    ]

    raw_output = getattr(raw_op, "output", None)

    output = (
        adapt_raw_varnode(
            raw_output,
            register_name_resolver=register_name_resolver,
        )
        if raw_output is not None
        else None
    )

    return AdaptedPcodeOp(
        raw=raw_op,
        opcode=getattr(raw_op, "opcode", None),
        inputs=inputs,
        output=output,
    )


def adapt_pcode_op(
    raw_op: Any,
    *,
    language: Any = None,
    register_name_resolver: Optional[RegisterNameResolver] = None,
) -> AdaptedPcodeOp:
    """
    adapt_raw_pcode_op() 的公共便利包装。

    与 adapt_varnode() 一样，支持 language=... 或
    register_name_resolver=...，但不允许同时传入。
    """
    resolver = _select_register_name_resolver(
        register_name_resolver=register_name_resolver,
        language=language,
    )

    return adapt_raw_pcode_op(
        raw_op,
        register_name_resolver=resolver,
    )

def _is_register_space(space: str) -> bool:
    return isinstance(space, str) and space.strip().lower() == "register"


def _require_authoritative_register_names(
    adapted_ops: Iterable[AdaptedPcodeOp],
    *,
    insn_addr: int,
) -> None:
    """
    校验一条机器指令中所有 register varnode 都拥有 authoritative name。

    注意：
    - 不根据 offset / size 生成名称；
    - 不根据 xN / ABI 表生成名称；
    - 不解析 str(raw varnode) 或 str(pcode op)；
    - 仅接受 AdaptedVarnode.name 中已经由 backend 或 resolver 给出的名字。
    """
    for op_index, op in enumerate(adapted_ops):
        varnodes: List[Tuple[str, AdaptedVarnode]] = [
            (f"input[{input_index}]", varnode)
            for input_index, varnode in enumerate(op.inputs)
        ]

        if op.output is not None:
            varnodes.append(("output", op.output))

        for role, varnode in varnodes:
            if not _is_register_space(varnode.space):
                continue

            if varnode.name.strip():
                continue

            opcode = getattr(op.opcode, "name", None)
            if not opcode:
                opcode = str(op.opcode)

            raise AuthoritativeRegisterNameUnavailableError(
                "authoritative register name unavailable for "
                f"register varnode at addr={hex(insn_addr)}, "
                f"op_index={op_index}, opcode={opcode!r}, "
                f"role={role}, offset={hex(varnode.offset)}, "
                f"size={varnode.size}. "
                "Provide register_name_resolver=... or language=... backed "
                "by the authoritative language/register database."
            )

def check_module(name: str):
    try:
        mod = __import__(name)
        ver = getattr(mod, "__version__", None)
        return True, ver
    except Exception as e:
        return False, str(e)


def _validate_base_addr(base_addr: int) -> None:
    """
    验证 absolute machine-code base address。

    CFG / canonical IR 的地址契约要求所有 LiftedInsn.addr 都是唯一、
    非负的绝对机器码地址，因此 base_addr 不可为 bool、字符串、浮点数或负数。
    """
    if isinstance(base_addr, bool) or not isinstance(base_addr, int):
        raise ValueError(
            f"base_addr must be a non-negative Python int, got {base_addr!r}"
        )

    if base_addr < 0:
        raise ValueError(
            f"base_addr must be non-negative, got {base_addr}"
        )


def _iter_relocations(relocations: Optional[list]) -> Iterable[Any]:
    """统一处理可选 relocation 列表。"""
    if relocations is None:
        return []

    return relocations


def lift(
    machine_code: bytes,
    xlen: int = 64,
    base_addr: int = 0x10000,
    relocations: Optional[list] = None,
    strict_disassembly: bool = False,
    register_name_resolver: Optional[RegisterNameResolver] = None,
    language: Any = None,
    csr_decoder_profile: Optional[CsrDecoderProfile] = None,

    # pipeline / canonical IR 入口必须启用。
    #
    # 保留 False 是为了允许纯诊断场景继续展示 p-code；
    # 但任何将结果送入 canonical IR、CFG、translate、lower 的调用
    # 必须传 True。
    require_authoritative_register_names: bool = False,
) -> LiftResult:
    """
    将 machine_code lift 成 LiftedInsn。

    地址契约：

        每条 LiftedInsn.addr 都是绝对机器码地址：

            insn.addr == base_addr + instruction_offset

    raw p-code 契约：

        LiftedInsn.raw_ops 保存 AdaptedPcodeOp，而不是直接保存
        pypcode PcodeOp。适配层负责保留 backend 已知的 register name，
        或通过显式注入的 authoritative resolver 填充
        AdaptedVarnode.name。

    register_name_resolver：

        可选的 authoritative register resolver。

        未传入 resolver 时，lift 仍然可以生成 canonicalizable p-code；
        但没有 backend 直接给出 name 的 register varnode 会保持
        name == ""。

        下游 lowerer 必须对 unnamed register identity fail-closed，
        不能自行根据 offset 猜测 a0/a1/a2 等 ABI register name。

    language：

        register_name_resolver 的便利替代参数。可传入：

        - 实现 register_name_for_varnode(...) 的 language；
        - 实现 register_name_for(...) 的 language；
        - 可被 GhidraLanguageRegisterResolver 使用的 language /
          translator 对象。

        不允许同时传入 language 和 register_name_resolver。

    说明：

    - 指令长度以 ctx.disassemble(...).instructions[0].length 为准；
    - ctx.translate(...).length 在某些 pypcode 环境中可能始终为 0；
      不得以该值作为 translate 失败或指令长度的唯一依据；
    - ctx.translate(...).ops 才是 p-code 是否实际产生结果的依据；
    - relocation 在全部指令 lift 完成后绑定到所属 LiftedInsn；
    - LiftedInsn.summary 由后续 canonicalization / analysis 层生成。
    """
    if not machine_code:
        return LiftResult(False, [], "empty machine code")

    try:
        _validate_base_addr(base_addr)

        resolver = _select_register_name_resolver(
            register_name_resolver=register_name_resolver,
            language=language,
        )

        lang_id = _lang_id(xlen)
        ctx = pypcode.Context(lang_id)
    except Exception as e:
        return LiftResult(False, [], f"pypcode context failed: {e}")

    insns: List[LiftedInsn] = []
    offset = 0

    while offset < len(machine_code):
        # cur_addr 始终是绝对机器码地址，不得使用 fragment-relative offset。
        cur_addr = base_addr + offset

        try:
            tx = ctx.translate(
                machine_code[offset:],
                base_address=cur_addr,
                max_instructions=1,
            )
        except Exception as e:
            return LiftResult(
                False,
                insns,
                f"translate failed at off={offset} addr={hex(cur_addr)}: {e}",
                language_id=lang_id,
            )

        raw_tx_ops = getattr(tx, "ops", None)

        # p-code 为空才是真正的 translate/lift 失败。
        if not raw_tx_ops:
            return LiftResult(
                False,
                insns,
                f"translate produced no p-code ops at off={offset} "
                f"(addr={hex(cur_addr)})",
                language_id=lang_id,
            )

        # tx.length == 0 在某些 pypcode 版本中是正常现象。
        tx_length_raw = getattr(tx, "length", None)

        if (
            tx_length_raw is None
            or isinstance(tx_length_raw, bool)
            or not isinstance(tx_length_raw, int)
        ):
            tx_length = None
        else:
            tx_length = tx_length_raw

        try:
            dx = ctx.disassemble(
                machine_code[offset:],
                base_address=cur_addr,
                max_instructions=1,
            )

            decoded = getattr(dx, "instructions", None)

            if not decoded:
                raise RuntimeError("disassemble returned no instruction")

            decoded_insn = decoded[0]
            mnem = str(getattr(decoded_insn, "mnem", ""))
            body = str(getattr(decoded_insn, "body", ""))

            raw_length = getattr(decoded_insn, "length", None)

            if isinstance(raw_length, bool) or not isinstance(raw_length, int):
                raise RuntimeError(
                    f"disassemble returned invalid instruction length {raw_length!r}"
                )

            length = raw_length

            if length <= 0:
                raise RuntimeError(
                    f"disassemble returned non-positive length {length}"
                )

            # tx.length 仅在其为正数时参加交叉校验。
            if tx_length is not None and tx_length > 0 and length != tx_length:
                raise RuntimeError(
                    "translate/disassemble length mismatch: "
                    f"translate={tx_length}, disassemble={length}"
                )

        except Exception as e:
            mode = "strict" if strict_disassembly else "non-strict"

            return LiftResult(
                False,
                insns,
                f"cannot determine instruction length at off={offset} "
                f"(addr={hex(cur_addr)}, mode={mode}): {e}",
                language_id=lang_id,
            )

        if offset + length > len(machine_code):
            return LiftResult(
                False,
                insns,
                "decoded instruction length exceeds machine-code buffer: "
                f"off={offset}, len={length}, total={len(machine_code)}",
                language_id=lang_id,
            )

        # pcode_ops 仅用于 diagnostics / Finding.pcodeText。
        text_ops = [_format_pcode_op(op) for op in raw_tx_ops]

        # raw_ops 是 canonical IR 唯一应消费的结构化 p-code 输入。
        #
        # 这里明确不保存 list(tx.ops)，而是保存 adapter 后对象。
        try:
            adapted_ops = [
                adapt_raw_pcode_op(
                    raw_op,
                    register_name_resolver=resolver,
                )
                for raw_op in raw_tx_ops
            ]

            if require_authoritative_register_names:
                _require_authoritative_register_names(
                    adapted_ops,
                    insn_addr=cur_addr,
                )

        except AuthoritativeRegisterNameUnavailableError as e:
            return LiftResult(
                False,
                insns,
                f"p-code register identity adaptation failed at "
                f"off={offset} addr={hex(cur_addr)}: {e}",
                language_id=lang_id,
                error_code="register_name_unavailable",
            )

        except Exception as e:
            return LiftResult(
                False,
                insns,
                f"p-code adaptation failed at off={offset} "
                f"(addr={hex(cur_addr)}): {e}",
                language_id=lang_id,
                error_code="pcode_adaptation_failed",
            )

        privileged_operations = decode_csr_privileged_operations(
            addr=cur_addr,
            decoder_mnemonic=mnem,
            decoder_operands=body,
            xlen_bits=xlen,
            profile=csr_decoder_profile,
        )

        insns.append(
            LiftedInsn(
                addr=cur_addr,
                length=length,
                asm_mnem=mnem,
                asm_body=body,
                pcode_ops=text_ops,
                raw_ops=adapted_ops,
                privileged_operations=privileged_operations,
                sym_ref=None,
                summary=None,
            )
        )

        # 只使用 disassemble 给出的真实长度推进。
        # compressed instruction 会自然按 2 字节推进。
        offset += length

    #
    # 将 relocation 挂到其 section-relative offset 所属的指令。
    #
    for rel in _iter_relocations(relocations):
        rel_off = getattr(rel, "offset", None)
        sym_index = getattr(rel, "sym_index", None)
        kind = getattr(rel, "kind", None)

        if (
            isinstance(rel_off, bool)
            or not isinstance(rel_off, int)
            or isinstance(sym_index, bool)
            or not isinstance(sym_index, int)
            or kind is None
        ):
            continue

        if rel_off < 0:
            continue

        kind_text = str(kind).strip()

        if not kind_text:
            continue

        target_abs = base_addr + rel_off

        for insn in insns:
            if insn.addr <= target_abs < insn.addr + insn.length:
                if insn.sym_ref is None:
                    insn.sym_ref = (sym_index, kind_text)
                break

    return LiftResult(
        True,
        insns,
        language_id=lang_id,
    )