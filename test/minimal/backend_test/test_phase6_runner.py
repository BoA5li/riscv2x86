from __future__ import annotations
import sys
from pathlib import Path
root_path = Path(__file__).parents[3]
sys.path.insert(0, str(root_path))

from typing import Optional

import pytest

from pytools.riscv2x86_py.assemble import assemble
from pytools.riscv2x86_py.cfg import build_cfg_from_blocks
from pytools.riscv2x86_py.ghidra_pythonrun_bridge import (
    GhidraPythonRunError,
    PythonRunRegisterNameResolver,
    load_riscv64_register_resolver_via_pythonrun,
)
from pytools.riscv2x86_py.lift import RegisterNameResolver, lift
from pytools.riscv2x86_py.pcode_ir import from_lifted
from pytools.riscv2x86_py.pipeline import (
    _get_fragment_operand_width_bits,
    run,
)
from pytools.riscv2x86_py.runtime_facts import (
    build_translation_runtime_facts,
)
from pytools.riscv2x86_py.schema import Finding, load_report
from pytools.riscv2x86_py.translate import TranslationOutput, translate

ACTIONABLE_TRANSLATION_KINDS = {
    "x86",
    "x86_inline_asm_att",
    "c",
}

NON_UNSUPPORTED_TRANSLATION_KINDS = {
    *ACTIONABLE_TRANSLATION_KINDS,
    "needs_route",
}

pytestmark = [
    pytest.mark.ghidra,
    pytest.mark.integration,
]

ADD_SUB_REPORT = Path("/root/src/poc_trans/path_b/riscv2x86/test/minimal/output/rv_add_sub_report.json")


@pytest.fixture(scope="session")
def riscv_register_resolver() -> PythonRunRegisterNameResolver:
    """
    通过 Ghidra support/pythonRun 获取权威 RISC-V 寄存器信息。

    注意：
      * 不依赖 pyghidra；
      * 不在 CPython 中直接启动 JVM；
      * 使用当前已可用的 /opt/ghidra_11.2_PUBLIC/support/pythonRun；
      * 返回的 register identity 仍由真实 Ghidra Language 提供。
    """
    try:
        return load_riscv64_register_resolver_via_pythonrun()
    except GhidraPythonRunError as exc:
        pytest.fail(
            "Cannot query Ghidra RISC-V register definitions via "
            "support/pythonRun.\n"
            f"Details:\n{exc}"
        )


def translate_finding_until_phase6(
    finding: Finding,
    *,
    xlen: int = 64,
    register_name_resolver: RegisterNameResolver,
) -> TranslationOutput:
    """
    覆盖：

        JSON -> Finding -> assemble -> runtime facts -> lift
             -> canonical p-code IR -> CFG -> translate

    不覆盖：

        verify()
        输出 JSON 写回
        原始源码修改
        CLI argparse
        source rewrite
    """
    if not finding.enters_asm_pipeline():
        raise ValueError(
            "finding does not contain a valid asm fragment"
        )

    fragment = finding.fragment

    if fragment is None:
        raise ValueError(
            "finding enters asm pipeline but has no fragment"
        )

    operand_width_bits, width_errors = (
        _get_fragment_operand_width_bits(fragment)
    )

    if width_errors:
        raise ValueError(
            "invalid fragment operand width facts: "
            + "; ".join(width_errors)
        )

    ar = assemble(
        fragment,
        xlen=xlen,
        operand_width_bits=operand_width_bits,
    )

    if not ar.ok:
        raise RuntimeError(f"assemble failed: {ar.error}")

    runtime_facts_result = build_translation_runtime_facts(
        finding=finding,
        assemble_result=ar,
    )

    if (
        not runtime_facts_result.ok
        or runtime_facts_result.facts is None
    ):
        raise RuntimeError(
            "runtime facts failed: "
            + (
                runtime_facts_result.error
                or "builder returned no facts"
            )
        )

    runtime_facts = runtime_facts_result.facts

    # 仅修改测试进程内存中的 Finding，不写回 JSON。
    finding.translationRuntimeFacts = runtime_facts

    lr = lift(
        ar.machine_code,
        xlen=xlen,
        relocations=ar.relocations,

        # 当前环境不能传 language=Ghidra Language，
        # 因为 CPython 中没有 pyghidra。
        language=None,

        # 使用 support/pythonRun 从真实 Ghidra 获取的 resolver。
        register_name_resolver=register_name_resolver,

        require_authoritative_register_names=True,
    )

    if not lr.ok:
        raise RuntimeError(f"lift failed: {lr.error}")

    blocks, summary = from_lifted(lr.insns)

    if blocks is None:
        raise RuntimeError(
            "from_lifted returned no canonical blocks"
        )

    cfg = build_cfg_from_blocks(blocks)

    if not cfg.ok:
        raise RuntimeError(f"CFG build failed: {cfg.error}")

    return translate(
        frag=fragment,
        lift=lr,
        summary=summary,
        machine_code=ar.machine_code,
        xlen=xlen,
        blocks=blocks,
        cfg=cfg,
        runtime_facts=runtime_facts,
    )


@pytest.fixture
def add_sub_finding() -> Finding:
    findings = load_report(str(ADD_SUB_REPORT))

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "NeedsAsmTranslation"
    assert finding.fragment is not None
    assert finding.fragment.kind == "InlineExtended"

    return finding


def test_riscv64_register_resolver_can_resolve_registers(
    riscv_register_resolver: PythonRunRegisterNameResolver,
) -> None:
    """
    验证 support/pythonRun -> Ghidra Language -> resolver 链路可用。

    offset 必须使用实际 lift 输出中的 register varnode offset。
    """
    register_name = riscv_register_resolver.register_name_for_varnode(
        space="register",
        offset=0x2050,
        size=8,
    )

    assert register_name is not None
    assert isinstance(register_name, str)
    assert register_name.strip()


def test_rv_add_sub_reaches_phase6(
    add_sub_finding: Finding,
    riscv_register_resolver: PythonRunRegisterNameResolver,
) -> None:
    tr = translate_finding_until_phase6(
        add_sub_finding,
        xlen=64,
        register_name_resolver=riscv_register_resolver,
    )

    assert tr is not None
    assert isinstance(tr.kind, str)
    assert tr.kind != ""
    assert isinstance(tr.notes, list)


def test_rv_add_sub_must_not_be_unsupported(
    add_sub_finding: Finding,
    riscv_register_resolver: PythonRunRegisterNameResolver,
) -> None:
    tr = translate_finding_until_phase6(
        add_sub_finding,
        xlen=64,
        register_name_resolver=riscv_register_resolver,
    )

    assert tr.kind in NON_UNSUPPORTED_TRANSLATION_KINDS, (
        "ADD/SUB RISC-V fragment should be translated or explicitly routed, "
        f"but got kind={tr.kind!r}, notes={tr.notes!r}"
    )

    assert tr.kind != "unsupported"


def test_rv_add_sub_returns_nonempty_actionable_replacement(
    add_sub_finding: Finding,
    riscv_register_resolver: PythonRunRegisterNameResolver,
) -> None:
    tr = translate_finding_until_phase6(
        add_sub_finding,
        xlen=64,
        register_name_resolver=riscv_register_resolver,
    )

    if tr.kind == "needs_route":
        pytest.skip(
            "ADD/SUB semantics were recognized, but no concrete "
            "x86/C lowering has been generated yet."
        )

    assert tr.kind in ACTIONABLE_TRANSLATION_KINDS, (
        "Expected a concrete actionable translation, "
        f"but got kind={tr.kind!r}, notes={tr.notes!r}"
    )

    assert isinstance(tr.replacement, str)
    assert tr.replacement.strip()


def test_dump_rv_add_sub_translation(
    add_sub_finding: Finding,
    riscv_register_resolver: PythonRunRegisterNameResolver,
) -> None:
    tr = translate_finding_until_phase6(
        add_sub_finding,
        xlen=64,
        register_name_resolver=riscv_register_resolver,
    )

    print("\n=== TranslationOutput ===")
    print(f"kind        : {tr.kind!r}")
    print(f"replacement : {tr.replacement!r}")
    print("notes:")

    for note in tr.notes:
        print(f"  - {note}")

    assert tr is not None

def test_rv_add_sub_lowers_to_x86_att_inline_asm(
    add_sub_finding: Finding,
    riscv_register_resolver: PythonRunRegisterNameResolver,
) -> None:
    tr = translate_finding_until_phase6(
        add_sub_finding,
        xlen=64,
        register_name_resolver=riscv_register_resolver,
    )

    assert tr.kind == "x86_inline_asm_att"

    assert tr.buildFamily == "x86_gnu_inline_asm"
    assert tr.preservationRoute == (
        "normalized_pcode_to_x86_att_integer"
    )

    assert isinstance(tr.replacement, str)
    assert "__asm__" in tr.replacement
    assert "__volatile__" in tr.replacement

    assert "addq" in tr.replacement
    assert "subq" in tr.replacement

    assert tr.metadata["requiredArchitecture"] == "x86_64"
    assert tr.metadata["assemblySyntax"] == "att"
    assert tr.metadata["usesVolatileInlineAsm"] is True

def test_rv_add_sub_pipeline_to_writeback_without_verify(
    tmp_path: Path,
    riscv_register_resolver: PythonRunRegisterNameResolver,
) -> None:
    output_json = tmp_path / "rv_add_sub_translated.json"

    stats = run(
        str(ADD_SUB_REPORT),
        str(output_json),
        xlen=64,
        register_name_resolver=riscv_register_resolver,
        verify_enabled=False,
    )

    assert output_json.is_file()
    assert stats["failed"] == 0
    assert stats["unsupported"] == 0
    assert stats["translated_unverified"] == 1

    translated_findings = load_report(str(output_json))

    assert len(translated_findings) == 1

    finding = translated_findings[0]

    assert finding.category == "ReplaceableByRule"
    assert finding.translationKind == "x86_inline_asm_att"

    assert isinstance(finding.suggestedReplacement, str)
    assert finding.suggestedReplacement.strip()

    assert "__asm__" in finding.suggestedReplacement
    assert "addq" in finding.suggestedReplacement
    assert "subq" in finding.suggestedReplacement

    assert finding.verificationStatus == "not_verified"
    assert "verification was explicitly disabled" in (
        finding.verificationDetail
    )