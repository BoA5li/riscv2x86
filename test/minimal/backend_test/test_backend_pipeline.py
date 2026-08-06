from __future__ import annotations

from types import SimpleNamespace
from pytools.riscv2x86_py import pipeline


def ns(**kwargs):
    return SimpleNamespace(**kwargs)


def patch_successful_front_half(monkeypatch, backend_module):
    """
    将 Phase 4、5、IR、CFG 固定为成功结果。

    返回保存各阶段调用参数的 calls 字典。
    """
    calls = {}

    fake_machine_code = bytes.fromhex("3305b5003305b540")

    fake_insns = [
        ns(
            addr=0x1000,
            asm_mnem="add",
            asm_body="a0,a1,a2",
            pcode_ops=[
                "unique[0x100:8] = a1 + a2",
                "a0 = unique[0x100:8]",
            ],
        ),
        ns(
            addr=0x1004,
            asm_mnem="sub",
            asm_body="a0,a0,a2",
            pcode_ops=[
                "unique[0x108:8] = a0 - a2",
                "a0 = unique[0x108:8]",
            ],
        ),
    ]

    fake_lift = ns(
        ok=True,
        error="",
        insns=fake_insns,
    )

    fake_blocks = [
        ns(
            start=0x1000,
            end=0x1008,
            instructions=fake_insns,
        )
    ]

    fake_summary = ns(
        has_branch=False,
        has_call_or_return=False,
        has_memory_barrier=False,
        has_atomic=False,
        reads_regs={"a1", "a2"},
        writes_regs={"a0"},
        reads_mem=False,
        writes_mem=False,
    )

    fake_cfg = ns(
        ok=True,
        nodes={0x1000: ns(successors=[])},
        entry=0x1000,
        error="",
    )

    def fake_assemble(fragment, xlen):
        calls["assemble"] = {
            "fragment": fragment,
            "xlen": xlen,
        }
        return ns(
            ok=True,
            error="",
            machine_code=fake_machine_code,
            relocations=[],
        )

    def fake_lift_fn(machine_code, xlen, relocations):
        calls["lift"] = {
            "machine_code": machine_code,
            "xlen": xlen,
            "relocations": relocations,
        }
        return fake_lift

    def fake_from_lifted(insns):
        calls["from_lifted"] = {
            "insns": insns,
        }
        return fake_blocks, fake_summary

    def fake_build_cfg(blocks):
        calls["build_cfg"] = {
            "blocks": blocks,
        }
        return fake_cfg

    monkeypatch.setattr(backend_module, "assemble", fake_assemble)
    monkeypatch.setattr(backend_module, "lift", fake_lift_fn)
    monkeypatch.setattr(backend_module, "from_lifted", fake_from_lifted)
    monkeypatch.setattr(backend_module, "build_cfg_from_blocks", fake_build_cfg)

    return {
        "calls": calls,
        "machine_code": fake_machine_code,
        "lift": fake_lift,
        "blocks": fake_blocks,
        "summary": fake_summary,
        "cfg": fake_cfg,
    }


def test_json_fragment_reaches_assembler(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
):
    env = patch_successful_front_half(monkeypatch, backend_module)
    output_json = tmp_path / "output.json"

    def fake_translate(**kwargs):
        return ns(
            kind="pure_c",
            replacement="result = a;",
            notes=["test translation"],
        )

    monkeypatch.setattr(backend_module, "translate", fake_translate)

    # 暂时绕过 Phase 8，不测试正式 verify。
    monkeypatch.setattr(
        backend_module,
        "verify",
        lambda fragment, lift, summary, translation: ns(
            status="verified",
            detail="test-only verification stub",
        ),
    )

    stats = backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    call = env["calls"]["assemble"]
    fragment = call["fragment"]

    assert call["xlen"] == 64
    assert fragment.rawAsmText == "add %0, %1, %2\n\tsub %0, %0, %2"
    assert fragment.enclosingFunction == "rv_add_sub"

    assert stats["total"] == 1
    assert output_json.exists()


def test_translate_receives_authoritative_inputs(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
):
    """
    检测 run() 是否将正确对象传入 translate()。

    该测试会检测：
        frag=fragment          错误
        machine_code=machine_code  错误

    正确形式应为：
        frag=f.fragment
        machine_code=ar.machine_code
    """
    env = patch_successful_front_half(monkeypatch, backend_module)
    output_json = tmp_path / "output.json"
    captured = {}

    def fake_translate(**kwargs):
        captured.update(kwargs)
        return ns(
            kind="pure_c",
            replacement="result = a;",
            notes=["translated by test strategy"],
        )

    monkeypatch.setattr(backend_module, "translate", fake_translate)

    monkeypatch.setattr(
        backend_module,
        "verify",
        lambda fragment, lift, summary, translation: ns(
            status="verified",
            detail="verify intentionally bypassed",
        ),
    )

    backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    assert captured["frag"] is env["calls"]["assemble"]["fragment"]
    assert captured["lift"] is env["lift"]
    assert captured["summary"] is env["summary"]
    assert captured["machine_code"] == env["machine_code"]
    assert captured["xlen"] == 64
    assert captured["blocks"] is env["blocks"]
    assert captured["cfg"] is env["cfg"]


def test_pcode_and_machine_code_are_written_to_output(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
    load_output_findings,
):
    env = patch_successful_front_half(monkeypatch, backend_module)
    output_json = tmp_path / "output.json"

    monkeypatch.setattr(
        backend_module,
        "translate",
        lambda **kwargs: ns(
            kind="pure_c",
            replacement="result = a;",
            notes=["pure C lowering selected"],
        ),
    )

    monkeypatch.setattr(
        backend_module,
        "verify",
        lambda *args, **kwargs: ns(
            status="verified",
            detail="test stub",
        ),
    )

    backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    findings = load_output_findings(output_json)
    assert len(findings) == 1

    finding = findings[0]

    assert finding["machineCodeHex"] == env["machine_code"].hex()
    assert "add" in finding["pcodeText"]
    assert "sub" in finding["pcodeText"]
    assert "a1 + a2" in finding["pcodeText"]
    assert "a0 - a2" in finding["pcodeText"]


def test_actionable_translation_is_recorded(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
    load_output_findings,
):
    patch_successful_front_half(monkeypatch, backend_module)
    output_json = tmp_path / "output.json"

    monkeypatch.setattr(
        backend_module,
        "translate",
        lambda **kwargs: ns(
            kind="pure_c",
            replacement="result = a;",
            notes=["lowered add/sub sequence to C"],
        ),
    )

    monkeypatch.setattr(
        backend_module,
        "verify",
        lambda *args, **kwargs: ns(
            status="verified",
            detail="verify bypassed by test",
        ),
    )

    stats = backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    finding = load_output_findings(output_json)[0]

    assert finding["category"] == "ReplaceableByRule"
    assert finding["ruleName"] == "phase6.lower_to_c"
    assert finding["suggestedReplacement"].strip() == "result = a;"
    assert finding["translationKind"] == "pure_c"
    assert finding["verificationStatus"] == "verified"

    assert stats["total"] == 1
    assert stats["verified"] == 1
    assert stats["failed"] == 0
    assert stats["unsupported"] == 0


def test_empty_actionable_replacement_is_rejected(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
    load_output_findings,
):
    patch_successful_front_half(monkeypatch, backend_module)
    output_json = tmp_path / "output.json"

    verify_called = False

    def fake_verify(*args, **kwargs):
        nonlocal verify_called
        verify_called = True
        return ns(status="verified", detail="must not be called")

    monkeypatch.setattr(
        backend_module,
        "translate",
        lambda **kwargs: ns(
            kind="pure_c",
            replacement="   ",
            notes=[],
        ),
    )
    monkeypatch.setattr(backend_module, "verify", fake_verify)

    stats = backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    finding = load_output_findings(output_json)[0]

    assert finding["category"] == "NeedsAsmTranslation"
    assert finding["ruleName"] == ""
    assert finding["suggestedReplacement"] == ""
    assert finding["verificationStatus"] == "failed"
    assert "empty replacement" in finding["verificationDetail"]

    assert stats["failed"] == 1
    assert verify_called is False


def test_unsupported_translation_does_not_enter_verify(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
    load_output_findings,
):
    patch_successful_front_half(monkeypatch, backend_module)
    output_json = tmp_path / "output.json"

    verify_called = False

    def fake_verify(*args, **kwargs):
        nonlocal verify_called
        verify_called = True
        raise AssertionError("verify must not be called for unsupported output")

    monkeypatch.setattr(
        backend_module,
        "translate",
        lambda **kwargs: ns(
            kind="unsupported",
            replacement="",
            notes=["no proven strategy matched"],
        ),
    )
    monkeypatch.setattr(backend_module, "verify", fake_verify)

    stats = backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    finding = load_output_findings(output_json)[0]

    assert finding["category"] == "Unsupported"
    assert finding["ruleName"] == "phase6.unsupported"
    assert finding["suggestedReplacement"] == ""
    assert finding["verificationStatus"] == "unsupported"

    assert stats["unsupported"] == 1
    assert verify_called is False


def test_assemble_failure_stops_pipeline(
    monkeypatch,
    backend_module,
    copied_input_json,
    tmp_path,
    load_output_findings,
):
    output_json = tmp_path / "output.json"

    monkeypatch.setattr(
        backend_module,
        "assemble",
        lambda fragment, xlen: ns(
            ok=False,
            error="synthetic assembler failure",
            machine_code=b"",
            relocations=[],
        ),
    )

    def must_not_run(*args, **kwargs):
        raise AssertionError("later pipeline stage must not run")

    monkeypatch.setattr(backend_module, "lift", must_not_run)
    monkeypatch.setattr(backend_module, "translate", must_not_run)
    monkeypatch.setattr(backend_module, "verify", must_not_run)

    stats = backend_module.run(
        str(copied_input_json),
        str(output_json),
        xlen=64,
    )

    finding = load_output_findings(output_json)[0]

    assert finding["verificationStatus"] == "failed"
    assert "synthetic assembler failure" in finding["verificationDetail"]
    assert stats["failed"] == 1