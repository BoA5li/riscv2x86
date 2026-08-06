import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import sys
from pathlib import Path

import pytest

# 请把 yourpkg 改成你的真实包名，例如：
# from translator.pipeline import run
# import translator.pipeline as pipeline_mod

root_path = Path(__file__).parent.parent
sys.path.insert(0, str(root_path))

from pytools.riscv2x86_py.pipeline import run
import pytools.riscv2x86_py.pipeline as pipeline_mod


@dataclass
class DummyAsmResult:
    ok: bool = True
    machine_code: bytes = b"\x13\x00\x00\x00"
    insn_listing: list = None
    error: str = ""

    def __post_init__(self):
        if self.insn_listing is None:
            self.insn_listing = [(0, self.machine_code, "addi x0, x0, 0")]


@dataclass
class DummyLiftInsn:
    addr: int = 0
    asm_mnem: str = "addi"
    asm_body: str = "x0, x0, 0"
    pcode_ops: list = None

    def __post_init__(self):
        if self.pcode_ops is None:
            self.pcode_ops = ["COPY tmp0, x0"]


@dataclass
class DummyLiftResult:
    ok: bool = True
    insns: list = None
    error: str = ""

    def __post_init__(self):
        if self.insns is None:
            self.insns = [DummyLiftInsn()]


@dataclass
class DummyTranslateResult:
    kind: str = "intrinsic"
    replacement: str = "__translated();"
    notes: list = None

    def __post_init__(self):
        if self.notes is None:
            self.notes = ["translated"]


@dataclass
class DummyVerifyResult:
    status: str = "verified"
    detail: str = "ok"


def _write_input_json(path: Path):
    data = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "description": "builtin-like finding, no fragment",
                "file": "a.c",
                "line": 10,
                "column": 3,
            },
            {
                "category": "NeedsAsmTranslation",
                "description": "real asm fragment",
                "file": "b.c",
                "line": 20,
                "column": 5,
                "fragment": {
                    "kind": "InlineExtended",
                    "rawAsmText": "addi %0, %1, 1",
                    "outputs": [{"constraint": "=r", "exprText": "out", "isOutput": True}],
                    "inputs": [{"constraint": "r", "exprText": "in"}],
                    "fileName": "b.c",
                    "line": 20,
                    "column": 5,
                },
            },
        ]
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def test_gap2_patch_defers_non_fragment_and_only_counts_real_asm(tmp_path, monkeypatch):
    in_json = tmp_path / "in.json"
    out_json = tmp_path / "out.json"
    _write_input_json(in_json)

    calls = {
        "assemble": 0,
        "lift": 0,
        "translate": 0,
        "verify": 0,
    }

    def fake_assemble(frag):
        calls["assemble"] += 1
        assert frag is not None
        assert (frag.rawAsmText or "").strip()
        return DummyAsmResult()

    def fake_lift(code, xlen=64):
        calls["lift"] += 1
        return DummyLiftResult()

    def fake_from_lifted(insns):
        return object(), {"summary": "ok"}

    def fake_translate(frag, lr, summary, machine_code=b"", xlen=64):
        calls["translate"] += 1
        return DummyTranslateResult()

    def fake_verify(frag, lr, summary, tr):
        calls["verify"] += 1
        return DummyVerifyResult()

    monkeypatch.setattr(pipeline_mod, "assemble", fake_assemble)
    monkeypatch.setattr(pipeline_mod, "lift", fake_lift)
    monkeypatch.setattr(pipeline_mod, "from_lifted", fake_from_lifted)
    monkeypatch.setattr(pipeline_mod, "translate", fake_translate)
    monkeypatch.setattr(pipeline_mod, "verify", fake_verify)

    stats = run(str(in_json), str(out_json), xlen=64)
    out = json.loads(out_json.read_text(encoding="utf-8"))
    findings = out["findings"]

    # 修订后：只有真正带 fragment 的 asm finding 才计入 total
    assert stats["total"] == 1
    assert stats["no_fragment"] == 1
    assert stats["deferred_non_fragment"] == 1
    assert stats["verified"] == 1
    assert calls == {
        "assemble": 1,
        "lift": 1,
        "translate": 1,
        "verify": 1,
    }

    # 第 1 条：不再标 skipped，而是 deferred，并明确说明未进入 asm pipeline
    assert findings[0]["verificationStatus"] == "deferred"
    assert findings[0]["category"] == "NeedsAsmTranslation"
    assert findings[0]["ruleName"] == ""
    assert findings[0]["suggestedReplacement"] == ""
    assert "missing fragment or empty rawAsmText" in findings[0]["verificationDetail"]
    assert any("not sent to Phase 4 assemble" in n for n in findings[0]["notes"])

    # 第 2 条：正常跑通 Phase 4+
    assert findings[1]["category"] == "ReplaceableByRule"
    assert findings[1]["verificationStatus"] == "verified"
    assert findings[1]["machineCodeHex"] == "13000000"


def test_empty_fragment_text_is_also_deferred(tmp_path, monkeypatch):
    in_json = tmp_path / "in_empty.json"
    out_json = tmp_path / "out_empty.json"
    data = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "description": "empty asm text",
                "file": "c.c",
                "line": 1,
                "column": 1,
                "fragment": {
                    "kind": "InlineExtended",
                    "rawAsmText": "   ",
                    "fileName": "c.c",
                    "line": 1,
                    "column": 1,
                },
            }
        ]
    }
    in_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def should_not_be_called(*args, **kwargs):
        raise AssertionError("assemble/lift/translate/verify should not be called")

    monkeypatch.setattr(pipeline_mod, "assemble", should_not_be_called)
    monkeypatch.setattr(pipeline_mod, "lift", should_not_be_called)
    monkeypatch.setattr(pipeline_mod, "from_lifted", should_not_be_called)
    monkeypatch.setattr(pipeline_mod, "translate", should_not_be_called)
    monkeypatch.setattr(pipeline_mod, "verify", should_not_be_called)

    stats = run(str(in_json), str(out_json), xlen=64)
    out = json.loads(out_json.read_text(encoding="utf-8"))
    f0 = out["findings"][0]

    assert stats["total"] == 0
    assert stats["no_fragment"] == 1
    assert stats["deferred_non_fragment"] == 1
    assert f0["verificationStatus"] == "deferred"
    assert f0["category"] == "NeedsAsmTranslation"
    assert f0["ruleName"] == ""
    assert f0["suggestedReplacement"] == ""

