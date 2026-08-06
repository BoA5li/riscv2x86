import json
from dataclasses import dataclass
from pathlib import Path
import sys

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


def test_pipeline_skips_already_rule_and_irrelevant_categories(tmp_path, monkeypatch):
    in_json = tmp_path / "mix.json"
    out_json = tmp_path / "mix.out.json"

    data = {
        "findings": [
            {
                "category": "ReplaceableByRule",
                "description": "already handled upstream",
                "file": "a.c",
                "line": 1,
                "column": 1,
                "fragment": {
                    "kind": "InlineExtended",
                    "rawAsmText": "addi %0, %1, 1",
                    "fileName": "a.c",
                    "line": 1,
                    "column": 1,
                },
            },
            {
                "category": "OtherCategory",
                "description": "not asm pipeline input",
                "file": "b.c",
                "line": 2,
                "column": 2,
                "fragment": {
                    "kind": "InlineExtended",
                    "rawAsmText": "addi %0, %1, 2",
                    "fileName": "b.c",
                    "line": 2,
                    "column": 2,
                },
            },
            {
                "category": "NeedsAsmTranslation",
                "description": "the only real phase3->4 input",
                "file": "c.c",
                "line": 3,
                "column": 3,
                "fragment": {
                    "kind": "InlineExtended",
                    "rawAsmText": "addi %0, %1, 3",
                    "outputs": [{"constraint": "=r", "exprText": "out", "isOutput": True}],
                    "inputs": [{"constraint": "r", "exprText": "in"}],
                    "fileName": "c.c",
                    "line": 3,
                    "column": 3,
                },
            },
        ]
    }
    in_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    calls = {"assemble": 0, "lift": 0, "translate": 0, "verify": 0}

    def fake_assemble(frag):
        calls["assemble"] += 1
        assert frag is not None
        assert (frag.rawAsmText or "").strip() == "addi %0, %1, 3"
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

    assert stats["already_rule"] == 1
    assert stats["total"] == 1
    assert stats["verified"] == 1

    assert calls == {
        "assemble": 1,
        "lift": 1,
        "translate": 1,
        "verify": 1,
    }

    # 已经是规则替换的 finding 不应被动到
    assert findings[0]["category"] == "ReplaceableByRule"

    # 非 NeedsAsmTranslation 的 finding 不应误入 asm pipeline
    assert findings[1]["category"] == "OtherCategory"
    assert findings[1]["verificationStatus"] == ""

    # 只有第 3 条真正走了 pipeline
    assert findings[2]["category"] == "ReplaceableByRule"
    assert findings[2]["ruleName"] == "phase6.intrinsic"
    assert findings[2]["verificationStatus"] == "verified"
    assert findings[2]["machineCodeHex"] == "13000000"


def test_legacy_asmText_input_still_enters_pipeline(tmp_path, monkeypatch):
    in_json = tmp_path / "legacy_in.json"
    out_json = tmp_path / "legacy_out.json"

    data = {
        "findings": [
            {
                "category": "NeedsAsmTranslation",
                "description": "legacy asmText format still supported",
                "file": "legacy.c",
                "line": 9,
                "column": 4,
                "asmText": "addi %0, %1, 1",
                "id": "legacy-frag-001",
                "outputBindings": [
                    {
                        "outputIndex": 0,
                        "sinkKind": "Result",
                        "sinkOpIndex": 0,
                        "aluExpr": "x+1",
                    }
                ],
                "symbols": [
                    {
                        "asmName": "g_foo",
                        "cName": "g_foo",
                        "addrTaken": True,
                    }
                ],
            }
        ]
    }
    in_json.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    calls = {"assemble": 0, "lift": 0, "translate": 0, "verify": 0}

    def fake_assemble(frag):
        calls["assemble"] += 1
        assert frag is not None
        assert frag.rawAsmText == "addi %0, %1, 1"
        assert frag.id == "legacy-frag-001"
        assert frag.fragmentId == "legacy-frag-001"
        assert len(frag.outputBindings) == 1
        assert len(frag.symbols) == 1
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
    f0 = out["findings"][0]

    assert stats["total"] == 1
    assert stats["verified"] == 1
    assert calls == {
        "assemble": 1,
        "lift": 1,
        "translate": 1,
        "verify": 1,
    }

    assert f0["category"] == "ReplaceableByRule"
    assert f0["ruleName"] == "phase6.intrinsic"
    assert f0["verificationStatus"] == "verified"
    assert f0["machineCodeHex"] == "13000000"

    # 旧格式输入在保存输出后应变成标准 fragment 结构
    assert f0["fragment"]["rawAsmText"] == "addi %0, %1, 1"
    assert f0["fragment"]["id"] == "legacy-frag-001"
    assert f0["fragment"]["fragmentId"] == "legacy-frag-001"
    assert len(f0["fragment"]["outputBindings"]) == 1
    assert len(f0["fragment"]["symbols"]) == 1