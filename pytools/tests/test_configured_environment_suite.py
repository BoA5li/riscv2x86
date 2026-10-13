from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from riscv2x86_py import configured_environment_suite as suite


def _identity(value):
    return "sha256:" + sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode()).hexdigest()


def _manifest(tmp_path: Path):
    sources = tmp_path / "sources"; sources.mkdir()
    config = tmp_path / "config"; config.mkdir()
    bindings = []
    for name, route, suffix in (
        ("ecall.c", "privileged", ".privileged-environment.json"),
        ("fence_i.c", "instruction_stream_sync", ".instruction-stream-sync.json"),
        ("time.c", "csr", ".csr-environment.json"),
    ):
        source = sources / name; source.write_text("void f(void){}\n")
        sidecar = config / (name + suffix); sidecar.write_text("{}\n")
        bindings.append({
            "sourceRelativePath": name,
            "sourceDigest": "sha256:" + sha256(source.read_bytes()).hexdigest(),
            "fragmentId": "fragment:" + name,
            "route": route,
            "sidecar": str(sidecar.relative_to(tmp_path)),
        })
    value = {"schemaVersion": suite.CONFIGURED_ENVIRONMENT_SUITE_SCHEMA,
             "sourceRoot": "sources", "cases": bindings}
    value["manifestIdentity"] = _identity(value)
    path = tmp_path / "suite.json"
    path.write_text(json.dumps(value))
    return path, value


def _patch_loaders(monkeypatch):
    monkeypatch.setattr(suite, "load_privileged_environment_manifest",
                        lambda path, source: SimpleNamespace(fragment_id="fragment:ecall.c"))
    monkeypatch.setattr(suite, "load_csr_environment_contract",
                        lambda path, source: SimpleNamespace(fragment_id="fragment:time.c"))
    monkeypatch.setattr(suite, "load_instruction_stream_sync_registry",
                        lambda path, source_path: SimpleNamespace(
                            binds_fragment=lambda fragment: fragment == "fragment:fence_i.c"))


def test_manifest_binds_complete_sidecars_and_separates_route_roots(tmp_path, monkeypatch):
    path, _ = _manifest(tmp_path); _patch_loaders(monkeypatch)
    source_root, roots, cases = suite.validate_configured_environment_suite(path)
    assert source_root == (tmp_path / "sources").resolve()
    assert set(roots) == {"privileged", "instruction_stream_sync", "csr"}
    assert len(cases) == 3


def test_manifest_rejects_stale_source_digest_before_route_loading(tmp_path, monkeypatch):
    path, value = _manifest(tmp_path); _patch_loaders(monkeypatch)
    value["cases"][0]["sourceDigest"] = "sha256:" + "0" * 64
    value["manifestIdentity"] = _identity({key: item for key, item in value.items()
                                           if key != "manifestIdentity"})
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="source digest mismatch"):
        suite.validate_configured_environment_suite(path)


def test_strict_command_never_receives_environment_sidecars(tmp_path):
    command = suite._batch_command(tmp_path, tmp_path / "frontend",
                                   tmp_path / "strict", {}, 120)
    assert "--privileged-config-directory" not in command
    assert "--instruction-stream-sync-directory" not in command
    assert "--csr-environment-contract-directory" not in command


def test_configured_command_forwards_only_explicit_route_roots(tmp_path):
    roots = {"privileged": tmp_path / "privileged",
             "csr": tmp_path / "csr"}
    command = suite._batch_command(tmp_path, tmp_path / "frontend",
                                   tmp_path / "configured", roots, 120)
    assert command[command.index("--privileged-config-directory") + 1] == \
        str(roots["privileged"])
    assert command[command.index("--csr-environment-contract-directory") + 1] == \
        str(roots["csr"])
    assert "--instruction-stream-sync-directory" not in command
