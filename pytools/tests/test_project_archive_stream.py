from hashlib import sha256
import importlib
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import pytest

from riscv2x86_py import project_archive_stream as archive_stream
from riscv2x86_py.project_source_release import verify


def xz_fixture(tmp_path):
    # Real external XZ also works on the affected Python without _lzma.
    xz = shutil.which('xz')
    if not xz:
        pytest.skip('XZ executable required')
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'a.c').write_bytes(b'int x;\n')
    raw = tmp_path / 'release.tar'
    with tarfile.open(raw, 'w') as tar:
        tar.add(source, arcname='release')
    archive = tmp_path / 'release.tar.xz'
    data = subprocess.run([xz, '--compress', '--stdout', str(raw)], check=True, capture_output=True).stdout
    archive.write_bytes(data)
    spec = {'id': 'fixture', 'version': '1', 'root': 'release', 'sha256': sha256(data).hexdigest()}
    return spec, archive, source


def no_lzma(monkeypatch):
    original = importlib.import_module
    def load(name):
        if name == 'lzma':
            raise ModuleNotFoundError("No module named '_lzma'")
        return original(name)
    monkeypatch.setattr(archive_stream.importlib, 'import_module', load)


def test_real_xz_fallback_has_identical_release_identity(tmp_path, monkeypatch):
    spec, archive, source = xz_fixture(tmp_path)
    try:
        importlib.import_module('lzma')
    except ImportError:
        pytest.skip('identity comparison also requires native decoder')
    native = verify(spec, archive, source)
    no_lzma(monkeypatch)
    selected = archive_stream.decoder(archive)
    assert selected['backend'] == 'external-xz' and selected['executableDigest'].startswith('sha256:')
    assert verify(spec, archive, source) == native


@pytest.mark.parametrize('fallback', [False, True])
@pytest.mark.parametrize('damage', ['truncate', 'corrupt', 'source', 'extra'])
def test_xz_damage_never_grants_source_proof(tmp_path, monkeypatch, fallback, damage):
    spec, archive, source = xz_fixture(tmp_path)
    if fallback:
        no_lzma(monkeypatch)
    if damage == 'truncate':
        archive.write_bytes(archive.read_bytes()[:-8])
    elif damage == 'corrupt':
        data = bytearray(archive.read_bytes()); data[-8] ^= 1; archive.write_bytes(data)
    elif damage == 'source':
        (source / 'a.c').write_bytes(b'changed')
    else:
        (source / 'extra').write_bytes(b'changed')
    # Corrupt but digest-pinned bytes must also fail decoding, not just hashing.
    spec['sha256'] = sha256(archive.read_bytes()).hexdigest()
    with pytest.raises((OSError, ValueError, tarfile.TarError)):
        verify(spec, archive, source)


def test_no_python_codec_and_no_external_tool_is_dependency_error(tmp_path, monkeypatch):
    spec, archive, source = xz_fixture(tmp_path)
    no_lzma(monkeypatch)
    def missing(name):
        raise FileNotFoundError(name)
    monkeypatch.setattr(archive_stream, 'resolve_executable', missing)
    with pytest.raises(ValueError, match='DECODER_UNAVAILABLE'):
        verify(spec, archive, source)


def test_external_nonzero_after_valid_tar_is_rejected(tmp_path, monkeypatch):
    spec, archive, source = xz_fixture(tmp_path)
    no_lzma(monkeypatch)
    fake = tmp_path / 'fake-xz'
    raw = tmp_path / 'release.tar'
    fake.write_text('#!/bin/sh\ncat "' + str(raw) + '"\necho bad-decoder >&2\nexit 7\n')
    fake.chmod(0o755)
    monkeypatch.setattr(archive_stream, 'resolve_executable', lambda name: fake)
    with pytest.raises(ValueError, match='DECOMPRESSION_FAILED:7:bad-decoder'):
        verify(spec, archive, source)


def test_external_decoder_mutation_is_rejected(tmp_path, monkeypatch):
    spec, archive, source = xz_fixture(tmp_path)
    no_lzma(monkeypatch)
    fake = tmp_path / 'fake-xz'
    fake.write_text('#!/bin/sh\ncat "' + str(tmp_path / 'release.tar') + '"\necho "#changed" >> "$0"\n')
    fake.chmod(0o755)
    monkeypatch.setattr(archive_stream, 'resolve_executable', lambda name: fake)
    with pytest.raises(ValueError, match='DECODER_CHANGED'):
        verify(spec, archive, source)


def test_fallback_success_and_independent_replay_without_python_codec(tmp_path, monkeypatch):
    import json
    from riscv2x86_py.project_source_release import replay
    spec, archive, source = xz_fixture(tmp_path)
    no_lzma(monkeypatch)
    proof = verify(spec, archive, source)
    path = tmp_path / 'proof.json'
    path.write_text(json.dumps(proof))
    assert replay(path) == proof['releaseIdentity']
    assert not proof['semanticApproval'] and not proof['productionAcceptanceComplete']


@pytest.mark.parametrize('compression', ['gz', 'bz2', ''])
def test_existing_archive_formats_remain_supported(tmp_path, compression):
    source = tmp_path / 'source'; source.mkdir()
    (source / 'a').write_bytes(b'data')
    path = tmp_path / ('release.tar.' + compression)
    try:
        with tarfile.open(path, 'w:' + compression) as tar:
            tar.add(source, arcname='release')
    except tarfile.CompressionError:
        pytest.skip('fixture codec unavailable')
    spec = {'id': 'fixture', 'version': '1', 'root': 'release', 'sha256': sha256(path.read_bytes()).hexdigest()}
    assert verify(spec, path, source)['sourceTreeMatchesRelease']
