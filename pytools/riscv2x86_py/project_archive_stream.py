"""Checked archive decoding, independent of release comparison/approval.

External decoding is selected only when the required Python codec is absent,
never as a retry after corrupt input. No shell or extraction is involved.
"""
from contextlib import contextmanager
import importlib
from pathlib import Path
import subprocess
import tarfile
import tempfile

from .project_compile_context import digest
from .project_tool_resolution import resolve_executable


def decoder(archive):
    archive = Path(archive).resolve(strict=True)
    with archive.open('rb') as stream:
        magic = stream.read(6)
    codec = ('xz' if magic == b'\xfd7zXZ\x00' else
             'gzip' if magic[:2] == b'\x1f\x8b' else
             'bz2' if magic[:3] == b'BZh' else 'tar')
    module = {'xz': 'lzma', 'gzip': 'gzip', 'bz2': 'bz2'}.get(codec)
    if module:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            if codec != 'xz':
                raise ValueError('PROJECT_ARCHIVE_DECODER_UNAVAILABLE:' + module) from exc
            try:
                executable = resolve_executable('xz')
            except (OSError, ValueError) as missing:
                raise ValueError('PROJECT_ARCHIVE_DECODER_UNAVAILABLE:lzma_and_xz') from missing
            return {'codec': codec, 'backend': 'external-xz',
                    'executable': str(executable), 'executableDigest': digest(executable)}
    return {'codec': codec, 'backend': 'python-tarfile'}


@contextmanager
def open_archive(archive):
    archive = Path(archive).resolve(strict=True)
    selected = decoder(archive)
    if selected['backend'] != 'external-xz':
        # Explicitly consume the codec through EOF, including checksums beyond
        # tar end markers. Tar iteration alone may stop before a codec trailer.
        module = {'xz': 'lzma', 'gzip': 'gzip', 'bz2': 'bz2'}.get(selected['codec'])
        codec_module = importlib.import_module(module) if module else None
        opener = codec_module.open if module else open
        errors = (EOFError,)
        if selected['codec'] == 'xz':
            errors += (codec_module.LZMAError,)
        elif selected['codec'] == 'gzip':
            errors += (codec_module.BadGzipFile,)
        try:
            with opener(archive, 'rb') as raw:
                with tarfile.open(fileobj=raw, mode='r|') as tar:
                    yield tar
                    while raw.read(1024 * 1024):
                        pass
        except errors as exc:
            raise ValueError('PROJECT_ARCHIVE_DECOMPRESSION_FAILED:' + str(exc)) from exc
        return
    executable = selected['executable']
    # A real file bounds memory use and avoids stderr/stdout pipe deadlocks.
    with tempfile.TemporaryFile() as errors, archive.open('rb') as source:
        process = subprocess.Popen([executable, '--decompress', '--stdout'],
                                   stdin=source, stdout=subprocess.PIPE, stderr=errors)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as tar:
                yield tar
                # Force validation of the complete XZ stream and its trailer.
                while process.stdout.read(1024 * 1024):
                    pass
            code = process.wait()
            if code != 0:
                errors.seek(0)
                detail = errors.read(4096).decode('utf-8', errors='replace')
                raise ValueError('PROJECT_ARCHIVE_DECOMPRESSION_FAILED:' + str(code) + ':' + detail)
            if digest(executable) != selected['executableDigest']:
                raise ValueError('PROJECT_ARCHIVE_DECODER_CHANGED')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
