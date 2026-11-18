"""Location-independent verifier identity; paths are capture provenance only.

Use the complete in-package Python source inventory conservatively: changing
any package source, including a transitive helper, requires a new audit. This
is not a claim that stdlib, Python runtime or external tools are all covered;
external candidate tools retain their existing artifact-bound checks.
"""
from pathlib import Path
import os
import sys

from .verification_session import measured
from .project_compile_context import digest
from .project_build_records import identity
from .native_external_providers import checked

SCHEMA = 'riscv2x86.native-verifier-manifest.v1'
POLICY = 'complete-package-python-source-inventory.v1'


@measured('native_verifier_manifest.capture')
def capture(package_root):
    root = Path(package_root).resolve(strict=True)
    files = {}
    def sources(directory):
        # DirEntry retains the enumeration's type information. Every source
        # is still freshly read/hashed; no directory or validity is cached.
        with os.scandir(directory) as entries:
            entries = sorted(entries, key=lambda entry: entry.name)
        for entry in entries:
            if entry.is_symlink():
                raise ValueError('DEPLOYMENT_VERIFIER_SOURCE_LINK_UNSUPPORTED')
            if entry.is_dir(follow_symlinks=False):
                yield from sources(entry.path)
            elif entry.is_file(follow_symlinks=False) and entry.name.endswith('.py'):
                yield Path(entry.path)
    for path in sources(root):
        # Bytecode and installed caches are not verifier source. Reject links
        # escaping this inventory rather than hashing an incomplete tree.
        files[path.relative_to(root).as_posix()] = digest(path)
    if '__init__.py' not in files:
        raise ValueError('DEPLOYMENT_VERIFIER_PACKAGE_INCOMPLETE')
    body = {'schemaVersion': SCHEMA, 'policy': POLICY, 'package': 'riscv2x86_py',
            'files': files}
    return dict(body, verifierIdentity=identity(body))


@measured('native_verifier_manifest.current')
def current():
    root = Path(__file__).resolve(strict=True).parent
    # Avoid declaring the current tree while already imported helpers come
    # from another worktree. File path equality matters locally, not between
    # two otherwise identical installations.
    for name, module in tuple(sys.modules.items()):
        if name != 'riscv2x86_py' and not name.startswith('riscv2x86_py.'):
            continue
        path = getattr(module, '__file__', None)
        if path is None:
            raise ValueError('DEPLOYMENT_VERIFIER_MODULE_ORIGIN_UNAVAILABLE:'+name)
        expected = root.joinpath(*name.split('.')[1:])
        expected = expected/'__init__.py' if hasattr(module, '__path__') else expected.with_suffix('.py')
        # A lexical match needs no pair of filesystem resolutions: capture()
        # below rejects every source-tree symlink and hashes the live files.
        if Path(path) != expected and Path(path).resolve(strict=True) != expected.resolve():
            raise ValueError('DEPLOYMENT_VERIFIER_MIXED_PACKAGE_ORIGIN:'+name)
    return capture(root)


def compare(stored, fresh):
    checked(stored, 'verifierIdentity')
    if stored != fresh:
        raise ValueError('DEPLOYMENT_AUDIT_VERIFIER_CONTENT_OR_POLICY_CHANGED_REAUDIT_REQUIRED')
