"""Conservative source-package pinning, separate from approval or calibration.

All package Python implementations are fixed, including dynamic registry targets
and transitive helpers. No import-graph approximation or validation cache grants
trust. External tools, runtime assets and contracts retain their own bindings.
"""
from pathlib import Path


def implementation_dependencies(root=None):
    root=Path(root) if root is not None else Path(__file__).resolve().parent
    if root.is_symlink() or not root.is_dir():
        raise ValueError('L3_IMPLEMENTATION_ROOT_INVALID')
    result=[]
    for path in root.rglob('*'):
        if '__pycache__' in path.relative_to(root).parts:
            continue
        if path.is_symlink() and (path.is_dir() or path.suffix=='.py'):
            raise ValueError('L3_IMPLEMENTATION_SYMLINK_UNSUPPORTED:'+str(path))
        if path.is_file() and path.suffix=='.py':
            result.append(path.relative_to(root).as_posix())
    if not result:
        raise ValueError('L3_IMPLEMENTATION_FILES_MISSING')
    return tuple(sorted(result))


def implementation_paths():
    root=Path(__file__).resolve().parent
    return tuple(str((root/name).resolve()) for name in implementation_dependencies(root))
