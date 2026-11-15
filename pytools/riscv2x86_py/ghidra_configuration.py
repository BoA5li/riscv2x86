"""One install-selection policy for the register query and p-code runtime.

An absent option may use the environment/default. An explicitly empty option
is an error, never the current working directory or permission to fall back.
"""
import os
from pathlib import Path

DEFAULT_INSTALL_DIR=Path('/opt/ghidra_11.2_PUBLIC')


class GhidraConfigurationError(ValueError):
    pass


def resolve_install_dir(explicit=None, *, environ=None, require_launcher=True):
    env=os.environ if environ is None else environ
    if explicit is not None:
        raw=explicit
    elif 'GHIDRA_INSTALL_DIR' in env:
        raw=env['GHIDRA_INSTALL_DIR']
    else:
        raw=DEFAULT_INSTALL_DIR
    try:raw=os.fspath(raw)
    except TypeError as exc:raise GhidraConfigurationError('GHIDRA_INSTALL_DIR_TYPE_INVALID') from exc
    if not isinstance(raw,str) or not raw.strip() or '\0' in raw:
        raise GhidraConfigurationError('GHIDRA_INSTALL_DIR_EMPTY_OR_INVALID')
    try:path=Path(raw).expanduser().resolve(strict=True)
    except (OSError,RuntimeError) as exc:
        raise GhidraConfigurationError('GHIDRA_INSTALL_DIRECTORY_UNAVAILABLE:'+raw) from exc
    if not path.is_dir():raise GhidraConfigurationError('GHIDRA_INSTALL_DIRECTORY_REQUIRED:'+str(path))
    if require_launcher:
        launcher=path/'support/pythonRun'
        if not launcher.is_file():raise GhidraConfigurationError('GHIDRA_PYTHON_RUN_MISSING:'+str(launcher))
        if not os.access(launcher,os.X_OK):raise GhidraConfigurationError('GHIDRA_PYTHON_RUN_NOT_EXECUTABLE:'+str(launcher))
    return path
