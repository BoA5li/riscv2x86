"""Explicit per-validator project recipe scope; isolated across tasks/threads."""
from contextlib import contextmanager
from contextvars import ContextVar
from .project_build_contract import validate
from .project_build_records import identity

_ACTIVE=ContextVar('rv2x86_project_build_contract',default=None)


def active():return _ACTIVE.get()


@contextmanager
def operation(contract):
    validate(contract)
    parent=active()
    if parent is not None and parent['contractIdentity']!=contract['contractIdentity']:
        raise ValueError('PROJECT_NESTED_CONTRACT_MISMATCH')
    before=identity(contract);token=_ACTIVE.set(contract)
    try:
        yield contract
        validate(contract)
        if identity(contract)!=before:raise ValueError('PROJECT_OPERATION_CONTRACT_MUTATED')
    finally:_ACTIVE.reset(token)


def wrap(validator,contract,report=None):
    validate(contract)
    def invoke(report,kwargs):return validator(**kwargs)
    bound=report_operation(invoke) if report is not None else None
    def checked(**kwargs):
        with operation(contract):
            return bound(report,kwargs) if bound is not None else validator(**kwargs)
    return checked


def require_compiler(side,compiler):
    if active() is not None:
        from .project_build_contract import profile
        profile(active(),side,compiler=compiler)


def flags(side,legacy,*,driver=False):
    if active() is None:return list(legacy)
    from .project_build_contract import profile
    return profile(active(),side,driver=driver)[1]


def report_operation(function):
    """Use a report-bound recipe for subprocess producer/rebuild entry points."""
    from functools import wraps
    from inspect import signature
    sig=signature(function)
    @wraps(function)
    def checked(*args,**kwargs):
        bound=sig.bind(*args,**kwargs).arguments
        report=bound.get('report')
        value=bound.get('value')
        if report is None and isinstance(value,dict):report=(value.get('inputs') or {}).get('report')
        if report is None:return function(*args,**kwargs)
        from .project_build_contract import report_contract
        contract=report_contract(report)
        if contract is None:
            if active() is not None:raise ValueError('PROJECT_REPORT_CONTRACT_MISSING')
            return function(*args,**kwargs)
        if bound.get('clang') is not None:
            from .project_build_contract import resolve_tool
            if resolve_tool(bound['clang'])!=contract['inspectionCompiler']:
                raise ValueError('PROJECT_DEPLOYMENT_INSPECTION_COMPILER_MISMATCH')
        from pathlib import Path
        import json
        from .project_build_contract import digest
        from .compiler_call_dependencies import _snapshot
        from .project_build_records import identity
        path=Path(report);snapshot_path=path.with_name('compiler-candidates.json')
        if not snapshot_path.is_file():raise ValueError('PROJECT_COMPILER_SNAPSHOT_REQUIRED')
        before={str(p):digest(p) for p in (path,snapshot_path)}
        snapshot=json.loads(snapshot_path.read_text())
        if identity(snapshot.get('projectBuildContract'))!=identity(contract):raise ValueError('PROJECT_REPORT_SNAPSHOT_CONTRACT_MISMATCH')
        rows=snapshot['dependencyManifest']['dependencies'];cwd=Path(snapshot['dependencyManifest']['workingDirectory'])
        with operation(contract):result=function(*args,**kwargs)
        if any(digest(p)!=value for p,value in before.items()):raise ValueError('PROJECT_REPORT_OPERATION_INPUT_CHANGED')
        if identity(rows)!=identity(_snapshot([r['compilerPath'] for r in rows],cwd)):
            raise ValueError('PROJECT_REPORT_OPERATION_DEPENDENCIES_CHANGED')
        for rows in snapshot['projectCompilerCompatibility']['dependencies'].values():
            if identity(rows)!=identity(_snapshot([r['compilerPath'] for r in rows],cwd)):
                raise ValueError('PROJECT_REPORT_NATIVE_DEPENDENCIES_CHANGED')
        return result
    return checked
