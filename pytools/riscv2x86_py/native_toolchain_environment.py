"""Per-operation subprocess environment; legacy calls keep their default behavior."""
from contextlib import contextmanager
from contextvars import ContextVar
_ACTIVE=ContextVar('native_toolchain_environment',default=None)


def kwargs(argv):
    value=_ACTIVE.get()
    if value is None:return {}
    return {'env':dict(value['tools'].get(str(argv[0]),value['default']))}


@contextmanager
def operation(default,tools):
    for env in [default,*tools.values()]:
        if not isinstance(env,dict) or 'PATH' not in env or any(not isinstance(k,str) or not isinstance(v,str) or '\0' in k+v for k,v in env.items()):
            raise ValueError('NATIVE_TOOLCHAIN_ENVIRONMENT_INVALID')
    value={'default':dict(default),'tools':{k:dict(v) for k,v in tools.items()}}
    token=_ACTIVE.set(value)
    try:yield
    finally:_ACTIVE.reset(token)
