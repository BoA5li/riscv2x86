"""Persisted harness algorithm selection, independent of audit process flags."""
SINGLE='single-object-loop-v1'
EXPANDED='expanded-typed-layouts-v1'
TABLE='table-typed-layouts-v1'


def selected(program):
    if 'objectLayout' not in program:return SINGLE
    from .joint_performance import enabled
    return TABLE if enabled() else EXPANDED


def legacy(program):return EXPANDED if 'objectLayout' in program else SINGLE


def require(program,value):
    allowed={TABLE,EXPANDED} if 'objectLayout' in program else {SINGLE}
    if type(value) is not str or value not in allowed:raise ValueError('JOINT_HARNESS_GENERATOR_UNSUPPORTED')
    return value
