"""Exact, type-sensitive contextual replay with a bounded first difference."""
from .project_build_records import identity


def first_difference(old, new, path='$'):
    if type(old) is not type(new):
        return {'path':path,'old':old,'new':new}
    if isinstance(old, dict):
        # Show the underlying changed field before its derived digest, where
        # both are present. This affects diagnostics only, not acceptance.
        for key in sorted(old.keys() | new.keys(), key=lambda k:(k.endswith('Identity'),k)):
            child = path + '.' + key
            if key not in old or key not in new:
                return {'path':child,'oldPresent':key in old,'newPresent':key in new,
                        'old':old.get(key),'new':new.get(key)}
            difference = first_difference(old[key],new[key],child)
            if difference is not None:return difference
    elif isinstance(old, list):
        if len(old) != len(new):
            return {'path':path+'.length','old':len(old),'new':len(new)}
        for index,(left,right) in enumerate(zip(old,new)):
            difference = first_difference(left,right,f'{path}[{index}]')
            if difference is not None:return difference
    elif old != new:
        return {'path':path,'old':old,'new':new}
    return None


class InspectionReplayMismatch(ValueError):
    def __init__(self, key, context, old, new):
        super().__init__('PROJECT_INSPECTION_REPLAY_MISMATCH:'+key)
        self.replay_difference = {'sourcePath':context['sourcePath'],
            'contextIdentity':context['contextIdentity'],'component':key,
            'difference':first_difference(old,new)}


def require_match(key, context, old, new):
    # Retain the canonical identity comparison used by the original gate.
    if identity(old) != identity(new):
        raise InspectionReplayMismatch(key,context,old,new)
