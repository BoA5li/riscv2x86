"""Explicit object-relative LRU cache model, not a physical-cache observation.

Only the declared fragment's successful memory stream is modeled. Compiler,
loader, harness, prefetch and speculative accesses are outside this model.
"""
from .l3_trace_support import identity

SCHEMA = 'riscv2x86.object-relative-lru-cache-model.v1'
LIMITATIONS = ['compiler-and-harness-cache-effects-not-modeled',
              'physical-cache-timing-and-speculation-not-claimed']
DEFAULT = {'schemaVersion': SCHEMA, 'lineBytes': 64, 'setCount': 16, 'ways': 4,
           'initialState': 'empty', 'addressMapping': 'one-private-object-origin-zero',
           'replacement': 'lru', 'stream': 'successful-fragment-memory-accesses-only'}


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT):
        raise ValueError('L3_CACHE_MODEL_FIELDS_INVALID')
    for name in ('schemaVersion', 'initialState', 'addressMapping', 'replacement', 'stream'):
        if value[name] != DEFAULT[name]: raise ValueError('L3_CACHE_MODEL_POLICY_UNSUPPORTED:' + name)
    for name in ('lineBytes', 'setCount', 'ways'):
        n = value[name]
        if type(n) is not int or n < 1 or n > 65536 or n & (n-1):
            raise ValueError('L3_CACHE_MODEL_GEOMETRY_INVALID:' + name)
    return dict(value)


def evaluate(events, model):
    model = validate(model)
    sets = [[] for _ in range(model['setCount'])]
    outcomes = []
    for event in events:
        if (set(event) != {'offset', 'size', 'access'} or event['access'] not in ('read', 'write') or
                type(event['offset']) is not int or event['offset'] < 0 or
                type(event['size']) is not int or event['size'] < 1):
            raise ValueError('L3_CACHE_MODEL_EVENT_INVALID')
        if event['size'] > 65536: raise ValueError('L3_CACHE_MODEL_EVENT_TOO_LARGE')
        first = event['offset']//model['lineBytes']; last = (event['offset']+event['size']-1)//model['lineBytes']
        for line in range(first, last+1):
            cache_set = sets[line % len(sets)]; hit = line in cache_set
            if hit: cache_set.remove(line)
            elif len(cache_set) == model['ways']: cache_set.pop(0)
            cache_set.append(line)
            outcomes.append({'line': line, 'hit': hit})
    payload = {'schemaVersion': 'riscv2x86.object-relative-cache-result.v1',
               'modelIdentity': identity(model), 'outcomes': outcomes,
               'hits': sum(x['hit'] for x in outcomes), 'misses': sum(not x['hit'] for x in outcomes),
               'physicalMicroarchitectureClaimed': False}
    return dict(payload, resultIdentity=identity(payload))


def main():
    import argparse
    import json
    from .l3_trace_support import save
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--line-bytes',type=int,default=64)
    parser.add_argument('--set-count',type=int,default=16)
    parser.add_argument('--ways',type=int,default=4)
    args=parser.parse_args()
    try:
        model=validate(dict(DEFAULT,lineBytes=args.line_bytes,setCount=args.set_count,ways=args.ways))
        save(args.output,model)
        print(json.dumps({'modelIdentity':identity(model),'physicalMicroarchitectureClaimed':False}))
        return 0
    except (OSError,ValueError) as exc:
        print(json.dumps({'reasonCode':str(exc)})); return 2


if __name__=='__main__':
    raise SystemExit(main())
