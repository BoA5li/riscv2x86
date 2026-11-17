"""Operation-local memoization of pure derivations and diagnostic timings.

Never memoize file reads, digests, receipt validators, tool checks or approvals.
Callers must read and validate current bytes on every use. Keys describe every
input of a registered pure calculation; mutable results are isolated by copies.
A new CLI invocation (including independent check) starts an empty session.
"""
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from functools import wraps
import hashlib
import sys
import time

_ACTIVE = ContextVar('rv2x86_verification_session', default=None)
_STACK = ContextVar('rv2x86_verification_spans', default=())


class ReadOnlyDict(dict):
    """Internal JSON view; normal mutation rejects, deepcopy makes an owned copy."""
    __slots__ = ('_sealed',)
    def __init__(self, *args, **kwargs):
        if getattr(self, '_sealed', False):
            self._reject()
        super().__init__(*args, **kwargs)
        object.__setattr__(self, '_sealed', True)
    def _reject(self, *args, **kwargs):
        raise TypeError('VERIFICATION_READ_ONLY_DERIVATION')
    __setattr__ = __delattr__ = _reject
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _reject
    def __deepcopy__(self, memo):
        result = {}; memo[id(self)] = result
        result.update((deepcopy(k, memo), deepcopy(v, memo)) for k, v in self.items())
        return result


class ReadOnlyList(list):
    __slots__ = ('_sealed',)
    def __init__(self, *args, **kwargs):
        if getattr(self, '_sealed', False):
            self._reject()
        super().__init__(*args, **kwargs)
        object.__setattr__(self, '_sealed', True)
    def _reject(self, *args, **kwargs):
        raise TypeError('VERIFICATION_READ_ONLY_DERIVATION')
    __setattr__ = __delattr__ = _reject
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = __iadd__ = __imul__ = _reject
    def __deepcopy__(self, memo):
        result = []; memo[id(self)] = result
        result.extend(deepcopy(v, memo) for v in self)
        return result


def readonly_json(value):
    """Freeze internally derived JSON, retaining existing dict/list readers.

    This is an internal ownership contract, not a sandbox against Python code
    invoking base-class mutation methods. Verifier code is part of the TCB.
    """
    if isinstance(value, (ReadOnlyDict, ReadOnlyList)):
        return value
    if isinstance(value, dict):
        return ReadOnlyDict({k: readonly_json(v) for k, v in value.items()})
    if isinstance(value, list):
        return ReadOnlyList(readonly_json(v) for v in value)
    if value is None or type(value) in (str, bytes, bool, int, float):
        return value
    raise TypeError('VERIFICATION_READ_ONLY_JSON_VALUE_REQUIRED')


def _size(value, seen=None):
    seen = set() if seen is None else seen
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(_size(k, seen) + _size(v, seen) for k, v in value.items())
    elif isinstance(value, (list, tuple)):
        size += sum(_size(v, seen) for v in value)
    return size


class VerificationSession:
    def __init__(self, max_cache_bytes=256 * 1024 * 1024):
        if type(max_cache_bytes) is not int or max_cache_bytes < 0:
            raise ValueError('VERIFICATION_CACHE_BUDGET_INVALID')
        self.max_cache_bytes = max_cache_bytes
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.peak_cache_bytes = 0
        self.timings = {}
        self.memo = {}
        self.started = time.monotonic()
        self.elapsed = None

    def profile(self):
        return {
            'schemaVersion': 'riscv2x86.verification-profile.v1',
            'wallSeconds': self.elapsed if self.elapsed is not None else time.monotonic() - self.started,
            'cacheBudgetBytes': self.max_cache_bytes,
            'peakCacheBytes': self.peak_cache_bytes,
            'retainedCacheBytes': self.cache_bytes,
            'memoization': deepcopy(self.memo),
            'timings': deepcopy(self.timings),
            'scope': 'diagnostic-timings-and-pure-derivation-reuse-not-validation-evidence',
            'timingPolicy': 'inclusive-spans-overlap-exclusive-spans-exclude-measured-children',
        }


@contextmanager
def session(max_cache_bytes=256 * 1024 * 1024):
    value = VerificationSession(max_cache_bytes)
    token = _ACTIVE.set(value)
    stack_token = _STACK.set(())
    try:
        yield value
    finally:
        value.elapsed = time.monotonic() - value.started
        # A closed operation must not retain a potentially large AST graph.
        value.cache.clear()
        value.cache_bytes = 0
        _STACK.reset(stack_token)
        _ACTIVE.reset(token)


@contextmanager
def span(name):
    current = _ACTIVE.get()
    if current is None:
        yield
        return
    frame = {'children': 0.0}
    parents = _STACK.get()
    token = _STACK.set(parents + (frame,))
    started = time.monotonic()
    failed = False
    try:
        yield
    except BaseException:
        failed = True
        raise
    finally:
        elapsed = time.monotonic() - started
        _STACK.reset(token)
        if parents:
            parents[-1]['children'] += elapsed
        row = current.timings.setdefault(name, {
            'calls': 0, 'failedCalls': 0,
            'inclusiveSeconds': 0.0, 'exclusiveSeconds': 0.0,
        })
        row['calls'] += 1
        row['failedCalls'] += int(failed)
        row['inclusiveSeconds'] += elapsed
        row['exclusiveSeconds'] += max(0.0, elapsed - frame['children'])


def measured(name):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with span(name):
                return function(*args, **kwargs)
        return wrapped
    return decorate


def pure(namespace, inputs, produce, *, readonly=False):
    """Memoize only an explicit, side-effect-free derivation of bytes/strings.

    Namespace versions must change when the derivation policy changes. A cache
    hit is never evidence that a file, dependency or receipt remains valid.
    """
    current = _ACTIVE.get()
    if type(readonly) is not bool:
        raise ValueError('VERIFICATION_READ_ONLY_POLICY_INVALID')
    if current is None:
        value = produce()
        return readonly_json(value) if readonly else value
    if not isinstance(namespace, str) or not namespace or not isinstance(inputs, tuple):
        raise ValueError('VERIFICATION_PURE_KEY_INVALID')
    key = hashlib.sha256(namespace.encode('utf-8'))
    with span('pure.key.' + namespace):
        for part in inputs:
            if not isinstance(part, (bytes, str)):
                raise ValueError('VERIFICATION_PURE_INPUT_BYTES_OR_STRING_REQUIRED')
            raw = part.encode('utf-8') if isinstance(part, str) else part
            key.update(b's' if isinstance(part, str) else b'b')
            key.update(len(raw).to_bytes(8, 'big'))
            key.update(raw)
    cache_key = (namespace, key.digest(), readonly)
    stats = current.memo.setdefault(namespace, {
        'hits': 0, 'misses': 0, 'budgetSkips': 0, 'evictions': 0,
    })
    if cache_key in current.cache:
        stats['hits'] += 1
        value, size = current.cache.pop(cache_key)
        current.cache[cache_key] = (value, size)
        if readonly:
            return value
        with span('pure.copy.' + namespace):
            return deepcopy(value)
    stats['misses'] += 1
    # Exceptions leave no cache entry.
    with span('pure.derive.' + namespace):
        value = produce()
    if readonly:
        with span('pure.freeze.' + namespace):
            value = readonly_json(value)
    if not current.max_cache_bytes:
        stats['budgetSkips'] += 1
        return value
    size = _size(value)
    if size > current.max_cache_bytes:
        stats['budgetSkips'] += 1
        return value
    while current.cache and current.cache_bytes + size > current.max_cache_bytes:
        old_key, (_, old_size) = current.cache.popitem(last=False)
        current.cache_bytes -= old_size
        current.memo[old_key[0]]['evictions'] += 1
    with span('pure.store.' + namespace):
        current.cache[cache_key] = (value if readonly else deepcopy(value), size)
    current.cache_bytes += size
    current.peak_cache_bytes = max(current.peak_cache_bytes, current.cache_bytes)
    return value
