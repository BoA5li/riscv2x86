"""Deterministic structured semantic payloads. No repr/object-address identities."""
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from types import SimpleNamespace
from .route_authority import content_identity


def semantic_payload(value):
    if isinstance(value, Enum):
        return semantic_payload(value.value)
    if value is None or type(value) in (str, bool, int):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: semantic_payload(getattr(value,f.name)) for f in fields(value)}
    if isinstance(value, SimpleNamespace):
        return semantic_payload(vars(value))
    if isinstance(value, Mapping):
        if any(not isinstance(k,str) for k in value):
            raise ValueError('SEMANTIC_CONTENT_NONSTRING_KEY')
        return {k:semantic_payload(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):
        return [semantic_payload(x) for x in value]
    if isinstance(value,(set,frozenset)):
        return sorted((semantic_payload(x) for x in value), key=content_identity)
    raise ValueError('SEMANTIC_CONTENT_UNSUPPORTED_TYPE:' + type(value).__name__)


def semantic_identity(value):
    return content_identity(semantic_payload(value))
