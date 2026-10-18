"""Content-bound relation between compiler AST and replacement byte ranges.

The AST range remains unchanged. Only compiler-exported file ranges are joined;
macro ranges without an explicit spelling/expansion contract are rejected.
"""
from collections.abc import Mapping
from hashlib import sha256
import json
import re

SCHEMA = 'riscv2x86.fragment-source-range.v1'
AUTHORITY_SCHEMA = 'riscv2x86.compiler-fragment-authority.v3'


def identity(payload):
    return 'sha256:' + sha256(json.dumps(payload, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


class FragmentRangeError(ValueError):
    failure_stage = 'compiler_fragment_range_join'

    def __init__(self, code, field, expected, actual):
        self.reason_code = code
        self.diagnostics = {'field': field, 'expected': expected, 'actual': actual}
        super().__init__(code + ': ' + json.dumps(self.diagnostics, sort_keys=True))


def equal(field, expected, actual):
    if type(expected) is not type(actual) or expected != actual or identity(expected) != identity(actual):
        raise FragmentRangeError('COMPILER_FRAGMENT_' + field.upper() + '_MISMATCH',
                                 field, expected, actual)


def _range(begin, end):
    if type(begin) is not int or type(end) is not int or not 0 <= begin < end:
        raise FragmentRangeError('COMPILER_FRAGMENT_RANGE_INVALID', 'range',
                                 'nonempty nonnegative byte range', [begin, end])
    return [begin, end]


# Only trivia and one final semicolon are allowed after a compiler AST node.
# This checks a compiler-selected suffix, never searches for an asm statement.
_TRIVIA = re.compile(rb'(?:[ \t\r\n\v\f]|/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|//[^\r\n]*(?:\r\n|\r|\n))*;\Z')


def bind_fragment_source_range(fragment, key, source):
    digest = 'sha256:' + sha256(source).hexdigest()
    equal('source_digest', key['sourceDigest'], digest)
    ast = _range(key['beginOffset'], key['endOffset'])
    frontend_ast = _range(fragment.get('astBeginOffset'), fragment.get('astEndOffset'))
    equal('ast_range', ast, frontend_ast)
    replacement = _range(fragment.get('beginOffset'), fragment.get('endOffset'))
    equal('begin_offset', ast[0], replacement[0])
    if not ast[1] <= replacement[1] <= len(source):
        raise FragmentRangeError('COMPILER_FRAGMENT_RANGE_INVALID', 'endOffset',
                                 [ast[1], len(source)], replacement[1])
    suffix = source[ast[1]:replacement[1]]
    if suffix and _TRIVIA.fullmatch(suffix) is None:
        raise FragmentRangeError('COMPILER_FRAGMENT_SUFFIX_INVALID', 'suffix',
                                 'trivia followed by one semicolon', suffix.hex())
    payload = {'schemaVersion': SCHEMA, 'sourceDigest': digest,
        'functionIdentity': key['functionIdentity'],
        'fragmentIdentity': fragment.get('fragmentId') or fragment.get('id'),
        'astNodeRange': ast, 'replacementRange': replacement,
        'rangeRelation': 'identical' if not suffix else 'statement_terminator',
        'suffixHex': suffix.hex(),
        'astSliceDigest': 'sha256:' + sha256(source[ast[0]:ast[1]]).hexdigest(),
        'producerIdentity': 'clang-tooling.ast-token-and-statement-range.v1'}
    payload['bindingIdentity'] = identity(payload)
    return payload


def validate_fragment_source_range(binding, key, *, fragment_id, source_digest,
                                   begin_offset, end_offset, frontend_fragment):
    fields = {'schemaVersion', 'sourceDigest', 'functionIdentity', 'fragmentIdentity',
              'astNodeRange', 'replacementRange', 'rangeRelation', 'suffixHex',
              'astSliceDigest', 'producerIdentity', 'bindingIdentity'}
    if not isinstance(binding, Mapping) or set(binding) != fields:
        raise FragmentRangeError('COMPILER_FRAGMENT_RANGE_SCHEMA_INVALID', 'fields',
                                 sorted(fields), sorted(binding) if isinstance(binding, Mapping) else None)
    equal('schema', SCHEMA, binding['schemaVersion'])
    equal('binding_identity', identity({k:v for k,v in binding.items() if k!='bindingIdentity'}), binding['bindingIdentity'])
    equal('producer', 'clang-tooling.ast-token-and-statement-range.v1', binding['producerIdentity'])
    for field, expected in [('sourceDigest', source_digest),
                            ('functionIdentity', key['functionIdentity']),
                            ('fragmentIdentity', fragment_id)]:
        equal(field, expected, binding[field])
    equal('source_digest', source_digest, key['sourceDigest'])
    ast = _range(key['beginOffset'], key['endOffset'])
    equal('ast_range', ast, binding['astNodeRange'])
    replacement = _range(begin_offset, end_offset)
    equal('replacement_range', replacement, binding['replacementRange'])
    equal('begin_offset', ast[0], replacement[0])
    if not isinstance(frontend_fragment, Mapping):
        raise FragmentRangeError('COMPILER_FRAGMENT_FRONTEND_RANGE_REQUIRED', 'frontend', 'current fragment', None)
    equal('frontend_fragment', fragment_id, frontend_fragment.get('fragmentId') or frontend_fragment.get('id'))
    equal('frontend_ast_range', ast, _range(frontend_fragment.get('astBeginOffset'), frontend_fragment.get('astEndOffset')))
    equal('frontend_replacement_range', replacement, _range(frontend_fragment.get('beginOffset'), frontend_fragment.get('endOffset')))
    try:
        suffix = bytes.fromhex(binding['suffixHex'])
    except (ValueError, TypeError) as exc:
        raise FragmentRangeError('COMPILER_FRAGMENT_SUFFIX_INVALID', 'suffixHex', 'hex bytes', binding['suffixHex']) from exc
    equal('suffix_length', replacement[1] - ast[1], len(suffix))
    equal('suffix_encoding', suffix.hex(), binding['suffixHex'])
    equal('range_relation', 'statement_terminator' if suffix else 'identical', binding['rangeRelation'])
    if (suffix and _TRIVIA.fullmatch(suffix) is None) or not isinstance(binding['astSliceDigest'], str) or re.fullmatch(r'sha256:[0-9a-f]{64}', binding['astSliceDigest']) is None:
        raise FragmentRangeError('COMPILER_FRAGMENT_SUFFIX_INVALID', 'suffix', 'compiler-approved trivia/terminator', binding['suffixHex'])
