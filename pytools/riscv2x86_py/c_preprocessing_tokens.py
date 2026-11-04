"""C preprocessing tokens, including maximal-munch punctuators and literals.

This lexer compares compiler-preprocessed text. It does not determine whether a
translation unit is valid C, resolve directives or certify compiler semantics.
Token spellings are retained: no literal/attribute/value normalization.
"""
from __future__ import annotations
import re
import unicodedata

VERSION = 'riscv2x86.c11-gnu-pp-token-spellings.v1'
_SPACE = ' \t\r\n\v\f'
_PUNCTUATORS = tuple(sorted({
    '[', ']', '(', ')', '{', '}', '.', '->', '++', '--', '&', '*', '+', '-',
    '~', '!', '/', '%', '<<', '>>', '<', '>', '<=', '>=', '==', '!=', '^',
    '|', '&&', '||', '?', ':', ';', '...', '=', '*=', '/=', '%=', '+=',
    '-=', '<<=', '>>=', '&=', '^=', '|=', ',', '#', '##',
    '<:', ':>', '<%', '%>', '%:', '%:%:'
}, key=lambda s: (-len(s), s)))
_UCN = re.compile(r'\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})')


def _identifier_unit(text, pos, first):
    if pos >= len(text):
        return pos
    if text[pos] == '\\':
        match = _UCN.match(text, pos)
        if not match:
            return pos
        value = int(match[0][2:], 16)
        if value > 0x10ffff or 0xd800 <= value <= 0xdfff:
            raise ValueError('PROJECT_PREPROCESSING_UCN_INVALID')
        ch = chr(value)
        end = match.end()
    else:
        ch = text[pos]
        end = pos + 1
    # GNU C permits '$'. Accepted compiler output still determines validity;
    # this does not expand the set of harness ABI classes.
    category = unicodedata.category(ch)
    start = ch in '_$' or category[0] == 'L' or category == 'Nl'
    continuation = start or category in {'Mn', 'Mc', 'Nd', 'Pc'}
    return end if (start if first else continuation) else pos


def _literal(text, pos):
    for prefix in ('u8', 'u', 'U', 'L', ''):
        start = pos + len(prefix)
        if not text.startswith(prefix, pos) or start >= len(text):
            continue
        quote = text[start]
        if quote not in "'\"":
            continue
        i = start + 1
        while i < len(text):
            ch = text[i]
            if ch == quote:
                return i + 1
            if ch in '\r\n':
                raise ValueError('PROJECT_PREPROCESSING_LITERAL_NEWLINE')
            if ch == '\\':
                i += 1
                if i >= len(text) or text[i] in '\r\n':
                    raise ValueError('PROJECT_PREPROCESSING_LITERAL_ESCAPE_INVALID')
            i += 1
        raise ValueError('PROJECT_PREPROCESSING_LITERAL_UNTERMINATED')
    return pos


def tokens(text):
    """Retain token boundaries; reject unhandled input instead of splitting it."""
    if not isinstance(text, str):
        raise ValueError('PROJECT_PREPROCESSING_TEXT_REQUIRED')
    out = []
    pos = 0
    line_start = True
    directive = False
    while pos < len(text):
        if text[pos] in _SPACE:
            if text[pos] == '\n':
                if directive:
                    out.append('\n')
                directive = False
                line_start = True
            pos += 1
            continue
        # Comments must already have been replaced by the compiler. Ignoring
        # them here could hide literal/token or -C/-CC recipe discrepancies.
        if text.startswith(('/*', '//'), pos):
            raise ValueError('PROJECT_PREPROCESSING_UNEXPECTED_COMMENT')
        end = _literal(text, pos)
        if end == pos and (text[pos].isascii() and text[pos].isdigit()
                           or text[pos] == '.' and pos + 1 < len(text)
                           and text[pos + 1].isascii() and text[pos + 1].isdigit()):
            end = pos + 1
            while end < len(text):
                if text[end] in '+-' and text[end - 1] in 'eEpP':
                    end += 1
                elif text[end] == '.':
                    end += 1
                else:
                    next_end = _identifier_unit(text, end, False)
                    if next_end == end:
                        break
                    end = next_end
        if end == pos:
            end = _identifier_unit(text, pos, True)
            while end != pos:
                next_end = _identifier_unit(text, end, False)
                if next_end == end:
                    break
                end = next_end
        if end == pos:
            punct = next((p for p in _PUNCTUATORS if text.startswith(p, pos)), None)
            if punct is None:
                raise ValueError('PROJECT_PREPROCESSING_TOKEN_UNSUPPORTED:' + repr(text[pos:pos + 16]))
            end = pos + len(punct)
        token = text[pos:end]
        if line_start and token in {'#', '%:'}:
            directive = True
        line_start = False
        out.append(token)
        pos = end
    if directive:
        out.append('\n')
    return out
