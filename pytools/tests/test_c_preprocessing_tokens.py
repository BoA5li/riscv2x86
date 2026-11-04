import shutil
import subprocess
import pytest
from riscv2x86_py.c_preprocessing_tokens import tokens


@pytest.mark.parametrize('joined,separated', [
    ('++', '+ +'), ('--', '- -'), ('->', '- >'), ('&&', '& &'), ('||', '| |'),
    ('<<', '< <'), ('>>', '> >'), ('<=', '< ='), ('>=', '> ='), ('==', '= ='),
    ('!=', '! ='), ('+=', '+ ='), ('-=', '- ='), ('*=', '* ='), ('/=', '/ ='),
    ('%=', '% ='), ('&=', '& ='), ('^=', '^ ='), ('|=', '| ='),
    ('<<=', '<< ='), ('>>=', '>> ='), ('...', '. . .'), ('##', '# #'),
    ('%:%:', '%: %:'), ('<:', '< :'), (':>', ': >'), ('<%', '< %'), ('%>', '% >'),
])
def test_maximal_munch_preserves_operator_boundaries(joined, separated):
    assert tokens(joined) == [joined]
    assert tokens(joined) != tokens(separated)


@pytest.mark.parametrize('text', [
    r'"\n"', r'"a\"b"', r'"a\\b"', r'"\x01"', r"'\n'", r"'\''",
    'L"wide"', 'u8"utf8"', 'u"utf16"', 'U"utf32"', "L'X'", '""',
])
def test_literals_are_one_exact_spelling(text):
    assert tokens(text) == [text]
    assert tokens(text) != tokens(text + ' "other"')


@pytest.mark.parametrize('number', ['.5', '1e+3', '1e-3', '0x1.fp+2', '0x1p-4',
                                  '0.5f', '0xFFULL', '123abc', '1...'])
def test_preprocessing_numbers_are_not_split(number):
    assert tokens(number) == [number]


def test_identifiers_and_adjacency():
    assert tokens('alpha βeta $gcc _x9') == ['alpha', 'βeta', '$gcc', '_x9']
    assert tokens('a b') != tokens('ab')
    assert tokens(r'a\u03B1') == [r'a\u03B1']
    assert tokens('u8 "text"') == ['u8', '"text"']
    assert tokens('"a b"') != tokens('"ab"')


@pytest.mark.parametrize('text', ['/*comment*/', '//comment', '"unterminated', '"line\nbreak"',
                                  '\\', '"trailing\\', '\x00', r'\uD800'])
def test_unhandled_or_malformed_text_is_rejected(text):
    with pytest.raises(ValueError):
        tokens(text)


def test_real_compiler_output_retains_escapes_and_operator_boundaries():
    gcc = shutil.which('gcc')
    if not gcc:
        pytest.skip('native GCC required')
    text = r'''
const char *s = "a\n\"quoted\"\\tail";
int entry(int a, int b) { a++; b = + +b; return (a<<b) + (a< +b); }
'''
    run = subprocess.run([gcc, '-E', '-P', '-x', 'c', '-'], input=text,
                         text=True, capture_output=True, check=False)
    assert run.returncode == 0
    out = tokens(run.stdout)
    assert r'"a\n\"quoted\"\\tail"' in out
    assert '++' in out and '<<' in out
    assert out.count('+') >= 4


def test_directive_newline_is_semantic_but_ordinary_layout_is_not():
    assert tokens('#pragma pack(1)\nstruct S { int x; };') != tokens('#pragma pack(1) struct S { int x; };')
    assert tokens('#pragma pack(1)') == tokens('  #pragma pack(1)\n')
    assert tokens('%:pragma pack(1)\n')[ -1] == '\n'
    assert tokens('int\nx;') == tokens('int x;')
    assert tokens('"#pragma"\n"text"') == ['"#pragma"','"text"']


def test_real_compiler_pragmas_preserve_directive_boundaries():
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('native GCC required')
    result=subprocess.run([gcc,'-E','-P','-x','c','-'],input='#pragma pack(1)\nstruct S { char c; int i; };\n#pragma pack()\n',
                          capture_output=True,text=True,check=True)
    assert tokens(result.stdout).count('\n') == 2
