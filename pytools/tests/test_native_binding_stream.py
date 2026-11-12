"""Byte-stream syntax tests; these do not assert stopped-process authenticity."""
import pytest

from riscv2x86_py.native_binding_syntax import BindingStream, parse


@pytest.mark.parametrize('tail',[b'\n',b' [VERSION_1]\n',b' [VERSION_1]',b''])
def test_header_is_observed_before_version_or_newline_and_retained_in_tail(tail):
    body=b"41: binding file /alias/a [0] to /alias/b [0]: normal symbol `export'"
    stream=BindingStream();first=stream.feed(body)
    assert len(first)==1
    if tail:assert stream.feed(tail)==first
    events,unknown=parse((body+tail).decode())
    assert len(events)==1 and not unknown
    assert events[0]['version']==('VERSION_1' if b'VERSION' in tail else None)


def test_every_byte_cut_including_utf8_headers_has_causal_observations():
    raw="41: binding file /路径/a [0] to /路径/b [0]: normal symbol `export' [V]\n".encode()
    expected=BindingStream().feed(raw)
    for cut in range(1,len(raw)):
        stream=BindingStream();first=stream.feed(raw[:cut]);second=stream.feed(raw[cut:])
        assert second==expected
        if first:assert first==expected and first[0]['headerEnd']<=cut
    stream=BindingStream()
    for i,byte in enumerate(raw):
        for header in stream.feed(bytes([byte])):
            assert header['headerEnd']<=i+1


def test_multiple_records_and_pending_tail_keep_absolute_offsets():
    a=b"41: binding file /a [0] to /b [0]: normal symbol `x'"
    b=b"41: binding file /c [0] to /d [0]: normal symbol `y'"
    stream=BindingStream();headers=stream.feed(b'noise\n'+a+b'\n'+b)
    assert [h['lineStart'] for h in headers]==[6,6+len(a)+1]
    assert stream.feed(b' [V]\n')==[headers[1]]
    assert stream.feed(b'noise\n')==[]


def test_terminating_previous_record_does_not_leak_labels_into_next_record():
    raw=b"41: binding file /a [0] to /b [0]: normal symbol `x'\n"
    stream=BindingStream();stream.feed(raw)
    assert stream.feed(b'\n')==[]
    assert stream.feed(b'41: binding fi')==[]


def test_partial_header_is_not_a_final_binding_or_a_retroactive_observation():
    prefix=b'41: binding file /a [0] to /'
    stream=BindingStream();assert stream.feed(prefix)==[]
    headers=stream.feed(b"b [0]: unknown symbol `x' [V]\n")
    assert len(headers)==1 and headers[0]['lineStart']==0
    assert parse(prefix.decode())[0]==[]


def test_line_budget_and_invalid_utf8_are_explicit_failures():
    stream=BindingStream(line_limit=32);stream.feed(b'x'*16)
    with pytest.raises(ValueError,match='LINE_BUDGET'):stream.feed(b'x'*17)
    with pytest.raises(ValueError,match='UTF8_INVALID'):BindingStream().feed(b'\xff\n')


def test_unicode_line_separator_in_label_does_not_change_byte_record_framing():
    line="41: binding file /a\u2028b [0] to /c [0]: normal symbol `x'\n"
    events,unknown=parse(line+line)
    assert not unknown and [e['line'] for e in events]==[0,1]
    headers=BindingStream().feed((line+line).encode())
    assert [h['lineStart'] for h in headers]==[0,len(line.encode())]
