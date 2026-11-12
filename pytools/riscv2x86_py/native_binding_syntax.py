"""Pure loader diagnostic syntax. No filesystem resolution or authority claims."""
import re
import codecs

HEADER_SOURCE = r"\s*(\d+):\s+binding file (.+?) \[(\d+)\] to (.+?) \[(\d+)\]: "
HEADER = re.compile(HEADER_SOURCE)

PATTERN = re.compile(
    HEADER_SOURCE +
    r"(\S+) symbol `([^']+)'(?: \[([^\]]+)\])?\s*")


def parse(text):
    events, unparsed = [], []
    # Match the byte stream's LF framing, including Unicode in file labels.
    for ordinal, line in enumerate(text.split('\n')):
        if 'binding file ' not in line:
            continue
        match = PATTERN.fullmatch(line)
        if match is None:
            unparsed.append({'line': ordinal, 'text': line})
            continue
        pid, requester, reqns, provider, provns, mode, symbol, version = match.groups()
        events.append({'line': ordinal, 'processId': int(pid),
                       'requesterNamespace': int(reqns), 'providerNamespace': int(provns),
                       'requester': {'kind': 'diagnostic-label', 'label': requester},
                       'provider': {'kind': 'diagnostic-label', 'label': provider},
                       'bindingMode': mode, 'symbol': symbol, 'version': version})
    return events, unparsed


class BindingStream:
    """Observe endpoint headers at each write without inventing prior facts.

    A header is enough to collect labels, never to approve a symbol/version.
    Full records still use parse(). Newlines finish records, not syscalls.
    """
    def __init__(self, line_limit=1024*1024):
        self.pending = b''
        self.line_start = 0
        self.line_limit = line_limit

    def feed(self, raw):
        if not isinstance(raw, bytes) or not raw:
            raise ValueError('BINDING_STREAM_NONEMPTY_BYTES_REQUIRED')
        chunks = (self.pending+raw).split(b'\n')
        observations = []
        for index, chunk in enumerate(chunks):
            complete = index < len(chunks)-1
            size = len(chunk)+(1 if complete else 0)
            if size > self.line_limit:
                raise ValueError('BINDING_STREAM_LINE_BUDGET_EXCEEDED')
            if chunk:
                try:
                    text = codecs.getincrementaldecoder('utf-8')().decode(chunk,final=complete)
                except UnicodeDecodeError as exc:
                    raise ValueError('BINDING_STREAM_UTF8_INVALID') from exc
                match = HEADER.match(text)
                if match:
                    pid, req, reqns, prov, provns = match.groups()
                    observations.append({'lineStart':self.line_start,
                        'headerEnd':self.line_start+len(text[:match.end()].encode('utf-8')),
                        'processId':int(pid),'requesterNamespace':int(reqns),'providerNamespace':int(provns),
                        'requesterLabel':req,'providerLabel':prov})
            if complete:
                self.line_start += size
            else:
                self.pending = chunk
        return observations
