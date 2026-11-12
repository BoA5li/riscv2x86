"""Pure loader diagnostic syntax. No filesystem resolution or authority claims."""
import re

PATTERN = re.compile(
    r"\s*(\d+):\s+binding file (.+?) \[(\d+)\] to (.+?) \[(\d+)\]: "
    r"(\S+) symbol `([^']+)'(?: \[([^\]]+)\])?\s*")


def parse(text):
    events, unparsed = [], []
    for ordinal, line in enumerate(text.splitlines()):
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
