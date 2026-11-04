"""Import build observations without executing shell text or granting acceptance.

A log is an observation, not proof of an action's exit status. Structured argv is
preferred. Shell expansion, pipelines, response files and implicit cwd changes
remain unresolved; they are never silently flattened into compilation commands.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import shlex


def identity(value):
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=False).encode()).hexdigest()


def logical_lines(text):
    """Remove POSIX backslash-newline only outside single quotes; retain ranges."""
    lines = text.splitlines(keepends=True)
    buffer = ''; start = 1; quote = None; escaped = False
    for number, physical in enumerate(lines, 1):
        if not buffer: start = number
        i = 0
        while i < len(physical):
            ch = physical[i]
            if ch == '\\' and quote != "'" and not escaped:
                ending = physical[i + 1:]
                if ending in ('\n', '\r\n'):
                    i = len(physical)
                    break
                escaped = True; buffer += ch; i += 1; continue
            if escaped:
                escaped = False
            elif ch in ("'", '"'):
                if quote is None: quote = ch
                elif quote == ch: quote = None
            buffer += ch; i += 1
        else:
            yield {'lineStart': start, 'lineEnd': number, 'text': buffer.rstrip('\r\n')}
            buffer = ''; quote = None; escaped = False
            continue
        # A continuation at EOF is not a complete command.
        if number == len(lines):
            yield {'lineStart': start, 'lineEnd': number, 'text': buffer,
                   'error': 'BUILD_LOG_DANGLING_CONTINUATION'}
            buffer = ''


def shell_argv(text):
    # Detect expansions before shlex removes quoting. Expansion in single quotes
    # is literal; quoted shell metacharacters are literal arguments as well.
    quote = None; escaped = False
    for ch in text:
        if escaped: escaped = False; continue
        if ch == '\\' and quote != "'": escaped = True; continue
        if ch in ("'", '"'):
            if quote is None: quote = ch
            elif quote == ch: quote = None
            continue
        if quote != "'" and ch in '$`':
            raise ValueError('BUILD_SHELL_EXPANSION_UNSUPPORTED')
        if quote is None and ch in '|;&<>()\n\r':
            raise ValueError('BUILD_SHELL_CONTROL_UNSUPPORTED')
    if quote is not None or escaped:
        raise ValueError('BUILD_SHELL_QUOTING_INVALID')
    return shlex.split(text, comments=False, posix=True)


def classify(argv):
    if not argv: return 'empty'
    name = Path(argv[0]).name
    if name in {'cd','pushd','popd','sh','bash','dash'} or re.match(r'^[A-Za-z_][A-Za-z_0-9]*=', name):
        return 'unresolved-shell'
    if name in {'ccache', 'sccache', 'distcc', 'env'}:
        return 'unresolved-wrapper'
    if re.fullmatch(r'(?:.*-)?(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+)(?:-\d+(?:\.\d+)*)?', name):
        if '-c' in argv:
            return 'assemble' if any(a.endswith(('.s', '.S')) for a in argv[1:]) else 'compile'
        if '-E' in argv: return 'preprocess'
        if '-S' in argv: return 'emit-assembly'
        return 'link'
    if re.fullmatch(r'(?:.*-)?ar', name): return 'archive'
    if re.fullmatch(r'(?:.*-)?ranlib', name): return 'ranlib'
    if name in {'cp', 'install', 'mv'}: return 'copy'
    return 'other'


def record(argv, directory, provenance, *, file=None, output=None):
    if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or not a for a in argv):
        raise ValueError('BUILD_ARGUMENTS_INVALID')
    cwd = Path(directory).resolve()
    body = {'directory': str(cwd), 'arguments': argv, 'kind': classify(argv),
            'provenance': provenance, 'exitStatusObserved': False}
    if file is not None: body['file'] = str(file)
    if output is not None: body['output'] = str(output)
    return dict(body, actionIdentity=identity(body))


def import_log(path, directory):
    path = Path(path).resolve(); raw = path.read_bytes()
    rows = []; unresolved = []; ignored = []
    digest = 'sha256:' + sha256(raw).hexdigest()
    for line in logical_lines(raw.decode('utf-8', errors='strict')):
        text = line['text'].strip()
        if not text: continue
        provenance = {'kind': 'build-log', 'path': str(path), 'digest': digest,
                      'lineStart': line['lineStart'], 'lineEnd': line['lineEnd'],
                      'rawLogicalText': line['text']}
        try:
            if line.get('error'): raise ValueError(line['error'])
            # Diagnostics and progress lines are retained but are not shell
            # recipes. Recognize the executable before parsing its full tail.
            first = shlex.shlex(text, posix=True); first.whitespace_split = True
            first.commenters = ''
            executable = next(first, '')
            if classify([executable]) == 'other':
                if re.search(r'make(?:\[\d+\])?: (?:Entering|Leaving) directory', text):
                    match = re.search(r"directory ['`](.*)['’]$", text)
                    if not match or Path(match[1]).resolve() != Path(directory).resolve():
                        raise ValueError('BUILD_LOG_WORKING_DIRECTORY_UNRESOLVED')
                ignored.append(provenance)
                continue
            argv = shell_argv(text)
            kind = classify(argv)
            if kind in {'other', 'empty'}:
                ignored.append(provenance)
            elif kind == 'unresolved-shell':
                raise ValueError('BUILD_SHELL_CONTEXT_UNRESOLVED')
            elif kind == 'unresolved-wrapper':
                raise ValueError('BUILD_COMPILER_WRAPPER_UNRESOLVED')
            else:
                rows.append(record(argv, directory, provenance))
        except ValueError as exc:
            unresolved.append(dict(provenance, reasonCode=str(exc)))
    return document(rows, unresolved, ignored, digest)


def import_database(path):
    path = Path(path).resolve(); raw = path.read_bytes(); digest = 'sha256:' + sha256(raw).hexdigest()
    source = json.loads(raw)
    if not isinstance(source, list): raise ValueError('BUILD_DATABASE_ARRAY_REQUIRED')
    rows = []; unresolved = []
    for index, item in enumerate(source):
        provenance = {'kind': 'compile-database', 'path': str(path), 'digest': digest, 'index': index}
        try:
            if not isinstance(item, dict) or not isinstance(item.get('directory'), str):
                raise ValueError('BUILD_DATABASE_RECORD_INVALID')
            directory = Path(item['directory'])
            if not directory.is_absolute(): raise ValueError('BUILD_DATABASE_ABSOLUTE_DIRECTORY_REQUIRED')
            if not isinstance(item.get('file'), str) or not item['file']:
                raise ValueError('BUILD_DATABASE_SOURCE_REQUIRED')
            argv = item.get('arguments')
            if argv is None:
                if not isinstance(item.get('command'), str): raise ValueError('BUILD_DATABASE_COMMAND_REQUIRED')
                argv = shell_argv(item['command'])
            rows.append(record(argv, directory, provenance, file=item['file'], output=item.get('output')))
        except ValueError as exc:
            unresolved.append(dict(provenance, reasonCode=str(exc)))
    return document(rows, unresolved, [], digest)


def document(rows, unresolved, ignored, digest):
    body = {'schemaVersion': 'riscv2x86.project-build-records.v1', 'inputDigest': digest,
            'actions': rows, 'unresolved': unresolved, 'unclassifiedLines': ignored,
            'actionCounts': dict(sorted(Counter(r['kind'] for r in rows).items())),
            'importComplete': not unresolved, 'buildSuccessVerified': False,
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, inventoryIdentity=identity(body))
