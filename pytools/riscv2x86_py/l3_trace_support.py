"""Small immutable-file and ELF helpers for the registered TCG trace route."""
from hashlib import sha256
import json
import math
from pathlib import Path
import struct
import subprocess
import sys
from contextlib import redirect_stdout


def emit_json(operation):
    """Reserve stdout for one JSON document; nested diagnostics go to stderr.

    Exceptions still propagate and the receiving process parses the entire
    stdout. This is output-channel ownership, not response recovery.
    """
    with redirect_stdout(sys.stderr):
        response = operation()
        encoded = json.dumps(response, sort_keys=True)
    print(encoded, flush=True)


def digest(path):
    return 'sha256:' + sha256(Path(path).read_bytes()).hexdigest()


def identity(value):
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def require_json_document(value, code='L3_JSON_DOCUMENT_INVALID'):
    """Require a lossless JSON-native DTO; do not coerce tuples, keys or types.

    Internal symbolic terms may use tuples. Only exported/persisted DTOs cross
    this boundary. Booleans and integers remain distinct during replay.
    """
    active = set()
    def visit(item, path):
        kind = type(item)
        if kind in (str, bool, int, type(None)):
            return
        if kind is float and math.isfinite(item):
            return
        if kind not in (dict, list) or id(item) in active:
            raise ValueError(code + ':' + json.dumps(
                {'path': path, 'type': kind.__name__, 'reason': 'non-json-native-or-cyclic'}, sort_keys=True))
        active.add(id(item))
        if kind is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError(code + ':' + json.dumps(
                        {'path': path, 'type': type(key).__name__, 'reason': 'non-string-key'}, sort_keys=True))
                visit(child, path + '[' + json.dumps(key) + ']')
        else:
            for index, child in enumerate(item):
                visit(child, path + '[' + str(index) + ']')
        active.remove(id(item))
    visit(value, '$')
    return value


def require_json_match(expected, actual, code):
    """Strict, type-preserving structural equality with bounded diagnostics.

    This checks every field, including identities; it neither drops fields nor
    equates documents merely because their serialized hashes match.
    """
    require_json_document(expected, code)
    require_json_document(actual, code)
    def difference(a, b, path):
        if type(a) is not type(b):
            return {'path': path, 'reason': 'type', 'expectedType': type(a).__name__, 'actualType': type(b).__name__}
        if type(a) is dict:
            if set(a) != set(b):
                return {'path': path, 'reason': 'keys', 'missing': sorted(set(a)-set(b)), 'extra': sorted(set(b)-set(a))}
            for key in sorted(a):
                found = difference(a[key], b[key], path + '[' + json.dumps(key) + ']')
                if found is not None: return found
        elif type(a) is list:
            if len(a) != len(b):
                return {'path': path, 'reason': 'length', 'expectedLength': len(a), 'actualLength': len(b)}
            for index, (left, right) in enumerate(zip(a, b)):
                found = difference(left, right, path + '[' + str(index) + ']')
                if found is not None: return found
        elif a != b:
            return {'path': path, 'reason': 'value', 'expected': repr(a)[:160], 'actual': repr(b)[:160]}
        return None
    detail = difference(expected, actual, '$')
    if detail is not None:
        raise ValueError(code + ':' + json.dumps(detail, sort_keys=True))


def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
    return path


def run(command, directory, tag, timeout=120, *, env=None):
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    command = list(map(str, command))
    try:
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True,
                                timeout=timeout, check=False, env=env)
        record = {'command': command, 'returnCode': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr, 'timedOut': False}
    except subprocess.TimeoutExpired as exc:
        record = {'command': command, 'returnCode': None, 'stdout': '',
                  'stderr': str(exc), 'timedOut': True}
        save(directory / (tag + '.command.json'), record)
        raise ValueError('L3_TRACE_TIMEOUT:' + tag) from exc
    except OSError as exc:
        record = {'command': command, 'returnCode': None, 'stdout': '',
                  'stderr': str(exc), 'timedOut': False, 'startupFailed': True}
        save(directory / (tag + '.command.json'), record)
        raise ValueError('L3_TRACE_COMMAND_START_FAILED:' + tag) from exc
    if env is not None:
        record['gitNetworkPolicy'] = env.get('GIT_ALLOW_PROTOCOL', '')
    save(directory / (tag + '.command.json'), record)
    if result.returncode:
        raise ValueError('L3_TRACE_COMMAND_FAILED:' + tag + ':' + result.stderr[-2000:])
    return result


class Elf:
    """Bounds-checked ELF64 little-endian symbol reader; no external decoder."""
    def __init__(self, path):
        self.path = Path(path); self.data = self.path.read_bytes()
        if self.data[:6] != b'\x7fELF\x02\x01' or len(self.data) < 64:
            raise ValueError('L3_TRACE_ELF64_LE_REQUIRED')
        self.type, self.machine = struct.unpack_from('<HH', self.data, 16)
        offset = struct.unpack_from('<Q', self.data, 40)[0]
        entry_size, count, strings = struct.unpack_from('<HHH', self.data, 58)
        if entry_size != 64 or not count or strings >= count:
            raise ValueError('L3_TRACE_ELF_SECTION_TABLE_INVALID')
        self.sections = [struct.unpack('<IIQQQQIIQQ', self.slice(offset+i*64, 64)) for i in range(count)]
        self.symbols = {}
        for table_index, section in enumerate(self.sections):
            if section[1] not in (2, 11): continue
            if section[9] != 24 or section[5] % 24 or section[6] >= count:
                raise ValueError('L3_TRACE_ELF_SYMBOL_TABLE_INVALID')
            table = self.sections[section[6]]
            if table[1] != 3:
                raise ValueError('L3_TRACE_ELF_STRING_TABLE_INVALID')
            names = self.slice(table[4], table[5])
            for i in range(section[5] // 24):
                name, info, other, idx, value, size = struct.unpack('<IBBHQQ', self.slice(section[4]+i*24, 24))
                if name >= len(names): raise ValueError('L3_TRACE_ELF_SYMBOL_NAME_INVALID')
                end = names.find(b'\0', name)
                if end < 0: raise ValueError('L3_TRACE_ELF_SYMBOL_NAME_INVALID')
                try:
                    label = names[name:end].decode('utf-8')
                except UnicodeDecodeError as exc:
                    raise ValueError('L3_TRACE_ELF_SYMBOL_NAME_INVALID') from exc
                if idx and idx < count and label:
                    # STB_LOCAL names have translation-unit scope. Retain all
                    # definitions and table provenance; resolve only on demand.
                    record = {'symbol': (value, size, idx, info & 15),
                              'binding': info >> 4, 'visibility': other & 3,
                              'tableIndex': table_index, 'entryIndex': i}
                    self.symbols.setdefault(label, []).append(record)

    def slice(self, offset, size):
        if offset < 0 or size < 0 or offset+size > len(self.data):
            raise ValueError('L3_TRACE_ELF_RANGE_INVALID')
        return self.data[offset:offset+size]

    def symbol(self, name):
        candidates = self.symbols.get(name, [])
        if not candidates: raise ValueError('L3_TRACE_ELF_SYMBOL_MISSING:' + name)
        # A name-only public query denotes its external definition when one
        # exists. Multiple distinct external definitions remain ambiguous;
        # weak/global strength is not permission to choose arbitrary bytes.
        external = [r for r in candidates if r['binding'] in (1, 2, 10)]
        candidates = external or candidates
        definitions = {(r['symbol'], r['binding'], r['visibility']) for r in candidates}
        if len(definitions) != 1:
            raise ValueError('L3_TRACE_ELF_AMBIGUOUS_SYMBOL:' + name)
        return next(iter(definitions))[0]

    def code(self, name):
        address, size, index, kind = self.symbol(name)
        section = self.sections[index]
        if kind != 2 or not size or not section[2] & 4 or address < section[3] or address+size > section[3]+section[5]:
            raise ValueError('L3_TRACE_ELF_FUNCTION_RANGE_INVALID:' + name)
        return self.slice(section[4]+address-section[3], size)

    def execution_image(self):
        """Loadable segments plus entry/ABI; exclude nonloaded FILE symbols.

        Build IDs are disabled for deployment builds. ELF section-table header
        fields describe nonloaded metadata, not executed bytes. Other segment
        bytes and program headers remain compared, including read-only data.
        """
        phoff = struct.unpack_from('<Q', self.data, 32)[0]
        phsize, count = struct.unpack_from('<HH', self.data, 54)
        if phsize != 56 or not count: raise ValueError('L3_TRACE_ELF_PROGRAM_HEADERS_INVALID')
        segments=[]
        for i in range(count):
            kind, flags, offset, virtual, physical, filesz, memsz, alignment = struct.unpack(
                '<IIQQQQQQ', self.slice(phoff+i*56,56))
            if kind != 1: continue
            if filesz>memsz: raise ValueError('L3_TRACE_ELF_LOAD_RANGE_INVALID')
            content=bytearray(self.slice(offset,filesz))
            if offset==0:
                if len(content)<64: raise ValueError('L3_TRACE_ELF_HEADER_LOAD_INVALID')
                # Only e_shoff/e_shentsize/e_shnum/e_shstrndx are excluded.
                content[40:48]=b'\0'*8
                content[58:64]=b'\0'*6
            segments.append({'address':virtual,'physical':physical,'flags':flags,
                'fileSize':filesz,'memorySize':memsz,'alignment':alignment,
                'digest':'sha256:'+sha256(content).hexdigest()})
        if not segments: raise ValueError('L3_TRACE_ELF_LOAD_SEGMENTS_MISSING')
        return {'machine':self.machine,'type':self.type,
                'entry':struct.unpack_from('<Q',self.data,24)[0],
                'abiFlags':struct.unpack_from('<I',self.data,48)[0],'segments':segments}

    def region(self, function):
        first = self.symbol('__rv2x86_fragment_begin'); last = self.symbol('__rv2x86_fragment_end')
        start, size, idx, _ = self.symbol(function)
        if first[2] != idx or last[2] != idx or not start <= first[0] < last[0] < start+size:
            raise ValueError('L3_TRACE_FRAGMENT_REGION_INVALID')
        return {'start': first[0], 'end': last[0], 'function': function,
                'functionStart': start, 'functionSize': size}
