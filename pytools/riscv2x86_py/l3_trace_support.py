"""Small immutable-file and ELF helpers for the registered TCG trace route."""
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess


def digest(path):
    return 'sha256:' + sha256(Path(path).read_bytes()).hexdigest()


def identity(value):
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
    return path


def run(command, directory, tag, timeout=120):
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    command = list(map(str, command))
    try:
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True,
                                timeout=timeout, check=False)
        record = {'command': command, 'returnCode': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr, 'timedOut': False}
    except subprocess.TimeoutExpired as exc:
        record = {'command': command, 'returnCode': None, 'stdout': '',
                  'stderr': str(exc), 'timedOut': True}
        save(directory / (tag + '.command.json'), record)
        raise ValueError('L3_TRACE_TIMEOUT:' + tag) from exc
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
        for section in self.sections:
            if section[1] not in (2, 11): continue
            if section[9] != 24 or section[5] % 24 or section[6] >= count:
                raise ValueError('L3_TRACE_ELF_SYMBOL_TABLE_INVALID')
            table = self.sections[section[6]]
            names = self.slice(table[4], table[5])
            for i in range(section[5] // 24):
                name, info, other, idx, value, size = struct.unpack('<IBBHQQ', self.slice(section[4]+i*24, 24))
                if name >= len(names): raise ValueError('L3_TRACE_ELF_SYMBOL_NAME_INVALID')
                label = names[name:].split(b'\0', 1)[0].decode('utf-8')
                if idx and idx < count and label:
                    symbol = (value, size, idx, info & 15)
                    if label in self.symbols and self.symbols[label] != symbol:
                        raise ValueError('L3_TRACE_ELF_AMBIGUOUS_SYMBOL:' + label)
                    self.symbols[label] = symbol

    def slice(self, offset, size):
        if offset < 0 or size < 0 or offset+size > len(self.data):
            raise ValueError('L3_TRACE_ELF_RANGE_INVALID')
        return self.data[offset:offset+size]

    def symbol(self, name):
        if name not in self.symbols: raise ValueError('L3_TRACE_ELF_SYMBOL_MISSING:' + name)
        return self.symbols[name]

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
