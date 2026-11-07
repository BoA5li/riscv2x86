"""Bind an explicitly selected captured test ELF to its dependency metadata.

No basename selects a test, no process is executed, and a DT_NEEDED record is
not treated as evidence of the library actually loaded at runtime.
"""
from pathlib import Path
import struct

from .project_build_records import identity
from .project_compile_context import digest
from .project_native_binding import read
from .l3_trace_support import Elf, require_json_match


def metadata(path, expected_machine=243):
    elf = Elf(path)
    if expected_machine not in (243, 62) or type(expected_machine) is not int:
        raise ValueError('NATIVE_TEST_EXPECTED_MACHINE_INVALID')
    if elf.machine != expected_machine or elf.type not in (2, 3):
        raise ValueError('NATIVE_TEST_RV64_EXECUTABLE_REQUIRED' if expected_machine == 243
                         else 'NATIVE_TEST_X86_64_EXECUTABLE_REQUIRED')
    header = elf.data
    phoff = struct.unpack_from('<Q', header, 32)[0]
    size, count = struct.unpack_from('<HH', header, 54)
    if size != 56 or not count:
        raise ValueError('NATIVE_TEST_PROGRAM_HEADERS_REQUIRED')
    interpreter = []
    for index in range(count):
        kind, flags, offset, _, _, filesz, _, _ = struct.unpack('<IIQQQQQQ', elf.slice(phoff+index*size, size))
        if kind == 3:
            value = elf.slice(offset, filesz)
            if not value.endswith(b'\0') or b'\0' in value[:-1]:
                raise ValueError('NATIVE_TEST_INTERPRETER_INVALID')
            interpreter.append(value[:-1].decode('utf-8'))
    if len(interpreter) > 1:
        raise ValueError('NATIVE_TEST_MULTIPLE_INTERPRETERS')
    result = {'interpreter': interpreter[0] if interpreter else None,
        'elfMachine': elf.machine, 'elfType': elf.type, 'needed': [], 'rpath': [], 'runpath': []}
    for section in elf.sections:
        if section[1] != 6:
            continue
        if section[9] != 16 or section[5] % 16 or section[6] >= len(elf.sections):
            raise ValueError('NATIVE_TEST_DYNAMIC_TABLE_INVALID')
        names_section = elf.sections[section[6]]
        if names_section[1] != 3:
            raise ValueError('NATIVE_TEST_DYNAMIC_STRINGS_REQUIRED')
        names = elf.slice(names_section[4], names_section[5])
        terminated = False
        for index in range(section[5]//16):
            tag, value = struct.unpack('<qQ', elf.slice(section[4]+16*index, 16))
            if tag == 0:
                terminated = True; break
            if tag not in (1, 15, 29):
                continue
            end = names.find(b'\0', value)
            if value >= len(names) or end < 0:
                raise ValueError('NATIVE_TEST_DYNAMIC_STRING_INVALID')
            result[{1: 'needed', 15: 'rpath', 29: 'runpath'}[tag]].append(names[value:end].decode('utf-8'))
        if not terminated:
            raise ValueError('NATIVE_TEST_DYNAMIC_TERMINATOR_REQUIRED')
    return result


def acquire(records_path, action_identity, *, expected_machine=None):
    path = Path(records_path).resolve(strict=True); before = digest(path); records = read(path)
    if (records.get('schemaVersion') != 'riscv2x86.project-build-records.v1'
            or records.get('inventoryIdentity') != identity({k: v for k, v in records.items() if k != 'inventoryIdentity'})):
        raise ValueError('NATIVE_TEST_BUILD_RECORDS_INVALID')
    from .project_build_capture import inventory
    fresh = inventory(records['captureConfig'], stage=records['stageSelection'])
    if not fresh['importComplete'] or fresh['unresolved'] or fresh['selectedRunFailures']:
        raise ValueError('NATIVE_TEST_CAPTURE_REPLAY_FAILED')
    require_json_match(records['actions'], fresh['actions'], 'NATIVE_TEST_CAPTURE_ACTIONS_CHANGED')
    matches = [a for a in records['actions'] if a['actionIdentity'] == action_identity]
    if len(matches) != 1:
        raise ValueError('NATIVE_TEST_EXPLICIT_LINK_ACTION_REQUIRED')
    action = matches[0]
    if (action['kind'] != 'link' or action['exitStatusObserved'] is not True
            or type(action.get('observedReturnCode')) is not int or action['observedReturnCode'] != 0):
        raise ValueError('NATIVE_TEST_SUCCESSFUL_CAPTURED_LINK_REQUIRED')
    observed = action.get('observedOutput')
    if not isinstance(observed, dict):
        raise ValueError('NATIVE_TEST_OBSERVED_OUTPUT_REQUIRED')
    executable = Path(observed['path']); artifact_digest = digest(executable)
    if artifact_digest != observed['digest'] or str(executable.resolve(strict=True)) != observed['resolvedPath']:
        raise ValueError('NATIVE_TEST_EXECUTABLE_CHANGED')
    detail = metadata(executable, 243 if expected_machine is None else expected_machine)
    expected_header = {'byteOrder': 'little', 'classBits': 64,
        'machine': detail['elfMachine'], 'type': detail['elfType']}
    require_json_match(expected_header, observed['elfHeader'], 'NATIVE_TEST_CAPTURED_ELF_HEADER_MISMATCH')
    if digest(path) != before or digest(executable) != artifact_digest:
        raise ValueError('NATIVE_TEST_CLOSING_INPUT_CHANGED')
    body = {'schemaVersion': 'riscv2x86.native-test-entry-metadata.v1',
        'recordsPath': str(path), 'recordsDigest': before, 'actionIdentity': action_identity,
        'executablePath': str(executable), 'executableDigest': artifact_digest,
        'metadata': detail, 'capturedOutputBindingVerified': True,
        'runtimeLibrarySelectionVerified': False, 'testExecutionPerformed': False,
        'targetAsmExecutionCoverageVerified': False, 'legalObjectDomainVerified': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    if expected_machine is not None:
        body.update(schemaVersion='riscv2x86.native-test-entry-metadata.v2',
                    expectedMachine=expected_machine)
    return dict(body, entryMetadataIdentity=identity(body))


def replay(value):
    if value.get('entryMetadataIdentity') != identity({k:v for k,v in value.items() if k != 'entryMetadataIdentity'}):
        raise ValueError('NATIVE_TEST_ENTRY_METADATA_IDENTITY_INVALID')
    schema = value.get('schemaVersion')
    if schema not in ('riscv2x86.native-test-entry-metadata.v1', 'riscv2x86.native-test-entry-metadata.v2'):
        raise ValueError('NATIVE_TEST_ENTRY_SCHEMA_INVALID')
    options = {} if schema.endswith('.v1') else {'expected_machine': value['expectedMachine']}
    require_json_match(acquire(value['recordsPath'], value['actionIdentity'], **options), value,
        'NATIVE_TEST_ENTRY_METADATA_REPLAY_MISMATCH')
    return {'entryMetadataReplayComplete': True, 'entryMetadataIdentity': value['entryMetadataIdentity'],
        'semanticApproval': False, 'productionAcceptanceComplete': False}
