"""Real native linked code and synthetic ELF-wrapped RV64 decoder fixtures.

The RV64 fixtures are not cross-built or executed and prove no program ABI.
Compiler-owner ingress for project tests is explicitly mocked.
"""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import struct
import subprocess

import pytest
from riscv2x86_py import program_machine_inventory as m, native_captured_deployment as d
from riscv2x86_py import native_original_applicability as app
from riscv2x86_py import native_project_evaluation as p
from .test_native_project_evaluation import toy_project
from .test_native_captured_deployment import captured


@pytest.fixture
def binary(tmp_path):
    cc = shutil.which('gcc')
    if not cc: pytest.skip('native GCC required')
    source = tmp_path / 'machine.S'
    source.write_text('.text\n.globl sample\n.type sample,@function\nsample:\n'
        'test %rdi,%rdi\nje 1f\ncall helper\nmov (%rdi),%rax\n1: ret\n.rept 20\nnop\n.endr\n.size sample,.-sample\n'
        '.globl helper\n.type helper,@function\nhelper: mov %rdi,%rax\nret\n.size helper,.-helper\n'
        '.section .note.GNU-stack,"",@progbits\n')
    result = tmp_path / 'machine.so'
    subprocess.run([cc, '-shared', '-fPIC', str(source), '-o', str(result)], check=True, capture_output=True)
    return result


def rv_elf(code):
    """Minimal sectioned ELF fixture around exact RV bytes, no runtime loader."""
    names = b'\0.text\0.symtab\0.strtab\0.shstrtab\0'; strings = b'\0rv\0'
    payload = bytearray(64); text_offset = len(payload); payload.extend(code)
    sym_offset = (len(payload) + 7) & ~7; payload.extend(b'\0' * (sym_offset - len(payload)))
    payload.extend(bytes(24) + struct.pack('<IBBHQQ', 1, 0x12, 0, 1, 4096, len(code)))
    str_offset = len(payload); payload.extend(strings); names_offset = len(payload); payload.extend(names)
    shoff = (len(payload) + 7) & ~7; payload.extend(b'\0' * (shoff - len(payload)))
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (1, 1, 6, 4096, text_offset, len(code), 0, 0, 2, 0),
                (7, 2, 0, 0, sym_offset, 48, 3, 1, 8, 24),
                (15, 3, 0, 0, str_offset, len(strings), 0, 0, 1, 0),
                (23, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)]
    for row in sections: payload.extend(struct.pack('<IIQQQQIIQQ', *row))
    payload[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                              3, 243, 1, 0, 0, shoff, 5, 64, 0, 0, 64, 5, 4)
    return bytes(payload)


def test_nonleaf_native_branches_calls_and_accesses_are_inventoried(binary):
    value = m.derive(binary.read_bytes(), 'sample')
    assert value['linearByteDecodeComplete'] and value['decodedByteCount'] == value['byteSize']
    assert {op['opcode'] for op in value['controlOperations']} >= {'CALL', 'CBRANCH', 'RETURN'}
    assert value['memoryOperations']
    assert not value['controlFlowGraphVerified'] and not value['machineAbiClosureVerified']
    assert not value['legalObjectDomainVerified'] and not value['candidateInstructionExecutionCoverageVerified']
    assert m.derive(binary.read_bytes(), 'sample') == value


def test_rv64_actual_instruction_bytes_and_compressed_instruction():
    # c.nop; addi a0,a0,1; ld a0,0(a0); ret
    value = m.derive(rv_elf(bytes.fromhex('0100130515000335050067800000')), 'rv')
    assert value['linearByteDecodeComplete']
    assert [r['size'] for r in value['instructions']] == [2, 4, 4, 4]
    assert value['memoryOperations'] and value['controlOperations']
    assert value['machine'] == 243 and not value['machineAbiClosureVerified']
    assert m.decoder(243)['language'] == m.LANGUAGES[243]


def test_partial_decode_and_budget_do_not_report_complete(binary, monkeypatch):
    value = m.derive(rv_elf(bytes.fromhex('13051500ff')), 'rv')
    assert not value['linearByteDecodeComplete'] and value['gaps']
    monkeypatch.setattr(m, 'MAX_OPS', 0)
    value = m.derive(binary.read_bytes(), 'sample')
    assert not value['linearByteDecodeComplete'] and value['decodedByteCount'] == 0
    assert value['gaps'][0]['reasonCode'] == 'MACHINE_PCODE_BUDGET_EXCEEDED'


def test_symbol_metadata_is_unique_and_region_is_bounded(binary):
    with pytest.raises(ValueError, match='UNIQUE_SIZED_SYMBOL'): m.derive(binary.read_bytes(), 'absent')
    with pytest.raises(ValueError, match='ELF64_LE_REQUIRED'): m.derive(b'not-elf', 'absent')


@pytest.fixture
def machine_project(toy_project, monkeypatch):
    root, _, spec, programs = toy_project
    ast = {'kind': 'TranslationUnitDecl', 'inner': [
        {'kind': 'FunctionDecl', 'id': 'fixture-declaration', 'mangledName': 'value'}]}
    records = [{'functionAstPath': [0], 'instanceBindingIdentity': 'fixture-instance'}]
    specfile = root / 'machine-project.json'; p.write(specfile, spec)
    monkeypatch.setattr(app, 'context', lambda path: (spec, ast, records, b'', {}))
    builds = {side: p.build_record(programs[side], spec, side) for side in ('source', 'target')}
    return root, specfile, spec, ast, builds


def test_current_build_receipts_and_machine_facts_are_rederived(machine_project):
    root, specfile, _, _, builds = machine_project
    file = root / 'machine-inventory.json'; value = m.acquire(specfile, builds, file)
    assert len(value['facts']['functions']) == 2
    assert all(row['facts']['linearByteDecodeComplete'] for row in value['facts']['functions'])
    assert m.check(file) == value
    value['facts']['functions'][0]['facts']['machineAbiClosureVerified'] = True
    p.write(file, d.seal({k: v for k, v in value.items() if k != 'machineInventoryIdentity'}, 'machineInventoryIdentity'))
    with pytest.raises(ValueError, match='REDERIVATION_MISMATCH'): m.check(file)


def test_no_linker_name_guess_and_missing_symbol_remains_gap(machine_project):
    _, specfile, _, ast, builds = machine_project
    del ast['inner'][0]['mangledName']
    value = m.project_facts(specfile, builds)
    assert all(row['reasonCodes'] == ['COMPILER_EXPLICIT_LINKER_NAME_REQUIRED'] for row in value['functions'])
    ast['inner'][0]['mangledName'] = 'not_present'
    assert all(row['reasonCodes'] == ['OBJECT_FUNCTION_SYMBOL_JOIN_UNAVAILABLE']
               for row in m.project_facts(specfile, builds)['functions'])


def test_changed_build_or_machine_code_cannot_reuse_receipt(machine_project):
    root, specfile, _, _, builds = machine_project
    file = root / 'machine-inventory.json'; m.acquire(specfile, builds, file)
    Path(builds['target']['library']['path']).write_bytes(b'changed')
    with pytest.raises(ValueError): m.check(file)


def test_l1_automatically_collects_real_machine_facts_without_promotion(machine_project, monkeypatch):
    from riscv2x86_py.translation_validation import ProgramArtifact, ValidationLevel
    from riscv2x86_py.validation_status import ValidationStatus
    root, specfile, _, _, builds = machine_project
    monkeypatch.setattr(app, 'check', lambda path: {'project': d.snapshot(specfile), 'facts': {'fixture': True}})
    original_command = p.command
    def command(argv, *args):
        if argv[:2] == ['/usr/bin/env', '-L']: argv = argv[3:]
        return original_command(argv, *args)
    monkeypatch.setattr(p, 'command', command)
    programs = {s: ProgramArtifact(s, r['program']['path'], 'executable', r['program']['digest']) for s, r in builds.items()}
    validator = p.factory({'specPath': str(specfile), 'level': 'L1', 'workDirectory': str(root / 'l1'),
                           'applicabilityPath': 'fixture-app'})
    result = validator(level=ValidationLevel.L1, source_program_artifact=programs['source'],
                       target_program_artifact=programs['target'])
    assert result.status is ValidationStatus.INCONCLUSIVE
    detail = json.loads(result.detail)
    evidence = m.check(detail['machineInventory']['path'])
    assert all(row['facts'] for row in evidence['facts']['functions'])
    assert 'ACTUAL_MACHINE_ABI_REQUIRED' in detail['reasonCodes']
    assert not detail['obligationAssessment']['programRequirementsComplete']
    assert d.read(root / 'l1/phase-timings.json')['machineInventorySeconds'] >= 0


def test_original_checker_requires_machine_receipt_bound_to_actual_programs(machine_project):
    from types import SimpleNamespace
    from riscv2x86_py.native_original_evaluation import check_project_machine_inventory
    root, specfile, _, _, builds = machine_project
    work = root / 'retained'; work.mkdir()
    file = work / 'machine-inventory.json'; m.acquire(specfile, builds, file)
    request = SimpleNamespace(runtime_registry_template={'validators': {'L1': {
        'type': 'original-captured-project', 'config': {'specPath': str(specfile), 'applicabilityPath': 'fixture'}}}})
    result = {'attempts': [{'validation': {'layers': [{'level': 'L1', 'detail': json.dumps({'machineInventory': d.snapshot(file)})}]}}],
              **{s + 'ProgramArtifact': {'artifact_path': r['program']['path'], 'artifact_digest': r['program']['digest']}
                 for s, r in builds.items()}}
    check_project_machine_inventory(result, request, work)
    wrong = deepcopy(result); wrong['targetProgramArtifact']['artifact_digest'] = 'sha256:' + '0' * 64
    with pytest.raises(ValueError, match='PROGRAM_MISMATCH'): check_project_machine_inventory(wrong, request, work)
    wrong = deepcopy(result); wrong['attempts'][0]['validation']['layers'][0]['detail'] = '{}'
    with pytest.raises(ValueError, match='INVENTORY_REQUIRED'): check_project_machine_inventory(wrong, request, work)
    with pytest.raises(ValueError, match='PATH_INVALID'): check_project_machine_inventory(result, request, work / 'other')


def test_decoder_windows_are_bounded_without_losing_function_bytes(binary, monkeypatch):
    import pypcode
    from types import SimpleNamespace
    original = pypcode.Context; lengths = []
    def context(language):
        ctx = original(language)
        def translate(code, **kwargs):
            lengths.append(len(code))
            return ctx.translate(code, **kwargs)
        return SimpleNamespace(translate=translate)
    monkeypatch.setattr(pypcode, 'Context', context)
    value = m.derive(binary.read_bytes(), 'sample')
    assert value['byteSize'] > 16 and value['linearByteDecodeComplete']
    assert max(lengths) <= 16
    assert sum(row['size'] for row in value['instructions']) == value['byteSize']
