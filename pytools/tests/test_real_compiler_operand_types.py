"""Real Clang tooling export and exact compiler-candidate join; no mocked AST."""
import json
import subprocess
import pytest

from riscv2x86_py.automatic_batch_cli import inspect_entry_points, _sysroot
from riscv2x86_py.automatic_translation_command import _inject_compiler_fragment_authority
from riscv2x86_py.compiler_operand_type import compiler_operand_type_from_dict
from tests.test_l2_real_production_chain import _tools


def test_real_frontend_exports_pointer_pointee_types_and_binds_exact_value_node(tmp_path):
    frontend = _tools()
    source = tmp_path / 'probe.c'
    source.write_text('#include <stdint.h>\nuint64_t probe(uint64_t *p, uint64_t x) {\n'
        'uint64_t old; __asm__ volatile("amoadd.d %0, %2, (%1)" : "=r"(old)'
        ' : "r"(p), "r"(x) : "memory"); return old; }\n')
    report = tmp_path / 'raw.json'
    run = subprocess.run([frontend, '--analysis-only', '-o', str(tmp_path/'unused'),
        '--src-root', str(tmp_path), '--report-json', str(report), str(source), '--',
        '--target=riscv64-linux-gnu', '--sysroot='+_sysroot(), '-std=gnu11',
        '-march=rv64gc', '-mabi=lp64d'], text=True, capture_output=True, timeout=120)
    assert run.returncode == 0, run.stderr
    _, functions = inspect_entry_points(source)
    _inject_compiler_fragment_authority(report, source, functions)
    fragment = json.loads(report.read_text())['findings'][0]['fragment']
    authority = fragment['compilerFragmentAuthority']
    assert authority['schemaVersion'] == 'riscv2x86.compiler-fragment-authority.v2'
    pointer = authority['compilerTypeBindings']['1']
    parsed = compiler_operand_type_from_dict(pointer['compilerType'])
    assert parsed.is_pointer and parsed.pointee_is_integer
    assert parsed.width_bits == parsed.pointee_width_bits == 64
    assert parsed.alignment_bytes == parsed.pointee_alignment_bytes == 8
    assert pointer['valueNodeIdentity'] == authority['candidate']['operandBindings'][1]['valueNodeIdentity']
    assert parsed.pointee_type_identity not in {parsed.type_identity, pointer['valueNodeIdentity']}


@pytest.mark.parametrize('body,role,access', [
    ('__asm__ volatile("" : "+m"(*p));', 'memory_lvalue', 'read_write'),
    ('__asm__ volatile("" : : "r"(x + 1UL));', 'scalar_value', 'input'),
    ('__asm__ volatile("" : : "r"((unsigned int)x));', 'scalar_value', 'input'),
])
def test_real_complex_expressions_join_before_legacy_declaration_closure(tmp_path, body, role, access):
    frontend = _tools()
    source = tmp_path / 'expression.c'
    source.write_text('void probe(unsigned long *p, unsigned long x) { '+body+' }\n')
    report = tmp_path / 'raw.json'
    run = subprocess.run([frontend, '--analysis-only', '-o', str(tmp_path/'unused'),
        '--src-root', str(tmp_path), '--report-json', str(report), str(source), '--',
        '--target=riscv64-linux-gnu', '--sysroot='+_sysroot(), '-std=gnu11',
        '-march=rv64gc', '-mabi=lp64d'], text=True, capture_output=True, timeout=120)
    assert run.returncode == 0, run.stderr
    _, functions = inspect_entry_points(source)
    _inject_compiler_fragment_authority(report, source, functions)
    fragment = json.loads(report.read_text())['findings'][0]['fragment']
    join = fragment['compilerExpressionJoin']
    assert join['schemaVersion'] == 'riscv2x86.compiler-expression-join.v1'
    assert join['complete'] is True
    assert join['semanticRouteApproved'] is False
    assert join['operands'][0]['role'] == role
    assert join['operands'][0]['access'] == access
    assert join['operands'][0]['declarationIdentity'] == ''
    # No fictional declaration or legacy carrier is supplied to the route.
    assert fragment['compilerFragmentJoin']['disposition'] == 'rejected'
    assert 'compilerFragmentAuthority' not in fragment
