from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from riscv2x86_py import native_original_pipeline as route
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.automatic_batch_cli import entry_points_from_ast
from .test_native_original_pipeline import adapted, backend_fixture


def test_original_ingress_keeps_compiler_functions_and_independently_rederives(adapted, monkeypatch):
    root, prepared, _, raw = adapted
    exported = d.read(prepared['frontendReport']['path'])
    assert len(exported['functions']) == 1
    assert exported['functions'][0]['name'] == 'entry'
    assert 'l2OperandBoundary' in exported['functions'][0]
    backend_fixture(monkeypatch, prepared, raw)
    value = route.translate(root / 'prepared/result.json', root / 'translated')
    report = d.read(value['report']['path'])
    assert report['functions'] == exported['functions']
    assert value['backendReport']['path'] != value['report']['path']
    assert route.check_translation(root / 'translated/result.json') == value
    assert not value['semanticApproval']
    changed = deepcopy(report); changed['functions'][0]['functionId'] = 'forged-owner'
    Path(value['report']['path']).write_text(json.dumps(changed))
    # Reseal outer receipt as well; independent authority reconstruction must reject.
    value['report'] = d.snapshot(value['report']['path'])
    value = d.seal({k: v for k, v in value.items() if k != 'originalTranslationIdentity'}, 'originalTranslationIdentity')
    Path(root / 'translated/result.json').write_text(json.dumps(value))
    with pytest.raises(ValueError, match='COMPILER_AUTHORITY_REDERIVATION'):
        route.check_translation(root / 'translated/result.json')


def test_frozen_ast_reuses_original_exporter_without_harness_signature_guess(tmp_path):
    clang = shutil.which('clang')
    if not clang:
        pytest.skip('real Clang required for frozen-input compiler integration')
    source = tmp_path / 'unit.i'
    raw = b'# 100 "diagnostic-header.h"\nstatic void arbitrary(long a,long b,long c,long d,long e,long f,long g){__asm__("" ::: "memory");}\n'
    source.write_bytes(raw)
    proc = subprocess.run([clang, '-x', 'cpp-output', '-Xclang', '-ast-dump=json', '-fsyntax-only', str(source)], capture_output=True, check=True)
    ast = json.loads(proc.stdout)
    nodes = [n for n in ast['inner'] if n.get('kind') == 'FunctionDecl']
    _, rows = entry_points_from_ast(ast, source, owning_nodes=nodes, source_bytes=raw)
    assert len(rows) == 1 and rows[0]['arity'] == 7
    assert rows[0]['sourceDigest'] == d.digest(source)
    assert rows[0]['compilerHarnessSignatureSupported'] is False
    assert 'l2OperandBoundary' in rows[0]


def test_gnu_partition_uses_exact_compiler_exports_without_mutating_receipt_ast():
    from .test_native_instance_binding import example
    from riscv2x86_py.compiler_native_instance_binding import derive
    ast, report, raw = example()
    before = deepcopy(ast)
    bindings = derive(ast, report, raw, 'fixture-input')
    enriched = route.compiler_ast_with_operands(ast, bindings)
    path = bindings['records'][0]['astPath']
    node = enriched
    for index in path:
        node = node['inner'][index]
    assert node['numOutputs'] == 1 and node['numInputs'] == 2
    assert node['inputConstraints'] == ['%r', 'r']
    assert ast == before
    node['numInputs'] = 99
    with pytest.raises(ValueError, match='OPERAND_FACT_CONFLICT'):
        route.compiler_ast_with_operands(enriched, bindings)


def test_native_main_owner_is_not_dropped_by_original_harness_entry_filter(tmp_path):
    from .test_native_instance_binding import example
    ast, _, raw = example(name='main')
    source = tmp_path / 'main.i'; source.write_bytes(raw)
    has_main, functions = entry_points_from_ast(ast, source, owning_nodes=ast['inner'], source_bytes=raw)
    assert has_main and len(functions) == 1 and functions[0]['name'] == 'main'
