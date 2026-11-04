"""Opt-in dual-ISA regression for an extra, uncalled, exported C function.

This verifies the existing direct joint domain, NOT a caller/callee route.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('before', [False, True])
def test_real_joint_extra_export_and_fresh_audit(tmp_path, before):
    backend = os.environ.get('RV2X86_L3_JOINT_BACKEND')
    if not backend:
        pytest.skip('explicit freshly calibrated joint backend required')
    frontend = os.environ.get('RISCV2X86_TEST_FRONTEND')
    assert frontend and Path(frontend).is_file() and Path(backend).is_file()
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    source = inputs / 'entry.c'
    entry = ('unsigned long selected(unsigned long *p,unsigned long x){unsigned long a,b;'
        '__asm__ volatile("ld %0,8(%1)":"=r"(a):"r"(p):"memory");'
        '__asm__ volatile("add %0,%1,%2":"=r"(b):"r"(a),"r"(x));'
        '__asm__ volatile("sd %0,16(%1)"::"r"(b),"r"(p):"memory");return b;}\n')
    other = 'unsigned long extra(unsigned long x){return x+1;}\n'
    source.write_text(other + entry if before else entry + other)
    repo = Path(__file__).resolve().parents[2]
    output = tmp_path / 'production'
    done = subprocess.run([sys.executable, str(repo / 'experiment/run_l3_joint_trace.py'),
        '--input', str(source), '--frontend', frontend, '--backend', backend,
        '--output', str(output), '--timeout-seconds', '240',
        '--l3-producer-timeout-seconds', '600'], capture_output=True, text=True,
        timeout=7200, check=False)
    logs = '\n'.join(p.read_text(errors='replace')[-12000:] for p in output.glob('*.log'))
    assert done.returncode == 0, done.stdout + done.stderr + logs
    state = json.loads((output / 'run-status.json').read_text())
    assert state['currentStage'] == 'complete' and not state['blockers']
    assert all(state[k] is True for k in ('executionComplete', 'independentResultAuditComplete',
                                         'productionAcceptanceComplete'))
    report_path, = output.glob('batch/cases/*/evaluation-result.json')
    report = json.loads(report_path.read_text())
    assert len(report['attempts']) == 3
    assert all([layer['status'] for layer in attempt['validation']['layers']] == ['verified'] * 4
               for attempt in report['attempts'])
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['programExecutionUnitCount'] == 1
    # Audit a pristine report in a distinct process; no operation cache crosses it.
    audited = subprocess.run([sys.executable, '-m', 'riscv2x86_py.l3_production_acceptance',
        '--evaluation', str(report_path), '--output', str(tmp_path / 'fresh-audit.json')],
        capture_output=True, text=True, timeout=7200, check=False)
    assert audited.returncode == 0, audited.stdout + audited.stderr
    assert json.loads((tmp_path / 'fresh-audit.json').read_text())['productionAcceptanceComplete'] is True
    missing = json.loads(json.dumps(report))
    missing['attempts'].pop()
    with pytest.raises(ValueError):
        audit_evaluation(missing)
    detail = json.loads(report['attempts'][0]['validation']['layers'][3]['detail'])
    group = json.loads(Path(detail['jointCapturePath']).read_text())
    trace = Path(group['reports']['source']['evidence']['rawTracePath'])
    trace.write_text(trace.read_text() + '\ninvalid-event\n')
    with pytest.raises(ValueError):
        audit_evaluation(report)
