"""Opt-in real compiler/proof/RV-system/native/bounded-L3/fresh-audit matrix."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest


@pytest.mark.parametrize('operation', ['ecall','wfi'])
def test_real_bounded_system_l3_and_fresh_audit(tmp_path, operation):
    backend = os.environ.get('RV2X86_CONTROLLED_SYSTEM_BACKEND')
    if not backend: pytest.skip('explicit controlled M-mode backend required')
    frontend = os.environ.get('RISCV2X86_TEST_FRONTEND')
    clang = os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    assert frontend and Path(frontend).is_file()
    assert clang and Path(clang).is_file() and Path(backend).is_file()
    source = tmp_path/'inputs'/'renamed.c'; source.parent.mkdir()
    source.write_text('unsigned unrelated(unsigned x){return x+1;}\n'
        'void arbitrary_entry(void){__asm__ volatile("'+operation+'" ::: "memory");}\n')
    repo = Path(__file__).resolve().parents[2]
    output = tmp_path/'production'
    result = subprocess.run([sys.executable, str(repo/'experiment/run_controlled_system_routes.py'),
        '--source',str(source),'--frontend',frontend,'--clang',clang,'--backend',backend,
        '--output',str(output),'--require-l3'], capture_output=True, text=True, check=False, timeout=7200)
    logs = '\n'.join(p.name+':\n'+p.read_text(errors='replace')[-10000:] for p in output.glob('*.log'))
    assert result.returncode == 0, result.stdout+result.stderr+logs
    state = json.loads((output/'run-status.json').read_text())
    assert not state['blockers'] and state['currentStage']=='complete'
    assert all(state[k] is True for k in ('productionAcceptanceComplete','executionComplete',
        'independentResultAuditComplete','boundedSystemL3Complete'))
    assert state['originalLinuxUserEquivalent'] is False
    report_path, = (output/'system-0-configured').glob('cases/*/evaluation-result.json')
    report = json.loads(report_path.read_text())
    configured = report_path.parents[2]
    batch = json.loads((configured/'batch-evaluation.json').read_text())
    assert batch['statusCounts'] == {'verified': 1}
    assert batch['l3BoundedSystemVerifiedProgramCount'] == 1
    assert batch['l3ArchitecturalIntentVerifiedProgramCount'] == 0
    case, = batch['cases']
    assert case['programValidationLevels']['L3'] == 'verified'
    counts = case['l3Coverage']['counts']
    assert counts['boundedSystemIntentVerified'] == counts['completeExecution'] == 1
    assert counts['architecturalIntentVerified'] == counts['notRun'] == 0
    acceptance = json.loads((configured/'l3-production-acceptance.json').read_text())
    assert all(acceptance[k] is True for k in ('productionAcceptanceComplete',
        'independentResultAuditComplete','batchSummaryComplete'))
    assert len(report['attempts'])==1
    assert [r['status'] for r in report['attempts'][0]['validation']['layers']]==['verified']*4
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    assert audit_evaluation(report)['status']=='verified'
    result = subprocess.run([sys.executable,'-m','riscv2x86_py.l3_production_acceptance',
        '--evaluation',str(report_path),'--output',str(tmp_path/'new-process-audit.json')],
        capture_output=True,text=True,check=False,timeout=3600)
    assert result.returncode==0, result.stdout+result.stderr
    damaged = json.loads(json.dumps(report))
    damaged['attempts'][0]['validation']['layers'][2]['status']='not_run'
    with pytest.raises(ValueError): audit_evaluation(damaged)
    detail = json.loads(report['attempts'][0]['validation']['layers'][3]['detail'])
    # Last: retained executable corruption must be detected by a fresh audit.
    program = Path(detail['programs']['source']['path'])
    original=program.read_bytes()
    try:
        program.write_bytes(original+b'changed')
        with pytest.raises(ValueError): audit_evaluation(report)
    finally:
        program.write_bytes(original)
