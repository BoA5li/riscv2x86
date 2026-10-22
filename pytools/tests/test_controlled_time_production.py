"""Actual optional compiler/QEMU/renderer/L0/L1/L2 production acceptance.

No mock/authority fixture substitutes for missing tools. Explicit controlled
backend variables are required; absence is a skip, never a successful claim.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


def test_real_controlled_time_production_and_central_provider_audit(tmp_path):
    from tests.test_l2_real_production_chain import _tools
    from riscv2x86_py.semantic_content import semantic_identity
    frontend=_tools()
    manifest=os.environ.get('RV2X86_CONTROLLED_QEMU_MANIFEST','')
    runner=os.environ.get('RV2X86_CONTROLLED_QEMU_RUNNER_JSON','')
    if not manifest or not runner:
        pytest.skip('explicit controlled QEMU manifest/runner not selected')
    if not Path(manifest).is_file():pytest.fail('selected controlled backend manifest is missing')
    root=Path(__file__).resolve().parents[2];source=tmp_path/'renamed_counter.c'
    source.write_text('#include <stdint.h>\nuint64_t renamed_counter(void){uint64_t tick;__asm__ volatile("rdtime %0":"=r"(tick));return tick;}\n')
    template={'schemaVersion':'riscv2x86.csr-architecture-template.v1',
        'privilegeSpecVersion':'riscv-privileged-1.12','xlenBits':64,'extensions':['i','zicsr']}
    template['templateIdentity']=semantic_identity(template)
    architecture=tmp_path/'architecture.json';architecture.write_text(json.dumps(template))
    review=tmp_path/'review.json';review.write_text(json.dumps({'owner':'controlled-production-regression',
        'basis':'explicit-controlled-environment-selection','evidenceIdentity':semantic_identity({'test':Path(__file__).read_text()})}))
    output=tmp_path/'production'
    completed=subprocess.run([sys.executable,str(root/'experiment/run_mechanism_routes.py'),
        '--frontend',frontend,'--output',str(output),'--architecture-template',str(architecture),
        '--time-source',str(source),'--time-review',str(review),'--time-backend',manifest,
        '--time-runner-json',runner,'--time-mode','controlled'],capture_output=True,text=True,timeout=1200,check=False)
    logs={p.name:p.read_text()[-10000:] for p in output.glob('*.log')}
    assert completed.returncode==0,completed.stdout+completed.stderr+json.dumps(logs)
    status=json.loads((output/'run-status.json').read_text())
    assert status['completedRoutes']==['time'] and not status['blockers']
    assert status['productionAcceptanceComplete']
    assert status['originalNativeTimeEquivalent'] is False
    audit=json.loads((output/'time-provider-audit.log').read_text())
    assert not audit['failures'] and audit['providerInvocations']>0
    from riscv2x86_py.l2_evidence_reader import load_case_evaluation_result,read_l2_provider_results
    results=output/'time-configured';batch=json.loads((results/'batch-evaluation.json').read_text());case=batch['cases'][0]
    evaluation=load_case_evaluation_result(results,case)
    records=read_l2_provider_results(evaluation,results/'cases'/case['caseId'])
    assert records
