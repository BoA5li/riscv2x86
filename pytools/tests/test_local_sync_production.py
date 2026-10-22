"""Optional real compiler/QEMU preparation-to-closer acceptance. No fake approvals."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
from riscv2x86_py.semantic_content import semantic_identity


def test_real_local_sync_contract_production_and_audit(tmp_path):
    from tests.test_l2_real_production_chain import _tools
    frontend=_tools()
    names=('RV2X86_LOCAL_SYNC_DECLARATION','RV2X86_QEMU_SOURCE',
           'RV2X86_QEMU_BUILD','RV2X86_NATIVE_RUNNER_JSON')
    values={name:os.environ.get(name) for name in names}
    if not all(values.values()):
        pytest.skip('explicit reviewed local-sync declaration/source/build/runner not selected')
    root=Path(__file__).resolve().parents[2]
    inputs=tmp_path/'inputs';inputs.mkdir()
    source=inputs/'renamed_visibility.c'
    source.write_text('void renamed_visibility(void){__asm__ volatile("fence.i" ::: "memory");}\n')
    template={'schemaVersion':'riscv2x86.csr-architecture-template.v1',
        'privilegeSpecVersion':'riscv-privileged-1.12','xlenBits':64,'extensions':['i','zicsr','zifencei']}
    template['templateIdentity']=semantic_identity(template)
    path=tmp_path/'architecture.json';path.write_text(json.dumps(template))
    output=tmp_path/'production'
    completed=subprocess.run([sys.executable,str(root/'experiment/run_mechanism_routes.py'),
        '--frontend',frontend,'--output',str(output),'--architecture-template',str(path),
        '--sync-source',str(source),'--sync-declaration',values['RV2X86_LOCAL_SYNC_DECLARATION'],
        '--qemu-source',values['RV2X86_QEMU_SOURCE'],'--qemu-build',values['RV2X86_QEMU_BUILD'],
        '--native-runner-json',values['RV2X86_NATIVE_RUNNER_JSON']],capture_output=True,text=True,
        timeout=1200,check=False)
    logs={p.name:p.read_text()[-10000:] for p in output.glob('*.log')}
    assert completed.returncode==0,completed.stdout+completed.stderr+json.dumps(logs)
    status=json.loads((output/'run-status.json').read_text())
    assert status['productionAcceptanceComplete'] and status['completedRoutes']==['sync']
    audit=json.loads((output/'sync-provider-audit.log').read_text())
    assert not audit['failures'] and audit['providerInvocations']>0
    consumed=json.loads((output/'sync-approval-consumption.json').read_text())
    assert consumed['disposition']=='consumed'
