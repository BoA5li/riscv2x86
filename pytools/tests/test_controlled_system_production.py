"""Real renamed input -> compiler -> proof -> kernel/native -> central audit.

No simulated source executable is accepted in these production tests.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import pytest


@pytest.mark.parametrize('operation',['ecall','wfi'])
def test_real_controlled_m_system_renamed_production(tmp_path,operation):
    backend=os.environ.get('RV2X86_CONTROLLED_SYSTEM_BACKEND','')
    frontend=os.environ.get('RISCV2X86_TEST_FRONTEND','')
    clang=os.environ.get('RV2X86_SYSTEM_CLANG','') or shutil.which('clang')
    if not backend:
        pytest.skip('explicit controlled M-mode backend not selected')
    assert Path(backend).is_file(),'selected M-mode backend manifest missing'
    assert frontend and Path(frontend).is_file(),'selected M-mode production frontend missing'
    assert clang and Path(clang).is_file(),'selected M-mode AST compiler missing'
    root=Path(__file__).resolve().parents[2]
    inputs=tmp_path/'inputs';inputs.mkdir()
    source=inputs/'unrelated_name.c'
    source.write_text('void independently_renamed(void) { __asm__ volatile("'+operation+'" ::: "memory"); }\n')
    output=tmp_path/'production'
    result=subprocess.run([sys.executable,str(root/'experiment/run_controlled_system_routes.py'),
        '--source',str(source),'--frontend',frontend,'--clang',clang,'--backend',backend,
        '--output',str(output)],capture_output=True,text=True,timeout=2400,check=False)
    logs={str(p.relative_to(output)):p.read_text(errors='replace')[-12000:]
          for p in output.rglob('*.log')}
    assert result.returncode==0,result.stdout+result.stderr+json.dumps(logs)
    status=json.loads((output/'run-status.json').read_text())
    assert status['productionAcceptanceComplete'] is True
    assert status['originalLinuxUserEquivalent'] is False
    assert status['L3Equivalent'] is False
    assert status['completedRoutes']==[operation]
    assert status['productionAcceptance'][0]['programValidationLevels']=={'L0':'verified','L1':'verified','L2':'verified'}
