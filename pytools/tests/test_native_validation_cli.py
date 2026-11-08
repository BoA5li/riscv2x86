import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from riscv2x86_py.native_experiment_driver import SCHEMA
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.project_build_profile import create

SCRIPT = Path(__file__).resolve().parents[2]/'experiment/advance_native_validation.py'


def test_cli_run_check_and_failure_are_not_semantic_approval(tmp_path):
    stage = {'id': 'build', 'dependsOn': [],
        'command': [sys.executable, '-c', "from pathlib import Path; Path('artifact').write_text('actual')"],
        'directory': '${STAGE}', 'environment': {'PATH': '/usr/bin:/bin'}, 'inputs': [],
        'outputs': ['artifact'], 'timeoutSeconds': 10, 'maxLogBytes': 4096}
    body = {'schemaVersion': SCHEMA, 'stages': [stage]}
    plan = dict(body, planIdentity=identity(body)); path = tmp_path/'plan.json'
    path.write_text(json.dumps(plan))
    result = subprocess.run([sys.executable, str(SCRIPT), 'run', '--plan', str(path),
                             '--output', str(tmp_path/'run')], capture_output=True, text=True)
    assert result.returncode == 0
    receipt = json.loads(result.stdout)
    assert receipt['acquisitionComplete'] and not receipt['semanticApproval']
    result = subprocess.run([sys.executable, str(SCRIPT), 'check-run', '--input', str(tmp_path/'run')],
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert not json.loads(result.stdout)['productionAcceptanceComplete']
    stage['command'] = [sys.executable, '-c', 'raise SystemExit(3)']
    body = {'schemaVersion': SCHEMA, 'stages': [stage]}
    path.write_text(json.dumps(dict(body, planIdentity=identity(body))))
    result = subprocess.run([sys.executable, str(SCRIPT), 'run', '--plan', str(path),
                            '--output', str(tmp_path/'failure')], capture_output=True, text=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)['primaryFailure']['stage'] == 'build'


def test_target_plan_requires_real_profile_and_includes_build_before_consumers(tmp_path):
    tools = {name: shutil.which(exe) for name, exe in
             [('cc','gcc'),('hostcc','gcc'),('ar','ar'),('ranlib','ranlib'),('ld','ld')]}
    if not all(tools.values()): pytest.skip('native build tools required')
    profile = create('target', 'x86_64-linux-gnu', tools, '-O2 -funsigned-char')
    profile_path = tmp_path/'profile.json'; profile_path.write_text(json.dumps(profile))
    req = {'schemaVersion': 'riscv2x86.native-external-requirements.v1'}
    req['requirementsIdentity'] = identity(req)
    requirements = tmp_path/'requirements.json'; requirements.write_text(json.dumps(req))
    result = subprocess.run([sys.executable, str(SCRIPT), 'prepare-target',
        '--tooling', str(SCRIPT.parents[1]), '--prep', str(tmp_path), '--archives', str(tmp_path),
        '--profile', str(profile_path), '--requirements', str(requirements),
        '--output', str(tmp_path/'plan.json')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    value = json.loads((tmp_path/'plan.json').read_text())
    assert value['stages'][0]['id'] == 'target-build'
    assert value['stages'][1]['dependsOn'] == ['target-build']
    assert 'gmp-target/test-records.json' in value['stages'][0]['outputs']
    assert '--test-target' in value['stages'][0]['command']
    assert all(s['outputs'] for s in value['stages'])
    # Template generation does not claim that any build actually ran.
    assert not (tmp_path/'target-build').exists()
    assert not json.loads(result.stdout)['semanticApproval']
