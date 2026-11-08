import json
from pathlib import Path
import sys

import pytest

from riscv2x86_py.native_experiment_driver import SCHEMA, execute, check_run, validate
from riscv2x86_py.project_build_records import identity


def plan(stages):
    body = {'schemaVersion': SCHEMA, 'stages': stages}
    return dict(body, planIdentity=identity(body))


def stage(name, code, deps=(), inputs=(), outputs=('result.json',), timeout=10, limit=65536):
    return {'id': name, 'dependsOn': list(deps), 'command': [sys.executable, '-c', code],
            'directory': '${STAGE}', 'environment': {'PATH': '/usr/bin:/bin'},
            'inputs': list(inputs), 'outputs': list(outputs),
            'timeoutSeconds': timeout, 'maxLogBytes': limit}


WRITE = "from pathlib import Path; Path('result.json').write_text('actual subprocess output')"


def test_real_stages_bind_inputs_and_outputs(tmp_path):
    value = plan([stage('first', WRITE), stage('second', WRITE, ['first'],
                  ['${RUN}/first/result.json'])])
    result = execute(value, tmp_path/'run')
    assert result['acquisitionComplete']
    assert not result['semanticApproval'] and not result['productionAcceptanceComplete']
    assert check_run(tmp_path/'run')['acquisitionIntegrityChecked']
    (tmp_path/'run/first/result.json').write_text('changed')
    with pytest.raises(ValueError, match='OUTPUT_CHANGED'):
        check_run(tmp_path/'run')


@pytest.mark.parametrize('code,inputs,reason', [
    ('raise SystemExit(17)', (), 'COMMAND_FAILED:17'),
    ('pass', (), 'No such file'),
    (WRITE, ('/missing-prerequisite.json',), 'No such file'),
])
def test_first_failure_stops_all_successors(tmp_path, code, inputs, reason):
    value = plan([stage('build', code, inputs=inputs), stage('entry', WRITE, ['build']),
                  stage('link', WRITE, ['entry'])])
    result = execute(value, tmp_path/'run')
    assert result['primaryFailure']['stage'] == 'build'
    assert reason in result['primaryFailure']['reason']
    assert [r['status'] for r in result['stages']] == ['failed', 'not_run', 'not_run']
    assert not (tmp_path/'run/entry').exists()
    assert check_run(tmp_path/'run')['acquisitionComplete'] is False


def test_descendant_timeout_and_log_limit(tmp_path):
    # The child inherits the pipes. Killing just the direct parent would leave
    # the reader blocked for 30 seconds; process-group termination must finish.
    code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])"
    result = execute(plan([stage('child', code, timeout=1)]), tmp_path/'timeout')
    assert 'TIMEOUT' in result['primaryFailure']['reason']
    code = "import os;\nwhile True: os.write(1,b'x'*65536)"
    result = execute(plan([stage('noisy', code, limit=1024)]), tmp_path/'noisy')
    assert 'LOG_BUDGET_EXCEEDED' in result['primaryFailure']['reason']
    assert (tmp_path/'noisy/noisy/stdout.log').stat().st_size <= 1024


def test_output_symlink_escape_and_input_mutation_reject(tmp_path):
    other = tmp_path/'outside'; other.write_text('original')
    code = "from pathlib import Path; Path('result.json').symlink_to("+repr(str(other))+")"
    result = execute(plan([stage('escape', code)]), tmp_path/'escape')
    assert 'ESCAPES_STAGE' in result['primaryFailure']['reason']
    code = WRITE+"; Path("+repr(str(other))+").write_text('changed')"
    result = execute(plan([stage('mutation', code, inputs=[str(other)])]), tmp_path/'mutation')
    assert 'INPUT_CHANGED' in result['primaryFailure']['reason']


def test_exclusive_run_and_no_success_claim_from_rehashed_flags(tmp_path):
    value = plan([stage('build', WRITE)])
    execute(value, tmp_path/'run')
    with pytest.raises(FileExistsError):
        execute(value, tmp_path/'run')
    path = tmp_path/'run/run-status.json'
    result = json.loads(path.read_text()); result['semanticApproval'] = True
    result['stateIdentity'] = identity({k: v for k, v in result.items() if k != 'stateIdentity'})
    path.write_text(json.dumps(result))
    with pytest.raises(ValueError, match='RUN_INVALID'):
        check_run(tmp_path/'run')


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(id='../escape'), lambda r: r.update(dependsOn=['future']),
    lambda r: r.update(outputs=['../outside']), lambda r: r.update(timeoutSeconds=True),
    lambda r: r.update(maxLogBytes=0), lambda r: r.update(environment={}),
    lambda r: r.update(approved=True),
])
def test_invalid_plans_never_start(tmp_path, mutate):
    row = stage('build', WRITE); mutate(row)
    with pytest.raises(ValueError):
        execute(plan([row]), tmp_path/'run')
    assert not (tmp_path/'run').exists()
