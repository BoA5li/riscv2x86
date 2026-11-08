"""Verifier relocation/changes with real package copies and deployment checks.

The audited_capture fixture stubs the cross-ISA candidate proof boundary,
explicitly; GCC capture/link/loader and receipt checks execute normally.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from .test_native_observation_integrity import audited_capture
from .test_native_captured_deployment import captured
from riscv2x86_py import native_verifier_manifest as manifest
from riscv2x86_py import native_deployment_prerequisites as prerequisite
from riscv2x86_py import native_captured_deployment as deployment
from riscv2x86_py import native_context_bridge as bridge


def package_tree(path):
    path.mkdir()
    (path/'__init__.py').write_text('')
    (path/'unrelated_name.py').write_text('def verify(): return True\n')
    (path/'helpers').mkdir()
    (path/'helpers/__init__.py').write_text('')
    (path/'helpers/transitive.py').write_text('GUARD = 1\n')
    return path


def test_installation_root_does_not_change_identity(tmp_path):
    first = package_tree(tmp_path/'tree-a')
    second = tmp_path/'tree-b'; shutil.copytree(first, second)
    assert manifest.capture(first) == manifest.capture(second)
    assert manifest.capture(first)['files']['helpers/transitive.py']


@pytest.mark.parametrize('mutation', ['edit', 'add', 'remove', 'policy'])
def test_dependency_inventory_and_policy_changes_require_reaudit(tmp_path, mutation):
    root = package_tree(tmp_path/'tree'); before = manifest.capture(root)
    if mutation == 'edit': (root/'helpers/transitive.py').write_text('GUARD = 0\n')
    if mutation == 'add': (root/'extra.py').write_text('EXTRA = 1\n')
    if mutation == 'remove': (root/'helpers/transitive.py').unlink()
    fresh = manifest.capture(root)
    if mutation == 'policy': fresh = {**fresh, 'policy': 'changed-policy'}
    with pytest.raises(ValueError, match='CONTENT_OR_POLICY_CHANGED_REAUDIT_REQUIRED'):
        manifest.compare(before, fresh)


def test_source_link_is_not_an_untracked_dependency(tmp_path):
    root = package_tree(tmp_path/'tree'); external = tmp_path/'outside.py'
    external.write_text('EXTERNAL = 1\n'); (root/'alias.py').symlink_to(external)
    with pytest.raises(ValueError, match='SOURCE_LINK_UNSUPPORTED'):
        manifest.capture(root)


def test_mixed_loaded_worktrees_are_rejected(tmp_path, monkeypatch):
    import types
    outside = tmp_path/'outside.py'; outside.write_text('')
    monkeypatch.setitem(sys.modules, 'riscv2x86_py.mixed_fixture', types.SimpleNamespace(__file__=str(outside)))
    with pytest.raises(ValueError, match='MIXED_PACKAGE_ORIGIN'):
        manifest.current()


def test_legacy_receipt_cannot_be_upgraded_by_dropping_paths(audited_capture):
    _, _, plan, receipt = audited_capture
    value = deployment.read(receipt)
    value['schemaVersion'] = prerequisite.LEGACY_SCHEMA
    value['verifierFiles'] = {'/old/location/module.py': 'fixture-only'}
    value.pop('verifierManifest')
    Path(receipt).write_text(json.dumps(deployment.seal(
        {k:v for k,v in value.items() if k != 'auditPrerequisiteIdentity'}, 'auditPrerequisiteIdentity')))
    with pytest.raises(ValueError, match='LEGACY_VERIFIER_SCOPE_REAUDIT_AND_REDEPLOY_REQUIRED'):
        prerequisite.check(plan, receipt)


def test_change_during_audit_never_writes_prerequisite(audited_capture, monkeypatch):
    root, _, plan, _ = audited_capture
    before = manifest.current(); after = deepcopy(before); after['policy'] = 'changed'
    states = iter((before, after))
    monkeypatch.setattr(manifest, 'current', lambda: next(states))
    with pytest.raises(ValueError, match='CONTENT_OR_POLICY_CHANGED'):
        prerequisite.audit(plan, root/'changed-during-audit')
    assert not (root/'changed-during-audit/deployment-audit.json').exists()


def test_real_relocated_package_checks_same_audit_and_deployment_then_rejects_change(audited_capture):
    root, _, plan, receipt = audited_capture
    deployed = deployment.execute(plan, root/'formal', audit_path=receipt)
    planfile = root/'relocation-plan.json'; planfile.write_text(json.dumps(plan))
    copied = root/'another-worktree/pytools/riscv2x86_py'
    shutil.copytree(Path(manifest.__file__).resolve().parent, copied,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    script = root/'check-in-second-worktree.py'
    script.write_text('''import json, sys
from pathlib import Path
from riscv2x86_py import native_deployment_prerequisites as prerequisite
from riscv2x86_py import native_captured_deployment as deployment
from riscv2x86_py import native_audit_evidence, project_native_binding
# Explicit boundary fixtures, matching audited_capture; no claim of translation.
native_audit_evidence.command_projection = lambda candidate: []
project_native_binding.validate_artifacts = lambda bundle: None
assert Path(prerequisite.__file__).resolve().is_relative_to(Path(sys.argv[4]).resolve())
plan = deployment.read(sys.argv[1])
prerequisite.check(plan, sys.argv[2])
assert deployment.check_result(sys.argv[3])['deploymentMode'] == 'audited-local-candidate'
print('relocated-audit-and-deployment-checked')
''')
    env = dict(os.environ, PYTHONPATH=str(copied.parent), PYTHONDONTWRITEBYTECODE='1')
    args = [sys.executable, str(script), str(planfile), receipt,
            str(root/'formal/result.json'), str(copied)]
    checked = subprocess.run(args, env=env, capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    assert 'relocated-audit-and-deployment-checked' in checked.stdout
    # Indirect helper changes are detected even if the three old v1 verifier
    # entry files remain unchanged.
    helper = copied/'native_dynamic_obligations.py'
    helper.write_text(helper.read_text()+'\n# content change requires re-audit\n')
    rejected = subprocess.run(args, env=env, capture_output=True, text=True)
    assert rejected.returncode != 0
    assert 'VERIFIER_CONTENT_OR_POLICY_CHANGED_REAUDIT_REQUIRED' in rejected.stderr
    assert not deployed['semanticApproval']


def test_context_preflight_stops_before_acquisition_or_output_creation(tmp_path, monkeypatch):
    planfile = tmp_path/'plan.json'; planfile.write_text('{}')
    monkeypatch.setattr(bridge, 'inputs', lambda _: (None,)*6)
    def reject(*_):
        raise ValueError('DEPLOYMENT_AUDIT_LEGACY_VERIFIER_SCOPE_REAUDIT_AND_REDEPLOY_REQUIRED')
    monkeypatch.setattr(bridge, 'observation_inventory', reject)
    def unexpected(*args, **kwargs):
        pytest.fail('target acquisition ran after failed preflight')
    monkeypatch.setattr(bridge.native, 'acquire', unexpected)
    with pytest.raises(ValueError, match='REAUDIT_AND_REDEPLOY_REQUIRED'):
        bridge.acquire(planfile, tmp_path/'output', clang='unused', observation_path='old-observation')
    assert not (tmp_path/'output').exists()


def test_source_directory_links_are_not_omitted(tmp_path):
    root = package_tree(tmp_path/'tree'); outside = tmp_path/'external-package'
    outside.mkdir(); (outside/'hidden.py').write_text('EXTERNAL = 1\n')
    (root/'external').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='SOURCE_LINK_UNSUPPORTED'):
        manifest.capture(root)
