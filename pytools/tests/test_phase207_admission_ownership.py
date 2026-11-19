"""Every original provider call checks admission; no decision is memoized."""
import json
from riscv2x86_py import automatic_l2_operand as runner
from riscv2x86_py import native_original_applicability as app
from riscv2x86_py import native_captured_deployment as d
from riscv2x86_py.translation_validation import ValidationLevel
from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
from .test_native_project_l2_entry import backend
from .test_native_original_api import native_pair
from .test_phase206_execution_contracts import subject
from .test_automatic_l2_operand import _artifact


def test_changed_dependency_does_not_reuse_an_earlier_checked_disposition(backend, monkeypatch):
    config, entry, _, _, root = backend
    finding, _, value = subject()
    finding['fragment']['enclosingFunction'] = config['functions'][0]['name']
    value['project'] = d.snapshot(config['typedProjectEntry']['specPath'])
    value['facts']['instances'][0]['instanceBindingIdentity'] = entry.selected['instanceBindingIdentities'][0]
    path = root/'app.json'; path.write_text(json.dumps(value))
    config['typedProjectEntry']['applicabilityPath'] = str(path)
    config.update(workDirectory=str(root/'work'), replayDirectory=str(root/'replay'), seed=0,
                  compilerEliminationDirectory=str(root/'compiler-elimination'))
    checks = []
    def check(p):
        checks.append(p)
        return d.read(p)
    monkeypatch.setattr(app, 'check', check)
    monkeypatch.setattr(runner, '_finding', lambda *a: finding)
    monkeypatch.setattr(runner, '_authority', lambda *a, **kw: ({'fixture': 'upstream'}, ''))
    validate = runner.build_auto_l2_operand_validator(config)
    kwargs = dict(level=ValidationLevel.L2, comparison_policy=ARCHITECTURAL_COMPARISON_POLICY,
                  translation_artifact=_artifact())
    first = json.loads(validate(**kwargs).detail)
    second = json.loads(validate(**kwargs).detail)
    assert len(checks) == 2
    assert first['instanceExecutionDisposition'] == second['instanceExecutionDisposition']
    assert first['operandAuthorityReady'] and first['evidenceProductionDisposition'] == 'not_produced'
    assert first['compilerEliminationEvidence'] == second['compilerEliminationEvidence']
    receipt = d.read(first['compilerEliminationEvidence']['receipt']['path'])
    assert not receipt['machineEliminationVerified']
    # Shared API fixture baseline is O0 while its compile profile is O2.
    assert receipt['sides'][0]['reasonCode'] == 'COMPILER_RTL_CANONICAL_OBJECT_DIFFERS'
    from riscv2x86_py import native_project_evaluation as project
    def forbidden(*a, **kw): raise AssertionError('readback ran compiler')
    monkeypatch.setattr(project, 'command', forbidden)
    replay = runner.build_auto_l2_operand_validator(config, readback=True)
    assert json.loads(replay(**kwargs).detail) == first
    value['facts']['instances'].clear(); path.write_text(json.dumps(value))
    changed = json.loads(validate(**kwargs).detail)
    assert 'instanceExecutionDisposition' not in changed
    assert changed['executionDisposition'] == 'precondition_rejected'
    assert changed['evidenceProductionDisposition'] == 'not_produced'
