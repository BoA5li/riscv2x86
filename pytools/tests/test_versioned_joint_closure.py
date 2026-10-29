"""Composite joint boundary closure with explicit native toolchain doubles.

AST/proof facts are fixtures; these tests do not claim dual-ISA production.
"""
import json
from copy import deepcopy

import pytest

from riscv2x86_py.source_model import (SourceStraightLineValueProgram as Program,
    SourceStraightLineValueInstruction as Instruction, SourceStraightLineValueOpcode as Code)
from riscv2x86_py.versioned_program_contract import load


def program():
    return Program(64,(Instruction(Code.UNSIGNED_ADD,0,(1,2)),Instruction(Code.BIT_XOR,0,(0,2))),
        (0,),(1,2),value_schema_version=2,
        definition_history=(('definition:0','input:1','input:2'),('definition:1','definition:0','input:2')))


@pytest.mark.parametrize('counterexample',[False,True])
def test_composite_joint_central_registry_and_independent_replay(tmp_path,monkeypatch,counterexample):
    from tests.test_l2_joint_registry import setup,registry,artifact,ValidationLevel,ValidationStatus
    from riscv2x86_py.l2_joint_contract import assess,providers,CAPABILITIES,EXECUTION_PROFILE
    from riscv2x86_py.l1_differential import ARCHITECTURAL_COMPARISON_POLICY
    from riscv2x86_py.l3_trace_support import digest
    findings,fn,config=setup(tmp_path,monkeypatch,
        scalar_template='movq %1,%0;addq %2,%0;xorq %2,%0',value_program=program())
    assert assess(findings,providers(config),CAPABILITIES,[EXECUTION_PROFILE])
    assert load(findings[1])==program()
    if counterexample:
        from pathlib import Path
        target=Path(config['targetPath']);target.write_bytes(target.read_bytes().replace(b'xorq',b'andq'))
        config['targetDigest']=digest(target)
    layer=registry(tmp_path,findings,config,findings[1]).validator_for(ValidationLevel.L2)(
        level=ValidationLevel.L2,translation_artifact=artifact(findings[1]),comparison_policy=ARCHITECTURAL_COMPARISON_POLICY)
    assert layer.status is (ValidationStatus.FAILED if counterexample else ValidationStatus.VERIFIED),layer.detail


def test_composite_observer_capability_cannot_be_omitted(tmp_path,monkeypatch):
    from tests.test_l2_joint_registry import setup
    from riscv2x86_py.l2_joint_contract import assess,providers,CAPABILITIES,EXECUTION_PROFILE
    findings,fn,config=setup(tmp_path,monkeypatch,
        scalar_template='movq %1,%0;addq %2,%0;xorq %2,%0',value_program=program())
    definitions=providers(config)
    for d in definitions:d['requiredCapabilities'].remove('composite_fragment_observation')
    with pytest.raises(ValueError):assess(findings,definitions,CAPABILITIES,[EXECUTION_PROFILE])


def test_composite_contract_changes_are_rejected(tmp_path):
    from tests.test_l3_joint_program import fixture
    _,findings,_=fixture(tmp_path,scalar_template='movq %1,%0;addq %2,%0;xorq %2,%0',value_program=program())
    changed=deepcopy(findings[1]);changed['approvalArtifact']['l2VersionedProgramBoundary']['intermediateValuesMeasured']=True
    with pytest.raises(ValueError):load(changed)
