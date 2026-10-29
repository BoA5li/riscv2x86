"""Exercise real production test setup without executing a compiler or observer.

The sentinel stops at the subprocess boundary. These tests establish filesystem
isolation only; they make no translation, execution or semantic acceptance claim.
"""
from pathlib import Path

import pytest

from tests import test_l3_joint_production as production


class LaunchInspected(Exception):
    pass


CASES = [("boundary", (arity, regions)) for arity, regions in
         ((1, 2), (3, 3), (4, 3), (2, 16))]
CASES += [("operation", (pointer, operation)) for pointer in (0, 1)
          for operation in ("add", "xor", "and", "or")]


@pytest.mark.parametrize("kind,parameters", CASES)
def test_joint_production_launch_keeps_input_and_work_trees_disjoint(
        tmp_path, monkeypatch, kind, parameters):
    frontend = tmp_path / "unexecuted-frontend"
    frontend.write_text("not an executable; layout inspection only\n")
    monkeypatch.setenv("RISCV2X86_TEST_FRONTEND", str(frontend))
    monkeypatch.setenv("RV2X86_L3_JOINT_BACKEND", "unexecuted-layout-backend.json")

    def inspect_launch(command, **kwargs):
        source = Path(command[command.index("--input") + 1]).resolve()
        output = Path(command[command.index("--output") + 1]).resolve()
        source_root = source.parent
        work = output / "batch" / "cases" / source.stem / "work"
        assert source.is_file()
        assert source_root != work
        assert source_root not in work.parents
        assert work not in source_root.parents
        assert not output.exists()
        assert "--backend" in command
        assert kwargs["check"] is False
        raise LaunchInspected

    monkeypatch.setattr(production.subprocess, "run", inspect_launch)
    test = (production.test_real_joint_declared_call_and_region_boundaries
            if kind == "boundary"
            else production.test_real_joint_load_scalar_store_and_audit)
    with pytest.raises(LaunchInspected):
        test(tmp_path, *parameters)
