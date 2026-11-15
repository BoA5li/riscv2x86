import json
from pathlib import Path
import pytest
from riscv2x86_py.project_acquisition import publish_checked


def test_final_result_is_absent_until_checker_passes(tmp_path):
    target=tmp_path/'result.json';value={'scope':'fixture','semanticApproval':False}
    def check(path):
        assert Path(path).parent==tmp_path and not target.exists()
        assert json.loads(Path(path).read_text())==value
    publish_checked(target,value,check)
    assert json.loads(target.read_text())==value
    assert not list(tmp_path.glob('*pending*'))


def test_failed_check_and_existing_result_are_never_published_or_overwritten(tmp_path):
    target=tmp_path/'result.json'
    def fail(path):raise ValueError('fixture independent check failed')
    with pytest.raises(ValueError,match='independent check failed'):publish_checked(target,{},fail)
    assert not target.exists() and not list(tmp_path.iterdir())
    target.write_text('earlier evidence')
    with pytest.raises(FileExistsError):publish_checked(target,{},lambda p:pytest.fail('must not run'))
    assert target.read_text()=='earlier evidence'
