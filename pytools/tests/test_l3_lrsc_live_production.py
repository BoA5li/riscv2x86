"""Opt-in full L0--L3 and fresh audit for live completion returns."""
import pytest
from tests.test_l3_lrsc_production import exercise_lrsc_production

CASES=[(width,op,False) for width in (32,64) for op in ('add','and','or','xor')]+[(32,'add',True)]

@pytest.mark.parametrize('width,operation,word',CASES)
@pytest.mark.parametrize('returned_role',['next','status'])
def test_live_return_production_and_independent_audit(tmp_path,width,operation,word,returned_role):
    exercise_lrsc_production(tmp_path,width,operation,word,returned_role=returned_role,extra_function=True)
