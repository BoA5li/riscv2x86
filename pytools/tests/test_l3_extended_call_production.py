"""Opt-in unchanged-source real production; no fixture grants acceptance."""
import pytest
from tests.test_l3_atomic_production import exercise_atomic_production
from tests.test_l3_lrsc_production import exercise_lrsc_production
from tests.test_l3_control_production import exercise_control_production


@pytest.mark.parametrize('width,op,discard,arity,pointer,value',[
    (32,'fetch_add',False,3,2,0),(64,'exchange',False,4,1,3),
    (32,'fetch_xor',False,4,3,2),(64,'fetch_and',True,3,0,2)])
def test_extended_atomic_call(tmp_path,width,op,discard,arity,pointer,value):
    exercise_atomic_production(tmp_path,width,op,'acq_rel',discard,arity=arity,pointer=pointer,value=value)


@pytest.mark.parametrize('width,op,word,role,arity,pointer,value',[
    (32,'add',True,'next',3,2,0),(64,'xor',False,'status',4,1,3),
    (32,'and',False,'old',4,3,2),(64,'or',False,'next',3,0,2)])
def test_extended_lrsc_call(tmp_path,width,op,word,role,arity,pointer,value):
    exercise_lrsc_production(tmp_path,width,op,word,returned_role=role,extra_function=True,
                             arity=arity,pointer=pointer,value=value)


@pytest.mark.parametrize('kind',['equal','signed_less','jump','goto'])
def test_control_entry_with_unrelated_function(tmp_path,kind):
    exercise_control_production(tmp_path,kind,extra_function=True)


@pytest.mark.parametrize('width,operation,discard,arity,pointer,value',[
    (32,'fetch_add',False,5,4,3),(64,'exchange',False,6,5,4),
    (32,'fetch_xor',False,6,4,5),(64,'fetch_or',True,6,5,4)])
def test_register_boundary_atomic_call(tmp_path,width,operation,discard,arity,pointer,value):
    exercise_atomic_production(tmp_path,width,operation,'acq_rel',discard,
                               arity=arity,pointer=pointer,value=value)


@pytest.mark.parametrize('width,word,role,arity,pointer,value',[
    (32,False,'old',2,0,1),(32,True,'next',6,5,4),
    (64,False,'status',5,4,3),(64,False,'next',6,4,5)])
def test_subtraction_production_and_negative_audit(tmp_path,width,word,role,arity,pointer,value):
    exercise_lrsc_production(tmp_path,width,'sub',word,returned_role=role,
                            extra_function=True,arity=arity,pointer=pointer,value=value)
