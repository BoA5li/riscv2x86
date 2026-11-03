"""Opt-in compatibility entry: full L0--L3, independent audit and negative evidence."""
import pytest
from tests.test_l3_lrsc_production import exercise_lrsc_production


@pytest.mark.parametrize('width,operation,word,role,arity,pointer,value',[
    (32,'add',True,'next',3,2,0),
    (64,'sub',False,'status',6,5,4),
])
def test_selected_lrsc_entry_keeps_full_production(tmp_path,width,operation,word,role,arity,pointer,value):
    exercise_lrsc_production(tmp_path,width,operation,word,returned_role=role,
        extra_function=True,arity=arity,pointer=pointer,value=value,entry_mode='selection')
