from dataclasses import replace
import pytest
from riscv2x86_py.function_cfg_analysis import *
from riscv2x86_py.whole_function import *


def facts():
    front=FrontendCfgFacts('c.entry',(FunctionCfgNode('c.entry','c',None,True),
        FunctionCfgNode('placeholder','asm_placeholder','f0',True),FunctionCfgNode('c.ret','return',None,True)),
        (FunctionCfgEdge('c.entry','placeholder','flow',True),FunctionCfgEdge('placeholder','c.ret','flow',True)),
        (FunctionExitBinding('exit','c.ret',FunctionExitKind.NORMAL_RETURN,True),),True)
    region=AsmRegionCfgFacts('f0','a.entry',('a.exit',),(FunctionCfgNode('a.entry','asm','f0',True),
        FunctionCfgNode('a.exit','asm_exit','f0',True)),
        (FunctionCfgEdge('a.entry','a.exit','flow',True),FunctionCfgEdge('a.exit','c.ret','flow',True)),
        ('c.ret',),True,frontend_node_id='placeholder')
    return front,region


def test_joins_actual_compiler_placeholder_with_explicit_continuation():
    front,region=facts();model=build_mixed_function_cfg(frontend=front,asm_regions=(region,),expected_fragment_ids=('f0',))
    assert model.complete and len(model.nodes)==4
    assert ('c.entry','a.entry') in {(e.source_node_id,e.target_node_id) for e in model.edges}
    assert ('a.exit','c.ret') in {(e.source_node_id,e.target_node_id) for e in model.edges}
    assert all(n.node_id!='placeholder' for n in model.nodes)


@pytest.mark.parametrize('change',['no-placeholder','no-continuation-edge','wrong-target','disconnected','incomplete-node','duplicate','unknown-exit'])
def test_disconnected_or_ambiguous_asm_never_becomes_complete(change):
    front,region=facts();regions=(region,)
    if change=='no-placeholder':regions=(replace(region,frontend_node_id=None),)
    elif change=='no-continuation-edge':regions=(replace(region,edges=region.edges[:1]),)
    elif change=='wrong-target':regions=(replace(region,continuation_targets=('missing',)),)
    elif change=='disconnected':front=replace(front,edges=front.edges[1:])
    elif change=='incomplete-node':regions=(replace(region,nodes=(replace(region.nodes[0],complete=False),region.nodes[1])),)
    elif change=='duplicate':regions=(region,region)
    else:front=replace(front,exits=(replace(front.exits[0],kind=FunctionExitKind.UNKNOWN),))
    assert not build_mixed_function_cfg(frontend=front,asm_regions=regions,expected_fragment_ids=('f0',)).complete


def test_missing_asm_cfg_is_never_assumed_to_fallthrough():
    front,_=facts()
    model=build_mixed_function_cfg(frontend=front,asm_regions=(),expected_fragment_ids=('f0',))
    assert not model.complete and 'whole-function.asm-region-membership-mismatch' in model.missing_fact_codes
