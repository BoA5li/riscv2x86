from riscv2x86_py.whole_function import (FunctionTranslationUnit, SourceFunctionStackModel,
    WholeFunctionClassification, WholeFunctionSemanticModel, WholeFunctionLoweringKind,
    classify_whole_function_route, generate_whole_function_candidate_plans,
    prove_whole_function_plan)

def test_ra_and_return_are_function_scope_not_local_asm():
    route=classify_whole_function_route(reads_registers=frozenset({"ra"}),writes_registers=frozenset(),has_call=False,has_return=True,has_tail_call=False,stack_kind="whole_function",dynamic_adjustment=False,stack_complete=True,has_unwind_or_exception_edge=False)
    assert route.required
    assert route.classification is WholeFunctionClassification.ELIGIBLE_STATIC
    assert route.route_id == "whole-function-abi-lowering.v1"

def test_dynamic_frame_and_unwind_are_not_accidentally_local_lowered():
    dynamic=classify_whole_function_route(reads_registers=frozenset(),writes_registers=frozenset({"sp"}),has_call=False,has_return=False,has_tail_call=False,stack_kind="whole_function",dynamic_adjustment=True,stack_complete=True,has_unwind_or_exception_edge=False)
    unwind=classify_whole_function_route(reads_registers=frozenset({"ra"}),writes_registers=frozenset(),has_call=False,has_return=True,has_tail_call=False,stack_kind="whole_function",dynamic_adjustment=False,stack_complete=True,has_unwind_or_exception_edge=True)
    assert dynamic.classification is WholeFunctionClassification.UNSUPPORTED
    assert unwind.classification is WholeFunctionClassification.REQUIRES_UNWIND_ROUTE

def test_incomplete_exit_facts_fail_closed():
    route=classify_whole_function_route(reads_registers=frozenset({"ra"}),writes_registers=frozenset(),has_call=False,has_return=None,has_tail_call=False,stack_kind="whole_function",dynamic_adjustment=False,stack_complete=True,has_unwind_or_exception_edge=False)
    assert route.classification is WholeFunctionClassification.UNKNOWN
    assert not route.complete

def test_function_scope_plan_is_separate_and_not_prematurely_approved():
    route=classify_whole_function_route(reads_registers=frozenset({"ra"}),writes_registers=frozenset(),has_call=False,has_return=True,has_tail_call=False,stack_kind="whole_function",dynamic_adjustment=False,stack_complete=True,has_unwind_or_exception_edge=False)
    unit=FunctionTranslationUnit("f","ast:f","rv64-lp64",True)
    model=WholeFunctionSemanticModel(unit,SourceFunctionStackModel("whole_function",0,False,False,True),True,False,False,True,False,(),False,True)
    plan=generate_whole_function_candidate_plans(model,route)[0]
    assert plan.kind is WholeFunctionLoweringKind.STRUCTURED_C_FUNCTION
    assert not prove_whole_function_plan(model=model,plan=plan).approved
