from riscv2x86_py.csr_structured_renderer import CsrRuntimeRecipe,render_csr_recipe
def test_renderer_uses_fixed_recipe_callable_and_token():
 r=CsrRuntimeRecipe("mstatus.write.v1","rv2x86_csr_write","0x300","ctx","value","old","riscv2x86_csr_runtime.h","riscv2x86_runtime","v1","runtime-trap-contract",True)
 x=render_csr_recipe(r,approved_recipe_ids={"mstatus.write.v1":"v1"},expected_runtime_version="v1")
 assert x.emitted_text=="old = rv2x86_csr_write(ctx, 0x300, value);"
def test_renderer_rejects_unapproved_or_invented_callable():
 r=CsrRuntimeRecipe("x","rv2x86_csr_mstatus","0x300","ctx","v","o","h","l","v1","runtime-trap-contract",True)
 assert render_csr_recipe(r,approved_recipe_ids={"x":"v1"},expected_runtime_version="v1").emitted_text is None
