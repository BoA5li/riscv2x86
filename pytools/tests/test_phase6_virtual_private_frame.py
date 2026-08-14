"""B-class virtual private frame: fact, proof, selection and C rendering."""
from dataclasses import replace
from types import SimpleNamespace
from pathlib import Path
import shutil, subprocess, tempfile
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.cfg import CFGResult
from riscv2x86_py.schema import AsmFragment, AsmOperand
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.source_model import build_source_semantic_model
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import TargetEnvironment,derive_target_constraints
from riscv2x86_py.phase6d_common import TargetSemanticCatalog,CompilerCapabilityModel,run_semantic_proof_gate
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan,SelectionTier
from riscv2x86_py.phase6f_renderer import RendererContract,RendererContractKind,VirtualPrivateFrameRecipe,RendererContext,Phase6FRenderRequest,render_approved_target_lowering

def test_static_private_frame_store_load_renders_compiler_managed_storage():
    class I: addr=0; size=4; asm_mnem=''; asm_body=''; terminator_kind=None
    def op(code,out,ins): return type('O',(),{'opcode':code,'output':out,'inputs':ins})
    v=lambda space,offset,size,name: SimpleNamespace(space=space,offset=offset,size=size,name=name)
    sp=v('register',2,8,'sp'); a0=v('register',10,8,'a0'); a1=v('register',11,8,'a1'); mem=v('ram',0,0,'')
    I.raw_ops=[op('INT_ADD',sp,[sp,v('const',-16,8,'')]),op('STORE',None,[mem,sp,a0]),op('LOAD',a1,[mem,sp]),op('INT_ADD',sp,[sp,v('const',16,8,'')])]
    blocks,summary=from_lifted([I()])
    fragment=AsmFragment(rawAsmText='private-frame',outputs=[AsmOperand(constraint='=r',exprText='out',isOutput=True)],inputs=[AsmOperand(constraint='r',exprText='in',isOutput=False)])
    model=build_source_semantic_model(fragment=fragment,blocks=blocks,cfg=CFGResult(ok=True),summary=summary,xlen=64,runtime_facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':1,'a1':0},operand_width_bits={0:64,1:64}))
    model=replace(model,operation=replace(model.operation,may_trap=False),microarch=replace(model.microarch,has_timing_source=False,has_cache_operation=False,has_speculation_control=False))
    assert model.stack_frame.virtual_private_frame_eligible
    plan=generate_candidate_plans(model)[0]
    assert plan.kind.value=='virtual_private_frame'
    env=TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived=derive_target_constraints(source_model=model,candidate_plan=plan,target_environment=env)
    assert derived.success and derived.constraints is not None
    proof=run_semantic_proof_gate(source_model=model,candidate_plan=plan,constraints=derived.constraints,target_environment=env,target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}),frozenset({'virtual-private-frame.c.scalar-v1'}),'private-v1'),compiler_capabilities=CompilerCapabilityModel(True,False))
    assert proof.approved
    approved=ApprovedTargetLoweringPlan(plan,derived.constraints,proof,proof.evidence.source_model_id,proof.evidence.preservation_decision_id,proof.evidence.target_environment_id,'test','1',SelectionTier.STRUCTURED_C)
    contract=RendererContract('virtual-private-frame.c.scalar-v1',plan.plan_id,RendererContractKind.VIRTUAL_PRIVATE_FRAME,VirtualPrivateFrameRecipe('virtual-private-frame.c.scalar-v1',16,8))
    rendered=render_approved_target_lowering(Phase6FRenderRequest(approved,env,RendererContext({plan.plan_id:contract},{0:'out',1:'in'})))
    assert '_Alignas(8) unsigned char __rv2x86_frame[16]' in rendered.emitted_text
    assert 'memcpy(__rv2x86_frame + 0, &(in), 8);' in rendered.emitted_text
    assert 'memcpy(&(out), __rv2x86_frame + 0, 8);' in rendered.emitted_text
    assert '%rsp' not in rendered.emitted_text and '%rbp' not in rendered.emitted_text
    compiler=shutil.which('cc')
    if compiler:
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'frame.c'
            source.write_text('#include <string.h>\n#include <stdint.h>\nuint64_t f(uint64_t in) { uint64_t out; '+rendered.emitted_text+' return out; }\n')
            result=subprocess.run([compiler,'-std=gnu11','-c',str(source),'-o',str(Path(d)/'frame.o')],capture_output=True,text=True,check=False)
            assert result.returncode == 0, result.stderr

def test_private_frame_load_before_store_is_not_classified_private():
    # The Phase-5 analyzer independently rejects source-frame initial content.
    from riscv2x86_py.stack_frame_analysis import analyze_stack_frame_semantics
    from riscv2x86_py.pcode_ir import Block,IRSummary,Op,Var,VarKind,StackFrameClassification
    sp=Var(VarKind.REG,'register',2,8,'sp'); out=Var(VarKind.REG,'register',10,8,'a0'); c=Var(VarKind.CONST,'const',-16,8,''); mem=Var(VarKind.OTHER,'ram',0,0,'')
    result=analyze_stack_frame_semantics(blocks=[Block(0,ops=[Op(0,'INT_ADD',sp,[sp,c]),Op(0,'LOAD',out,[mem,sp])])],summary=IRSummary(True,False,False,False,False,{'sp'},{'sp','a0'},True,False,has_return=False,has_indirect_control_flow=False))
    assert result.classification is StackFrameClassification.UNKNOWN
    assert 'private-frame-initial-content-observable' in result.missing_fact_codes
