"""Original 6A--6F path; real p-code and host binaries, no GMP name rules."""
from copy import deepcopy
from dataclasses import replace
import ctypes
import json
from pathlib import Path
import random
import shutil
import subprocess
from types import SimpleNamespace
import pytest
import pypcode
from riscv2x86_py.schema import load_report
from riscv2x86_py.lift import lift
from riscv2x86_py.ghidra_pythonrun_bridge import PythonRunRegisterNameResolver
from riscv2x86_py.pcode_ir import from_lifted
from riscv2x86_py.cfg import build_cfg_from_blocks
from riscv2x86_py.source_model import build_source_semantic_model
from riscv2x86_py.runtime_facts import TranslationRuntimeFacts
from riscv2x86_py.candidate_plans import generate_candidate_plans
from riscv2x86_py.phase6c_constraints import TargetEnvironment,derive_target_constraints
from riscv2x86_py.phase6d_common import CompilerCapabilityModel,TargetSemanticCatalog,run_semantic_proof_gate
from riscv2x86_py.phase6e_selection import ApprovedTargetLoweringPlan,SelectionTier
from riscv2x86_py.phase6f_contract_registry import GPR_INTEGER_RENDERER_CONTRACT_REGISTRY
from riscv2x86_py.phase6f_renderer import Phase6FRenderRequest,RendererContext,render_approved_target_lowering
from riscv2x86_py import wide_integer_target as target
from .test_native_instance_binding import example
from .test_native_original_pipeline import adapted

REAL_SUBPROCESS_RUN=subprocess.run


def build(tmp_path,width=64,mutation=None):
    _,report,_=example(name='renamed_real_input')
    f=report['findings'][0];f['fragment']['id']='independent-instance'
    f['fragment']['isVolatile']=True
    if width==32:
        for o in f['fragment']['outputs']+f['fragment']['inputs']:
            o['compilerType'].update(canonicalType='unsigned int',widthBits=32,alignmentBytes=4)
    path=tmp_path/'input.json';path.write_text(json.dumps(report));fragment=load_report(str(path))[0].fragment
    ctx=pypcode.Context('RISCV:LE:'+str(width)+':default');names={}
    for name in ('a0','a1','a2'):
        v=ctx.registers[name];names[('register',v.offset,v.size)]=name
    lifted=lift(bytes.fromhex('33b5c502'),xlen=width,
        register_name_resolver=PythonRunRegisterNameResolver(names),require_authoritative_register_names=True)
    assert lifted.ok,lifted.error
    blocks,summary=from_lifted(lifted.insns)
    if mutation:mutation(fragment,blocks)
    model=build_source_semantic_model(fragment=fragment,blocks=blocks,cfg=build_cfg_from_blocks(blocks),
        summary=summary,xlen=width,runtime_facts=TranslationRuntimeFacts(
            rv_to_operand_index={'a0':0,'a1':1,'a2':2},operand_width_bits={i:width for i in range(3)}))
    return model


def lower(model):
    env=TargetEnvironment.fixed_sysv_amd64_gnu_att()
    plans=generate_candidate_plans(model)
    plan=next(p for p in plans if p.metadata.get('renderer_semantic_contract_id')==target.CONTRACT)
    derived=derive_target_constraints(source_model=model,candidate_plan=plan,target_environment=env)
    assert derived.success,derived
    proof=run_semantic_proof_gate(source_model=model,preservation_decision=model.preservation,
        candidate_plan=plan,constraints=derived.constraints,target_environment=env,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}),frozenset({target.CONTRACT}),'wide-test-v1'),
        compiler_capabilities=CompilerCapabilityModel(True,False))
    assert proof.approved,proof
    approved=ApprovedTargetLoweringPlan(plan,derived.constraints,proof,proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id,proof.evidence.target_environment_id,
        'phase6e.semantic-fidelity','1',SelectionTier.X86_INLINE_ASM)
    registered=GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    assert registered is not None
    request=Phase6FRenderRequest(approved,env,RendererContext({plan.plan_id:registered},
        {0:'hi',1:'left',2:'right'}))
    rendered=render_approved_target_lowering(request)
    assert rendered.emitted_text and not rendered.diagnostics
    return rendered.emitted_text,request,registered


@pytest.mark.parametrize('width',[32,64])
def test_actual_pcode_proves_and_renders_original_registered_contract(tmp_path,width):
    model=build(tmp_path,width)
    assert model.value_operation.kind.value=='unsigned_multiply_high'
    assert model.operand_permutations==((0,1,2),(0,2,1))
    assert all(o.compiler_integer_type_complete for o in model.operands.operands)
    assert target.bitvector_lemma(width)
    text,_,_=lower(model)
    assert '"rax", "rdx", "cc"' in text
    assert '__asm__ volatile' in text and '"%r"' not in text


@pytest.mark.parametrize('mutation',['sext','low','width','extra-write','missing-type','constraint','extra-op','output-evaluation'])
def test_wrong_or_incomplete_semantics_are_not_admitted(tmp_path,mutation):
    def change(fragment,blocks):
        ops=blocks[0].ops
        semantic=[o for o in ops if o.opcode!='IMARK']
        if mutation=='sext':semantic[0].opcode='INT_SEXT'
        elif mutation=='low':semantic[-1].inputs[1]=replace(semantic[-1].inputs[1],offset=0)
        elif mutation=='width':semantic[0].output=replace(semantic[0].output,size=8)
        elif mutation=='extra-write':ops.append(deepcopy(semantic[-1]))
        elif mutation=='extra-op':ops.append(deepcopy(semantic[0]))
        elif mutation=='missing-type':fragment.inputs[0].compilerType={}
        elif mutation=='constraint':fragment.inputs[0].constraint='r,m'
        elif mutation=='output-evaluation':fragment.outputs[0].compilerType['sideEffectFree']=False
    model=build(tmp_path,mutation=change)
    assert not target.applicable(model)


def test_proof_and_renderer_reject_forged_resource_contracts(tmp_path):
    model=build(tmp_path);_,request,registered=lower(model)
    changed=replace(registered,payload=replace(registered.payload,register_clobbers=()))
    forged=replace(request,renderer_context=RendererContext({request.approved_plan.plan.plan_id:changed},
        {0:'hi',1:'left',2:'right'}))
    assert render_approved_target_lowering(forged).diagnostics
    assert not target.applicable(replace(model,implicit_state=replace(model.implicit_state,writes_implicit_machine_state=True)))


def test_original_pipeline_reaches_emitted_archive_with_real_lifter(tmp_path,monkeypatch):
    from riscv2x86_py import pipeline
    from riscv2x86_py.assemble import AssembleResult
    from riscv2x86_py.translation_attempt import load_translation_attempt_archive
    _,report,_=example(name='different_owner')
    finding=report['findings'][0];finding['fragment']['id']='pipeline-instance'
    finding['fileName']=str(tmp_path/'input.i');finding['fragment']['fileName']=finding['fileName']
    finding['hasRewriteRange']=True
    input_path=tmp_path/'report.json';input_path.write_text(json.dumps(report))
    ctx=pypcode.Context('RISCV:LE:64:default');names={}
    for name in ('a0','a1','a2'):
        v=ctx.registers[name];names[('register',v.offset,v.size)]=name
    facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1,'a2':2},operand_width_bits={0:64,1:64,2:64})
    # Only the unavailable source assembler boundary is a fixture. Actual
    # lifting, source modeling, original selection/proof/render and archive run.
    monkeypatch.setattr(pipeline,'assemble',lambda *a,**kw:AssembleResult(True,bytes.fromhex('33b5c502'),[],translation_runtime_facts=facts))
    output=tmp_path/'translated.json'
    stats=pipeline.run(str(input_path),str(output),register_name_resolver=PythonRunRegisterNameResolver(names),verify_enabled=False)
    archived=load_translation_attempt_archive(str(output)+'.attempts.json')
    assert len(archived.attempts)==1
    assert archived.attempts[0].translation_outcome.value=='emitted',output.read_text()
    value=json.loads(output.read_text())['findings'][0]
    assert value['sourceModelDiagnostics']['valueOperationKind']=='unsigned_multiply_high'
    assert value['sourceModelDiagnostics']['missingSourceFacts']==[]
    assert value['validationOutcome']=='not_verified' and value['publicationOutcome']=='withheld'


def test_physical_adapter_real_pipeline_materializer_and_replay_join(adapted,monkeypatch):
    from riscv2x86_py import pipeline,native_original_pipeline as route
    from riscv2x86_py.assemble import AssembleResult
    root,prepared,_,raw=adapted
    frontend_run=route.subprocess.run
    ctx=pypcode.Context('RISCV:LE:64:default');names={}
    for name in ('a0','a1','a2'):
        v=ctx.registers[name];names[('register',v.offset,v.size)]=name
    resolver=PythonRunRegisterNameResolver(names)
    facts=TranslationRuntimeFacts(rv_to_operand_index={'a0':0,'a1':1,'a2':2},operand_width_bits={0:64,1:64,2:64})
    monkeypatch.setattr(pipeline,'assemble',lambda *a,**kw:AssembleResult(True,bytes.fromhex('33b5c502'),[],translation_runtime_facts=facts))
    def original_backend(command,**kwargs):
        if '--report-json' in command:return frontend_run(command,**kwargs)
        if '--in' in command and 'riscv2x86_py.cli' in command:
            stats=pipeline.run(command[command.index('--in')+1],command[command.index('--out')+1],
                register_name_resolver=resolver,verify_enabled=False)
            return SimpleNamespace(returncode=0,stdout=json.dumps(stats).encode(),stderr=b'')
        return REAL_SUBPROCESS_RUN(command,**kwargs)
    monkeypatch.setattr(route.subprocess,'run',original_backend)
    result=route.translate(root/'prepared/result.json',root/'actual-original')
    assert result['attemptOutcomes']==['emitted']
    candidate=(root/'actual-original/candidate-staging/input.i').read_bytes()
    assert b'mulq' in candidate and b'__asm__("mulhu' not in candidate
    assert Path(prepared['source']['path']).read_bytes()==raw
    assert route.audit(root/'actual-original/result.json',root/'actual-audit')['originalBackendReplayComplete']


@pytest.mark.parametrize('width',[32,64])
@pytest.mark.parametrize('optimization',['-O0','-O2','-O3'])
def test_host_binary_matches_independent_arbitrary_precision_oracle(tmp_path,width,optimization):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('real host GCC required')
    text,request,registered=lower(build(tmp_path,width))
    typ='unsigned long long' if width==64 else 'unsigned int'
    source=tmp_path/'target.c'
    alias_request=replace(request,renderer_context=RendererContext(
        {request.approved_plan.plan.plan_id:registered},{0:'left',1:'left',2:'right'}))
    alias=render_approved_target_lowering(alias_request).emitted_text
    # The second function uses exactly the same C variable for input/output.
    source.write_text(f'{typ} eval({typ} left,{typ} right){{{typ} hi; {text} return hi;}}\n'
        f'{typ} eval_alias({typ} left,{typ} right){{{alias} return left;}}\n')
    library=tmp_path/'target.so'
    subprocess.run([cc,'-shared','-fPIC',optimization,'-Wall','-Wextra','-Werror',str(source),'-o',str(library)],check=True,capture_output=True)
    loaded=ctypes.CDLL(str(library))
    carrier=ctypes.c_uint64 if width==64 else ctypes.c_uint32
    mask=(1<<width)-1;boundary=[0,1,2,mask,mask-1,1<<(width-1),(1<<(width-1))-1]
    rng=random.Random(721)
    pairs=[(a,b) for a in boundary for b in boundary]+[(rng.getrandbits(width),rng.getrandbits(width)) for _ in range(2048)]
    for name in ('eval','eval_alias'):
        fn=getattr(loaded,name);fn.argtypes=[carrier,carrier];fn.restype=carrier
        for a,b in pairs:assert fn(a,b)==((a*b)>>width)&mask
