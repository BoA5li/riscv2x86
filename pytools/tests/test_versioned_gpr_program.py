"""Canonical p-code redefinitions, proof-bound rendering and real native checks."""
from dataclasses import replace
import shutil
import subprocess

import pytest

from tests.test_phase6_add_shift_early_clobber_contract import (
    AsmFragment, AsmOperand, Op, Var, VarKind, IRSummary, Block, CFGResult,
    TranslationRuntimeFacts, build_source_semantic_model, generate_candidate_plans,
    TargetEnvironment, derive_target_constraints, run_semantic_proof_gate,
    TargetSemanticCatalog, CompilerCapabilityModel, ApprovedTargetLoweringPlan,
    SelectionTier, GPR_INTEGER_RENDERER_CONTRACT_REGISTRY,
    render_approved_target_lowering, Phase6FRenderRequest, RendererContext, _ID)


def model(width=64, codes=('INT_ADD', 'INT_ADD'), rhs=False, lifted_copy=False, mutate=None):
    size = width // 8
    regs = [Var(VarKind.REG, 'register', 10+i, size, 'a'+str(i)) for i in range(len(codes)+2)]
    fragment = AsmFragment(outputs=[AsmOperand(constraint='=&r', exprText='result', isOutput=True, isEarlyClobber=True)],
        inputs=[AsmOperand(constraint='r', exprText='x'+str(i)) for i in range(len(codes)+1)], isVolatile=True)
    ops = []
    for n, code in enumerate(codes):
        args = [regs[1] if n == 0 else regs[0], regs[n+2]]
        if rhs and n:
            args.reverse()
        out = Var(VarKind.UNIQUE, 'unique', 100+n, size) if lifted_copy else regs[0]
        ops.append(Op(0x1000+4*n, code, out, args))
        if lifted_copy:
            ops.append(Op(0x1000+4*n, 'COPY', regs[0], [out]))
    if mutate:
        mutate(ops, regs)
    summary = IRSummary(is_single_block=True, has_branch=False, has_call_or_return=False,
        has_memory_barrier=False, has_atomic=False, reads_regs={r.name for r in regs[1:]},
        writes_regs={'a0'}, reads_mem=False, writes_mem=False,
        has_return=False, has_tail_call=False, has_indirect_control_flow=False,
        has_timing_source=False, has_cache_operation=False, has_speculation_control=False)
    return build_source_semantic_model(fragment=fragment, blocks=(Block(0x1000, ops, summary),),
        cfg=CFGResult(ok=True), summary=summary, xlen=64,
        runtime_facts=TranslationRuntimeFacts({r.name:i for i,r in enumerate(regs)},
            {i:width for i in range(len(regs))}, 'canonical-pcode-test'))


def render(m):
    plan = next(p for p in generate_candidate_plans(m) if p.metadata.get('renderer_semantic_contract_id') == _ID)
    env = TargetEnvironment.fixed_sysv_amd64_gnu_att()
    derived = derive_target_constraints(source_model=m, candidate_plan=plan, target_environment=env)
    assert derived.success
    proof = run_semantic_proof_gate(source_model=m, preservation_decision=m.preservation,
        candidate_plan=plan, constraints=derived.constraints, target_environment=env,
        target_semantic_catalog=TargetSemanticCatalog(frozenset({plan.kind}), frozenset({_ID}), 'test'),
        compiler_capabilities=CompilerCapabilityModel(True, False))
    assert proof.approved
    approved = ApprovedTargetLoweringPlan(plan, derived.constraints, proof, proof.evidence.source_model_id,
        proof.evidence.preservation_decision_id, proof.evidence.target_environment_id,
        'phase6e.semantic-fidelity', '1', SelectionTier.X86_INLINE_ASM)
    contract = GPR_INTEGER_RENDERER_CONTRACT_REGISTRY.resolve(approved)
    expressions = {0:'result', **{i:'x'+str(i-1) for i in m.value_program.input_operand_indexes}}
    result = render_approved_target_lowering(Phase6FRenderRequest(approved, env,
        RendererContext({plan.plan_id:contract}, expressions)))
    assert result.emitted_text
    return result.emitted_text


@pytest.mark.parametrize('width', [32, 64])
@pytest.mark.parametrize('lifted_copy', [False, True])
@pytest.mark.parametrize('codes,rhs', [
    (('INT_ADD','INT_ADD'),False), (('INT_ADD','INT_ADD','INT_ADD'),False),
    (('INT_XOR','INT_AND'),False), (('INT_OR','INT_SUB'),True)])
def test_redefinitions_bind_current_versions_and_execute(tmp_path, width, lifted_copy, codes, rhs):
    m = model(width, codes, rhs, lifted_copy)
    p = m.value_program
    assert p is not None and p.value_schema_version == 2
    assert p.definition_history[1][1 if not rhs else 2] == 'definition:0'
    text = render(m)
    cc = shutil.which('gcc')
    if not cc:
        pytest.skip('real native gcc required')
    typ = 'uint'+str(width)+'_t'
    parameters = ','.join(typ+' x'+str(i) for i in range(len(codes)+1))
    expression = 'x0'
    symbols = {'INT_ADD':'+','INT_SUB':'-','INT_AND':'&','INT_OR':'|','INT_XOR':'^'}
    for n, code in enumerate(codes):
        left,right = expression,'x'+str(n+1)
        if rhs and n:
            left,right = right,left
        expression = '('+left+symbols[code]+right+')'
    source = tmp_path/'native.c'
    source.write_text('#include <stdint.h>\n'+typ+' probe('+parameters+'){'+typ+' result;'+text+'return result;}\n'
        'int main(void){for(uint64_t i=0;i<128;i++){'+
        ''.join(typ+' x'+str(n)+'=('+typ+')(i*UINT64_C(0xfedcba9876543211)+'+str(n)+');' for n in range(len(codes)+1))+
        'if(probe('+','.join('x'+str(n) for n in range(len(codes)+1))+')!=('+typ+')('+expression+'))return 1;}return 0;}')
    for optimization in ('-O0','-O2','-O3'):
        binary = tmp_path/'native'
        r = subprocess.run([cc,'-std=gnu11',optimization,'-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],capture_output=True,text=True)
        assert r.returncode == 0, r.stderr
        assert subprocess.run([str(binary)],check=False).returncode == 0


def test_stale_definition_and_legacy_redefinition_are_rejected():
    p = model().value_program
    assert p is not None
    stale = list(p.definition_history)
    stale[1] = ('definition:1', 'input:1', 'input:3')
    with pytest.raises(ValueError, match='stale'):
        replace(p, definition_history=tuple(stale))
    with pytest.raises(ValueError, match='redefinitions'):
        replace(p, value_schema_version=1, definition_history=())


@pytest.mark.parametrize('mutation', ['undefined', 'memory', 'mixed_width', 'stale_temporary'])
def test_incomplete_or_stale_pcode_never_enters_versioned_contract(mutation):
    def mutate(ops, regs):
        if mutation == 'undefined':
            ops[0].inputs[0] = regs[0]
        elif mutation == 'memory':
            ops[2].opcode = 'LOAD'
        elif mutation == 'mixed_width':
            ops[2].inputs[1] = Var(VarKind.REG, 'register', 13, 4, 'a3')
        else:
            # Value 0 still exists as a lifter temporary, but its only
            # operand storage was overwritten by definition 1.
            ops[4].inputs[0] = ops[0].output
    m = model(codes=('INT_ADD','INT_ADD','INT_ADD'), lifted_copy=True, mutate=mutate)
    assert m.value_program is None


def test_definition_history_survives_json_roundtrip_with_exact_identity():
    import json
    from dataclasses import asdict
    from riscv2x86_py.semantic_content import semantic_identity
    from riscv2x86_py.source_model import SourceStraightLineValueInstruction, SourceStraightLineValueOpcode
    p = model().value_program
    data = json.loads(json.dumps(asdict(p)))
    data['instructions'] = tuple(SourceStraightLineValueInstruction(
        SourceStraightLineValueOpcode(i['opcode']), i['output_operand_index'],
        tuple(i['input_operand_indexes']), i['immediate_value']) for i in data['instructions'])
    for key in ('output_operand_indexes','input_operand_indexes'):
        data[key] = tuple(data[key])
    data['definition_history'] = tuple(tuple(h) for h in data['definition_history'])
    rebuilt = type(p)(**data)
    assert rebuilt == p and semantic_identity(asdict(rebuilt)) == semantic_identity(asdict(p))
    with pytest.raises(ValueError, match='schema'):
        replace(p, value_schema_version=True)
    with pytest.raises(ValueError, match='typed'):
        replace(p, input_operand_indexes=(True,2,3))
