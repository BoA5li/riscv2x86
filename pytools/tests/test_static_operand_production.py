"""Compiler AST fixtures exercise static-role production; real tools are separate."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json

import pytest
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts
from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
from riscv2x86_py.compiler_static_operand import static_operands
from tests.test_compiler_expression_contracts import ctype
from tests.l2_profile_fixtures import profile_dict
from tests.l2_effect_proof_fixtures import attach_effect_proof

S='sha256:'+'1'*64
F='sha256:'+'2'*64


def literal_finding(value=67):
    source=f'unsigned long renamed(unsigned long x) {{ unsigned long out; __asm__ volatile("addi %0,%1,%2" : "=r"(out) : "r"(x), "i"({value})); return out; }}'.encode()
    def extent(a,b):return {'begin':{'offset':a,'line':1,'col':a+1},'end':{'offset':b-1,'tokLen':1}}
    def ref(name,a):return {'kind':'DeclRefExpr','range':extent(a,a+len(name)),
        'referencedDecl':{'id':'ast:'+name},'type':{'qualType':'unsigned long'},'valueCategory':'lvalue'}
    begin=source.index(b'__asm__');end=source.index(b';',begin)+1
    out=source.index(b'(out)',begin)+1;x=source.index(b'(x)',begin)+1;lit=source.index(b'"i"(')+4
    asm={'kind':'GCCAsmStmt','range':extent(begin,end),'numOutputs':1,'outputConstraints':['=r'],'inner':[ref('out',out),ref('x',x),
        {'kind':'IntegerLiteral','type':{'qualType':'int'},'valueCategory':'prvalue',
         'range':extent(lit,lit+len(str(value))),'value':str(value)}]}
    if value<0:
        asm['inner'][-1]={'kind':'UnaryOperator','opcode':'-','type':{'qualType':'int'},
            'valueCategory':'prvalue','range':extent(lit,lit+len(str(value))),
            'inner':[{'kind':'IntegerLiteral','type':{'qualType':'int'},'valueCategory':'prvalue',
                      'range':extent(lit+1,lit+len(str(value))),'value':str(-value)}]}
    returned=source.index(b'out;',end)
    function_ast={'kind':'FunctionDecl','name':'renamed','range':extent(0,len(source)),
        'inner':[{'kind':'ParmVarDecl','id':'ast:x','name':'x','range':extent(22,37),'type':{'qualType':'unsigned long'}},
            {'kind':'CompoundStmt','inner':[{'kind':'DeclStmt','inner':[
                {'kind':'VarDecl','id':'ast:out','name':'out','range':extent(40,57),'type':{'qualType':'unsigned long'}}]},asm,
                {'kind':'ReturnStmt','inner':[ref('out',returned)]}]}]}
    boundary=_l2_operand_boundary_facts(function_ast,source_digest=S,function_identity=F,
        source_file='/tmp/independent.c',source_bytes=source)
    raw=boundary['fragmentCandidates'][0]
    fragment={'id':'/tmp/independent.c:1:'+str(begin+1),'enclosingFunction':'renamed','file':'/tmp/independent.c',
        'line':1,'column':begin+1,'beginOffset':begin,'endOffset':end,
        'outputs':[{'constraint':'=r','compilerType':ctype()}],
        'inputs':[{'constraint':'r','compilerType':ctype()},{'constraint':'i','compilerType':ctype(canonicalType='int',widthBits=32,alignmentBytes=4,isSigned=True)}]}
    closed=close_compiler_fragment_candidate(raw,fragment,source_digest=S,function_identity=F)
    authority={'schemaVersion':'riscv2x86.compiler-fragment-authority.v2','sourceDigest':S,
        'functionIdentity':F,'fragmentId':fragment['id'],'targetTriple':'riscv64-linux-gnu',
        'fragmentBindingKey':raw['fragmentBindingKey'],'candidate':closed,
        'compilerTypeBindings':{str(b['operandIndex']):{'operandIndex':b['operandIndex'],
            'valueNodeIdentity':b['valueNodeIdentity'],'compilerType':(fragment['outputs']+fragment['inputs'])[b['operandIndex']]['compilerType']} for b in closed['operandBindings']}}
    authority['authorityIdentity']=identity(authority);fragment['compilerFragmentAuthority']=authority
    f={'fragment':fragment,'approvalArtifact':{'proofStatus':'approved','architectureSemanticsPreserved':True,
        'shellSemanticsPreserved':True,'planId':S,'constraintsId':F},'l2SemanticProfile':profile_dict(fragment['id'])}
    attach_effect_proof(f['approvalArtifact'],fragment['id'])
    function={'name':'renamed','functionId':F,'sourceDigest':S,'sourceFile':'/tmp/independent.c',
        'arity':1,'parameterTypes':['unsigned long'],'returnType':'unsigned long','l2OperandBoundary':boundary}
    return f,function


def test_literal_candidate_replays_and_produces_complete_boundary():
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority,fragment_boundary_from_dict
    f,function=literal_finding()
    literals=static_operands(f['fragment'])
    assert literals[2]['value']==67
    boundaries,graph,execution=materialize_fragment_execution_authority([f],function,S)
    b=boundaries[f['fragment']['id']]
    assert b.complete,b.reason_codes
    assert b.input_bindings[-1].declaration_identity==''
    assert fragment_boundary_from_dict(b.to_dict())==b
    assert graph.complete and execution.complete


def test_static_role_reaches_canonical_sidecar_and_compiler_consumption(tmp_path):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.compiler_provenance import bind_compiler_provenance
    f,function=literal_finding();frontend=tmp_path/'frontend';frontend.write_text('fixture')
    count=materialize_automatic_l2_authority({'findings':[f]},[function],frontend)
    assert count==1,json.dumps(f['approvalArtifact'],indent=2)
    raw=f['approvalArtifact']['l2AuthoritySidecar'];sidecar=l2_authority_sidecar_from_dict(raw)
    assert sidecar.schema_version.endswith('.v6')
    assert sidecar.operands[2].static_operand['value']==67
    assert sidecar.operand_observation_authority.bindings[2].closure_kind=='compiler_constant'
    assert bind_compiler_provenance(f['fragment'],sidecar)


def test_static_authority_is_independently_consumed_by_observation_provider(tmp_path):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.automatic_l2_operand import _authority,_sample_observations
    from riscv2x86_py.l2_operand_observation_plan import CanonicalOperandObservationPlan
    f,function=literal_finding();frontend=tmp_path/'frontend';frontend.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},[function],frontend)==1
    a=f['approvalArtifact'];sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    artifact=SimpleNamespace(fragment_id=f['fragment']['id'],proof_identity=a['proofIdentity'],
        shell_facts_identity=sidecar.shell_fact_identity,l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity,l2_authority_complete=True)
    authority,reason=_authority(f,[function],artifact)
    assert authority is not None,reason
    plan=CanonicalOperandObservationPlan(sidecar.operand_observation_authority)
    # Rows contain actual dynamic parameter/return positions; literal uses a
    # separately labelled static compiler witness and no invented parameter.
    observations=_sample_observations(((5,72),),plan,trace_arity=1)
    constant=observations[0]['logicalOperands'][2]
    assert constant['observationKind']=='compiler_constant'
    assert int(constant['valueBefore'],16)==67
    assert observations[0]['logicalOperands'][0]['valueAfter']=='0x0000000000000048'


@pytest.mark.parametrize('value',[-7,0,18,67,2047])
def test_static_value_changes_follow_compiler_replay_not_case_identity(value):
    f,_=literal_finding(value)
    assert static_operands(f['fragment'])[2]['value']==value


@pytest.mark.parametrize('field,value',[('value',68),('widthBits',16),('expressionIdentity',S)])
def test_rehashed_static_mutations_cannot_change_compiler_provenance(tmp_path,field,value):
    from dataclasses import replace
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.compiler_provenance import bind_compiler_provenance
    f,function=literal_finding();frontend=tmp_path/'frontend';frontend.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},[function],frontend)==1
    sidecar=l2_authority_sidecar_from_dict(f['approvalArtifact']['l2AuthoritySidecar'])
    operand=sidecar.operands[2];raw=deepcopy(operand.static_operand)
    raw[field]=value;raw['bindingIdentity']=identity({k:v for k,v in raw.items() if k!='bindingIdentity'})
    with pytest.raises(ValueError):
        changed=replace(operand,static_operand=raw)
        bind_compiler_provenance(f['fragment'],SimpleNamespace(fragment_id=sidecar.fragment_id,
            operands=sidecar.operands[:2]+(changed,),authority_identity=S))


def test_constant_payload_cannot_be_downgraded_to_legacy_schemas(tmp_path):
    from riscv2x86_py.automatic_l2_authority import materialize_automatic_l2_authority
    from riscv2x86_py.l2_authority import l2_authority_sidecar_from_dict
    from riscv2x86_py.l2_fragment_execution import fragment_boundary_from_dict,operand_observation_authority_from_dict
    from riscv2x86_py.canonical_l2_operand import canonical_l2_operand_bindings_from_dict
    f,function=literal_finding();frontend=tmp_path/'frontend';frontend.write_text('fixture')
    assert materialize_automatic_l2_authority({'findings':[f]},[function],frontend)==1
    a=f['approvalArtifact']
    for raw,parser,version,identity_key in [
        (a['l2AuthoritySidecar'],l2_authority_sidecar_from_dict,'riscv2x86.l2-authority-sidecar.v4','authorityIdentity'),
        (a['l2FragmentOperandBoundary'],fragment_boundary_from_dict,'riscv2x86.fragment-operand-boundary.v2','boundaryIdentity'),
        (a['l2CanonicalOperandBindings'],canonical_l2_operand_bindings_from_dict,'riscv2x86.canonical-l2-operand-binding-set.v1','bindingSetIdentity'),
        (a['l2OperandObservationAuthority'],operand_observation_authority_from_dict,'riscv2x86.l2-operand-observation-authority.v2','authorityIdentity')]:
        raw=deepcopy(raw);raw['schemaVersion']=version
        raw[identity_key]=identity({k:v for k,v in raw.items() if k!=identity_key})
        with pytest.raises(ValueError):parser(raw)


def test_closed_candidate_without_compiler_envelope_does_not_grant_boundary():
    from riscv2x86_py.l2_fragment_execution import materialize_fragment_execution_authority
    f,function=literal_finding()
    closed=f['fragment']['compilerFragmentAuthority']['candidate']
    f['fragment'].pop('compilerFragmentAuthority')
    function['l2OperandBoundary']['fragmentCandidates']=[closed]
    boundaries,_,_=materialize_fragment_execution_authority([f],function,S)
    boundary=boundaries[f['fragment']['id']]
    assert not boundary.complete
    assert 'L2_FRAGMENT_CANDIDATE_SCHEMA_UNSUPPORTED' in boundary.reason_codes
