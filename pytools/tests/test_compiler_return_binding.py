"""Typed AST/return binding, native observations and rejection controls."""
from copy import deepcopy
import json
import shutil
import subprocess

import pytest
from riscv2x86_py.automatic_batch_cli import _l2_operand_boundary_facts, _decl_identity
from riscv2x86_py.compiler_return_binding import export, analyze, evaluate
from riscv2x86_py.compiler_memory_signature import type_fact, export as signature
from riscv2x86_py.compiler_value_flow import identity
from riscv2x86_py.l3_memory_call import bind_load, load_value, validate_load_call

SD = 'sha256:' + '1'*64
FD = 'sha256:' + '2'*64
DECL = 'sha256:' + '3'*64


def node(kind, typ, children=(), **extra):
    return dict(kind=kind, type={'qualType':typ}, valueCategory='prvalue',
        range={'begin':{'offset':100}, 'end':{'offset':110,'tokLen':1}},
        inner=list(children), **extra)


def expression(types):
    leaf=node('DeclRefExpr', types[0], referencedDecl={'id':'raw-output'})
    leaf['valueCategory']='lvalue'
    value=node('ImplicitCastExpr', types[0], [leaf], castKind='LValueToRValue')
    for typ in types[1:]:
        value=node('ImplicitCastExpr', typ, [value], castKind='IntegralCast')
    return value


def binding(types, expr=None):
    from riscv2x86_py.automatic_batch_cli import _source_range
    returned=node('ReturnStmt',types[-1],[expr or expression(types)])
    return export(returned, source_digest=SD, function_identity=FD,
        declaration_identity=lambda raw:DECL if raw=='raw-output' else '',
        source_range=_source_range, result_type=types[-1], type_resolver=lambda t:t)


def relation(b):
    return analyze(b, source_digest=SD, function_identity=FD, result_type=b['resultType'])


def fixture(types=('int','long')):
    from tests.test_typed_load_execution import fixture as load_fixture, model
    from riscv2x86_py.l2_memory_object import memory_proof_facts_from_source_model
    f,fn,spec=load_fixture(32,'zero_extend',types[0]=='int',types[-1]=='long')
    fn.update(functionId=FD,sourceDigest=SD)
    boundary=fn['l2OperandBoundary'];boundary.update(returnDeclarationId='',compilerReturnBinding=binding(types))
    operands=f['approvalArtifact']['l2AuthoritySidecar']['operands']
    operands[1].update(declarationId=DECL,widthBits=32,signedness='signed' if type_fact(types[0])['signed'] else 'unsigned')
    fn['compilerMemoryCallSignature']=signature(fn,['unsigned int *'],types[-1],lambda t:t)
    scope=fn['compilerAtomicFunctionScope'];scope.update(sourceDigest=SD,functionIdentity=FD)
    scope['scopeIdentity']=identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
    facts=memory_proof_facts_from_source_model(f['fragment']['id'],model(32,32,'zero_extend',12))
    assert facts.value_projection=='identity' and facts.carrier_width_bits==32
    f['approvalArtifact']['l2MemoryProofFacts']=facts.to_dict()
    return f,fn,spec


@pytest.mark.parametrize('types', [('int','long'),('unsigned int','unsigned long'),
    ('int','unsigned long'),('unsigned int','long'),('int','unsigned int','unsigned long')])
def test_native_return_chain_and_full_object(tmp_path,types):
    from riscv2x86_py.l3_trace_deployment import harness
    from riscv2x86_py.l3_qemu_memory_route import parse_objects
    f,fn,spec=fixture(types);call=bind_load(fn,f,spec)
    assert call['schemaVersion'].endswith('.v2')
    assert validate_load_call(json.loads(json.dumps(call)))==call
    text=harness({'name':'converted_load','callSignature':call},spec,4)
    returned='out'
    for typ in types[1:-1]:returned='('+typ+')('+returned+')'
    text+='\n'+types[-1]+' converted_load(unsigned int *p){'+types[0]+' out;'
    text+='__asm__ volatile("movl 12(%1), %k0" : "=r"(out) : "r"(p) : "memory");return '+returned+';}\n'
    source=tmp_path/'probe.c';binary=tmp_path/'probe';source.write_text(text)
    done=subprocess.run([shutil.which('cc'),'-std=gnu11','-O2','-fstrict-aliasing','-Wall','-Wextra','-Werror',str(source),'-o',str(binary)],capture_output=True,text=True)
    assert done.returncode==0,done.stderr
    run=subprocess.run([str(binary),'a'*64],capture_output=True,text=True)
    assert run.returncode==0
    rows=parse_objects(run.stdout,'a'*64,spec,4,call)
    expected_high=0xffffffff80000000 if types[0]=='int' and len(types)==2 else 0x80000000
    assert int(rows[2]['value'],16)==expected_high
    bad=[json.loads(x) for x in run.stdout.splitlines()]
    bad[2]['value']=f'{(expected_high ^ (1<<63)):016x}'
    with pytest.raises(ValueError,match='LOAD_VALUE_OR_OBJECT'):
        parse_objects('\n'.join(json.dumps(x) for x in bad),'a'*64,spec,4,call)


@pytest.mark.parametrize('types', [('signed char','long'),('unsigned char','long'),
    ('short','long'),('unsigned short','unsigned long'),('int','long'),
    ('unsigned int','unsigned long'),('int','unsigned long'),('unsigned int','long'),
    ('long','long'),('unsigned long','unsigned long')])
def test_general_integer_conversions_keep_all_output_bits(types):
    b=binding(types);r=relation(b);inp=type_fact(types[0]);bits=inp['widthBits']
    for raw in (0,(1<<(bits-1))-1,1<<(bits-1),(1<<bits)-1):
        value=raw-(1<<bits) if inp['signed'] and raw&(1<<(bits-1)) else raw
        actual=evaluate(value,r)&((1<<64)-1)
        assert actual==value&((1<<64)-1)


@pytest.mark.parametrize('types', [('long','int','long'),('int','unsigned char','unsigned long'),
    ('unsigned int','int','long'),('unsigned long','long')])
def test_narrowing_or_implementation_defined_signed_conversion_rejected(types):
    with pytest.raises(ValueError,match='CONVERSION_UNSUPPORTED'):relation(binding(types))


def test_arithmetic_is_not_a_declaration_alias():
    value=node('BinaryOperator','long',[expression(['long']),node('IntegerLiteral','long',value='1')],opcode='+')
    with pytest.raises(ValueError,match='CONVERSION_UNSUPPORTED'):relation(binding(['long'],value))
    assert _decl_identity(expression(['int','long']))==''
    assert _decl_identity(expression(['int']))=='raw-output'


@pytest.mark.parametrize('change',['declaration','source','function','result','input','stale','range','bool','downgrade','missing'])
def test_return_binding_and_call_mutation_rejected(change):
    f,fn,spec=fixture();boundary=fn['l2OperandBoundary'];b=boundary['compilerReturnBinding']
    if change=='declaration':
        leaf=b['expression']['children'][0]['children'][0];leaf['declarationIdentity']='sha256:'+'4'*64
        # Rehash all levels so rejection is about the compiler join, not stale hashes.
        def rehash(e):
            for c in e['children']:rehash(c)
            e['expressionIdentity']=identity({k:v for k,v in e.items() if k!='expressionIdentity'})
        rehash(b['expression'])
    if change=='source':b['sourceDigest']='sha256:'+'4'*64
    if change=='function':b['functionIdentity']='sha256:'+'4'*64
    if change=='result':b['resultType']=type_fact('unsigned long')
    if change=='input':f['approvalArtifact']['l2AuthoritySidecar']['operands'][1]['signedness']='unsigned'
    if change=='range':b['returnRange']=[1,2]
    if change=='bool':b['resultType']['signed']=1
    if change=='missing':del boundary['compilerReturnBinding']
    if change not in ('stale','missing'):
        b['factsIdentity']=identity({k:v for k,v in b.items() if k!='factsIdentity'})
    if change=='stale':b['factsIdentity']='sha256:'+'0'*64
    if change=='downgrade':
        call=bind_load(fn,f,spec);call['schemaVersion']='riscv2x86.l3-memory-load-call.v1'
        del call['returnBinding']
        call['callIdentity']=identity({k:v for k,v in call.items() if k!='callIdentity'})
        with pytest.raises(ValueError,match='RETURN_BINDING_REQUIRED'):validate_load_call(call)
    else:
        with pytest.raises(ValueError):bind_load(fn,f,spec)


def test_export_through_actual_boundary_code_preserves_integral_cast():
    param=node('ParmVarDecl','unsigned int *',id='raw-base',name='address')
    local=node('VarDecl','int',id='raw-output',name='output')
    out=node('DeclRefExpr','int',referencedDecl={'id':'raw-output'})
    base=node('DeclRefExpr','unsigned int *',referencedDecl={'id':'raw-base'})
    asm=node('GCCAsmStmt','void',[out,base])
    returned=node('ReturnStmt','long',[expression(['int','long'])])
    function=node('FunctionDecl','long (unsigned int *)',[param,node('CompoundStmt','void',[node('DeclStmt','void',[local]),asm,returned])],name='probe')
    boundary=_l2_operand_boundary_facts(function,source_digest=SD,function_identity=FD,type_resolver=lambda t:t)
    assert boundary['returnDeclarationId']==''
    r=relation(boundary['compilerReturnBinding'])
    assert r['inputType']==type_fact('int') and r['resultType']==type_fact('long')
    assert boundary['declarations'][r['declarationIdentity']]['name']=='output'
    assert len(r['conversions'])==1


def test_v2_return_contract_roundtrip_through_generic_experiment_dispatch():
    from tests.test_l3_memory_trace import contract
    from riscv2x86_py.l3_qemu_memory_route import parse_contract, TYPED_LOAD_CONTRACT_SCHEMA
    from riscv2x86_py.l3_experiment_runner import parse_experiment_contract
    f,fn,spec=fixture();call=bind_load(fn,f,spec)
    value=contract();value.update(schemaVersion=TYPED_LOAD_CONTRACT_SCHEMA,spec=spec,loadCall=call,
        deployment={'schemaVersion':'riscv2x86.compiler-region-execution-deployment.v3','spec':spec,
                    'sampleCount':4,'functionScope':{'callSignature':call}})
    restored=json.loads(json.dumps(value))
    parse_contract(restored);parse_experiment_contract(restored)
    bad=deepcopy(restored);bad['deployment']['functionScope']['callSignature']['outputSigned']=False
    with pytest.raises(ValueError,match='CALL_CHANGED'):parse_contract(bad)
