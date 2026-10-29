"""Opt-in real Clang ingress checks. These do not claim runtime acceptance."""
import os
from pathlib import Path
import pytest

from riscv2x86_py.automatic_batch_cli import inspect_entry_points
from riscv2x86_py.compiler_return_binding import analyze
from riscv2x86_py.l3_memory_call import bind_load
from riscv2x86_py.l2_memory_object import memory_proof_facts_from_source_model
from tests.test_typed_load_execution import fixture, model


@pytest.mark.parametrize('width',[8,16,32])
@pytest.mark.parametrize('signed',[False,True])
def test_real_clang_return_conversion_to_load_binding(tmp_path,width,signed):
    clang=os.environ.get('RV2X86_SYSTEM_CLANG')
    if not clang:pytest.skip('explicit RV2X86_SYSTEM_CLANG required for real AST inspection')
    assert Path(clang).is_file()
    out=('int' if signed else 'uint')+str(width)+'_t'
    result='int64_t' if signed else 'uint64_t'
    op={8:'lbu',16:'lhu',32:'lwu'}[width]
    source=tmp_path/'typed-return.c'
    source.write_text('#include <stdint.h>\n'+result+' probe(uint'+str(width)+'_t *address){\n'+out+' output;\n'
        '__asm__ volatile("'+op+' %[out],'+str(3*width//8)+'(%[base])" : [out] "=r"(output) : [base] "r"(address) : "memory");\nreturn output;\n}\n')
    _,functions=inspect_entry_points(source,clang=clang)
    assert len(functions)==1
    fn=functions[0];boundary=fn['l2OperandBoundary']
    assert boundary['returnDeclarationId']==''
    b=boundary['compilerReturnBinding']
    relation=analyze(b,source_digest=fn['sourceDigest'],function_identity=fn['functionId'],
                     result_type=fn['compilerMemoryCallSignature']['result'])
    assert len(relation['conversions'])==1
    assert relation['inputType']['widthBits']==width and relation['inputType']['signed'] is signed
    assert relation['resultType']['widthBits']==64
    f,_,spec=fixture(width,'zero_extend',signed,signed)
    facts=memory_proof_facts_from_source_model(f['fragment']['id'],model(width,width,'zero_extend',3*width//8))
    f['approvalArtifact']['l2MemoryProofFacts']=facts.to_dict()
    operands=f['approvalArtifact']['l2AuthoritySidecar']['operands']
    operands[0]['declarationId']=boundary['parameterDeclarationIds'][0]
    operands[1].update(declarationId=relation['declarationIdentity'],widthBits=width)
    scope=fn['compilerAtomicFunctionScope']
    f['fragment']['compilerFragmentAuthority']['fragmentBindingKey'].update(beginOffset=scope['asmBegin'],endOffset=scope['asmEnd'])
    call=bind_load(fn,f,spec)
    assert call['returnBinding']==b and call['schemaVersion'].endswith('.v2')
