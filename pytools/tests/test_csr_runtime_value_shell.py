"""Native ABI and shell checks; these are not a RISC-V production run."""
from copy import deepcopy
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace as NS
import shutil
import subprocess
import pytest
from riscv2x86_py.csr_runtime_shell import prove_runtime_shell, render_runtime_shell, AUTOMATIC_RUNTIME_BUILD_CONTRACT
from riscv2x86_py.csr_runtime_implementation import validate_implementation
from riscv2x86_py.csr_structured_renderer import CsrRuntimeRecipe, render_approved_csr_recipe
from riscv2x86_py.csr_value_flow import SourceCsrOperandBinding
from riscv2x86_py.route_authority import content_identity
from tests.test_compiler_expression_contracts import ctype


def fragment_and_binding(shape):
    from tests.test_production_route_authority import _compiler_authority
    from riscv2x86_py.compiler_fragment_closure import close_compiler_fragment_candidate
    from riscv2x86_py.schema import AsmFragment, AsmOperand
    a=_compiler_authority(carrier_kind='integer');c=deepcopy(a['candidate'])
    c.pop('closureIdentity');c.pop('closureProvenance')
    c['schemaVersion']=c.pop('sourceCandidateSchemaVersion')
    if shape=='separate':
        outputs=[AsmOperand(constraint='=r',isOutput=True,exprText='out',compilerType=ctype())]
        inputs=[AsmOperand(constraint='r',exprText='value',compilerType=ctype())]
        read,write=0,1
    elif shape=='tied':
        outputs=[AsmOperand(constraint='+r',isOutput=True,exprText='value',compilerType=ctype())]
        inputs=[];read,write=0,0
        c['operandCarriers']=c['operandCarriers'][:1];c['valueNodes']=c['valueNodes'][:1]
    else:
        outputs=[];inputs=[AsmOperand(constraint='r',exprText='value',compilerType=ctype())]
        read,write=None,0
        c['operandCarriers']=c['operandCarriers'][:1];c['valueNodes']=c['valueNodes'][:1]
    c['downstreamUses']=[]
    f=AsmFragment(id=a['fragmentId'],beginOffset=100,endOffset=140,isVolatile=True,
        clobbers=['memory','cc'],outputs=outputs,inputs=inputs)
    a['candidate']=close_compiler_fragment_candidate(c,asdict(f),source_digest=a['sourceDigest'],
        function_identity=a['functionIdentity'])
    a['compilerTypeBindings']={str(i):{'operandIndex':i,'valueNodeIdentity':b['valueNodeIdentity'],
        'compilerType':ctype()} for i,b in enumerate(a['candidate']['operandBindings'])}
    a['authorityIdentity']=content_identity({k:v for k,v in a.items() if k!='authorityIdentity'})
    f.compilerFragmentAuthority=a
    b=SourceCsrOperandBinding('e:scratch',read,write,None,64,'unsigned',True)
    return f,b


def recipe(operation,shape):
    symbol={'read_write':'write','write':'write','set_bits':'set_bits','clear_bits':'clear_bits'}[operation]
    return CsrRuntimeRecipe('scratch','rv2x86_csr_'+symbol+'_checked_v1','832','&ctx','value',
        None if shape=='discard' else 'value' if shape=='tied' else 'out',
        'riscv2x86_csr_runtime.h','libriscv2x86_runtime','v1','no-trap-observation',True)


def implementation(r,operation):
    effect=NS(operation=NS(value=operation),csr_class=NS(value='other'),csr_id='riscv.csr.mscratch',
        affected_fields=(NS(field_id='scratch.value',warl_or_wlrl_policy_id=None,side_effect_ids=(),behavior='rw',writable_mask=(1<<64)-1),),xlen_bits=64)
    return validate_implementation(r,(effect,),(NS(field_mappings=('scratch.value',)),))


@pytest.mark.parametrize('shape',['separate','tied','discard'])
@pytest.mark.parametrize('operation',['read_write','set_bits','clear_bits'])
def test_actual_checked_runtime_and_scalar_shell_preserve_old_and_new_values(tmp_path,shape,operation):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('requires a native C compiler')
    f,b=fragment_and_binding(shape);r=recipe(operation,shape);_,identity=implementation(r,operation)
    shell=prove_runtime_shell(f,identity,AUTOMATIC_RUNTIME_BUILD_CONTRACT,operand_binding=b)
    assert shell['schemaVersion']=='riscv2x86.csr-runtime-shell.v2'
    rendered=render_approved_csr_recipe(r,approved_recipe_ids={'scratch':'v1'},expected_runtime_version='v1',
        proof_approved=True,proof_identity='native-abi-test-only')
    assert rendered.emitted_text is not None
    statement=render_runtime_shell(rendered.emitted_text,shell)
    # The integer reference relation is independent of runtime/renderer code.
    old=0x8123456789abcdef;value=0xf0f00f0f98765432
    expected=value if operation=='read_write' else old|value if operation=='set_bits' else old & (~value & ((1<<64)-1))
    result='value' if shape=='tied' else 'out'
    check='' if shape=='discard' else f'if ({result} != UINT64_C({old})) return 2;'
    root=Path(__file__).resolve().parents[2];main=tmp_path/'main.c';binary=tmp_path/'probe';obj=tmp_path/'runtime.o'
    main.write_text('#include "riscv2x86_csr_runtime.h"\nint main(void) {\n'
        'struct rv2x86_csr_context ctx = {0}; ctx.version=1; ctx.profile=RV2X86_CSR_SCRATCH_PROFILE_V1;\n'
        f'ctx.values[832]=UINT64_C({old}); uint64_t value=UINT64_C({value});\n'
        +('uint64_t out=0;\n' if shape=='separate' else '')+statement+'\n'+check+
        f'\nreturn ctx.values[832] != UINT64_C({expected}); }}\n')
    for command in ([gcc,'-O2','-fno-lto','-I'+str(root/'runtime/include'),'-c',str(root/'runtime/riscv2x86_csr_runtime.c'),'-o',str(obj)],
                    [gcc,'-O2','-fno-lto','-Wall','-Wextra','-Werror','-I'+str(root/'runtime/include'),str(main),str(obj),'-o',str(binary)]):
        completed=subprocess.run(command,capture_output=True,text=True)
        assert completed.returncode==0,completed.stderr
    assert subprocess.run([str(binary)]).returncode==0


@pytest.mark.parametrize('mutation,reason',[
    ('missing','OPERAND_PROOF_REQUIRED'),('read','OUTPUT_BINDING_MISMATCH'),
    ('write','INPUT_BINDING_MISMATCH'),('constraint','CONSTRAINT_UNSUPPORTED'),
    ('type','EVALUATION_UNPROVEN'),('width','CONVERSION_REQUIRED'),('signed','CONVERSION_REQUIRED')])
def test_runtime_shell_rejects_unsupported_or_inconsistent_shapes(mutation,reason):
    f,b=fragment_and_binding('separate')
    if mutation=='missing':b=None
    if mutation=='read':b=replace(b,read_result_operand_index=1)
    if mutation=='write':b=replace(b,write_value_operand_index=0)
    if mutation=='constraint':f.outputs[0].constraint='=&r'
    if mutation in {'type','width','signed'}:
        a=f.compilerFragmentAuthority
        if mutation=='type':a['compilerTypeBindings']['1']['compilerType']['sideEffectFree']=False
        elif mutation=='signed':
            a['compilerTypeBindings']['1']['compilerType']['isSigned']=True
            a['candidate']['operandBindings'][1]['signedness']='signed'
            a['candidate']['operandCarriers'][1]['signedness']='signed'
            a['candidate']['closureIdentity']=content_identity({k:v for k,v in a['candidate'].items() if k!='closureIdentity'})
        else:
            a['compilerTypeBindings']['1']['compilerType']['widthBits']=32
            a['candidate']['operandBindings'][1]['widthBits']=32
            a['candidate']['operandCarriers'][1]['widthBits']=32
            a['candidate']['closureIdentity']=content_identity({k:v for k,v in a['candidate'].items() if k!='closureIdentity'})
        a['authorityIdentity']=content_identity({k:v for k,v in a.items() if k!='authorityIdentity'})
    with pytest.raises(ValueError,match=reason):
        prove_runtime_shell(f,'sha256:'+'1'*64,AUTOMATIC_RUNTIME_BUILD_CONTRACT,operand_binding=b)


def test_unchecked_state_abi_cannot_be_approved_as_production_backend():
    r=replace(recipe('read_write','separate'),callable_identifier='rv2x86_csr_write')
    with pytest.raises(ValueError,match='CHECKED_STATE_IMPLEMENTATION_REQUIRED'):implementation(r,'read_write')


@pytest.mark.parametrize('failure',['null','version','profile','token'])
def test_checked_backend_failure_is_not_a_successful_zero_value(tmp_path,failure):
    gcc=shutil.which('gcc')
    if not gcc:pytest.skip('requires a native C compiler')
    root=Path(__file__).resolve().parents[2];main=tmp_path/'main.c';binary=tmp_path/'probe'
    main.write_text('#include "riscv2x86_csr_runtime.h"\n#include <sys/resource.h>\n'
        'int main(void) { struct rlimit lim={0,0}; setrlimit(RLIMIT_CORE,&lim);\n'
        'struct rv2x86_csr_context c={0}; c.version=1; c.profile=RV2X86_CSR_SCRATCH_PROFILE_V1;\n'
        +('c.version=0;\n' if failure=='version' else 'c.profile=0;\n' if failure=='profile' else '')+
        'return (int)rv2x86_csr_read_checked_v1('+('0' if failure=='null' else '&c')+
        ', '+('768' if failure=='token' else '832')+'); }\n')
    compiled=subprocess.run([gcc,'-O2','-I'+str(root/'runtime/include'),str(main),
        str(root/'runtime/riscv2x86_csr_runtime.c'),'-o',str(binary)],capture_output=True,text=True)
    assert compiled.returncode==0,compiled.stderr
    assert subprocess.run([str(binary)],cwd=tmp_path).returncode<0
