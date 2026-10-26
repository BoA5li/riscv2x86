"""Binary-level graphs and native compiler encodings; no QEMU success claim."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import pytest
from riscv2x86_py.l3_control_machine import decode,graph,condition,selected_path
from riscv2x86_py.l3_control_backend import parse_capture
from riscv2x86_py.l3_trace_support import Elf


def branch(rs,rt,offset,funct=0):
    x=offset&8191
    return ((x>>12)<<31|((x>>5)&63)<<25|rt<<20|rs<<15|funct<<12|((x>>1)&15)<<8|((x>>11)&1)<<7|0x63).to_bytes(4,'little')


def test_rv_acyclic_graph_binary_semantics_and_unreachable_code():
    # beq a0,a1,true; mv a5,a3; j end; true: mv a5,a2
    code=branch(10,11,12)+(0x00068793).to_bytes(4,'little')+(0x0080006f).to_bytes(4,'little')+(0x00060793).to_bytes(4,'little')
    region={'start':4096,'end':4112,'exits':[4112],'exitRoles':{'fallthrough':4112}}
    g=graph(code,4096,region,243)
    assert len(g['paths'])==2
    for inputs in ([1,1,33,44],[1,2,33,44]):
        p=next(p for p in g['paths'] if p['conditions'][0]['taken']==(inputs[0]==inputs[1]))
        assert selected_path(g,p['pcs'],4112,inputs)==p
    p=g['paths'][0]
    with pytest.raises(ValueError):selected_path(g,p['pcs']+[4108],4112,[1,2,33,44])
    with pytest.raises(ValueError,match='CYCLIC'):graph(branch(10,11,0),4096,dict(region,end=4100,exits=[4100]),243)


def test_rvc_stack_prefix_and_direct_jump_decoding():
    # addi sp,-32; sdsp a0,8(sp); ldsp a5,8(sp); mv a4,a5;
    # j +4; unreachable mv a4,a1; mv a4,a5
    words=[0x1101,0xe42a,0x67a2,0x873e,0xa011,0x872e,0x873e]
    code=b''.join(w.to_bytes(2,'little') for w in words)
    g=graph(code,0x1000,{'start':0x1008,'end':0x100e,'exits':[0x100e],'exitRoles':{'fallthrough':0x100e}},243)
    assert len(g['paths'])==1 and g['paths'][0]['pcs']==[0x1008,0x100c]
    assert g['paths'][0]['transfers'][0]['kind']=='direct'
    assert decode((0xc391).to_bytes(2,'little'),4096,243)[0]['target']==4100


def test_native_compiler_prefix_and_local_cfg(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    c=tmp_path/'probe.c';so=tmp_path/'probe.so'
    c.write_text('unsigned long f(unsigned long a,unsigned long b,unsigned long t,unsigned long n){unsigned long o;'
      '__asm__ volatile(".globl begin\\nbegin:\\n\\tcmpq %2,%1\\n\\tje 1f\\n\\tmovq %4,%0\\n\\tjmp 2f\\n1: movq %3,%0\\n2:\\n.globl end\\nend:" : "=&r"(o):"r"(a),"r"(b),"r"(t),"r"(n):"cc");return o;}')
    result=subprocess.run([cc,'-O0','-fPIC','-shared',str(c),'-o',str(so)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    elf=Elf(so);start=elf.symbol('f')[0];begin=elf.symbol('begin')[0];end=elf.symbol('end')[0]
    g=graph(elf.code('f'),start,{'start':begin,'end':end,'exits':[end],'exitRoles':{'fallthrough':end}},62)
    assert len(g['paths'])==2
    assert all(p['conditions'][0]['left']=='parameter:0' and p['conditions'][0]['right']=='parameter:1' for p in g['paths'])


@pytest.mark.parametrize('kind,a,b,wanted',[('equal',0,0,True),('not_equal',1,0,True),('signed_less',2**64-1,1,True),('unsigned_less',2**64-1,1,False)])
def test_signed_predicates(kind,a,b,wanted):assert condition(kind,a,b)==wanted


def test_control_capture_requires_positions_allowed_exit_and_complete_footer():
    token='a'*64;r={'start':4096,'end':4104,'exits':[4104,8192]}
    text=f'H 2 {token} riscv64 1000 1008\nB 0 1000\nP 0 0 1000\nX 0 2000\nF 1 1 1 0 0\n'
    assert parse_capture(text,token,'riscv64',r,1)=={'paths':[{'pcs':[4096],'exit':8192}],'memory':[]}
    for bad in ('',text.replace('P 0 0 1000\n',''),text.replace('X 0 2000','X 0 3000'),text.replace('F 1 1 1 0 0','F 1 0 1 0 1'),text+'P 1 0 1004\n',text.replace('P 0 0 1000','P 1 0 1000'),text.replace('X 0 2000','U 0 2000')):
        with pytest.raises(ValueError):parse_capture(bad,token,'riscv64',r,1)


def test_unsupported_call_indirect_and_unknown_binary_fail_closed():
    for machine,code in ((243,(0x00008067).to_bytes(4,'little')),(62,b'\xff\xe0'),(62,b'\xe8\0\0\0\0'),(62,b'\xff')):
        with pytest.raises(ValueError):decode(code,4096,machine)


def test_flags_are_invalidated_by_intervening_amd64_arithmetic():
    # cmp rsi,rdi; sub $8,rsp; je end. Flags no longer describe parameters.
    code=bytes.fromhex('4839f74883ec08740190')
    with pytest.raises(ValueError,match='PREDICATE_UNBOUND'):
        graph(code,4096,{'start':4096,'end':4106,'exits':[4106]},62)


def test_overlapping_stack_write_invalidates_previous_value():
    from riscv2x86_py.l3_control_machine import initial,step
    state=initial(243)
    step(state,{'op':'store','rs':2,'rd':10,'imm':0,'width':64},243)
    step(state,{'op':'store','rs':2,'rd':11,'imm':4,'width':64},243)
    with pytest.raises(ValueError,match='STACK_VALUE_UNBOUND'):
        step(state,{'op':'load','rs':2,'rd':12,'imm':0,'width':64},243)
