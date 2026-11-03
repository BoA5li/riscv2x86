"""ISA-byte and symbolic-memory regression; fixture success is not ISA execution."""
from copy import deepcopy
import json
import random
import pytest
from riscv2x86_py import l3_control_machine as m,l3_stack_values as stack
from riscv2x86_py.l3_lrsc_machine import source,attempts

# Captured unchanged GCC7 -O0 RV64GC function from Phase137-MsKEpT.
# The production implementation does not refer to this name, PC or byte vector.
CAPTURE=bytes.fromhex('5d71a2e480082334a4fcae87233cc4fa2322f4fc033584fb833784fb033784fc833684fbafa507143b86e5002fa8c71ae31a08fec286233cb4fc2330c4fe2334d4fe833704fe3e85266461618280')


def invocation(role='next'):
    return {'pointerParameter':2,'valueParameter':0,'operation':{'width_bits':32,'rmw_operation':'fetch_add'},
        'sourceSequence':{'memory_width_bits':32,'arithmetic_width_bits':32,'operation':'fetch_add',
                          'lr_ordering_bits':[True,False],'sc_ordering_bits':[False,True]},'returnRole':role}


def sw(rs,base,offset,width=32):
    imm=offset&4095;funct={8:0,16:1,32:2,64:3}[width]
    return ((imm>>5)<<25|rs<<20|base<<15|funct<<12|(imm&31)<<7|0x23).to_bytes(4,'little')


def lw(rd,base,offset,width=32,unsigned=False):
    funct={8:0,16:1,32:2,64:3}[width]+(4 if unsigned else 0)
    return (((offset&4095)<<20)|base<<15|funct<<12|rd<<7|3).to_bytes(4,'little')


@pytest.mark.parametrize('base',[0,0x1000,0x1085a,0x400002])
def test_complete_captured_lrsc_function_and_actual_path_partition(base):
    machine=source(CAPTURE,base,invocation())
    assert machine['prefix'][6]['op']=='store' and machine['prefix'][6]['width']==32
    assert machine['prefix'][6]['bytes']=='2322f4fc'
    assert machine['region']=={'start':base+36,'end':base+52,'exits':[base+52]}
    for count in (1,2,32):
        assert attempts(machine,{'pcs':machine['retry']['loopPCs']*count,'exit':base+52})==count
    with pytest.raises(ValueError):attempts(machine,{'pcs':machine['retry']['loopPCs'][:-1],'exit':base+52})


@pytest.mark.parametrize('mutation',['pointer','input','return','overlap-pointer','stack','ordering','unknown-prefix'])
def test_captured_function_does_not_bypass_proof_binding(mutation):
    raw=bytearray(CAPTURE);spec=invocation()
    if mutation=='pointer':spec['pointerParameter']=1
    if mutation=='input':spec['valueParameter']=1
    if mutation=='return':spec['returnRole']='status'
    if mutation=='overlap-pointer':raw[16:20]=sw(15,8,-72)
    if mutation=='stack':raw[-4:-2]=(0x6121).to_bytes(2,'little')  # restore 64 instead of 80
    if mutation=='ordering':spec['sourceSequence']['lr_ordering_bits']=[False,False]
    if mutation=='unknown-prefix':raw[16:20]=(0x73).to_bytes(4,'little')
    with pytest.raises(ValueError):source(bytes(raw),0x1085a,spec)


@pytest.mark.parametrize('width',[8,16,32,64])
@pytest.mark.parametrize('offset',[-2048,-60,-1,0,4,2047])
def test_regular_rv_load_store_fields(width,offset):
    for rs,base,rd in ((0,2,15),(15,8,10),(31,31,31)):
        s=m.decode(sw(rs,base,offset,width),0x1000,243)[0]
        assert (s['op'],s['rd'],s['rs'],s['imm'],s['width'])==('store',rs,base,offset,width)
        for unsigned in ((False,True) if width<64 else (False,)):
            l=m.decode(lw(rd,base,offset,width,unsigned),0x1000,243)[0]
            assert (l['op'],l['rd'],l['rs'],l['imm'],l['width'])==('load',rd,base,offset,width)
            assert l.get('unsigned',False)==unsigned


def cword(reg,base,offset,store=False):
    return (((6 if store else 2)<<13)|((offset>>3)&7)<<10|(base-8)<<7|
            ((offset>>2)&1)<<6|((offset>>6)&1)<<5|(reg-8)<<2).to_bytes(2,'little')


def csp(reg,offset,store=False):
    if store:
        w=6<<13|((offset>>2)&15)<<9|((offset>>6)&3)<<7|reg<<2|2
    else:w=2<<13|((offset>>5)&1)<<12|reg<<7|((offset>>2)&7)<<4|((offset>>6)&3)<<2|2
    return w.to_bytes(2,'little')


def test_all_compressed_word_offsets_register_roles_and_reserved_codes():
    for store in (False,True):
        for offset in range(0,128,4):
            for reg,base in ((8,8),(15,8),(8,15),(15,15)):
                d=m.decode(cword(reg,base,offset,store),0x1000,243)[0]
                assert (d['op'],d['rd'],d['rs'],d['imm'],d['width'])==('store' if store else 'load',reg,base,offset,32)
        for offset in range(0,256,4):
            for reg in ((0,1,31) if store else (1,2,31)):
                d=m.decode(csp(reg,offset,store),0x1000,243)[0]
                assert (d['op'],d['rd'],d['rs'],d['imm'],d['width'])==('store' if store else 'load',reg,2,offset,32)
    for raw in (csp(0,0), (0x2001).to_bytes(2,'little')):
        with pytest.raises(ValueError,match='RESERVED'):m.decode(raw,0x1000,243)
    for funct in (4,5,6,7):
        with pytest.raises(ValueError):m.decode((funct<<12|0x23).to_bytes(4,'little'),0x1000,243)
    with pytest.raises(ValueError,match='TRUNCATED'):m.decode(sw(1,2,0)[:2],0x1000,243)


@pytest.mark.parametrize('width',[8,16,32])
@pytest.mark.parametrize('unsigned',[False,True])
@pytest.mark.parametrize('symbolic',[False,True])
def test_loaded_extension_and_low_store_semantics(width,unsigned,symbolic):
    state=m.initial(243);value=0xfedcba98ffffffff
    if not symbolic:state['registers'][10]=value
    for row in m.decode(sw(10,2,0,width)+lw(11,2,0,width,unsigned),0x1000,243):m.step(state,row,243)
    low=value&((1<<width)-1)
    expected=low if unsigned else (low-(1<<width) if low&(1<<(width-1)) else low)&stack.MASK
    assert m.value_of(state['registers'][11],[value])==expected
    if symbolic:assert state['registers'][11]!='parameter:0'


def test_overlapping_symbolic_bytes_never_restore_old_pointer_or_value():
    mem={};stack.store(mem,-16,'parameter:0',64);stack.store(mem,-12,'parameter:1',32)
    value=stack.load(mem,-16,64)
    assert value!='parameter:0'
    assert stack.evaluate(value,[0x0123456789abcdef,0xfedcba9876543210])==0x7654321089abcdef
    assert stack.evaluate(json.loads(json.dumps(value)),[0x0123456789abcdef,0xfedcba9876543210])==0x7654321089abcdef
    stack.store(mem,0,('stack',-80),64)
    assert stack.load(mem,0,64)==('stack',-80)
    stack.store(mem,0,0,32)
    state=m.initial(243);state['registers'][8]=stack.load(mem,0,64)
    with pytest.raises(ValueError,match='STACK_BINDING_UNPROVEN'):
        m.step(state,{'op':'load','rs':8,'rd':10,'imm':0,'width':64},243)


def test_missing_bytes_and_general_object_access_stay_rejected():
    mem={};stack.store(mem,0,0,32)
    with pytest.raises(ValueError,match='STACK_VALUE_UNBOUND'):stack.load(mem,0,64)
    state=m.initial(243)
    with pytest.raises(ValueError,match='STACK_BINDING_UNPROVEN'):
        m.step(state,m.decode(lw(0,10,0),0x1000,243)[0],243)
    m.step(state,m.decode(sw(0,2,0),0x1000,243)[0],243)
    m.step(state,m.decode(lw(0,2,0),0x1000,243)[0],243)
    assert state['registers'][0]==0


@pytest.mark.parametrize('compressed',[False,True])
@pytest.mark.parametrize('immediate',[-32,-1,0,1,31])
def test_word_arithmetic_sign_extends_and_wraps(compressed,immediate):
    if compressed:
        imm=immediate&63;raw=(1<<13|((imm>>5)&1)<<12|10<<7|(imm&31)<<2|1).to_bytes(2,'little')
    else:raw=(((immediate&4095)<<20)|10<<15|10<<7|0x1b).to_bytes(4,'little')
    for value in (0,0x7fffffff,0x80000000,0xffffffff,0x12345678ffffffff):
        for symbolic in (False,True):
            state=m.initial(243)
            if not symbolic:state['registers'][10]=value
            m.step(state,m.decode(raw,0x1000,243)[0],243)
            assert m.value_of(state['registers'][10],[value])==stack.sign_extend((value+immediate)&0xffffffff,32)


def test_byte_memory_against_independent_concrete_reference():
    rng=random.Random(20261103);mem={};reference={};inputs=[rng.getrandbits(64) for _ in range(4)]
    for _ in range(1000):
        width=rng.choice((8,16,32,64));at=rng.randrange(-40,41)
        symbolic=bool(rng.getrandbits(1));index=rng.randrange(4);number=rng.getrandbits(64)
        value='parameter:'+str(index) if symbolic else number
        stack.store(mem,at,value,width)
        concrete=inputs[index] if symbolic else number
        for i in range(width//8):reference[at+i]=(concrete>>(8*i))&255
        addr=rng.randrange(-40,41);bits=rng.choice((8,16,32,64))
        if all(addr+i in reference for i in range(bits//8)):
            expected=int.from_bytes(bytes(reference[addr+i] for i in range(bits//8)),'little')
            assert stack.evaluate(stack.load(mem,addr,bits),inputs)==expected
        else:
            with pytest.raises(ValueError,match='STACK_VALUE_UNBOUND'):stack.load(mem,addr,bits)


def test_unknown_encoding_keeps_raw_bytes_and_lrsc_phase_in_diagnostic():
    raw=CAPTURE[:16]+bytes.fromhex('73000000')+CAPTURE[20:]
    with pytest.raises(ValueError,match='bytes=73000000:lrsc-prefix'):source(raw,0x1085a,invocation())


def test_symbolic_graph_exports_lossless_json_and_replays_low_bits():
    from riscv2x86_py.l3_trace_support import require_json_document,require_json_match
    code=sw(10,2,0)+lw(11,2,0,32,True)+bytes.fromhex('0100')
    graph=m.graph(code,0x1000,{'start':0x1008,'end':0x100a,'exits':[0x100a]},243,result_register=11)
    require_json_document(graph)
    require_json_match(graph,json.loads(json.dumps(graph)),'GRAPH_JSON_ROUNDTRIP_CHANGED')
    path=m.selected_path(graph,[0x1008],0x100a,[0xfedcba9876543210])
    assert m.value_of(path['value'],[0xfedcba9876543210])==0x76543210


@pytest.mark.parametrize('optimization',['-O0','-O2'])
@pytest.mark.parametrize('compressed',[False,True])
@pytest.mark.parametrize('width,op,word,role,arity,pointer,value',[
    (32,'add',True,'next',3,2,0),(64,'xor',False,'status',4,1,3),
    (32,'and',False,'old',4,3,2),(64,'or',False,'next',3,0,2),
    (32,'sub',True,'next',6,5,4),(64,'sub',False,'old',6,4,5)])
def test_real_riscv_compiler_shell_when_toolchain_available(tmp_path,optimization,compressed,width,op,word,role,arity,pointer,value):
    import os,shutil,subprocess
    from riscv2x86_py.l3_trace_support import Elf
    requested=os.environ.get('RV2X86_TEST_RISCV_CC')
    cc=shutil.which(requested) if requested else shutil.which('riscv64-linux-gnu-gcc')
    if requested:assert cc,'configured RISC-V compiler unavailable: '+requested
    if not cc:pytest.skip('real RISC-V compiler unavailable; byte fixture is not production approval')
    name='compiler_probe'
    parameters=['uint32_t aux'+str(i)+' __attribute__((unused))' for i in range(arity)]
    parameters[pointer]='uint'+str(width)+'_t *p';parameters[value]='uint64_t value'
    sequence='1: lr.'+('w' if width==32 else 'd')+'.aq %[old],(%[p])\\n\\t'+op+('w' if word else '')+' %[next],%[old],%[value]\\n\\tsc.'+('w' if width==32 else 'd')+'.rl %[status],%[next],(%[p])\\n\\tbnez %[status],1b'
    c=tmp_path/'probe.c';obj=tmp_path/'probe.o'
    c.write_text('#include <stdint.h>\nuint64_t '+name+'('+','.join(parameters)+'){uint64_t old,next,status;__asm__ volatile("'+sequence+'": [old]"=&r"(old),[next]"=&r"(next),[status]"=&r"(status),[object]"+A"(*p):[p]"r"(p),[value]"r"(value):"memory");return '+role+';}')
    r=subprocess.run([cc,optimization,'-std=gnu11','-march='+('rv64gc' if compressed else 'rv64g'),'-mabi=lp64d','-c',str(c),'-o',str(obj)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
    from tests.test_l3_lrsc_sequence import invocation as approved_invocation
    inv=approved_invocation(width,'fetch_'+op,word)
    inv.update(pointerParameter=pointer,valueParameter=value,returnRole=role)
    elf=Elf(obj)
    assert source(elf.code(name),elf.symbol(name)[0],inv)['machine']==243


def test_amd64_push_rsp_saves_predecrement_pointer_identity(tmp_path):
    state=m.initial(62)
    m.step(state,m.decode(bytes.fromhex('54'),0x1000,62)[0],62)
    assert state['registers'][4]==('stack',-8)
    assert stack.load(state['memory'],-8,64)==('stack',0)
    import shutil,subprocess
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC unavailable')
    asm=tmp_path/'push.S';binary=tmp_path/'push'
    asm.write_text('.text\n.globl main\nmain:\nmov %rsp,%rax\npush %rsp\npop %rcx\ncmp %rax,%rcx\nsetne %al\nmovzbl %al,%eax\nret\n.section .note.GNU-stack,"",@progbits\n')
    result=subprocess.run([cc,str(asm),'-o',str(binary)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    result=subprocess.run([str(binary)],capture_output=True,text=True)
    assert result.returncode==0 and not result.stdout and not result.stderr
