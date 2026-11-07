"""Actual GNU ELF versions and relocation metadata; no text-based acceptance."""
from copy import deepcopy
from pathlib import Path
import shutil
import struct
import subprocess
import pytest
from riscv2x86_py.native_elf_runtime import parse,candidates


@pytest.fixture
def elves(tmp_path):
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GNU GCC required')
    (tmp_path/'api.c').write_text('''
int object=7;
__thread int tls_object=3;
__attribute__((weak)) int weak_api(int x){return x;}
int old_api(int x){return x+1;}
int new_api(int x){return x+2;}
__asm__(".symver old_api,api@ABI_1");
__asm__(".symver new_api,api@@ABI_2");
''')
    (tmp_path/'versions').write_text('ABI_1 {global:api; object;}; ABI_2 {global:api;} ABI_1;')
    subprocess.run([cc,'-shared','-fPIC','api.c','-Wl,--version-script=versions',
                    '-Wl,-soname,libapi.so','-o','libapi.so'],cwd=tmp_path,check=True)
    (tmp_path/'use.c').write_text('extern int api(int); int use(int x){return api(x);}')
    subprocess.run([cc,'-shared','-fPIC','use.c','-L.','-lapi','-Wl,-rpath,$ORIGIN',
                    '-o','libuse.so'],cwd=tmp_path,check=True)
    return tmp_path,cc


def provider(p):
    return {'path':str(p),'digest':'test-digest','elf':parse(p.read_bytes())}


def test_real_version_definitions_requirements_and_exact_soname(elves):
    p,cc=elves;a=provider(p/'libapi.so');u=parse((p/'libuse.so').read_bytes())
    req=next(s for s in u['dynamicSymbols'] if s['name']=='api')
    assert not req['defined'] and req['version']=={'name':'ABI_2','file':'libapi.so','flags':0}
    request={k:req[k] for k in ('name','type','version')};request['machine']=u['machine']
    matches=candidates(request,[a]);assert len(matches)==1
    assert matches[0]['symbol']['version']['name']=='ABI_2'
    assert candidates(dict(request,version={'name':'ABI_2','file':'wrong.so'}),[a])==[]
    assert candidates(dict(request,machine=0),[a])==[]
    assert candidates(dict(request,type=1),[a])==[]
    assert 'libapi.so' in u['needed'] and u['searchPaths'][0]['value']=='$ORIGIN'
    assert any(r['symbol']=='api' for r in u['relocations'])
    assert not u['relocationSemanticsVerified']


def test_default_hidden_and_explicit_old_version(elves):
    p,cc=elves;a=provider(p/'libapi.so');machine=a['elf']['machine']
    plain={'name':'api','machine':machine,'type':2,'version':None}
    assert len(candidates(plain,[a]))==1
    assert candidates(plain,[a])[0]['symbol']['version']['name']=='ABI_2'
    old=candidates(dict(plain,version={'name':'ABI_1','file':'libapi.so'}),[a])
    assert len(old)==1 and old[0]['symbol']['versionHidden']
    assert candidates(dict(plain,version={'name':'MISSING','file':'libapi.so'}),[a])==[]


def test_undefined_reference_never_becomes_provider(elves):
    p,cc=elves;u=provider(p/'libuse.so');machine=u['elf']['machine']
    assert candidates({'name':'api','machine':machine,'type':0,'version':None},[u])==[]


def test_weak_tls_and_ambiguity_are_explicit(elves):
    p,cc=elves;a=provider(p/'libapi.so');machine=a['elf']['machine']
    for name in ('weak_api','tls_object'):
        found=candidates({'name':name,'machine':machine,'type':0,'version':None},[a])
        assert len(found)==1 and found[0]['specialContractRequired']
    request={'name':'api','machine':machine,'type':2,'version':None}
    assert len(candidates(request,[a,dict(a,path='another-provider')]))==2


def test_linked_copy_storage_does_not_become_original_provider(elves):
    p,cc=elves
    if parse((p/'libapi.so').read_bytes())['machine']!=62:pytest.skip('x86 COPY relocation fixture')
    (p/'main.c').write_text('extern int object; int main(void){return object;}')
    subprocess.run([cc,'-no-pie','main.c','-L.','-lapi','-o','copy-program'],cwd=p,check=True)
    e=parse((p/'copy-program').read_bytes())
    sym=next(s for s in e['dynamicSymbols'] if s['name']=='object')
    assert sym['defined'] and sym['versionSource']=='requirement'
    assert sym['version']['file']=='libapi.so'
    assert candidates({'name':'object','machine':62,'type':1,'version':None},
        [{'path':str(p/'copy-program'),'digest':'fixture','elf':e}])==[]
    assert e['interpreter'] and any(r['symbol']=='object' for r in e['relocations'])


@pytest.mark.parametrize('offset,value',[(4,1),(5,2),(6,0)])
def test_wrong_elf_class_endian_or_version_rejected(elves,offset,value):
    p,cc=elves;raw=bytearray((p/'libapi.so').read_bytes());raw[offset]=value
    with pytest.raises(ValueError,match='ELF64_LE_REQUIRED'):parse(raw)


def section(raw,typ):
    off=struct.unpack_from('<Q',raw,40)[0];count=struct.unpack_from('<H',raw,60)[0]
    return next(off+i*64 for i in range(count) if struct.unpack_from('<I',raw,off+i*64+4)[0]==typ)


def test_broken_version_link_and_count_reject(elves):
    p,cc=elves;raw=bytearray((p/'libapi.so').read_bytes())
    pos=section(raw,0x6ffffffd);struct.pack_into('<I',raw,pos+44,999)
    with pytest.raises(ValueError,match='VERSION_COUNT_INVALID'):parse(raw)
    raw=bytearray((p/'libuse.so').read_bytes());pos=section(raw,0x6ffffffe)
    offset=struct.unpack_from('<Q',raw,pos+24)[0];struct.pack_into('<I',raw,offset+8,0xffffffff)
    with pytest.raises(ValueError,match='VERSION_RANGE_INVALID'):parse(raw)


def test_truncated_and_invalid_versym_reject(elves):
    p,cc=elves;original=(p/'libapi.so').read_bytes()
    with pytest.raises(ValueError):parse(original[:80])
    raw=bytearray(original);pos=section(raw,0x6fffffff)
    struct.pack_into('<Q',raw,pos+32,2)
    with pytest.raises(ValueError,match='VERSYM_SIZE_INVALID'):parse(raw)


def test_metadata_matches_independent_readelf(elves):
    p,cc=elves;readelf=shutil.which('readelf')
    if not readelf:pytest.skip('readelf required')
    out=subprocess.check_output([readelf,'--wide','--dyn-syms','--version-info',str(p/'libapi.so')],text=True)
    e=parse((p/'libapi.so').read_bytes())
    assert 'api@ABI_1' in out and 'api@@ABI_2' in out
    assert {s['version']['name'] for s in e['dynamicSymbols'] if s['name']=='api'}=={'ABI_1','ABI_2'}


def test_wrong_version_hash_rejects_even_with_matching_name(elves):
    p,cc=elves;raw=bytearray((p/'libapi.so').read_bytes());pos=section(raw,0x6ffffffd)
    offset=struct.unpack_from('<Q',raw,pos+24)[0];struct.pack_into('<I',raw,offset+8,123)
    with pytest.raises(ValueError,match='VERSION_HASH_INVALID'):parse(raw)


def test_invalid_relocation_symbol_index_rejects(elves):
    p,cc=elves;raw=bytearray((p/'libuse.so').read_bytes());pos=section(raw,4)
    offset=struct.unpack_from('<Q',raw,pos+24)[0];info=struct.unpack_from('<Q',raw,offset+8)[0]
    struct.pack_into('<Q',raw,offset+8,(0xffffffff<<32)|(info&0xffffffff))
    with pytest.raises(ValueError,match='RELOCATION_SYMBOL_INVALID'):parse(raw)


def test_real_ifunc_is_special_contract_not_ordinary_function(elves):
    p,cc=elves
    (p/'ifunc.c').write_text('int impl(void){return 1;} static void *resolve(void){return impl;} int fun(void) __attribute__((ifunc("resolve")));')
    result=subprocess.run([cc,'-shared','-fPIC','ifunc.c','-o','libifunc.so'],cwd=p,capture_output=True)
    if result.returncode:pytest.skip('native toolchain lacks IFUNC fixture support')
    a=provider(p/'libifunc.so');req={'name':'fun','machine':a['elf']['machine'],'type':0,'version':None}
    found=candidates(req,[a]);assert len(found)==1 and found[0]['specialContractRequired']
    # A function request may name an IFUNC, but resolver semantics stay open.
    assert candidates(dict(req,type=2),[a])[0]['specialContractRequired']


def test_native_system_runtime_parses_without_text_filtering():
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC required')
    path=Path(subprocess.check_output([cc,'-print-file-name=libc.so.6'],text=True).strip())
    if not path.is_absolute() or not path.is_file():pytest.skip('native libc query unavailable')
    e=parse(path.read_bytes());assert e['dynamicSymbols'] and e['elfType']==3
    assert not e['abiContractVerified']
