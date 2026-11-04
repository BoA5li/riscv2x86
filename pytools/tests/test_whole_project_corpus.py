"""Whole-release collection and conservative inclusion regression."""
import base64
import gzip
import io
import json
from pathlib import Path
import runpy
import tarfile

import pytest

M=runpy.run_path(str(Path(__file__).resolve().parents[2]/'experiment/whole_project_corpus.py'))


def rows(raw,path='shared/test.c'):
    return M['inventory'](raw,'test','1',path)


def test_negated_riscv_and_else_branches_are_both_retained():
    result=rows(b'#if !defined(__riscv)\nasm("x86");\n#else\nasm("riscv");\n#endif\n')
    assert len(result)==2
    assert all(x['collectionDisposition']=='retained-pending-upstream-activation' for x in result)
    assert all(x['activationStatus']=='not_checked' for x in result)


def test_unknown_and_other_architectures_never_disappear():
    raw=b'asm volatile("unknown.op %0" : "+r"(x));'
    assert len(rows(raw,'arch/x86/test.c'))==1
    assert rows(raw,'arch/x86/test.c')[0]['architectureHint']=='other-architecture-path-retained'


def test_comments_strings_includes_and_byte_provenance():
    raw='/*中文 asm(fake)*/\n#include <asm/asm.h>\n'.encode()+b'char *p="asm(fake)"; as\\\nm volatile("x" : "=r"(x));'
    result,=rows(raw)
    assert base64.b64decode(result['sourceSliceBase64'])==raw[result['beginByte']:result['endByte']]
    assert result['sourceSliceDigest']=='sha256:'+M['sha'](raw[result['beginByte']:result['endByte']])


def test_macro_provider_transitive_closure_keeps_duplicate_conditions():
    definitions=M['macro_definitions'](b'#define A asm\n#define B(x) A volatile(x)\n#define C B\n#define U(x) x\n','test.h')
    assert M['providers'](definitions)=={'A','B','C'}


def fixture(tmp_path):
    root=tmp_path/'lock';root.mkdir();archives=tmp_path/'archives';archives.mkdir()
    files={'include/p.h':b'#define WRAP(x) asm volatile(x)\n',
           'src/riscv64/fp.c':b'void f(){__asm__("fsqrt.d %0,%1" : "=f"(x) : "f"(y));}\n',
           'shared/caller.c':b'#include "p.h"\nvoid f(){ WRAP("fence rw,rw"); }\n',
           'arch/x86/test.c':b'asm("x86");\n','generator.py':b'emit("asm volatile(\\"ecall\\");")\n',
           'paste.h':b'#define MAKE(a,b) a ## b\n','COPYING':b'upstream license\n',
           'unrelated.txt':b'ordinary file\n'}
    archive=archives/'fixture.tar.gz';archive.write_bytes(M['V1']['archive_bytes']({'release/'+p:v for p,v in files.items()}))
    source={'id':'fixture','version':'1','root':'release','archive':archive.name,
            'sha256':M['sha'](archive.read_bytes()),'licenseFiles':['COPYING'],'licensePrefixes':[]}
    lock={'schemaVersion':'riscv2x86.whole-project-source-lock.v2','sources':[source]}
    (root/'sources.lock.json').write_text(json.dumps(lock));output=tmp_path/'corpus'
    M['build'](root,archives,output)
    return output,archives,source,files


def test_whole_release_manifest_contains_callers_generators_and_pending_paste(tmp_path):
    output,archives,source,files=fixture(tmp_path)
    manifest=json.loads((output/'fixture/manifest.json').read_text())
    payload={n:M['read_chunks'](output/'fixture',r) for n,r in manifest['artifacts'].items()}
    inventory=[json.loads(l) for l in gzip.decompress(payload['release-files.jsonl.gz']).splitlines()]
    assert {r['path'] for r in inventory}==set(files)
    refs=[json.loads(l) for l in gzip.decompress(payload['macro-references.jsonl.gz']).splitlines()]
    assert any(r['sourcePath']=='shared/caller.c' and 'WRAP' in r['providerNames'] for r in refs)
    pending=[json.loads(l) for l in gzip.decompress(payload['review-required.jsonl.gz']).splitlines()]
    assert any(r['path']=='paste.h' for r in pending)
    assert any(r['path']=='generator.py' for r in pending)
    assert M['verify'](output,archives)['upstreamReplayComplete'] is True
    assert M['verify'](output)['compilerActivationComplete'] is False
    dest=tmp_path/'materialized';M['materialize'](output,dest,archives)
    assert (dest/'fixture/full-release/shared/caller.c').read_bytes()==files['shared/caller.c']
    assert (dest/'fixture/upstream/arch/x86/test.c').read_bytes()==files['arch/x86/test.c']


@pytest.mark.parametrize('mode',['shard','missing-shard','manifest-label','wrong-archive'])
def test_corrupt_data_or_acceptance_labels_are_rejected(tmp_path,mode):
    output,archives,source,_=fixture(tmp_path)
    manifest=json.loads((output/'fixture/manifest.json').read_text())
    if mode in {'shard','missing-shard'}:
        path=output/'fixture'/manifest['artifacts']['sites.jsonl.gz']['parts'][0]['path']
        if mode=='shard':path.write_bytes(b'bad')
        else:path.unlink()
    elif mode=='manifest-label':
        manifest['semanticApproval']=True
        manifest=M['sealed']({k:v for k,v in manifest.items() if k!='manifestIdentity'},'manifestIdentity')
        (output/'fixture/manifest.json').write_text(json.dumps(manifest))
    else:(archives/source['archive']).write_bytes(b'changed')
    with pytest.raises((ValueError,OSError)):M['verify'](output,archives if mode=='wrong-archive' else None)


def test_source_scope_does_not_depend_on_small_shard_size(tmp_path):
    M['write_chunks'].__globals__['CHUNK']=11
    try:
        output,archives,_,_=fixture(tmp_path)
        assert M['verify'](output,archives)['status']=='verified-whole-release-census'
    finally:M['write_chunks'].__globals__['CHUNK']=512*1024


def test_reproducible_materialization_does_not_overwrite(tmp_path):
    output,archives,_,_=fixture(tmp_path);other=tmp_path/'other'
    M['build'](output,archives,other)
    for p in output.rglob('*'):
        if p.is_file():assert p.read_bytes()==(other/p.relative_to(output)).read_bytes()
    dest=tmp_path/'dest';M['materialize'](output,dest)
    with pytest.raises(ValueError):M['materialize'](output,dest)


@pytest.mark.parametrize('spelling',[b'asm',b'__asm',b'__asm__',b'asm_inline'])
def test_prefilter_accepts_every_supported_asm_spelling(spelling):
    raw=spelling+b' volatile("nop");'
    assert M['ASM_HINT'].search(raw)
    assert len(rows(raw))==1


def test_macro_formal_parameters_strings_and_comments_do_not_create_providers():
    data=(b'#define ID(asm) asm\n#define TEXT "asm"\n#define COMMENT(x) x /* asm */\n'
          b'#define REAL(x) __asm__ volatile(x)\n#define ALIAS REAL\n')
    definitions=M['macro_definitions'](data,'macros.h')
    assert M['providers'](definitions)=={'REAL','ALIAS'}


def test_published_corpus_retains_v1_and_known_out_of_scope_sources():
    root=M['DEFAULT']
    assert M['verify'](root)['status']=='verified-whole-release-census'
    assert M['audit_v1'](root,root.with_name('real-projects-v1'))['missingCount']==0
    def paths(project):
        directory=root/project
        manifest=json.loads((directory/'manifest.json').read_text())
        raw=M['read_chunks'](directory,manifest['artifacts']['sites.jsonl.gz'])
        return {json.loads(line)['sourcePath'] for line in gzip.decompress(raw).splitlines()}
    musl=paths('musl')
    assert {'src/math/riscv64/'+name+'.c' for name in
            ('copysign','copysignf','fabs','fabsf','fma','fmaf','fmax','fmaxf','fmin','fminf','sqrt','sqrtf')} <= musl
    linux=paths('linux')
    assert {'arch/riscv/'+name+'.c' for name in
            ('kernel/irq','kernel/process','kernel/sbi','kernel/traps','kernel/traps_misaligned',
             'kvm/aia_imsic','kvm/tlb','kvm/vcpu_exit','mm/tlbflush')} <= linux


@pytest.mark.parametrize('comment',[b'/* comment */',b'// comment\n'])
def test_asm_keyword_can_be_followed_immediately_by_a_comment(comment):
    raw=b'asm'+comment+b' volatile("nop");'
    assert M['ASM_HINT'].search(raw)
    assert len(rows(raw))==1
