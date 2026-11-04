"""Corpus source preservation and fail-closed bookkeeping; no translation claims."""
import base64
from copy import deepcopy
import gzip
import io
import json
from pathlib import Path
import runpy
import tarfile

import pytest

M = runpy.run_path(str(Path(__file__).resolve().parents[2]/'experiment/real_project_corpus.py'))


def sites(raw, rule='all_asm_syntax_sites'):
    return M['inventory'](raw,project='fixture',version='1',path='arch/test.h',rule=rule)


def test_comments_include_names_strings_and_spliced_comments_are_not_asm():
    raw=(b'#include <asm/asm.h>\n/*\n#if __riscv\nasm("fake");\n*/\n'
         b'char *s="asm(\\"fake\\")";\n// asm( \\\n still a comment\n'
         b'__asm__ __volatile__("add %0, %1, %2" : "=r"(x) : "r"(y), "r"(z));\n')
    row, = sites(raw)
    assert row['syntaxKind']=='extended_asm_candidate'
    assert base64.b64decode(row['sourceSliceBase64']) == raw[row['beginByte']:row['endByte']]
    assert row['conditionalContext']==[]
    assert row['semanticApproval'] is False


def test_riscv_selection_does_not_delete_other_architectures_or_claim_activation():
    raw=b'#if __x86_64__\nasm("nop");\n#elif defined(__riscv)\nasm("fence rw,rw" ::: "memory");\n#endif\n'
    rows=sites(raw,'riscv_preprocessor_branch')
    assert [r['selectedByScope'] for r in rows]==[False,True]
    assert all(r['activationStatus']=='not_checked' for r in rows)
    assert all(r['translationStatus']=='not_run' for r in rows)


def test_parentheses_literals_splices_utf8_and_register_bindings_keep_byte_offsets():
    raw='/*中文*/\nregister long x __asm__("a0");\n'.encode()+b'asm \\\r\nvolatile("(" ")" : "=r"(x) : "r"(f((y))));\n'
    rows=sites(raw)
    assert [r['syntaxKind'] for r in rows]==['register_binding_candidate','extended_asm_candidate']
    for row in rows:
        assert base64.b64decode(row['sourceSliceBase64'])==raw[row['beginByte']:row['endByte']]
        assert row['sourceSliceDigest']=='sha256:'+M['sha'](raw[row['beginByte']:row['endByte']])


def test_unresolved_macro_alias_is_retained():
    row,=sites(b'#define ASM asm\n')
    assert row['syntaxKind']=='unresolved_asm_token'
    assert row['eligibilityStatus']=='not_assessed'


@pytest.mark.parametrize('raw',[b'/* never closed',b'asm("never closed',b'#endif\n',b'#if A\n'])
def test_invalid_source_scan_cannot_silently_omit_data(raw):
    with pytest.raises(ValueError): sites(raw)


def fixture(tmp_path):
    lock_root=tmp_path/'lock';lock_root.mkdir(); archives=tmp_path/'archives';archives.mkdir()
    files={'arch/header.h':b'asm volatile("nop");\n','COPYING':b'License text\n'}
    archive=archives/'fixture.tar.gz';archive.write_bytes(M['archive_bytes']({'fixture/'+k:v for k,v in files.items()}))
    source={'id':'fixture','version':'1','archive':archive.name,'root':'fixture','sha256':M['sha'](archive.read_bytes()),
            'scope':{'files':[],'prefixes':['arch/'],'suffix':'.h','siteRule':'all_asm_syntax_sites'},
            'supportFiles':[],'licenseFiles':['COPYING'],'licensePrefixes':[]}
    lock={'schemaVersion':'riscv2x86.real-project-sources.v1','sources':[source]}
    (lock_root/'sources.lock.json').write_text(json.dumps(lock))
    output=tmp_path/'corpus';M['build'](lock_root,archives,output)
    return output,archives,files


def test_reproducible_build_materialization_and_independent_upstream_replay(tmp_path):
    corpus,archives,files=fixture(tmp_path)
    result=M['verify'](corpus,archives)
    assert result['status']=='verified-source-inventory'
    assert result['upstreamArchiveReplayComplete'] is True
    assert result['productionAcceptanceComplete'] is False
    second=tmp_path/'second';M['build'](corpus,archives,second)
    for p in corpus.rglob('*'):
        if p.is_file(): assert p.read_bytes()==(second/p.relative_to(corpus)).read_bytes()
    out=tmp_path/'materialized';M['materialize'](corpus,out)
    for path,raw in files.items(): assert (out/'fixture/upstream'/path).read_bytes()==raw
    with pytest.raises(ValueError):M['materialize'](corpus,out)


@pytest.mark.parametrize('artifact',['sources.tar.gz','sites.jsonl.gz','index.tsv','manifest.json','catalog.json','sources.lock.json'])
def test_tampered_corpus_is_rejected_before_materialization(tmp_path,artifact):
    corpus,archives,_=fixture(tmp_path)
    path=corpus/artifact if artifact in {'catalog.json','sources.lock.json'} else corpus/'fixture'/artifact
    path.write_bytes(path.read_bytes()+b'changed')
    with pytest.raises((ValueError,tarfile.TarError)): M['materialize'](corpus,tmp_path/'bad')
    assert not (tmp_path/'bad').exists()


def test_wrong_upstream_digest_rejects_build(tmp_path):
    corpus,archives,_=fixture(tmp_path)
    (archives/'fixture.tar.gz').write_bytes(b'bad')
    with pytest.raises(ValueError):M['build'](corpus,archives,tmp_path/'bad-build')


@pytest.mark.parametrize('name',['../escape','/absolute','a/../../escape','a\\b'])
def test_snapshot_paths_are_not_executable_or_escaping(tmp_path,name):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as t:
        entry=tarfile.TarInfo(name);entry.size=1;t.addfile(entry,io.BytesIO(b'x'))
    path=tmp_path/'bad.tar.gz';path.write_bytes(buffer.getvalue())
    with pytest.raises(ValueError):M['read_snapshot'](path)


def test_snapshot_symlink_rejects(tmp_path):
    path=tmp_path/'symlink.tar.gz'
    with tarfile.open(path,'w:gz') as t:
        entry=tarfile.TarInfo('alias');entry.type=tarfile.SYMTYPE;entry.linkname='/outside';t.addfile(entry)
    with pytest.raises(ValueError):M['read_snapshot'](path)


def test_committed_real_sources_are_traceable_and_never_preapproved():
    root=Path(__file__).resolve().parents[2]/'experiment/corpora/real-projects-v1'
    result=M['verify'](root)
    assert [p['id'] for p in result['projects']]==['gmp','musl','linux']
    assert [p['counts']['selectedCandidates'] for p in result['projects']]==[1,36,102]
    assert result['compilerActivationComplete'] is False
    assert result['semanticApproval'] is False
    for project in ('gmp','musl','linux'):
        rows=[json.loads(line) for line in gzip.decompress((root/project/'sites.jsonl.gz').read_bytes()).splitlines()]
        files=M['read_snapshot'](root/project/'sources.tar.gz')
        for row in rows:
            assert base64.b64decode(row['sourceSliceBase64']) == files[row['sourcePath']][row['beginByte']:row['endByte']]
            assert row['translationStatus']=='not_run'


@pytest.mark.parametrize('mutation',['syntax-count','approval-flag','index'])
def test_rehashed_labels_cannot_replace_a_fresh_inventory(tmp_path,mutation):
    corpus,_,_=fixture(tmp_path); directory=corpus/'fixture'
    manifest=json.loads((directory/'manifest.json').read_text())
    if mutation=='syntax-count':manifest['counts']['syntaxKinds']={'invented':100}
    elif mutation=='approval-flag':manifest['semanticApproval']=True
    else:
        p=directory/'index.tsv';p.write_bytes(b'fake\n')
        manifest['artifacts']['index.tsv']={'sha256':M['sha'](p.read_bytes()),'bytes':p.stat().st_size}
    manifest=M['sealed']({k:v for k,v in manifest.items() if k!='manifestIdentity'},'manifestIdentity')
    (directory/'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError):M['verify'](corpus)
