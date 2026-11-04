"""Filtering must not turn unknown configuration or unsupported semantics into exclusion."""
import gzip
import json
from pathlib import Path
import runpy
import shutil
import subprocess

import pytest

M = runpy.run_path(str(Path(__file__).resolve().parents[2]/'experiment/filter_rv64_c_corpus.py'))
W = M['W']


@pytest.mark.parametrize('expression,expected', [
    ('defined(__riscv)',1), ('!defined(__riscv)',0), ('__riscv_xlen == 64',1),
    ('defined(__x86_64__) || defined(__arm__)',0), ('defined(CONFIG_X86)',None),
    ('defined(__GNUC__) && defined(__riscv)',None), ('0 && UNKNOWN',0),
    ('1 || UNKNOWN',1), ('0 || UNKNOWN',None), ('1 && UNKNOWN',None),
    ('UNKNOWN == 0',None), ('0x40 == 64',1), ('010 == 8',1), ('0xffffffffU < 0',None),
    ('1 + 1 == 2',None), ('0 && call(x)',None), ('1 ? 0 : 1',None), ('__riscv_xlen < 32',0),
    ('!(!defined(__riscv))',1), ('9223372036854775808',None),
    ('defined(__i386__) && (UNKNOWN * 100 + OTHER > 42)',0),
])
def test_three_valued_guard_evaluation(expression,expected):
    assert M['evaluate'](expression) == expected


def states(raw):
    lookup = M['conditional_spans'](raw)
    return [lookup(r['beginByte'])[0] for r in W['inventory'](raw,'linux','test','shared.h')]


def test_nested_elif_else_and_unknown_config():
    raw=(b'#if !defined(__riscv)\nasm("foreign");\n#elif __riscv_xlen == 32\nasm("rv32");\n'
         b'#else\n#if CONFIG_FEATURE\nasm("unknown");\n#else\nasm("unknown too");\n#endif\n#endif\n')
    assert states(raw) == [0,0,None,None]


@pytest.mark.parametrize('raw',[
    b'#if 0\nasm("x");\n', b'#if 0\nasm("x");\n#else junk\n#endif\n',
    b'%:if 0\nasm("x");\n%:endif\n',
])
def test_malformed_or_unsupported_directives_never_exclude(raw):
    assert states(raw) == [None]


def test_local_redefinition_and_spliced_byte_mapping():
    raw=b'#undef __riscv\n#if defined(__riscv)\nas\\\nm("x");\n#else\nasm("y");\n#endif\n'
    assert states(raw) == [None,None]


def test_multiline_comments_inside_condition_and_macro_definition():
    raw=b'#define F(x) x /*\ncomment */\n#if 0 /*\n*/ || 1\nasm("x");\n#else\nasm("y");\n#endif\n'
    assert states(raw) == [1,0]


@pytest.mark.parametrize('project,path,excluded',[
    ('linux','arch/x86/include/asm/a.h',True), ('linux','arch/riscv/include/asm/a.h',False),
    ('linux','include/asm-generic/a.h',False), ('linux','shared/armature.c',False),
    ('musl','src/math/riscv64/fma.c',False), ('musl','src/math/aarch64/fma.c',True),
    ('musl','arch/riscv32/atomic_arch.h',True), ('musl','src/string/memcpy.c',False),
    ('gmp','mpn/x86_64/a.c',True), ('gmp','mpn/generic/a.c',False),
    ('gmp','mpn/riscv/64/a.h',False), ('gmp','mpn/riscv/32/a.h',True),
    ('linux','tools/testing/selftests/kvm/lib/x86_64/a.c',True),
    ('linux','tools/perf/arch/riscv/a.c',False),
])
def test_architecture_namespaces_are_explicit(project,path,excluded):
    assert bool(M['foreign_namespace'](project,path)) == excluded


def fixture(tmp_path):
    source = tmp_path/'source'; source.mkdir(); archives = tmp_path/'archives'; archives.mkdir()
    files={'COPYING':b'license\n','arch/x86/foreign.c':b'void f(){asm("x":::"memory");}\n',
        'shared/foreign.cpp':b'void f(){asm("x":::"memory");}\n',
        'shared/maybe_c.hpp':b'asm("unknown.op":::"memory");\n',
        'shared/armature.c':b'asm("unknown.op":::"memory");\n',
        'shared/regions.h':b'#if !defined(__riscv)\nasm("foreign":::"memory");\n#else\nasm("unknown.op":::"memory");\n#endif\n',
        'arch/riscv/fp.c':b'void f(){asm("fsqrt.d %0,%1" : "=f"(x) : "f"(y)); asm("ecall":::"memory");}\n',
        'shared/binding.c':b'register long r asm("a0");\n',
        'shared/barrier.c':b'void f(){asm("":::"memory");}\n',
        'shared/alias.c':b'extern int f() asm("alias");\n',
        'shared/provider.h':b'#define RUN(x) asm(x)\n',
        'shared/caller.c':b'#include "provider.h"\nvoid f(){RUN("fence rw,rw");}\n',
        'template.c.in':b'asm("generated":::"memory");\n',
        'generator.py':b'emit("asm(whatever)")\n'}
    archive=archives/'release.tar.gz';archive.write_bytes(W['V1']['archive_bytes']({'release/'+p:v for p,v in files.items()}))
    spec={'id':'linux','version':'test','root':'release','archive':archive.name,
          'sha256':W['sha'](archive.read_bytes()),'licenseFiles':['COPYING'],'licensePrefixes':[]}
    (source/'sources.lock.json').write_text(json.dumps({'schemaVersion':'riscv2x86.whole-project-source-lock.v2','sources':[spec]}))
    census=tmp_path/'census';W['build'](source,archives,census)
    output=tmp_path/'view';M['build'](census,output)
    return census,output,files


def test_partition_preserves_unsupported_sources_context_and_unknowns(tmp_path):
    census,output,files=fixture(tmp_path)
    result=M['verify'](census,output);counts=result['projects'][0]['counts']
    assert sum(counts['siteStatusCounts'].values())==counts['sourceSites']
    assert counts['compilerConfirmedTestInstances']==0
    manifest=json.loads((output/'manifest.json').read_text());a=manifest['projects'][0]['artifacts'];d=output/'linux'
    rows=M['read_rows'](d,a,'site-decisions.jsonl.gz')
    assert any(r['reasonCode']=='INACTIVE_UNDER_DECLARED_TARGET_GUARD' for r in rows)
    assert all(r['status']=='candidate' for r in rows if r['sourcePath']=='arch/riscv/fp.c')
    assert all(r['status']=='excluded' for r in rows if r['sourcePath'].endswith('.cpp'))
    assert any(r['status']=='supporting' for r in rows if r['sourcePath']=='shared/barrier.c')
    assert any(r['status']=='review' for r in rows if r['sourcePath']=='shared/alias.c')
    assert any(r['status']=='review' for r in rows if r['sourcePath']=='shared/maybe_c.hpp')
    assert any(r['status']=='review' for r in rows if r['sourcePath']=='shared/armature.c')
    file_rows=M['read_rows'](d,a,'file-decisions.jsonl.gz')
    assert any(r['status']=='review_source' for r in file_rows if r['sourcePath']=='shared/caller.c')
    assert any(r['status']=='supporting_context' for r in file_rows if r['sourcePath']=='generator.py')
    dest=tmp_path/'materialized';M['materialize'](census,output,dest)
    for p in ['shared/regions.h','arch/riscv/fp.c','shared/barrier.c','COPYING']:
        assert (dest/'linux/upstream'/p).read_bytes()==files[p]
    assert not (dest/'linux/upstream/arch/x86/foreign.c').exists()


def test_replay_rejects_missing_decisions_and_modified_policy(tmp_path):
    census,output,_=fixture(tmp_path)
    manifest=json.loads((output/'manifest.json').read_text());p=manifest['projects'][0]
    a=p['artifacts']['site-decisions.jsonl.gz'];path=output/'linux'/a['parts'][0]['path']
    path.write_bytes(b'bad')
    with pytest.raises(ValueError):M['verify'](census,output)


def test_policy_is_bound_and_no_false_acceptance(tmp_path):
    census,output,_=fixture(tmp_path)
    path=output/'selection-policy.json';policy=json.loads(path.read_text());policy['semanticApproval']=True
    policy=W['sealed']({k:v for k,v in policy.items() if k!='policyIdentity'},'policyIdentity');path.write_text(json.dumps(policy))
    with pytest.raises(ValueError):M['verify'](census,output)


def test_known_partial_results_agree_with_real_cpp():
    cc=shutil.which('cc')
    if not cc:pytest.skip('host C preprocessor unavailable')
    expressions=['defined(__riscv) && !defined(__i386__)',
        'defined(__i386__) && (X * 100 + Y > 42)',
        '__riscv_xlen == 64 || X', '0 && (X / Y)', '1 < 2 < 3']
    for expression in expressions:
        expected=M['evaluate'](expression)
        assert expected is not None
        for x,y in [(0,0),(1,2),(-1,64),(64,-1)]:
            args=[cc,'-E','-P','-undef','-D__riscv=1','-D__riscv_xlen=64',f'-DX={x}',f'-DY={y}','-x','c','-']
            result=subprocess.run(args,input=f'#if {expression}\nYES\n#else\nNO\n#endif\n',text=True,capture_output=True)
            assert result.returncode==0,result.stderr
            assert result.stdout.strip()==('YES' if expected else 'NO')
    assert states(b'#if 0 /*\n*/ || 1\nasm("x");\n#endif\n')==[1]


def test_published_partition_is_exhaustive_and_replayable():
    result=M['verify'](W['DEFAULT'],M['DEFAULT'])
    assert result['compilerConfirmedTestInstances']==0
    assert sum(p['counts']['sourceSites'] for p in result['projects'])==13857
    for project in result['projects']:
        counts=project['counts']
        assert sum(counts['siteStatusCounts'].values())==counts['sourceSites']
        assert sum(counts['fileStatusCounts'].values())==counts['sourceFiles']
    manifest=json.loads((M['DEFAULT']/'manifest.json').read_text())
    for project in manifest['projects']:
        candidates=M['read_rows'](M['DEFAULT']/project['id'],project['artifacts'],'candidate-sites.jsonl.gz')
        assert all(r['architectureHint']!='other-architecture-path-retained' for r in candidates)
