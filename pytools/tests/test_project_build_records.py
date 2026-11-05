from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import pytest
from riscv2x86_py.project_build_records import (logical_lines, shell_argv, import_log,
    import_database, record, identity)
from riscv2x86_py.project_compile_context import derive, validate


def tool():
    spec=importlib.util.spec_from_file_location('project_prepare',Path(__file__).resolve().parents[2]/'experiment/prepare_real_project_experiment.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def test_multiline_link_is_not_lost_or_miscounted(tmp_path):
    log=tmp_path/'build.log'
    log.write_text('gcc -c -o a.o a.c\ngcc -shared \\\n-Wl,-e,_dlstart -o libc.so a.o -lgcc\ncp a.o b.o\n')
    doc=import_log(log,tmp_path)
    assert doc['actionCounts']=={'compile':1,'copy':1,'link':1}
    assert doc['actions'][1]['provenance']['lineStart']==2
    assert doc['actions'][1]['provenance']['lineEnd']==3
    assert doc['actions'][1]['arguments']==['gcc','-shared','-Wl,-e,_dlstart','-o','libc.so','a.o','-lgcc']
    assert not doc['buildSuccessVerified'] and not doc['productionAcceptanceComplete']


def test_log_unparsed_compile_is_explicit_but_diagnostic_is_not_a_recipe(tmp_path):
    log=tmp_path/'build.log'; log.write_text('warning: missing \' delimiter\ngcc -c "bad\n')
    result=import_log(log,tmp_path)
    assert len(result['unclassifiedLines'])==1
    assert len(result['unresolved'])==1 and not result['importComplete']


@pytest.mark.parametrize('text', ['gcc x.c; touch bad','gcc $(whoami) x.c','gcc `whoami` x.c',
    'gcc x.c > other','gcc x.c | cat','gcc "$HOME/x.c"','gcc x.c && true'])
def test_shell_expansion_and_controls_are_never_executed(text):
    with pytest.raises(ValueError): shell_argv(text)


def test_quoted_literals_and_single_quote_continuation():
    assert shell_argv("gcc '-DVALUE=$x;|' -I'dir space' x.c")==['gcc','-DVALUE=$x;|','-Idir space','x.c']
    rows=list(logical_lines("gcc -DMSG=\"a\\\nb\" x.c\n"))
    assert rows[0]['text']=='gcc -DMSG="ab" x.c'
    assert rows[0]['lineEnd']==2
    assert list(logical_lines('gcc -c \\\n'))[0]['error']=='BUILD_LOG_DANGLING_CONTINUATION'


def test_nested_make_working_directory_is_not_guessed(tmp_path):
    log=tmp_path/'build.log'; log.write_text("make[1]: Entering directory '/another/path'\ngcc -c a.c\n")
    assert import_log(log,tmp_path)['unresolved'][0]['reasonCode']=='BUILD_LOG_WORKING_DIRECTORY_UNRESOLVED'


def action(tmp_path, extra=(), name='input.c'):
    source=tmp_path/name; source.write_text('unsigned entry(unsigned x) { return x; }\n')
    import shutil
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native compiler required for context binding test')
    return record([cc,'-std=c99','-nostdinc','-ffreestanding','-frounding-math',
        '-I','relative headers','-DVALUE=3','-O2',*extra,'-c',name,'-o','obj/input.o'],tmp_path,
        {'kind':'test'})


def test_variant_order_cwd_and_source_bytes_are_bound(tmp_path):
    a=action(tmp_path); a['kind']='compile'; a['actionIdentity']=identity({k:v for k,v in a.items() if k!='actionIdentity'})
    context=derive(a)
    assert context['inspectionReady']
    assert '-nostdinc' in context['inspectionArguments']
    assert context['workingDirectory']==str(tmp_path)
    validate(context)
    variant=deepcopy(a); variant['arguments'].insert(-4,'-fPIC')
    variant['actionIdentity']=identity({k:v for k,v in variant.items() if k!='actionIdentity'})
    assert derive(variant)['contextIdentity'] != context['contextIdentity']
    (tmp_path/'input.c').write_text('unsigned entry(unsigned x) { return x+1; }\n')
    with pytest.raises(ValueError,match='CONTENT_CHANGED'):validate(context)


@pytest.mark.parametrize('extra', [('-fplugin=unknown.so',),('@options',),('-munknown',),('-Wp,-DNEW',)])
def test_unknown_semantic_flags_are_blockers_not_discarded(tmp_path,extra):
    a=action(tmp_path,extra);a['kind']='compile';a['actionIdentity']=identity({k:v for k,v in a.items() if k!='actionIdentity'})
    context=derive(a)
    assert not context['inspectionReady']
    assert any('UNSUPPORTED' in r for r in context['blockers'])
    assert all(not row['arguments'][0].startswith(extra[0]) for row in context['projectionExclusions'])


def test_database_preserves_argv_and_does_not_accept_relative_cwd(tmp_path):
    import json
    p=tmp_path/'commands.json';p.write_text(json.dumps([
        {'directory':str(tmp_path),'arguments':['gcc','-c','a.c','-o','a.o'],'file':'a.c'},
        {'directory':'relative','command':'gcc -c b.c','file':'b.c'}]))
    d=import_database(p)
    assert len(d['actions'])==1 and len(d['unresolved'])==1
    assert d['actions'][0]['arguments']==['gcc','-c','a.c','-o','a.o']


def test_renamed_sources_and_pic_variants_are_not_deduplicated(tmp_path):
    p=tmp_path/'build.log';(tmp_path/'renamed.c').write_text('int x;')
    p.write_text(f'{sys.executable} -c renamed.c -o a.o\n')
    # Use a normal compiler name; interpretation never executes the recipe.
    p.write_text('gcc -c renamed.c -o a.o\ngcc -fPIC -c renamed.c -o a.lo\n')
    d=import_log(p,tmp_path); report=tool().inspect(d)
    assert report['sourceCount']==1 and report['buildVariantCount']==2
    assert len({r['context']['contextIdentity'] for r in report['records']})==2
    assert not report['semanticApproval']
    assert all(r['translationEvaluationBlockers'] for r in report['records'])


def test_cli_evidence_is_exclusive_and_replay_detects_log_change(tmp_path):
    m=tool();p=tmp_path/'build.log';(tmp_path/'x.c').write_text('int x;')
    p.write_text('gcc -c x.c -o x.o\n')
    records=tmp_path/'records.json'
    assert m.main(['import-log','--log',str(p),'--working-directory',str(tmp_path),'--output',str(records)])==0
    assert m.main(['import-log','--log',str(p),'--working-directory',str(tmp_path),'--output',str(records)])==2
    import json
    report=m.inspect(json.loads(records.read_text()))
    assert m.replay(report)['contextReplayComplete']
    p.write_text('gcc -DNEW -c x.c -o x.o\n')
    with pytest.raises(ValueError,match='REPLAY_MISMATCH'):m.replay(report)


def test_context_tampering_even_when_rehashed_cannot_change_recipe(tmp_path):
    a=action(tmp_path);a['kind']='compile';a['actionIdentity']=identity({k:v for k,v in a.items() if k!='actionIdentity'})
    c=derive(a);c['inspectionArguments'].append('-DOTHER=2')
    c['contextIdentity']=identity({k:v for k,v in c.items() if k!='contextIdentity'})
    with pytest.raises(ValueError,match='DERIVATION_MISMATCH'):validate(c)


def test_multiline_literal_inside_single_quotes_is_not_joined():
    # A literal newline in a shell word is intentionally outside the supported
    # build-log dialect, rather than being mistaken for backslash continuation.
    rows=list(logical_lines("gcc '-DSTR=a\\\nb' x.c\n"))
    assert len(rows)==2
    with pytest.raises(ValueError):shell_argv(rows[0]['text'])


def test_missing_selected_source_and_empty_inventory_are_not_success(tmp_path):
    m=tool();p=tmp_path/'build.log';p.write_text('warning: no compile action\n')
    report=m.inspect(import_log(p,tmp_path),sources=[tmp_path/'missing.c'])
    assert report['errors'] and report['buildVariantCount']==0


def test_acquisition_preserves_original_context_flags_and_header_binding(tmp_path,monkeypatch):
    from types import SimpleNamespace
    import json
    from riscv2x86_py.project_compile_context import acquire
    a=action(tmp_path);a['kind']='compile';a['actionIdentity']=identity({k:v for k,v in a.items() if k!='actionIdentity'})
    source=tmp_path/'input.c';header=tmp_path/'generated.h';header.write_text('#define X 1\n')
    ast={'kind':'TranslationUnitDecl','inner':[{'kind':'FunctionDecl','id':'function',
        'name':'arbitrary_name','type':{'qualType':'double (double)'},
        'inner':[{'kind':'ParmVarDecl','type':{'qualType':'double'}},{'kind':'CompoundStmt'}]}]}
    observed=[]
    def run(command,**kwargs):
        observed.append((command,kwargs))
        if '-v' in command:
            return SimpleNamespace(returncode=0,stdout='',stderr='#include \"...\" search starts here:\n#include <...> search starts here:\nEnd of search list.\n')
        return SimpleNamespace(returncode=0,stderr='',stdout=(
            f'rv2x86_call_inventory: {source} {header}\n' if '-M' in command else json.dumps(ast)))
    monkeypatch.setattr('riscv2x86_py.compiler_call_dependencies.subprocess.run',run)
    result=acquire(derive(a),clang=sys.executable,target='riscv64')
    assert all(str(tmp_path)==str(kwargs['cwd']) for _,kwargs in observed)
    assert all('-frounding-math' in command and '-nostdinc' in command for command,_ in observed)
    assert result['snapshot']['functionTypeInventory']['functions'][0]['returnType']['kind']=='binary-floating'
    assert not result['compilerEquivalenceVerified']
    assert len(result['snapshot']['dependencyManifest']['dependencies'])==2


def test_real_contextual_clang_scan(tmp_path):
    import os, shutil
    from riscv2x86_py.project_compile_context import acquire
    clang=os.environ.get('RV2X86_SYSTEM_CLANG') or shutil.which('clang')
    if not clang:pytest.skip('real Clang required for contextual AST integration')
    (tmp_path/'generated').mkdir();(tmp_path/'generated/types.h').write_text('typedef double real_t;\n')
    (tmp_path/'entry.c').write_text('#include "types.h"\nreal_t renamed(real_t x) { return x; }\n')
    a=record(['gcc','-Igenerated','-O2','-std=c99','-c','entry.c','-o','entry.o'],tmp_path,{'kind':'test'})
    c=derive(a);result=acquire(c,clang=clang,target='x86_64')
    assert result['snapshot']['functionTypeInventory']['functions'][0]['parameterTypes'][0]['kind']=='binary-floating'
    assert result['snapshot']['inventory']['functions'][0]['symbol']['name']=='renamed'


@pytest.mark.parametrize('text',['cd subdir && gcc -c x.c','CC=gcc gcc -c x.c','bash build.sh','ccache gcc -c x.c'])
def test_shell_context_or_wrapper_cannot_be_silently_ignored(tmp_path,text):
    p=tmp_path/'build.log';p.write_text(text+'\n')
    assert import_log(p,tmp_path)['unresolved']


def test_native_replay_uses_original_optimization_and_preserves_original_object(tmp_path):
    import shutil
    from riscv2x86_py.project_native_build import build
    cc=shutil.which('gcc')
    if not cc:pytest.skip('native GCC required')
    (tmp_path/'types.h').write_text('#define VALUE 7\n')
    (tmp_path/'native.c').write_text('#include "types.h"\nint entry(void) { return VALUE; }\n')
    original=tmp_path/'native.o';original.write_bytes(b'keep-original')
    a=record([cc,'-O2','-std=c99','-MMD','-MF','original.d','-c','native.c','-o','native.o'],tmp_path,{'kind':'test'})
    result=build(derive(a),tmp_path/'replay')
    assert original.read_bytes()==b'keep-original'
    assert not (tmp_path/'original.d').exists()
    assert (tmp_path/'replay/native.d').exists()
    assert result['nativeCompileReplayed'] and result['elfMachine']==62
    assert '-O2' in result['commands'][1]['arguments']
    assert not result['semanticApproval'] and not result['linkClosureVerified']
    assert str(tmp_path/'types.h') in {r['resolvedPath'] for r in result['dependencies']}
