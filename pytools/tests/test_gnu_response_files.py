"""Real GNU ar raw/frozen response parity and captured immutable replay."""
from copy import deepcopy
from pathlib import Path
import json
import os
import shutil
import subprocess

import pytest

from riscv2x86_py import gnu_response_files as response
from riscv2x86_py import project_archive_provenance as archives
from riscv2x86_py.project_build_capture import create,run,inventory
from riscv2x86_py.project_compile_context import digest
from riscv2x86_py.project_build_records import identity
from riscv2x86_py.native_dependency_evidence import archive_members


@pytest.fixture
def capture(tmp_path):
    ar=shutil.which('ar')
    if not ar:pytest.skip('GNU ar required')
    if not subprocess.check_output([ar,'--version'],text=True).startswith('GNU ar '):pytest.skip('GNU ar required')
    config=create(tmp_path/'capture',{'ar':ar},archive_tools={'ar':'gnu-ar'})
    return tmp_path,config,tmp_path/'capture/capture.json'


@pytest.mark.parametrize('contents',[
    b'"space name.o" simple.o',b"'quote name.o' simple.o",b'space\\ name.o simple.o',
    b'\n\t simple.o \r\n',b'',b'@nested.lst',b'"back\\\\slash.o"',
])
def test_real_ar_response_expansion_matches_frozen_arguments(capture,contents):
    root,config,path=capture
    for name in ('space name.o','simple.o','quote name.o','back\\slash.o'):(root/name).write_bytes(name.encode())
    (root/'nested.lst').write_bytes(b'"space name.o" simple.o')
    (root/'outer.lst').write_bytes(contents)
    # Empty lists have no members: skip append parity because the supported
    # append grammar intentionally requires at least one actual input.
    proof=response.capture(config['directory'],['cq','frozen.a','@outer.lst'],str(root))
    if not contents.strip():assert proof['effectiveArguments']==['cq','frozen.a'];return
    subprocess.run([config['tools']['ar']['path'],'cq','raw.a','@outer.lst'],cwd=root,check=True,capture_output=True)
    subprocess.run([config['tools']['ar']['path'],*proof['effectiveArguments']],cwd=root,check=True,capture_output=True)
    a=archive_members((root/'raw.a').read_bytes());b=archive_members((root/'frozen.a').read_bytes())
    assert [(m['name'],m['digest']) for m in a]==[(m['name'],m['digest']) for m in b]
    assert response.replay(config['directory'],proof,['cq','frozen.a','@outer.lst'],str(root))==proof['effectiveArguments']


def test_capture_binds_response_blobs_and_replays_after_file_is_deleted(capture):
    root,config,path=capture
    (root/'leaf.o').write_bytes(b'payload');(root/'list.rsp').write_text('leaf.o')
    _,code=run(path,'build',[config['wrappers']['ar']['path'],'cq','providers.a','@list.rsp'],cwd=root)
    assert code==0
    (root/'list.rsp').unlink()
    records=inventory(path,stage='build');assert records['importComplete']
    action=records['actions'][0];before=action['archiveOperationEvidence']['before']
    assert before['supported'] and before['responseExpansion']['effectiveArguments']==['cq','providers.a','leaf.o']
    assert action['observedOutput']['digest']==digest(root/'providers.a')
    selection=archives.select(records['actions'],config['directory'],root/'providers.a',digest(root/'providers.a'))
    assert selection['complete'] and selection['members'][0]['path']==str(root/'leaf.o')


@pytest.mark.parametrize('raw',[b"'unterminated",b'trailing\\',b'zero\0byte',b'\xff'])
def test_malformed_or_unsupported_encoding_never_gets_authority(capture,raw):
    root,config,_=capture;(root/'bad').write_bytes(raw)
    with pytest.raises(ValueError):response.capture(config['directory'],['@bad'],str(root))


def test_nested_paths_are_relative_to_invocation_directory(capture):
    root,config,_=capture;(root/'sub').mkdir()
    (root/'sub/outer').write_text('@inner')
    (root/'inner').write_text('actual.o');(root/'sub/inner').write_text('wrong.o')
    result=response.capture(config['directory'],['@sub/outer'],str(root))
    assert result['effectiveArguments']==['actual.o']


def test_cycle_missing_file_and_budgets_reject(capture):
    root,config,_=capture;(root/'cycle').write_text('@cycle')
    with pytest.raises(ValueError,match='CYCLE'):response.capture(config['directory'],['@cycle'],str(root))
    with pytest.raises(ValueError,match='UNAVAILABLE'):response.capture(config['directory'],['@absent'],str(root))
    with pytest.raises(ValueError,match='ARGUMENT_BUDGET'):
        response.expand(['a','b'],str(root),lambda _:None,limits={**response.LIMITS,'arguments':1})


def test_rehashed_effective_argv_or_changed_blob_is_rejected(capture):
    root,config,_=capture;(root/'list').write_text('one.o')
    value=response.capture(config['directory'],['@list'],str(root))
    changed=deepcopy(value);changed['effectiveArguments']=['different.o']
    changed['responseExpansionIdentity']=identity({k:v for k,v in changed.items() if k!='responseExpansionIdentity'})
    with pytest.raises(ValueError,match='REDERIVATION'):response.replay(config['directory'],changed,['@list'],str(root))
    blob=Path(config['directory'])/'archive-blobs'/value['files'][0]['digest'][7:]
    blob.write_bytes(b'changed')
    with pytest.raises(ValueError,match='BLOB_CHANGED'):response.replay(config['directory'],value,['@list'],str(root))


def test_whole_command_response_keeps_output_and_production_chain(capture):
    root,config,path=capture
    (root/'member.o').write_bytes(b'whole command member')
    (root/'command.rsp').write_text('cq output.a member.o')
    _,code=run(path,'build',[config['wrappers']['ar']['path'],'@command.rsp'],cwd=root)
    assert code==0
    action=inventory(path,stage='build')['actions'][0]
    assert action['observedOutput']['path']==str(root/'output.a')
    selection=archives.select([action],config['directory'],root/'output.a',digest(root/'output.a'))
    assert selection['complete']


def test_execution_arguments_are_frozen_before_native_tool_reads_response(capture,monkeypatch):
    root,config,_=capture;monkeypatch.chdir(root)
    (root/'one.o').write_bytes(b'original');(root/'other.o').write_bytes(b'changed')
    (root/'list.rsp').write_text('one.o')
    session=archives.Session(config,'ar',['cq','frozen.a','@list.rsp'])
    with session:
        (root/'list.rsp').write_text('other.o')
        subprocess.run([config['tools']['ar']['path'],*session.execution_arguments],check=True)
        after=session.finish(0)
    result=archives.verify(config['directory'],session.before,after,
        [config['tools']['ar']['path'],'cq','frozen.a','@list.rsp'],str(root),0)
    assert result['verified'] and result['members'][0]['name']=='one.o'


def test_nonregular_response_is_rejected_without_waiting_for_fifo_writer(capture):
    root,config,_=capture
    if not hasattr(os,'mkfifo'):pytest.skip('FIFO support required')
    os.mkfifo(root/'pipe.rsp')
    with pytest.raises(ValueError,match='REGULAR_FILE_REQUIRED'):
        response.capture(config['directory'],['@pipe.rsp'],str(root))


def test_active_response_parser_must_match_registered_source(capture,monkeypatch):
    from riscv2x86_py.project_build_capture import load
    root,_,path=capture;different=root/'different-parser.py';different.write_text('# different implementation\n')
    monkeypatch.setattr(response,'__file__',str(different))
    with pytest.raises(ValueError,match='RESPONSE_IMPLEMENTATION_CHANGED'):load(path)
