"""Real subprocess/transport checks with synthetic query executables.

The optional real-install integration is separate and never replaced by these.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import pytest
from riscv2x86_py import ghidra_preflight as module
from riscv2x86_py import ghidra_pythonrun_bridge as bridge
from riscv2x86_py import native_captured_deployment as d


def payload():
    return {'schemaVersion':'riscv2x86.ghidra-register-database.v2','ok':True,
        'language_id':'RISCV:LE:64:default','bigEndian':False,
        'registers':[{'name':'arbitrary-register','offset':16,'size':8,'bitLength':64,
            'isProcessorContext':False,'baseName':'arbitrary-register','baseOffset':16,'baseSize':8}]}


def launcher(root,value=None,*,exit_code=0,sleep=0):
    (root/'support').mkdir(parents=True)
    file=root/'support/pythonRun'
    text=json.dumps(payload() if value is None else value)
    file.write_text('#!'+sys.executable+'\nimport time\ntime.sleep('+str(sleep)+')\nprint('+repr(text)+')\nraise SystemExit('+str(exit_code)+')\n')
    file.chmod(0o755);return root


def test_real_process_acquisition_and_stored_response_rederivation(tmp_path):
    install=launcher(tmp_path/'install with spaces')
    result=module.acquire(tmp_path/'evidence',ghidra_install_dir=str(install))
    assert result['registerDatabaseAcquisitionComplete'] and not result['semanticApproval']
    assert module.check(tmp_path/'evidence/result.json')==result
    query=d.read(result['query']['path'])
    assert query['environment']==result['environment']
    assert query['returnCode']==0 and query['failureReason'] is None
    file=Path(result['database']['path']);changed=d.read(file);changed['registers'][0]['size']=4
    file.write_text(json.dumps(changed));result['database']=d.snapshot(file);result['databaseIdentity']=d.identity(changed)
    (tmp_path/'evidence/result.json').write_text(json.dumps(d.seal(
        {k:v for k,v in result.items() if k!='backendPreflightIdentity'},'backendPreflightIdentity')))
    with pytest.raises(ValueError,match='REDERIVATION'):module.check(tmp_path/'evidence/result.json')


@pytest.mark.parametrize('mutation',['ok','language','endian','offset','size','empty','width','schema','base','duplicate'])
def test_invalid_capability_metadata_is_rejected(tmp_path,mutation):
    value=payload();reg=value['registers'][0]
    if mutation=='ok':value['ok']='true'
    elif mutation=='language':value['language_id']='RISCV:LE:32:default'
    elif mutation=='endian':value['bigEndian']=True
    elif mutation=='offset':reg['offset']=True
    elif mutation=='size':reg['size']=8.0
    elif mutation=='empty':value['registers']=[]
    elif mutation=='width':reg['size']=4;reg['bitLength']=32
    elif mutation=='schema':value['schemaVersion']='unknown'
    elif mutation=='base':reg['baseSize']=0
    elif mutation=='duplicate':value['registers'].append(dict(reg,offset=24))
    install=launcher(tmp_path/'install',value)
    with pytest.raises(bridge.GhidraPythonRunError):module.acquire(tmp_path/'evidence',ghidra_install_dir=str(install))
    assert not (tmp_path/'evidence/result.json').exists()
    assert d.read(tmp_path/'evidence/run-status.json')['status']=='failed'
    assert (tmp_path/'evidence/query/stdout.log').is_file()


@pytest.mark.parametrize('kind',['exit','timeout'])
def test_process_failure_keeps_query_evidence_without_complete_result(tmp_path,kind):
    install=launcher(tmp_path/'install',exit_code=7 if kind=='exit' else 0,sleep=3 if kind=='timeout' else 0)
    with pytest.raises(bridge.GhidraPythonRunError):
        module.acquire(tmp_path/'evidence',ghidra_install_dir=str(install),timeout=1)
    assert not (tmp_path/'evidence/result.json').exists()
    query=d.read(tmp_path/'evidence/query/query.json')
    assert query['returnCode']==7 if kind=='exit' else query['failureReason']=='TIMEOUT'


def test_invalid_path_creates_no_evidence_directory(tmp_path):
    with pytest.raises(ValueError):module.acquire(tmp_path/'never',ghidra_install_dir='')
    assert not (tmp_path/'never').exists()


def test_banner_braces_do_not_replace_the_unique_protocol_response():
    value=json.dumps(payload())
    result=bridge.parse_register_query_output('starting {not-json}\n'+json.dumps({'log':'initializing'})+'\n'+value+'\n')
    assert result.language_id=='RISCV:LE:64:default' and result.big_endian is False
    with pytest.raises(bridge.GhidraPythonRunError,match='AMBIGUOUS'):
        bridge.parse_register_query_output(value+'\n'+value)
    duplicate=value.replace('"ok": true','"ok": false, "ok": true')
    with pytest.raises(bridge.GhidraPythonRunError,match='DUPLICATE_JSON_KEY'):
        bridge.parse_register_query_output(duplicate)


def test_real_ghidra_installation_when_explicitly_available(tmp_path):
    install=os.environ.get('RV2X86_REAL_GHIDRA_INSTALL_DIR')
    if not install:pytest.skip('real Ghidra installation not supplied; synthetic query tests are not real Ghidra')
    result=module.acquire(tmp_path/'real',ghidra_install_dir=install)
    assert result['registerDatabaseAcquisitionComplete']
    assert module.check(tmp_path/'real/result.json')==result


def test_public_cli_import_failure_stops_before_query(tmp_path,monkeypatch):
    from riscv2x86_py import native_experiment_driver as driver
    install=launcher(tmp_path/'install')
    calls=[]
    def failed_import(argv,cwd,env,output,timeout,max_bytes):
        calls.append(argv)
        assert argv==[sys.executable,'-m','riscv2x86_py.cli','--help']
        folder=Path(output)
        (folder/'stdout.log').write_text('')
        (folder/'stderr.log').write_text('simulated missing backend dependency\n')
        return 7,None
    monkeypatch.setattr(driver,'command',failed_import)
    with pytest.raises(ValueError,match='ORIGINAL_BACKEND_IMPORT_FAILED:7'):
        module.acquire(tmp_path/'evidence',ghidra_install_dir=str(install))
    assert len(calls)==1
    assert not (tmp_path/'evidence/query').exists()
    assert not (tmp_path/'evidence/result.json').exists()
    state=d.read(tmp_path/'evidence/run-status.json')
    assert state['status']=='failed' and state['currentStage']=='original-backend-import'
    assert d.read(tmp_path/'evidence/backend-import/command.json')['returnCode']==7
