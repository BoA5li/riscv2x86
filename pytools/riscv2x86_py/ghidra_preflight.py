"""Acquire/check the existing register-query capability, not translation proof."""
import json
import os
import sys
from pathlib import Path
from . import native_captured_deployment as d
from .ghidra_configuration import resolve_install_dir
from .ghidra_pythonrun_bridge import (load_riscv64_register_resolver_via_pythonrun,
    parse_register_query_output, _default_register_query_script, GhidraPythonRunError)
from .native_verifier_manifest import current, compare
from .native_external_providers import checked
from .project_acquisition import Runner, publish_checked

SCHEMA='riscv2x86.ghidra-backend-preflight.v1'
RUNTIME_ENV_KEYS=frozenset(('JAVA_HOME','HOME','LANG','LC_ALL','TMPDIR','XDG_CACHE_HOME'))


def runtime_environment(value=None):
    if value is None:return {k:os.environ[k] for k in sorted(RUNTIME_ENV_KEYS) if os.environ.get(k)}
    if (not isinstance(value,dict) or set(value)-RUNTIME_ENV_KEYS
            or any(not isinstance(v,str) or not v or '\0' in v for v in value.values())):
        raise ValueError('GHIDRA_RUNTIME_ENVIRONMENT_INVALID')
    return dict(value)


def database(resolver):
    if not resolver.registers or resolver.big_endian is not False:
        raise GhidraPythonRunError('GHIDRA_PREFLIGHT_VERSIONED_REGISTER_VIEWS_REQUIRED')
    return {'schemaVersion':'riscv2x86.ghidra-register-database.v2','ok':True,
            'language_id':resolver.language_id,'bigEndian':resolver.big_endian,
            'registers':list(resolver.registers)}


def acquire(output,*,ghidra_install_dir=None,environment=None,timeout=60):
    install=resolve_install_dir(ghidra_install_dir)
    if type(timeout) is not int or not 1<=timeout<=86400:raise ValueError('GHIDRA_QUERY_TIMEOUT_INVALID')
    env=dict(os.environ) if environment is None else dict(environment)
    # Standalone callers deliberately capture a bounded tool environment rather
    # than serialize arbitrary shell credentials. Orchestrated calls pass the
    # exact same backend environment used by the original public CLI.
    if environment is None:
        env={k:v for k,v in env.items() if k in RUNTIME_ENV_KEYS or k in ('PATH','LD_LIBRARY_PATH')}
    if not env.get('PATH') or any(not isinstance(k,str) or not isinstance(v,str) or '\0' in k+v for k,v in env.items()):
        raise ValueError('GHIDRA_PREFLIGHT_ENVIRONMENT_INVALID')
    env['GHIDRA_INSTALL_DIR']=str(install)
    env['PYTHONPATH']=str(Path(__file__).resolve().parents[1])
    runner=Runner(output,'ghidra-backend-preflight')
    try:
        # Probe the real public entry point, not a guessed list of optional
        # dependencies. --help imports the backend but performs no translation.
        from .native_experiment_driver import command as bounded_command
        runner.state['currentStage']='original-backend-import';runner.save()
        folder=runner.output/'backend-import';folder.mkdir()
        argv=[sys.executable,'-m','riscv2x86_py.cli','--help']
        code,reason=bounded_command(argv,runner.output,env,folder,timeout,8*1024*1024)
        imported={'command':argv,'environment':env,'directory':str(runner.output),
            'returnCode':code,'failureReason':reason,
            'stdout':d.snapshot(folder/'stdout.log'),'stderr':d.snapshot(folder/'stderr.log')}
        (folder/'command.json').write_text(json.dumps(imported,indent=2)+'\n')
        if code!=0 or reason is not None:raise ValueError('ORIGINAL_BACKEND_IMPORT_FAILED:'+str(reason or code))
        runner.state['currentStage']='ghidra-register-query';runner.save()
        resolver=load_riscv64_register_resolver_via_pythonrun(ghidra_install_dir=str(install),
            evidence_directory=runner.output/'query',environment=env,timeout=timeout)
        db=database(resolver);file=runner.output/'register-database.json';file.write_text(json.dumps(db,indent=2)+'\n')
        value=d.seal({'schemaVersion':SCHEMA,'verifier':current(),'installationDirectory':str(install),
            'python':d.snapshot(sys.executable),'backendImport':d.snapshot(folder/'command.json'),
            'environment':env,'query':d.snapshot(runner.output/'query/query.json'),
            'stdout':d.snapshot(runner.output/'query/stdout.log'),'stderr':d.snapshot(runner.output/'query/stderr.log'),
            'database':d.snapshot(file),'databaseIdentity':d.identity(db),
            'registerDatabaseAcquisitionComplete':True,
            'originalBackendImportChecked':True,
            'scope':'original-cli-import-and-register-query-not-translation',
            'semanticApproval':False,'productionAcceptanceComplete':False},'backendPreflightIdentity')
        publish_checked(runner.output/'result.json',value,check)
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True);runner.save()
        return value
    except Exception as exc:
        runner.failure(runner.state['currentStage'],exc);raise


def check(path):
    value=d.read(path);checked(value,'backendPreflightIdentity');compare(value['verifier'],current())
    if value['schemaVersion']!=SCHEMA:raise ValueError('GHIDRA_PREFLIGHT_SCHEMA_INVALID')
    install=resolve_install_dir(value['installationDirectory'])
    env=value['environment']
    if (not isinstance(env,dict) or not env.get('PATH')
            or any(not isinstance(k,str) or not isinstance(v,str) or '\0' in k+v for k,v in env.items())):
        raise ValueError('GHIDRA_PREFLIGHT_ENVIRONMENT_INVALID')
    if str(install)!=value['installationDirectory'] or value['environment'].get('GHIDRA_INSTALL_DIR')!=str(install):
        raise ValueError('GHIDRA_PREFLIGHT_CONFIGURATION_MISMATCH')
    for key in ('python','backendImport','query','stdout','stderr','database'):d.verify_snapshot(value[key])
    imported=d.read(value['backendImport']['path'])
    root=Path(path).resolve().parent
    for key in ('stdout','stderr'):d.verify_snapshot(imported[key])
    if (imported['command']!=[value['python']['path'],'-m','riscv2x86_py.cli','--help']
            or imported['environment']!=env or imported['directory']!=str(root)
            or imported['returnCode']!=0 or imported['failureReason'] is not None
            or env.get('PYTHONPATH')!=str(Path(__file__).resolve().parents[1])
            or value['originalBackendImportChecked'] is not True):
        raise ValueError('GHIDRA_PREFLIGHT_BACKEND_IMPORT_MISMATCH')
    query=d.read(value['query']['path']);checked(query,'queryIdentity')
    tools={str((install/'support/pythonRun').resolve()):d.digest(install/'support/pythonRun'),
           str(_default_register_query_script().resolve()):d.digest(_default_register_query_script())}
    if (query['tools']!=tools or query['command']!=list(tools) or query['returnCode']!=0
            or query['environment']!=value['environment']
            or query['failureReason'] is not None or query['maxLogBytes']!=8*1024*1024
            or query['installationDirectory']!=str(install)
            or query['stdoutDigest']!=value['stdout']['digest'] or query['stderrDigest']!=value['stderr']['digest']):
        raise ValueError('GHIDRA_PREFLIGHT_QUERY_OR_TOOL_MISMATCH')
    db=database(parse_register_query_output(Path(value['stdout']['path']).read_text()))
    if (d.read(value['database']['path'])!=db or value['databaseIdentity']!=d.identity(db)
            or value['registerDatabaseAcquisitionComplete'] is not True
            or value['scope']!='original-cli-import-and-register-query-not-translation'
            or value['semanticApproval'] is not False or value['productionAcceptanceComplete'] is not False):
        raise ValueError('GHIDRA_PREFLIGHT_REDERIVATION_MISMATCH')
    return value
