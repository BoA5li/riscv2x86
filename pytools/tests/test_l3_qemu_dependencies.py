"""Real local Git integration, including QEMU 7.2's actual validation script.

Temporary repositories are dependency fixtures, not QEMU semantic approval.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess

import pytest

from riscv2x86_py import l3_qemu_dependencies as deps
from riscv2x86_py.l3_trace_support import digest, identity, run


def git(root,*args):
    return subprocess.run(['git','-C',str(root),*map(str,args)],capture_output=True,text=True,
        check=True,env=dict(os.environ,GIT_ALLOW_PROTOCOL='file',GIT_TERMINAL_PROMPT='0')).stdout.strip()


def init(root):
    root.mkdir(parents=True)
    git(root,'init','-q');git(root,'config','user.name','Dependency Fixture')
    git(root,'config','user.email','fixture@example.invalid')
    git(root,'config','core.autocrlf','false')


def commit(root):
    git(root,'add','.');git(root,'commit','-qm','dependency fixture')
    return git(root,'rev-parse','HEAD')


@pytest.fixture
def repositories(tmp_path):
    source=tmp_path/'donor';init(source)
    modules=[];gitmodules=[]
    for index,path in enumerate(deps.PATHS):
        repo=source/path;init(repo)
        (repo/'input.txt').write_text('fixed dependency '+str(index)+'\n')
        (repo/'test cases').mkdir();(repo/'test cases/example file.c').write_text('/* upstream-style spaced paths */')
        (repo/'executable.sh').write_text('#!/bin/sh\ntrue\n');(repo/'executable.sh').chmod(0o755)
        (repo/'link').symlink_to('input.txt')
        sha=commit(repo);modules.append((path,sha))
        gitmodules.append('[submodule "'+path+'"]\n path = '+path+'\n url = https://unreachable.invalid/'+path+'\n')
    (source/'.gitmodules').write_text(''.join(gitmodules))
    (source/'.gitignore').write_text('.git-submodule-status\n*.pyc\n')
    (source/'VERSION').write_text('7.2.0\n')
    (source/'configure').write_text('#!/bin/sh\n# fixture: no emulator is built\n');(source/'configure').chmod(0o755)
    scripts=source/'scripts';scripts.mkdir()
    (scripts/'git-submodule.sh').write_bytes((Path(__file__).parent/'fixtures/qemu72-git-submodule.sh').read_bytes())
    git(source,'add','.gitmodules','.gitignore','VERSION','configure','scripts')
    for path,sha in modules:
        git(source,'update-index','--add','--cacheinfo','160000,'+sha+','+path)
    git(source,'commit','-qm','pinned source fixture')
    sha=git(source,'rev-parse','HEAD')
    return source,sha,tmp_path/'prepared',tmp_path/'logs'


def prepare(values):
    source,sha,target,logs=values
    return deps.prepare_source(source,target,logs,commit=sha)


def verify(record,values):
    return deps.verify_prepared_dependencies(record,expected_commit=values[1])


def test_real_offline_independent_preparation_and_upstream_validate(repositories):
    source,sha,target,logs=repositories
    original_config=(source/'.git/config').read_bytes()
    original_heads={p:git(source/p,'rev-parse','HEAD') for p in deps.PATHS}
    record=prepare(repositories)
    assert verify(record,repositories)==record
    assert (source/'.git/config').read_bytes()==original_config
    assert record['requirements']==deps.discover_dependencies(source,sha)
    for item in record['dependencies']:
        clone=Path(item['preparedPath']);donor=Path(item['donorPath'])
        assert clone/'.git' != donor/'.git'
        assert not (clone/'.git/objects/info/alternates').exists()
        assert git(clone,'rev-parse','HEAD')==original_heads[item['path']]
        assert git(clone,'status','--porcelain')==''
    result=run(['sh',target/'scripts/git-submodule.sh','validate',*deps.PATHS],logs,'verify-upstream')
    assert result.returncode==0
    command=json.loads((logs/'source-clone.command.json').read_text())
    assert command['gitNetworkPolicy']=='file'
    assert '--no-hardlinks' in command['command'] and '--dissociate' in command['command']
    # Independent clones remain usable when donors are moved away.
    source.rename(source.with_name('donor-moved'))
    assert verify(record,repositories)==record


@pytest.mark.parametrize('mutation',['missing','wrong-commit','tracked-dirty','untracked','hidden-dirty','missing-blob'])
def test_invalid_donors_reject_before_cloning_primary_source(repositories,mutation):
    source,sha,target,logs=repositories;module=source/deps.PATHS[0]
    if mutation=='missing':module.rename(source/'outside-module')
    if mutation=='wrong-commit':(module/'extra').write_text('another revision');commit(module)
    if mutation=='tracked-dirty':(module/'input.txt').write_text('changed')
    if mutation=='untracked':(module/'extra.c').write_text('unexpected source')
    if mutation=='hidden-dirty':
        git(module,'update-index','--assume-unchanged','input.txt');(module/'input.txt').write_text('hidden mutation')
    if mutation=='missing-blob':
        blob=git(module,'rev-parse','HEAD:input.txt');(module/'.git/objects'/blob[:2]/blob[2:]).unlink()
    with pytest.raises((deps.DependencyError,OSError)):prepare(repositories)
    assert not target.exists()


@pytest.mark.parametrize('mutation',['source-file','module-file','snapshot','wrong-checkout','forged-record','extra-module'])
def test_prepared_inputs_and_rehashed_records_are_revalidated(repositories,mutation):
    source,sha,target,logs=repositories;record=prepare(repositories)
    if mutation=='source-file':(target/'configure').write_text('changed')
    if mutation=='module-file':(target/deps.PATHS[0]/'input.txt').write_text('changed')
    if mutation=='snapshot':(target/'.git-submodule-status').write_text('fake')
    if mutation=='wrong-checkout':
        repo=target/deps.PATHS[0];git(repo,'config','user.name','Fixture');git(repo,'config','user.email','f@example.invalid')
        (repo/'extra').write_text('new commit');commit(repo)
    if mutation=='forged-record':record['dependencies'][0]['preparedSnapshot']['contentIdentity']='sha256:'+'a'*64
    if mutation=='extra-module':record['requirements'].append({'path':'another','name':'another','commit':sha})
    record['preparationIdentity']=identity({k:v for k,v in record.items() if k!='preparationIdentity'})
    with pytest.raises(deps.DependencyError):verify(record,repositories)


def test_qemu_status_snapshot_alone_does_not_prove_gitlink_or_content(repositories):
    source,sha,target,logs=repositories;record=prepare(repositories)
    module=target/deps.PATHS[0]
    # Upstream validate compares status, and does not detect this blob mutation.
    git(module,'update-index','--assume-unchanged','input.txt');(module/'input.txt').write_text('concealed')
    assert subprocess.run(['sh',str(target/'scripts/git-submodule.sh'),'validate',*deps.PATHS],check=False).returncode==0
    with pytest.raises(deps.DependencyError,match='CONTENT_MISMATCH'):verify(record,repositories)


def test_shared_git_config_and_external_object_references_reject(repositories):
    source,sha,target,logs=repositories;record=prepare(repositories)
    module=target/deps.PATHS[0]
    alternates=module/'.git/objects/info/alternates';alternates.write_text(str(source/deps.PATHS[0]/'.git/objects')+'\n')
    with pytest.raises(deps.DependencyError,match='EXTERNAL_OBJECT_STORE'):verify(record,repositories)


def test_configuration_must_match_prepared_profile(tmp_path):
    build=tmp_path/'build';build.mkdir()
    text='TARGET_DIRS=riscv64-linux-user x86_64-linux-user\nCONFIG_PLUGIN=y\nGIT_SUBMODULES_ACTION=validate\nGIT_SUBMODULES='+' '.join(deps.PATHS)+'\n'
    text+='SRC_PATH='+str(tmp_path/'source')+'\nMESON=/usr/bin/python3 -B '+str(tmp_path/'source/meson/meson.py')+'\n'
    path=build/'config-host.mak';path.write_text(text)
    req=[{'path':p} for p in deps.PATHS]
    assert deps.validate_build_configuration(build,req)['gitSubmodulesAction']=='validate'
    for original,changed in [('validate','update'),('CONFIG_PLUGIN=y','CONFIG_PLUGIN=n'),
            ('x86_64-linux-user',''),('GIT_SUBMODULES=','GIT_SUBMODULES=unreviewed '),
            ('TARGET_DIRS=','TARGET_DIRS=another ' )]:
        path.write_text(text.replace(original,changed))
        with pytest.raises(deps.DependencyError,match='CONFIGURATION_MISMATCH'):deps.validate_build_configuration(build,req)


def test_v1_backend_does_not_gain_v2_preparation_by_renaming():
    from riscv2x86_py.l3_qemu_backend import validate_backend,SCHEMA
    with pytest.raises(ValueError,match='LEGACY_PREPARATION_MISSING'):
        validate_backend({'schemaVersion':'riscv2x86.qemu-fragment-trace-backend.v1'})
    with pytest.raises(ValueError,match='SCHEMA_INVALID'):
        validate_backend({'schemaVersion':SCHEMA})


def test_donor_alternate_objects_are_dissociated_into_independent_clones(repositories,tmp_path):
    source,sha,target,logs=repositories
    module=source/deps.PATHS[0]; backup=tmp_path/'object-donor'
    module.rename(backup)
    subprocess.run(['git','clone','--shared',str(backup),str(module)],check=True,capture_output=True)
    assert (module/'.git/objects/info/alternates').is_file()
    record=prepare(repositories)
    assert not (target/deps.PATHS[0]/'.git/objects/info/alternates').exists()
    backup.rename(tmp_path/'object-donor-moved')
    assert verify(record,repositories)==record


def test_dependency_source_changed_during_materialization_rejects(repositories):
    source,sha,target,logs=repositories
    def stage(name):
        if name=='dependency_snapshot':(source/deps.PATHS[0]/'input.txt').write_text('concurrent change')
    with pytest.raises(deps.DependencyError):deps.prepare_source(source,target,logs,commit=sha,stage=stage)
    assert not (logs/'source-preparation.json').exists()


@pytest.mark.parametrize('mutation',['missing-command','false-policy','wrong-command','missing-gitlink','rewritten-snapshot'])
def test_snapshot_or_rehashed_preparation_cannot_remove_required_checks(repositories,mutation):
    source,sha,target,logs=repositories;record=prepare(repositories)
    if mutation=='missing-command':record['commands'].pop(next(iter(record['commands'])))
    if mutation in ('false-policy','wrong-command'):
        path=logs/'source-clone.command.json';value=json.loads(path.read_text())
        if mutation=='false-policy':value['gitNetworkPolicy']='https'
        else:value['command']=['git','clone','--shared','unbound','unbound']
        path.write_text(json.dumps(value));record['commands'][str(path)]=digest(path)
    if mutation=='missing-gitlink':record['requirements'].pop()
    if mutation=='rewritten-snapshot':
        value='fake self-consistent snapshot\n';record['qemuStatusSnapshot']=value;(target/'.git-submodule-status').write_text(value)
    record['preparationIdentity']=identity({k:v for k,v in record.items() if k!='preparationIdentity'})
    with pytest.raises(deps.DependencyError):verify(record,repositories)


@pytest.fixture
def configured_binding(repositories):
    """Binding fixture only: no QEMU binary or instruction result is asserted."""
    from riscv2x86_py.l3_qemu_backend import _validate_source_preparation
    source,sha,target,logs=repositories;record=prepare(repositories)
    build=target.parent/'build';build.mkdir()
    text='TARGET_DIRS=riscv64-linux-user x86_64-linux-user\nCONFIG_PLUGIN=y\nGIT_SUBMODULES_ACTION=validate\nGIT_SUBMODULES='+' '.join(deps.PATHS)+'\n'
    text+='SRC_PATH='+str(target)+'\nMESON=/usr/bin/python3 -B '+str(target/'meson/meson.py')+'\n'
    (build/'config-host.mak').write_text(text)
    compiler='/binding-fixture/compiler'
    command=[str(target/'configure'),'--target-list=riscv64-linux-user,x86_64-linux-user',
        '--disable-system','--enable-plugins','--with-git-submodules=validate','--meson=git','--enable-tcg','--cc='+compiler]
    for name,cmd in [('configure',command),('compile',['make','-j2'])]:
        (build/(name+'.command.json')).write_text(json.dumps({'command':cmd,'returnCode':0,'timedOut':False,'gitNetworkPolicy':'file'}))
    (build/'config.status').write_text('binding fixture only')
    (build/'meson-info').mkdir();(build/'meson-info/intro-buildoptions.json').write_text('[]')
    for name in ('qemu-riscv64','qemu-x86_64'):(build/name).write_text('binding fixture, never executed')
    prep_path=logs/'source-preparation.json'
    files={str(path):digest(path) for path in build.rglob('*') if path.is_file()}
    files[str(prep_path)]=digest(prep_path)
    backend={'sourceCommit':sha,'sourceExecutor':str(build/'qemu-riscv64'),'targetExecutor':str(build/'qemu-x86_64'),
        'targetCompiler':compiler,'files':files,'sourcePreparation':{'recordPath':str(prep_path),
        'recordDigest':digest(prep_path),'preparationIdentity':record['preparationIdentity'],
        'configuration':deps.validate_build_configuration(build,record['requirements'],prepared_source=target)}}
    assert _validate_source_preparation(backend)==record
    return backend,record,build


@pytest.mark.parametrize('mutation',['drop-binding','preparation-file','dependency-file','configuration','command','missing-config-hash','source-location'])
def test_backend_consumer_replays_preparation_and_configuration(configured_binding,mutation):
    from riscv2x86_py.l3_qemu_backend import _validate_source_preparation
    backend,record,build=configured_binding
    if mutation=='drop-binding':backend['sourcePreparation']={}
    if mutation=='preparation-file':Path(backend['sourcePreparation']['recordPath']).write_text('{}')
    if mutation=='dependency-file':(Path(record['preparedSourcePath'])/deps.PATHS[0]/'input.txt').write_text('changed')
    if mutation=='configuration':
        path=build/'config-host.mak';path.write_text(path.read_text().replace('validate','ignore'))
        backend['files'][str(path)]=digest(path)
    if mutation=='command':
        path=build/'configure.command.json';value=json.loads(path.read_text());value['command'].remove('--with-git-submodules=validate')
        path.write_text(json.dumps(value));backend['files'][str(path)]=digest(path)
    if mutation=='missing-config-hash':backend['files'].pop(str(build/'config.status'))
    if mutation=='source-location':backend['sourceExecutor']=str(build/'other-executor')
    with pytest.raises(ValueError):_validate_source_preparation(backend)


def test_prepare_failure_stays_in_dependency_stage_and_does_not_publish_backend(repositories,tmp_path,monkeypatch):
    import shutil
    from riscv2x86_py import l3_qemu_backend as backend
    source,sha,target,logs=repositories
    monkeypatch.setattr(backend,'REVIEWED_COMMIT',sha)
    # This only exercises dependency failure before a source compiler is used.
    (source/deps.PATHS[0]/'input.txt').write_text('dirty dependency')
    output=tmp_path/'backend';cc=shutil.which('gcc')
    with pytest.raises(ValueError):backend.prepare(source,output,2,cc,cc,tmp_path)
    status=json.loads((output/'build-status.json').read_text())
    assert not status['complete'] and status['semanticApproval'] is False
    assert status['currentStage'] in ('source','dependency_validation')
    assert not (output/'backend.json').exists() and not (output/'build').exists()


def test_backend_orchestration_reaches_validated_configuration_without_network(repositories,tmp_path,monkeypatch):
    import shutil
    from riscv2x86_py import l3_qemu_backend as backend
    source,sha,target,logs=repositories
    monkeypatch.setattr(backend,'REVIEWED_COMMIT',sha)
    original_run=backend.run;called=[]
    def observed(command,directory,tag,*args,**kwargs):
        called.append(tag)
        if tag=='configure':
            assert '--with-git-submodules=validate' in command and '--meson=git' in command and '--enable-tcg' in command
            assert kwargs['env']['GIT_ALLOW_PROTOCOL']=='file'
            prepared=Path(command[0]).parent
            text='TARGET_DIRS=riscv64-linux-user x86_64-linux-user\nCONFIG_PLUGIN=y\nGIT_SUBMODULES_ACTION=validate\nGIT_SUBMODULES='+' '.join(deps.PATHS)+'\n'
            text+='SRC_PATH='+str(prepared)+'\nMESON=/usr/bin/python3 -B '+str(prepared/'meson/meson.py')+'\n'
            (Path(directory)/'config-host.mak').write_text(text)
            return None
        if tag=='compile':raise ValueError('STOP_BEFORE_COMPILATION_FIXTURE')
        return original_run(command,directory,tag,*args,**kwargs)
    monkeypatch.setattr(backend,'run',observed)
    cc=shutil.which('gcc');output=tmp_path/'backend'
    with pytest.raises(ValueError,match='STOP_BEFORE_COMPILATION_FIXTURE'):
        backend.prepare(source,output,2,cc,cc,tmp_path)
    assert called[-2:]==['configure','compile']
    status=json.loads((output/'build-status.json').read_text())
    assert status['currentStage']=='compile' and not status['complete']
    assert not (output/'backend.json').exists()


def test_missing_command_records_startup_failure(tmp_path):
    with pytest.raises(ValueError,match='COMMAND_START_FAILED'):
        run([str(tmp_path/'no-such-command')],tmp_path,'startup')
    value=json.loads((tmp_path/'startup.command.json').read_text())
    assert value['startupFailed'] and value['returnCode'] is None
