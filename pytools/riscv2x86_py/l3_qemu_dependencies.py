"""Offline, independently checked QEMU source and dependency preparation.

QEMU's .git-submodule-status is a build-system snapshot, not semantic authority.
The consumer checks actual pinned gitlinks and checkout bytes independently.
No donor Git configuration, working files or object database is modified.
"""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import shlex
import stat
import subprocess

from .l3_trace_support import digest, identity, run, save

SCHEMA = 'riscv2x86.qemu-source-preparation.v1'
REVIEWED_COMMIT = 'b67b00e6b4c7831a3f5bc684bc0df7a9bfd1bd56'
PROFILE_ID = 'qemu-7.2-dual-linux-user-plugin-v1'
PATHS = ('dtc', 'meson', 'tests/fp/berkeley-softfloat-3',
         'tests/fp/berkeley-testfloat-3', 'ui/keycodemapdb')
METADATA = ('.gitmodules', 'VERSION', 'configure', 'scripts/git-submodule.sh')


class DependencyError(ValueError):
    def __init__(self, code, path='', expected='', actual=''):
        self.failure = {'reasonCode': code, 'modulePath': str(path),
                        'expected': str(expected), 'actual': str(actual)}
        super().__init__(code + ':' + str(path))


def _git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *map(str, args)],
        capture_output=True, timeout=120, check=False, env=_offline_env())
    if result.returncode:
        raise DependencyError('L3_TRACE_DEPENDENCY_GIT_FAILED', root,
                              'git ' + ' '.join(map(str, args)), result.stderr.decode(errors='replace')[-2000:])
    return result.stdout


def _offline_env():
    env = dict(os.environ)
    env.update(GIT_ALLOW_PROTOCOL='file', GIT_TERMINAL_PROMPT='0',
               GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_NOSYSTEM='1', GIT='git')
    # Caller-provided repository selectors must not change the meaning of -C.
    for name in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
                 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
        env.pop(name, None)
    return env


def _text(root, *args):
    return _git(root, *args).decode('utf-8').strip()


def _safe_path(path):
    value = PurePosixPath(path)
    if (not path or value.is_absolute() or str(value) != path or
            any(part in ('.', '..', '.git') for part in value.parts) or
            any(ord(char)<32 or ord(char)==127 for char in path)):
        raise DependencyError('L3_TRACE_DEPENDENCY_PATH_INVALID', path)
    return path


def _root(root, *, independent=False):
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise DependencyError('L3_TRACE_DEPENDENCY_MISSING', root)
    root = root.resolve()
    if Path(_text(root, 'rev-parse', '--show-toplevel')).resolve() != root:
        raise DependencyError('L3_TRACE_DEPENDENCY_REPOSITORY_ROOT_MISMATCH', root)
    if independent:
        for argument in ('--git-dir', '--git-common-dir'):
            raw = Path(_text(root, 'rev-parse', argument))
            actual = (root / raw).resolve() if not raw.is_absolute() else raw.resolve()
            if actual != root / '.git' or (root / '.git').is_symlink():
                raise DependencyError('L3_TRACE_DEPENDENCY_SHARED_GIT_DIRECTORY', root)
        alternates = root / '.git/objects/info/alternates'
        if alternates.exists() and alternates.read_text().strip():
            raise DependencyError('L3_TRACE_DEPENDENCY_EXTERNAL_OBJECT_STORE', root)
    return root


def _tree_entries(root, commit, paths=()):
    raw = _git(root, 'ls-tree', '-r', '-z', '--full-tree', commit, '--', *paths)
    entries = []
    for item in raw.split(b'\0'):
        if not item:
            continue
        info, path = item.split(b'\t', 1)
        mode, kind, oid = info.decode('ascii').split()
        path = _safe_path(path.decode('utf-8'))
        if not re.fullmatch('[0-9a-f]{40}', oid):
            raise DependencyError('L3_TRACE_DEPENDENCY_OBJECT_FORMAT_UNSUPPORTED', path)
        entries.append((mode, kind, oid, path))
    return entries


def discover_dependencies(source, commit=REVIEWED_COMMIT):
    source = _root(source)
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise DependencyError('L3_TRACE_QEMU_COMMIT_INVALID', source)
    mappings = _git(source, 'config', '--blob', commit + ':.gitmodules',
                    '--get-regexp', r'^submodule\..*\.path$').decode().splitlines()
    names = {}
    for line in mappings:
        key, path = line.split(None, 1)
        if path in PATHS:
            if path in names:
                raise DependencyError('L3_TRACE_DEPENDENCY_PATH_AMBIGUOUS', path)
            name = key[len('submodule.'):-len('.path')]
            if not re.fullmatch(r'[A-Za-z0-9_./-]+', name):
                raise DependencyError('L3_TRACE_DEPENDENCY_NAME_INVALID', path)
            names[path] = name
    entries = _tree_entries(source, commit, PATHS)
    requirements = []
    for mode, kind, oid, path in entries:
        if path not in PATHS or mode != '160000' or kind != 'commit' or path not in names:
            raise DependencyError('L3_TRACE_DEPENDENCY_GITLINK_INVALID', path)
        requirements.append({'path': path, 'name': names[path], 'commit': oid})
    requirements.sort(key=lambda value: value['path'])
    if [item['path'] for item in requirements] != list(PATHS):
        raise DependencyError('L3_TRACE_DEPENDENCY_SET_INCOMPLETE', source)
    return requirements


def inspect_checkout(root, commit, *, independent=False, allow_gitlinks=False):
    root = _root(root, independent=independent)
    actual = _text(root, 'rev-parse', 'HEAD')
    if actual != commit:
        raise DependencyError('L3_TRACE_DEPENDENCY_COMMIT_MISMATCH', root, commit, actual)
    # Do not trust the index/stat cache alone: read every tracked blob below.
    status = _git(root, 'status', '--porcelain', '--untracked-files=normal', '--ignore-submodules=none').decode()
    if status:
        raise DependencyError('L3_TRACE_DEPENDENCY_DIRTY', root, '', status)
    _git(root, 'fsck', '--connectivity-only', '--no-dangling', '--no-reflogs', commit)
    tree = _text(root, 'rev-parse', commit + '^{tree}')
    files = []
    for mode, kind, oid, relative in _tree_entries(root, commit):
        path = root / relative
        if mode == '160000' and kind == 'commit' and allow_gitlinks:
            continue
        if kind != 'blob' or mode not in ('100644', '100755', '120000'):
            raise DependencyError('L3_TRACE_DEPENDENCY_NESTED_OR_UNKNOWN_ENTRY', relative)
        for parent in path.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise DependencyError('L3_TRACE_DEPENDENCY_SYMLINK_PARENT', relative)
        try:
            actual_mode = path.lstat().st_mode
            if mode == '120000':
                if not stat.S_ISLNK(actual_mode):
                    raise DependencyError('L3_TRACE_DEPENDENCY_MODE_MISMATCH', relative)
                content = os.fsencode(os.readlink(path))
                # Reviewed dependencies must not fetch input from outside their checkout.
                try:
                    path.resolve().relative_to(root)
                except ValueError as exc:
                    raise DependencyError('L3_TRACE_DEPENDENCY_SYMLINK_ESCAPE', relative) from exc
            else:
                if not stat.S_ISREG(actual_mode) or bool(actual_mode & stat.S_IXUSR) != (mode == '100755'):
                    raise DependencyError('L3_TRACE_DEPENDENCY_MODE_MISMATCH', relative)
                content = path.read_bytes()
        except OSError as exc:
            raise DependencyError('L3_TRACE_DEPENDENCY_CONTENT_MISSING', relative) from exc
        actual_oid = sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        if actual_oid != oid:
            raise DependencyError('L3_TRACE_DEPENDENCY_CONTENT_MISMATCH', relative, oid, actual_oid)
        files.append({'path': relative, 'mode': mode, 'blobId': oid,
                      'contentDigest': 'sha256:' + sha256(content).hexdigest()})
    return {'commit': commit, 'treeIdentity': tree, 'contentIdentity': identity(files), 'fileCount': len(files)}


def _logged_git(root, directory, tag, *args):
    return run(['git', '-C', str(root), *map(str, args)], directory, tag, 1200, env=_offline_env())


def prepare_source(source, destination, directory, *, commit=REVIEWED_COMMIT, stage=lambda name: None):
    """Prepare without remote access. Output belongs solely to this invocation."""
    source = _root(source); destination = Path(destination).resolve(); directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise DependencyError('L3_TRACE_DEPENDENCY_OUTPUT_EXISTS', destination)
    stage('dependency_discovery')
    requirements = discover_dependencies(source, commit)
    stage('dependency_validation')
    before = {item['path']: inspect_checkout(source / item['path'], item['commit']) for item in requirements}
    # The primary source may contain ignored build output; only its tracked
    # versioned files enter a clone, and are checked in the new source below.
    if _text(source, 'rev-parse', 'HEAD') != commit:
        raise DependencyError('L3_TRACE_QEMU_COMMIT_UNREVIEWED', source)
    stage('source_checkout')
    run(['git', 'clone', '--no-checkout', '--no-hardlinks', '--dissociate', '--config', 'core.autocrlf=false', str(source), str(destination)],
        directory, 'source-clone', 1200, env=_offline_env())
    _logged_git(destination, directory, 'source-checkout', 'checkout', '--detach', commit)
    # This writes only the independent clone's config, never a worktree's
    # shared main-repository config. init does not fetch dependency content.
    _logged_git(destination, directory, 'submodule-init', 'submodule', 'init', '--', *PATHS)
    stage('dependency_materialization')
    dependencies = []
    for index, item in enumerate(requirements):
        local = source / item['path']; target = destination / item['path']
        tag = 'dependency-' + format(index, '02d')
        logs = directory / tag; logs.mkdir()
        if target.exists():
            if target.is_symlink() or not target.is_dir() or any(target.iterdir()):
                raise DependencyError('L3_TRACE_DEPENDENCY_TARGET_NOT_EMPTY', target)
            target.rmdir()
        target.parent.mkdir(parents=True, exist_ok=True)
        run(['git', 'clone', '--no-checkout', '--no-hardlinks', '--dissociate', '--config', 'core.autocrlf=false', str(local), str(target)],
            logs, 'clone', 1200, env=_offline_env())
        _logged_git(target, logs, 'checkout', 'checkout', '--detach', item['commit'])
        actual = inspect_checkout(target, item['commit'], independent=True)
        if actual != before[item['path']]:
            raise DependencyError('L3_TRACE_DEPENDENCY_COPY_MISMATCH', item['path'])
        dependencies.append({**item, 'donorPath': str(local), 'donorSnapshot': before[item['path']],
                             'preparedPath': str(target), 'preparedSnapshot': actual})
    stage('dependency_snapshot')
    for item in requirements:
        if inspect_checkout(source / item['path'], item['commit']) != before[item['path']]:
            raise DependencyError('L3_TRACE_DEPENDENCY_SOURCE_CHANGED', item['path'])
    snapshot = _logged_git(destination, directory, 'submodule-status', 'submodule', 'status', '--', *PATHS).stdout
    lines = snapshot.splitlines()
    if len(lines) != len(PATHS) or any(not line.startswith(' ') for line in lines):
        raise DependencyError('L3_TRACE_DEPENDENCY_REGISTRATION_INCOMPLETE', destination, '', snapshot)
    (destination / '.git-submodule-status').write_text(snapshot)
    # At this point the snapshot follows independent gitlink/content checks.
    _logged_git(destination, directory, 'qemu-validate', '-c', 'core.quotePath=false',
                'status', '--porcelain', '--untracked-files=no')
    result = run(['sh', str(destination / 'scripts/git-submodule.sh'), 'validate', *PATHS],
                 directory, 'qemu-submodule-validate', 120, env=_offline_env())
    if result.stdout.strip() or result.stderr.strip():
        raise DependencyError('L3_TRACE_DEPENDENCY_QEMU_VALIDATION_UNEXPECTED_OUTPUT', destination)
    source_snapshot = inspect_checkout(destination, commit, independent=True, allow_gitlinks=True)
    metadata = {name: digest(destination / name) for name in METADATA}
    commands = {str(path): digest(path) for path in sorted(directory.rglob('*.command.json'))}
    git_tool=Path(shutil.which('git')).resolve()
    value = {'schemaVersion': SCHEMA, 'profileId': PROFILE_ID, 'qemuCommit': commit,
             'preparedSourcePath': str(destination), 'donorSourcePath': str(source),
             'materialization': 'independent-local-clones-no-external-alternates',
             'requirements': requirements, 'dependencies': dependencies, 'sourceSnapshot': source_snapshot,
             'logDirectory': str(directory), 'gitTool': {'path':str(git_tool),'digest':digest(git_tool)},
             'metadata': metadata, 'qemuStatusSnapshot': snapshot, 'commands': commands}
    value['preparationIdentity'] = identity(value)
    verify_prepared_dependencies(value, expected_commit=commit)
    save(directory / 'source-preparation.json', value)
    return value


def verify_prepared_dependencies(value, *, expected_commit=REVIEWED_COMMIT):
    fields = {'schemaVersion', 'profileId', 'qemuCommit', 'preparedSourcePath', 'donorSourcePath',
              'materialization', 'requirements', 'dependencies', 'sourceSnapshot', 'metadata',
              'qemuStatusSnapshot', 'commands', 'preparationIdentity','logDirectory','gitTool'}
    if (not isinstance(value, dict) or set(value) != fields or value['schemaVersion'] != SCHEMA or
            value['profileId'] != PROFILE_ID or value['qemuCommit'] != expected_commit or
            value['materialization'] != 'independent-local-clones-no-external-alternates' or
            value['preparationIdentity'] != identity({k: v for k, v in value.items() if k != 'preparationIdentity'})):
        raise DependencyError('L3_TRACE_DEPENDENCY_PREPARATION_INVALID')
    git_tool=value['gitTool']
    if (not isinstance(git_tool,dict) or set(git_tool)!={'path','digest'} or
            str(Path(shutil.which('git')).resolve())!=git_tool['path'] or digest(git_tool['path'])!=git_tool['digest']):
        raise DependencyError('L3_TRACE_DEPENDENCY_GIT_TOOL_CHANGED')
    root = _root(value['preparedSourcePath'], independent=True)
    if discover_dependencies(root, expected_commit) != value['requirements']:
        raise DependencyError('L3_TRACE_DEPENDENCY_REQUIREMENTS_CHANGED', root)
    if inspect_checkout(root, expected_commit, independent=True, allow_gitlinks=True) != value['sourceSnapshot']:
        raise DependencyError('L3_TRACE_QEMU_SOURCE_CHANGED', root)
    if {name: digest(root / name) for name in METADATA} != value['metadata']:
        raise DependencyError('L3_TRACE_DEPENDENCY_METADATA_CHANGED', root)
    if len(value['dependencies']) != len(PATHS):
        raise DependencyError('L3_TRACE_DEPENDENCY_SET_INCOMPLETE', root)
    for required, item in zip(value['requirements'], value['dependencies']):
        if (set(item) != {'path', 'name', 'commit', 'donorPath', 'donorSnapshot', 'preparedPath', 'preparedSnapshot'} or
                {k: item[k] for k in ('path', 'name', 'commit')} != required or
                Path(item['preparedPath']) != root / required['path'] or
                item['donorSnapshot'] != item['preparedSnapshot']):
            raise DependencyError('L3_TRACE_DEPENDENCY_PREPARATION_BINDING_INVALID', required['path'])
        if inspect_checkout(item['preparedPath'], required['commit'], independent=True) != item['preparedSnapshot']:
            raise DependencyError('L3_TRACE_DEPENDENCY_CHECKOUT_CHANGED', required['path'])
    current = _git(root, 'submodule', 'status', '--', *PATHS).decode()
    if current != value['qemuStatusSnapshot'] or (root / '.git-submodule-status').read_text() != current:
        raise DependencyError('L3_TRACE_DEPENDENCY_STATUS_SNAPSHOT_CHANGED', root)
    plan=_command_plan(root,Path(value['donorSourcePath']),Path(value['logDirectory']),value['requirements'])
    if set(value['commands'])!=set(plan):
        raise DependencyError('L3_TRACE_DEPENDENCY_COMMAND_SET_INCOMPLETE',root)
    for path, expected in value['commands'].items():
        if digest(path) != expected:
            raise DependencyError('L3_TRACE_DEPENDENCY_COMMAND_CHANGED', path)
        record = json.loads(Path(path).read_text())
        if (record['returnCode'] != 0 or record['timedOut'] is not False or
                record.get('gitNetworkPolicy')!='file' or record['command']!=plan[path]):
            raise DependencyError('L3_TRACE_DEPENDENCY_COMMAND_INCOMPLETE', path)
    return value


def _command_plan(root, donor, directory, requirements):
    def clone(source, target):
        return ['git','clone','--no-checkout','--no-hardlinks','--dissociate',
                '--config','core.autocrlf=false',str(source),str(target)]
    def git(path,*args):
        return ['git','-C',str(path),*args]
    commands={
        'source-clone':clone(donor,root),
        'source-checkout':git(root,'checkout','--detach',_text(root,'rev-parse','HEAD')),
        'submodule-init':git(root,'submodule','init','--',*PATHS),
        'submodule-status':git(root,'submodule','status','--',*PATHS),
        'qemu-validate':git(root,'-c','core.quotePath=false','status','--porcelain','--untracked-files=no'),
        'qemu-submodule-validate':['sh',str(root/'scripts/git-submodule.sh'),'validate',*PATHS],
    }
    for index,item in enumerate(requirements):
        prefix='dependency-'+format(index,'02d')+'/'
        commands[prefix+'clone']=clone(donor/item['path'],root/item['path'])
        commands[prefix+'checkout']=git(root/item['path'],'checkout','--detach',item['commit'])
    return {str(directory/(tag+'.command.json')):command for tag,command in commands.items()}


def validate_build_configuration(build, requirements, *, prepared_source=None):
    path = Path(build) / 'config-host.mak'
    values = {}
    for line in path.read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            if key in values:
                raise DependencyError('L3_TRACE_DEPENDENCY_CONFIGURATION_DUPLICATE', key)
            values[key] = value.strip()
    expected = {item['path'] for item in requirements}
    source=Path(prepared_source).resolve() if prepared_source is not None else (Path(build).resolve().parent/'source')
    meson=shlex.split(values.get('MESON',''))
    if (sorted(values.get('TARGET_DIRS', '').split()) != ['riscv64-linux-user', 'x86_64-linux-user'] or
            values.get('CONFIG_PLUGIN') != 'y' or values.get('GIT_SUBMODULES_ACTION') != 'validate' or
            sorted(values.get('GIT_SUBMODULES', '').split()) != sorted(expected) or
            values.get('SRC_PATH')!=str(source) or not meson or meson[-1]!=str(source/'meson/meson.py')):
        raise DependencyError('L3_TRACE_DEPENDENCY_CONFIGURATION_MISMATCH', path)
    return {'sourcePath':str(source),'mesonPath':str(source/'meson/meson.py'),'targets': sorted(values['TARGET_DIRS'].split()), 'plugins': True,
            'gitSubmodulesAction': 'validate', 'dependencies': sorted(expected),
            'configPath': str(path.resolve()), 'configDigest': digest(path)}
