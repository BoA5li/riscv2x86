"""Batched provenance inspection for the unchanged v2 backend contract.

No persistent metadata cache. Every invocation executes fsck/status and reads
all tracked bytes. Parent-directory checks remain per file, as in the baseline.
Legacy validators/files remain immutable, so existing prepared QEMU is reusable.
"""
from hashlib import sha1,sha256
import json
import os
import re
from pathlib import Path
import stat
import shutil
from .l3_qemu_dependencies import (DependencyError,PATHS,METADATA,REVIEWED_COMMIT,SCHEMA,PROFILE_ID,
    _git as _legacy_git,_safe_path,validate_build_configuration)
from .l3_trace_support import digest,identity
from .validation_timing import timed



def _git(root,*args):
    # Commands and outputs retain the legacy implementation and offline policy.
    return timed('joint.provenance-git.'+str(args[0]))(_legacy_git)(root,*args)


def _text(root,*args):return _git(root,*args).decode('utf-8').strip()


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


@timed('joint.provenance-repository-metadata')
def _facts(root,independent):
    root=Path(root).absolute()
    if root.is_symlink() or not root.is_dir():raise DependencyError('L3_TRACE_DEPENDENCY_MISSING',root)
    root=root.resolve()
    # Old Git supports these options; no --path-format or shell batching needed.
    rows=_git(root,'rev-parse','--show-toplevel','--git-dir','--git-common-dir','HEAD','HEAD^{tree}').decode().splitlines()
    if len(rows)!=5:
        # Preserve unusual path handling supported by the legacy API.
        from .l3_qemu_dependencies import _root as legacy_root
        root=legacy_root(root,independent=independent)
        return root,_text(root,'rev-parse','HEAD'),_text(root,'rev-parse','HEAD^{tree}')
    top,gitdir,common,head,tree=(row.strip() for row in rows)
    if Path(top).resolve()!=root:raise DependencyError('L3_TRACE_DEPENDENCY_REPOSITORY_ROOT_MISMATCH',root)
    if independent:
        for raw in (gitdir,common):
            path=Path(raw);actual=(root/path).resolve() if not path.is_absolute() else path.resolve()
            if actual!=root/'.git' or (root/'.git').is_symlink():
                raise DependencyError('L3_TRACE_DEPENDENCY_SHARED_GIT_DIRECTORY',root)
        alternate=root/'.git/objects/info/alternates'
        if alternate.exists() and alternate.read_text().strip():
            raise DependencyError('L3_TRACE_DEPENDENCY_EXTERNAL_OBJECT_STORE',root)
    return root,head,tree


def _root(root,*,independent=False):return _facts(root,independent)[0]


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


@timed('joint.provenance-checkout-content')
def inspect_checkout(root, commit, *, independent=False, allow_gitlinks=False):
    root,actual,tree = _facts(root,independent)
    if actual != commit:
        raise DependencyError('L3_TRACE_DEPENDENCY_COMMIT_MISMATCH', root, commit, actual)
    # Do not trust the index/stat cache alone: read every tracked blob below.
    status = _git(root, 'status', '--porcelain', '--untracked-files=normal', '--ignore-submodules=none').decode()
    if status:
        raise DependencyError('L3_TRACE_DEPENDENCY_DIRTY', root, '', status)
    _git(root, 'fsck', '--connectivity-only', '--no-dangling', '--no-reflogs', commit)
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


@timed('joint.provenance-full-validation')
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
    root = Path(value['preparedSourcePath']).absolute()
    if root.is_symlink() or not root.is_dir():raise DependencyError('L3_TRACE_DEPENDENCY_MISSING',root)
    root=root.resolve()
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
