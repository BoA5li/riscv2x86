"""Byte/type comparison of a complete source tree with a pinned release archive.

Read-only: never extract, delete, repair, ignore unlisted files or grant semantic
approval. This is not a filesystem snapshot or a publisher signature check.
"""
from hashlib import sha256
import json
import os
from pathlib import Path,PurePosixPath
import stat
import tarfile

from .project_archive_stream import open_archive
from .project_build_records import identity
from .project_compile_context import digest

SCHEMA='riscv2x86.project-source-release.v1'


def relative(name,root):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!=root:
        raise ValueError('PROJECT_RELEASE_MEMBER_PATH_INVALID:'+name)
    return '/'.join(p.parts[1:])


def verify(spec,archive,source):
    source=Path(source).resolve(strict=True);archive=Path(archive).resolve(strict=True)
    expected=spec['sha256']
    if digest(archive)!='sha256:'+expected:raise ValueError('PROJECT_RELEASE_ARCHIVE_DIGEST_MISMATCH')
    if not source.is_dir():raise ValueError('PROJECT_RELEASE_DIRECTORY_REQUIRED')
    entries={};file_digests={};records=[]
    try:
        with open_archive(archive) as tar:
            for member in tar:
                name=relative(member.name,spec['root'])
                if not name:
                    if not member.isdir():raise ValueError('PROJECT_RELEASE_ROOT_INVALID')
                    continue
                if name in entries:raise ValueError('PROJECT_RELEASE_DUPLICATE_MEMBER:'+name)
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError('PROJECT_RELEASE_MEMBER_KIND_UNSUPPORTED:'+name)
                entries[name]=member
                if member.isfile():
                    stream=tar.extractfile(member);h=sha256()
                    for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
                    file_digests[name]='sha256:'+h.hexdigest()
            # Verify ancestors with lstat before touching a member's bytes.
            for name,member in sorted(entries.items()):
                path=source/name
                for parent in PurePosixPath(name).parents:
                    if str(parent)=='.':continue
                    if not stat.S_ISDIR((source/str(parent)).lstat().st_mode):
                        raise ValueError('PROJECT_RELEASE_PARENT_NOT_DIRECTORY:'+name)
                mode=path.lstat().st_mode
                row={'path':name}
                if member.isdir():
                    if not stat.S_ISDIR(mode):raise ValueError('PROJECT_RELEASE_TYPE_MISMATCH:'+name)
                    row['kind']='directory'
                elif member.issym():
                    if not stat.S_ISLNK(mode) or os.readlink(path)!=member.linkname:
                        raise ValueError('PROJECT_RELEASE_SYMLINK_MISMATCH:'+name)
                    # Preserve exact link spelling; do not dereference it to
                    # claim that an external file belongs to this release.
                    row.update(kind='symlink',target=member.linkname)
                else:
                    if not stat.S_ISREG(mode):raise ValueError('PROJECT_RELEASE_TYPE_MISMATCH:'+name)
                    target=member;seen=set()
                    while target.islnk():
                        key=relative(target.linkname,spec['root'])
                        if key in seen or key not in entries:raise ValueError('PROJECT_RELEASE_HARDLINK_INVALID:'+name)
                        seen.add(key);target=entries[key]
                    if not target.isfile():raise ValueError('PROJECT_RELEASE_HARDLINK_INVALID:'+name)
                    declared=file_digests[relative(target.name,spec['root'])];actual=digest(path)
                    if declared!=actual:raise ValueError('PROJECT_RELEASE_CONTENT_MISMATCH:'+name)
                    if mode&0o111 != member.mode&0o111:raise ValueError('PROJECT_RELEASE_EXEC_MODE_MISMATCH:'+name)
                    row.update(kind='file',digest=actual,executableMask=mode&0o111)
                    if member.islnk():row['archiveHardlink']=member.linkname
                records.append(row)
    except (tarfile.TarError,EOFError,KeyError,RecursionError) as exc:
        raise ValueError('PROJECT_RELEASE_ARCHIVE_INVALID:'+str(exc)) from exc
    # Include implicit archive directories but no unrelated/generated files.
    allowed=set(entries)
    for name in entries:
        allowed.update(str(p) for p in PurePosixPath(name).parents if str(p)!='.')
    actual=set()
    for directory,dirs,files in os.walk(source,followlinks=False):
        for name in dirs+files:actual.add((Path(directory)/name).relative_to(source).as_posix())
    if actual!=allowed:
        raise ValueError('PROJECT_RELEASE_ENTRY_SET_MISMATCH:'+json.dumps({
            'missing':sorted(allowed-actual)[:20],'extra':sorted(actual-allowed)[:20],
            'missingCount':len(allowed-actual),'extraCount':len(actual-allowed)}))
    if digest(archive)!='sha256:'+expected:raise ValueError('PROJECT_RELEASE_ARCHIVE_CHANGED')
    body={'schemaVersion':SCHEMA,'project':spec['id'],'version':spec['version'],
        'archive':str(archive),'sourceRoot':str(source),'sourceSpec':spec,
        'entries':records,'entrySetIdentity':identity(sorted(actual)),
        'sourceTreeMatchesRelease':True,'comparisonScope':'entry-types-file-bytes-link-spellings-executable-bits',
        'immutableSnapshot':False,'signatureVerified':False,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,releaseIdentity=identity(body))


def replay(path):
    value=json.loads(Path(path).read_text())
    if (value.get('schemaVersion')!=SCHEMA or value.get('releaseIdentity')!=identity({k:v for k,v in value.items() if k!='releaseIdentity'})
            or value.get('semanticApproval') is not False or value.get('productionAcceptanceComplete') is not False):
        raise ValueError('PROJECT_RELEASE_PROOF_INVALID')
    fresh=verify(value['sourceSpec'],value['archive'],value['sourceRoot'])
    if identity(fresh)!=identity(value):raise ValueError('PROJECT_RELEASE_REPLAY_MISMATCH')
    return value['releaseIdentity']
