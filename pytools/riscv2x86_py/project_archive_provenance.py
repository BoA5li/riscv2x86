"""Opt-in GNU regular-ar append/index evidence, never link or semantic approval.

Snapshots attest observed bytes under cooperating archive-writer serialization.
They do not attest process-tree completeness or absence of hostile external writes.
"""
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from .native_dependency_evidence import archive_members, bytes_digest
from .project_build_records import identity
from .project_compile_context import digest

POLICY = 'riscv2x86.gnu-archive-append-index.v1'


def clock_domain():
    # Linux monotonic timestamps are comparable only within the same boot.
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def configure(tools, profiles):
    result = {}
    for name, profile in profiles.items():
        if name not in tools or profile not in ('gnu-ar', 'gnu-ranlib'):
            raise ValueError('ARCHIVE_TOOL_PROFILE_INVALID')
        executable = tools[name]['path']
        run = subprocess.run([executable, '--version'], check=True, capture_output=True,
                             text=True, timeout=30, env=dict(os.environ, LC_ALL='C'))
        prefix = 'GNU ar ' if profile == 'gnu-ar' else 'GNU ranlib '
        if not run.stdout.startswith(prefix):
            raise ValueError('ARCHIVE_GNU_TOOL_REQUIRED')
        result[name] = {'profile': profile, 'version': run.stdout, 'stderr': run.stderr}
    from . import native_dependency_evidence as parser
    return {'policy': POLICY, 'clockDomain':clock_domain(), 'parserPath':str(Path(parser.__file__).resolve()),
            'parserDigest':digest(parser.__file__), 'modulePath': str(Path(__file__).resolve()),
            'moduleDigest': digest(__file__), 'tools': result}


def grammar(profile, args, cwd):
    args = list(args)
    if profile == 'gnu-ar':
        if len(args) < 3:
            raise ValueError('ARCHIVE_APPEND_INPUTS_REQUIRED')
        flags = args.pop(0).removeprefix('-')
        if (flags.count('q') != 1 or any(c not in 'qcDsSUv' for c in flags)
                or len(flags) != len(set(flags)) or ('D' in flags and 'U' in flags)
                or ('s' in flags and 'S' in flags)):
            raise ValueError('ARCHIVE_OPERATION_UNSUPPORTED')
        operation = 'append'
    elif profile == 'gnu-ranlib':
        if args[:1] in (['-D'], ['-U']): args.pop(0)
        if len(args) != 1:
            raise ValueError('ARCHIVE_INDEX_ARGUMENTS_UNSUPPORTED')
        operation = 'index'
    else:
        raise ValueError('ARCHIVE_TOOL_PROFILE_INVALID')
    if any(not a or a.startswith(('-', '@')) for a in args):
        raise ValueError('ARCHIVE_ARGUMENTS_UNSUPPORTED')
    def absolute(p):
        return os.path.abspath(os.path.join(cwd, p))
    return {'operation': operation, 'archivePath': absolute(args[0]),
            'inputPaths': [absolute(p) for p in args[1:]]}


def _blob(directory, raw):
    folder = Path(directory) / 'archive-blobs'; folder.mkdir(exist_ok=True)
    sha = bytes_digest(raw); path = folder / sha.split(':')[1]
    fd, tmp = tempfile.mkstemp(dir=folder)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        try: os.link(tmp, path)
        except FileExistsError: pass
        if path.read_bytes() != raw:
            raise ValueError('ARCHIVE_BLOB_COLLISION_OR_CHANGE')
    finally:
        os.unlink(tmp)
    return sha


def snapshot(directory, name, *, missing=False):
    path = Path(name)
    try:
        with path.open('rb') as stream:
            first = os.fstat(stream.fileno())
            if not stat.S_ISREG(first.st_mode): raise ValueError('ARCHIVE_REGULAR_FILE_REQUIRED')
            resolved = str(path.resolve(strict=True)); raw = stream.read()
            last = os.fstat(stream.fileno())
        fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        if (any(getattr(first,k) != getattr(last,k) for k in fields)
                or path.stat().st_ino != last.st_ino
                or str(path.resolve(strict=True)) != resolved):
            raise ValueError('ARCHIVE_SNAPSHOT_CHANGED')
        return {'path': str(path), 'resolvedPath': resolved, 'status': 'present',
                'digest': _blob(directory, raw)}
    except FileNotFoundError:
        if not missing: raise
        return {'path': str(path), 'status': 'missing'}


def blob(directory, row):
    sha = row['digest']
    if (not isinstance(sha, str) or not sha.startswith('sha256:') or len(sha) != 71
            or any(c not in '0123456789abcdef' for c in sha[7:])):
        raise ValueError('ARCHIVE_BLOB_DIGEST_INVALID')
    raw = (Path(directory)/'archive-blobs'/sha[7:]).read_bytes()
    if bytes_digest(raw) != sha: raise ValueError('ARCHIVE_BLOB_CHANGED')
    return raw


def members(directory, row):
    if row['status'] == 'missing': return []
    return [{k:r[k] for k in ('name','digest','size')}
            for r in archive_members(blob(directory, row))]


class Session:
    def __init__(self, config, tool, args):
        self.config = config; self.directory = config['directory']; self.lock = None
        self.profile = config.get('archiveCapture', {}).get('tools', {}).get(tool)
        self.before = None; self.args = args; self.tool = tool

    def __enter__(self):
        policy = self.config.get('archiveCapture')
        if policy is not None and policy['clockDomain'] != clock_domain():
            raise ValueError('ARCHIVE_CAPTURE_CLOCK_DOMAIN_CHANGED')
        if self.profile is None: return self
        base = {'policy': POLICY, 'profile': self.profile['profile'],
                'arguments': list(self.args), 'directory': os.getcwd()}
        try:
            plan = grammar(self.profile['profile'], self.args, os.getcwd())
        except ValueError as exc:
            self.before = dict(base, supported=False, reason=str(exc)); return self
        folder = Path(self.directory)/'archive-locks'; folder.mkdir(exist_ok=True)
        # Canonical paths serialize cooperating ar/ranlib aliases in this capture.
        key = bytes_digest(str(Path(plan['archivePath']).resolve()).encode())[7:]
        self.lock = (folder/key).open('a+b'); fcntl.flock(self.lock, fcntl.LOCK_EX)
        try:
            archive = snapshot(self.directory, plan['archivePath'], missing=True)
            inputs = [snapshot(self.directory,p) for p in plan['inputPaths']]
            self.before = dict(base, supported=True, plan=plan, archive=archive, inputs=inputs)
            return self
        except BaseException:
            self.__exit__(None,None,None); raise

    def finish(self, code):
        if self.before is None: return None
        if not self.before['supported']: return {'status': 'unsupported'}
        if code != 0: return {'status': 'tool-failed', 'returnCode': code}
        try:
            after = snapshot(self.directory,self.before['plan']['archivePath'])
            inputs = [snapshot(self.directory,p) for p in self.before['plan']['inputPaths']]
            return {'status':'observed', 'archive':after, 'inputs':inputs}
        except (OSError,ValueError) as exc:
            return {'status':'observation-failed', 'detail':str(exc)}

    def __exit__(self, *unused):
        if self.lock is not None:
            self.lock.close(); self.lock = None


def verify(directory, before, after, argv, cwd, code):
    """Reconstruct member relations from bound blobs; no command execution."""
    if before['policy'] != POLICY or before['directory'] != cwd or before['arguments'] != argv[1:]:
        raise ValueError('ARCHIVE_OPERATION_BINDING_INVALID')
    if not before['supported']:
        if after != {'status':'unsupported'}: raise ValueError('ARCHIVE_UNSUPPORTED_STATUS_INVALID')
        return {'verified':False, 'reason':before['reason']}
    plan = grammar(before['profile'],argv[1:],cwd)
    if plan != before['plan']: raise ValueError('ARCHIVE_PLAN_MISMATCH')
    if code != 0:
        if after != {'status':'tool-failed','returnCode':code}: raise ValueError('ARCHIVE_FAILURE_STATUS_INVALID')
        return {'verified':False,'reason':'ARCHIVE_TOOL_FAILED'}
    if after.get('status') != 'observed':
        return {'verified':False,'reason':'ARCHIVE_OBSERVATION_FAILED'}
    if [r['path'] for r in before['inputs']] != plan['inputPaths']:
        raise ValueError('ARCHIVE_INPUT_PATH_MISMATCH')
    if before['inputs'] != after['inputs']:
        return {'verified':False,'reason':'ARCHIVE_INPUT_CHANGED'}
    if any(r['path'] != plan['archivePath'] for r in (before['archive'],after['archive'])):
        raise ValueError('ARCHIVE_OUTPUT_PATH_MISMATCH')
    if after['archive']['status'] != 'present': raise ValueError('ARCHIVE_OUTPUT_REQUIRED')
    previous = members(directory,before['archive']); actual = members(directory,after['archive'])
    appended = []
    for row in before['inputs']:
        raw = blob(directory,row)
        appended.append({'name':Path(row['path']).name, 'digest':row['digest'], 'size':len(raw)})
    if plan['operation'] == 'index' and before['archive']['status'] != 'present':
        raise ValueError('ARCHIVE_INDEX_INPUT_REQUIRED')
    expected = previous + appended
    if actual != expected:
        return {'verified':False,'reason':'ARCHIVE_MEMBER_TRANSITION_MISMATCH'}
    return {'verified':True,'operation':plan['operation'], 'archivePath':plan['archivePath'],
            'beforeDigest':before['archive'].get('digest'), 'afterDigest':after['archive']['digest'],
            'previousMembers':previous,'members':actual,'appendedInputs':before['inputs']}


def select(actions, directory, archive_path, archive_digest):
    """Trace a complete append/index chain to an observed absent archive."""
    path = os.path.abspath(archive_path); operations = []
    for action in actions:
        evidence = action.get('archiveOperationEvidence')
        if evidence is None: continue
        before = evidence['before']; after = evidence['after']
        result = verify(directory,before,after,action['arguments'],action['directory'],action['observedReturnCode'])
        if not result['verified']:
            plan = before.get('plan')
            if plan is None or plan['archivePath'] == path:
                return {'complete':False,'reason':result['reason']}
            continue
        if result['archivePath'] == path:
            operations.append((evidence['startedMonotonicNs'],evidence['finishedMonotonicNs'],action,result))
    operations.sort(key=lambda r:r[0])
    if not operations: return {'complete':False,'reason':'ARCHIVE_OPERATION_EVIDENCE_MISSING'}
    # All observed writes to this archive must be explained, not merely a matching tail.
    relations = []; previous = None; end = None
    for start,finish,action,result in operations:
        if finish < start or end is not None and start <= end:
            return {'complete':False,'reason':'ARCHIVE_OPERATION_INTERVAL_INVALID'}
        if result['beforeDigest'] != previous:
            return {'complete':False,'reason':'ARCHIVE_OPERATION_CHAIN_GAP'}
        if result['operation'] == 'append':
            for row in result['appendedInputs']:
                relations.append({'path':row['path'],'resolvedPath':row['resolvedPath'],
                                  'digest':row['digest'],'archiveActionIdentity':action['actionIdentity'],
                                  'archiveStartedMonotonicNs':start})
        previous = result['afterDigest']; end = finish
    if previous != archive_digest:
        return {'complete':False,'reason':'ARCHIVE_FINAL_DIGEST_MISMATCH'}
    return {'complete':True,'members':relations,
            'operationIdentities':[r[2]['actionIdentity'] for r in operations]}


def acquire_chain(records_path, archive_path):
    from .native_dependency_inventory import checked_records, read
    records_path = str(Path(records_path).resolve(strict=True))
    archive_path = str(Path(archive_path).resolve(strict=True))
    records_hash = digest(records_path); archive_hash = digest(archive_path)
    records = checked_records(records_path); config = read(records['captureConfig'])
    if 'archiveCapture' not in config:
        selection = {'complete':False,'reason':'ARCHIVE_CAPTURE_PROFILE_REQUIRED'}
    else:
        selection = select(records['actions'],config['directory'],archive_path,archive_hash)
    if digest(records_path) != records_hash or digest(archive_path) != archive_hash:
        raise ValueError('ARCHIVE_CHAIN_CLOSING_INPUT_CHANGED')
    blockers = [] if selection['complete'] else [{'reason':selection['reason']}]
    body = {'schemaVersion':'riscv2x86.native-archive-chain.v1',
        'recordsPath':records_path, 'recordsDigest':records_hash,
        'archivePath':archive_path, 'archiveDigest':archive_hash,
        'selection':selection, 'blockers':blockers,
        'archiveActionSelectionVerified':selection['complete'],
        'status':'blocked' if blockers else 'inventory-only',
        'targetDependencyCompatibilityVerified':False,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,inventoryIdentity=identity(body))


def replay_chain(value):
    if (value.get('schemaVersion') != 'riscv2x86.native-archive-chain.v1'
            or value.get('inventoryIdentity') != identity({k:v for k,v in value.items() if k!='inventoryIdentity'})):
        raise ValueError('ARCHIVE_CHAIN_IDENTITY_INVALID')
    if acquire_chain(value['recordsPath'],value['archivePath']) != value:
        raise ValueError('ARCHIVE_CHAIN_REPLAY_MISMATCH')
    return {'archiveChainReplayComplete':True,'replayedInventoryIdentity':value['inventoryIdentity'],
        'replayedBlockerCount':len(value['blockers']),
        'semanticApproval':False,'productionAcceptanceComplete':False}
