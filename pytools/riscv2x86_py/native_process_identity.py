"""Stopped-process mapping evidence for a bounded x86-64 Linux traced run.

ptrace is an intervention. This backend never proves equivalence to an
untraced run, instruction coverage, ABI, object legality or program semantics.
Fork/clone/exec-after-start are explicitly outside this single-process scope.
"""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import signal
import stat
import time
import threading

from .native_captured_deployment import seal
from .project_compile_context import digest
from .native_binding_syntax import BindingStream

REG_NAMES = ('r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi '
             'orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs').split()


class Registers(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in REG_NAMES]


class SyscallInfo(ctypes.Structure):
    # linux/ptrace.h: fixed header followed by a union (entry/exit/seccomp).
    _fields_=[('op',ctypes.c_ubyte),('pad',ctypes.c_ubyte*3),('arch',ctypes.c_uint),
              ('instruction_pointer',ctypes.c_ulonglong),('stack_pointer',ctypes.c_ulonglong),
              ('payload',ctypes.c_ubyte*64)]


def parse_maps(text):
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            raise ValueError('PROCESS_MAP_LINE_INVALID')
        start, end = (int(x, 16) for x in parts[0].split('-'))
        major, minor = (int(x, 16) for x in parts[3].split(':'))
        if start >= end:
            raise ValueError('PROCESS_MAP_RANGE_INVALID')
        rows.append({'start': start, 'end': end, 'permissions': parts[1],
                     'offset': int(parts[2], 16), 'device': [major, minor],
                     'inode': int(parts[4]), 'path': parts[5] if len(parts) == 6 else ''})
    return rows


def _stable_stat(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def binding_aliases(headers, pid, cache, *, proc_root=Path('/proc')):
    """Resolve labels while the child is stopped, never during report replay.

    Headers come from the incremental stream at this stop. Pending headers
    remain visible in later writes, including version/newline-only tails.
    The stat must refer to an image already captured in this process.
    """
    labels = sorted({e[side+'Label'] for e in headers for side in ('requester', 'provider')
                     if e['processId'] == pid and e[side+'Namespace'] == 0
                     and Path(e[side+'Label']).is_absolute()})
    rows = []
    for label in labels:
        row = {'label': label}
        try:
            source = proc_root/str(pid)/'root'/label.lstrip('/')
            with source.open('rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError('ALIAS_NOT_REGULAR_FILE')
                signature = _stable_stat(before)
                if (signature != _stable_stat(os.fstat(stream.fileno()))
                        or signature != _stable_stat(source.stat())):
                    raise ValueError('ALIAS_CHANGED_DURING_CAPTURE')
                evidence = cache.get(tuple(signature))
                if evidence is None:
                    raise ValueError('ALIAS_BACKING_IMAGE_NOT_CAPTURED')
                row.update(capturedFileStat=signature, imageDigest=evidence['digest'])
        except (OSError, ValueError) as exc:
            row['failureReason'] = str(exc)
        rows.append(row)
    return rows


def capture(argv, cwd, environment, output, *, timeout=300, log_limit=16*1024*1024,
            image_limit=64*1024*1024, stop_limit=200000, entry_probe=None):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or ctypes.sizeof(ctypes.c_void_p)!=8:
        raise ValueError('PROCESS_IDENTITY_X86_64_LINUX_REQUIRED')
    if threading.active_count()!=1:
        raise ValueError('PROCESS_IDENTITY_SINGLE_THREADED_COLLECTOR_REQUIRED')
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError('PROCESS_IDENTITY_TIMEOUT_INVALID')
    if (type(log_limit) is not int or not 1024 <= log_limit <= 2**30
            or type(image_limit) is not int or not 1024 <= image_limit <= 2**30
            or type(stop_limit) is not int or not 1 <= stop_limit <= 10**7):
        raise ValueError('PROCESS_IDENTITY_BUDGET_INVALID')
    if not argv or any(not isinstance(v, str) or '\0' in v for v in argv):
        raise ValueError('PROCESS_IDENTITY_ARGV_INVALID')
    root = Path(output).resolve(); root.mkdir()
    (root/'blobs').mkdir(); (root/'maps').mkdir()
    out = os.open(root/'stdout.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    err = os.open(root/'stderr.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    def ptrace(request, pid, address=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(request, pid, address, data)
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'PROCESS_IDENTITY_PTRACE_FAILED')
        return result
    started = time.monotonic(); pid = os.fork()
    if pid == 0:
        try:
            os.setsid(); os.chdir(cwd)
            stdin = os.open('/dev/null', os.O_RDONLY)
            os.dup2(stdin, 0); os.dup2(out, 1); os.dup2(err, 2)
            for fd in {stdin, out, err}:
                if fd > 2: os.close(fd)
            ptrace(0, 0)  # TRACEME, stop before exec: syscall phase is known.
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execve(argv[0], argv, environment)
        except BaseException as exc:
            try: os.write(2, ('PROCESS_IDENTITY_CHILD_FAILED:'+str(exc)+'\n').encode())
            except OSError: pass
            os._exit(127)
    os.close(out); os.close(err)
    epochs = []; writes = []; cache = {}; image_bytes = 0; map_bytes = 0; stops = 0
    alias_bytes = 0
    binding_stream = BindingStream()
    pending = None; executed = False; reaped = False
    failure = None; code = None
    def wait():
        while True:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done: return status
            if time.monotonic()-started > timeout:
                raise TimeoutError('PROCESS_IDENTITY_TIMEOUT')
            time.sleep(0.001)
    def blob(raw):
        nonlocal image_bytes
        sha = sha256(raw).hexdigest(); path = root/'blobs'/(sha+'.elf')
        if not path.exists():
            image_bytes += len(raw)
            if image_bytes > image_limit:
                raise ValueError('PROCESS_IDENTITY_IMAGE_BUDGET_EXCEEDED')
            path.write_bytes(raw)
        return {'blob': str(path.relative_to(root)), 'digest': 'sha256:'+sha}
    def mappings(mutation):
        nonlocal map_bytes
        if len(epochs)>=4096:raise ValueError('PROCESS_IDENTITY_MAP_EPOCH_BUDGET_EXCEEDED')
        rows = parse_maps(Path('/proc', str(pid), 'maps').read_text())
        captured = []; seen = set()
        for row in rows:
            key = (tuple(row['device']), row['inode']) if row['inode'] else ('memory', row['path'])
            if key in seen: continue
            seen.add(key)
            if row['path'] == '[vdso]':
                if row['end']-row['start'] > 1024*1024:
                    raise ValueError('PROCESS_IDENTITY_VIRTUAL_IMAGE_TOO_LARGE')
                with Path('/proc', str(pid), 'mem').open('rb', buffering=0) as stream:
                    stream.seek(row['start']); raw = stream.read(row['end']-row['start'])
                captured.append({'kind': 'mapped-virtual-elf', 'maps': [row], **blob(raw)})
            elif row['inode'] and row['path'].startswith('/'):
                item = {'kind': 'backing-file', 'maps': [r for r in rows if r['inode'] == row['inode']
                        and r['device'] == row['device']], 'path': row['path']}
                try:
                    if row['path'].endswith(' (deleted)'):
                        raise ValueError('MAPPED_FILE_DELETED')
                    source = Path('/proc', str(pid), 'root')/row['path'].lstrip('/')
                    with source.open('rb') as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode):raise ValueError('MAPPED_BACKING_FILE_NOT_REGULAR')
                        if ([os.major(before.st_dev), os.minor(before.st_dev)] != row['device']
                                or before.st_ino != row['inode']):
                            raise ValueError('MAPPED_FILE_DEVICE_INODE_MISMATCH')
                        signature = tuple(_stable_stat(before))
                        if signature not in cache:
                            prefix=stream.read(4)
                            raw=prefix+stream.read(image_limit-3) if prefix==b'\x7fELF' else prefix
                            if len(raw) > image_limit: raise ValueError('MAPPED_FILE_TOO_LARGE')
                            if _stable_stat(before) != _stable_stat(os.fstat(stream.fileno())):
                                raise ValueError('MAPPED_FILE_CHANGED_DURING_CAPTURE')
                            cache[signature] = blob(raw) if raw.startswith(b'\x7fELF') else None
                        evidence = cache[signature]
                    if evidence is not None:
                        item.update(evidence, capturedFileStat=list(signature),
                                    resolvedPath=str(source.resolve(strict=True)))
                        captured.append(item)
                except (OSError, ValueError) as exc:
                    captured.append(dict(item, captureFailure=str(exc)))
        epoch = {'index': len(epochs), 'stopOrdinal': stops, 'mappingMutation': mutation,
                 'maps': rows, 'objects': captured}
        encoded=json.dumps(epoch,sort_keys=True).encode('utf-8');map_bytes+=len(encoded)
        if map_bytes>64*1024*1024:raise ValueError('PROCESS_IDENTITY_MAP_METADATA_BUDGET_EXCEEDED')
        path = root/'maps'/('%06d.json' % len(epochs)); path.write_bytes(encoded)
        epochs.append({'path': str(path.relative_to(root)), 'digest': digest(path)})
        if entry_probe is not None:entry_probe.mapped(pid,ptrace,epoch,root,stops)
    try:
        status = wait()
        if os.WIFEXITED(status) or os.WIFSIGNALED(status): reaped = True
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise ValueError('PROCESS_IDENTITY_TRACEME_UNAVAILABLE')
        # TRACESYSGOOD | TRACEEXEC | EXITKILL, available on the supported Linux scope.
        ptrace(0x4200, pid, 0, 1|16|0x100000)
        ptrace(24, pid)  # SYSCALL
        while True:
            status = wait()
            if os.WIFEXITED(status): code = os.WEXITSTATUS(status); reaped = True; break
            if os.WIFSIGNALED(status): code = -os.WTERMSIG(status); reaped = True; break
            stops += 1
            if stops > stop_limit: raise ValueError('PROCESS_IDENTITY_STOP_BUDGET_EXCEEDED')
            if (root/'stdout.log').stat().st_size+(root/'stderr.log').stat().st_size > log_limit:
                raise ValueError('PROCESS_IDENTITY_LOG_BUDGET_EXCEEDED')
            sig = os.WSTOPSIG(status); event = status >> 16
            if event == 4:
                if executed: raise ValueError('PROCESS_IDENTITY_REEXEC_UNSUPPORTED')
                executed = True; mappings({'kind':'exec'})
            elif sig == signal.SIGTRAP|0x80:
                regs = Registers(); ptrace(12, pid, 0, ctypes.byref(regs))
                info=SyscallInfo()
                try:
                    returned=ptrace(0x420e,pid,ctypes.sizeof(info),ctypes.byref(info))
                except OSError as exc:
                    raise ValueError('PROCESS_IDENTITY_SYSCALL_INFO_UNAVAILABLE') from exc
                if info.arch != 0xc000003e or info.op not in (1,2) or returned < (80 if info.op==1 else 33):
                    raise ValueError('PROCESS_IDENTITY_SYSCALL_ABI_OR_PHASE_UNSUPPORTED')
                number = regs.orig_rax
                if number & 0x40000000:
                    raise ValueError('PROCESS_IDENTITY_X32_ABI_UNSUPPORTED')
                if info.op == 1:
                    if executed and number in (56, 57, 58, 435):
                        raise ValueError('PROCESS_IDENTITY_MULTIPROCESS_UNSUPPORTED')
                    # shmat/shmdt/remap_file_pages/pkey_mprotect can change
                    # mapping state outside the four recorded transitions.
                    # Reject rather than silently reusing a stale epoch.
                    if executed and number in (30, 67, 216, 329):
                        raise ValueError('PROCESS_IDENTITY_MAPPING_SYSCALL_UNSUPPORTED:'+str(number))
                    if executed and ((number == 3 and regs.rdi == 2)
                            or (number in (33, 292) and regs.rsi == 2)
                            or (number == 436 and regs.rdi <= 2 <= regs.rsi)):
                        raise ValueError('PROCESS_IDENTITY_STDERR_REBIND_UNSUPPORTED')
                    pending = {'number': number, 'write': executed and number in (1, 20) and regs.rdi == 2,
                               'arguments':[regs.rdi,regs.rsi,regs.rdx,regs.r10,regs.r8,regs.r9],
                               'offset': (root/'stderr.log').stat().st_size,
                               'epoch': len(epochs)-1}
                else:
                    result = ctypes.c_longlong(regs.rax).value
                    if executed and pending is not None:
                        if pending['write'] and result > 0:
                            with (root/'stderr.log').open('rb') as stream:
                                stream.seek(pending['offset']); written = stream.read(result)
                            if len(written) != result:
                                raise ValueError('PROCESS_IDENTITY_WRITE_BYTES_MISMATCH')
                            headers = binding_stream.feed(written)
                            aliases = binding_aliases(headers, pid, cache)
                            alias_bytes += len(json.dumps([headers,aliases]).encode('utf-8'))
                            if alias_bytes > 64*1024*1024:
                                raise ValueError('PROCESS_IDENTITY_ALIAS_METADATA_BUDGET_EXCEEDED')
                            writes.append({'offset': pending['offset'], 'size': result,
                                           'epoch': pending['epoch'], 'stopOrdinal': stops,
                                           'bindingAliases': aliases, 'bindingHeaders':headers})
                        if pending['number'] in (9, 10, 11, 25) and result >= 0:
                            mappings({'kind':'syscall','number':pending['number'],
                                      'arguments':pending['arguments'],'returnValue':result})
                    pending = None
            elif sig==signal.SIGTRAP and entry_probe is not None:
                regs=Registers();ptrace(12,pid,0,ctypes.byref(regs))
                if not entry_probe.trapped(pid,ptrace,regs,len(epochs)-1,stops):
                    raise ValueError('ENTRY_PROBE_UNEXPECTED_TRAP')
            elif sig not in (signal.SIGSTOP,):
                ptrace(24, pid, 0, sig); continue
            ptrace(24, pid)
        if not executed: raise ValueError('PROCESS_IDENTITY_EXEC_NOT_OBSERVED')
        if (root/'stdout.log').stat().st_size+(root/'stderr.log').stat().st_size > log_limit:
            raise ValueError('PROCESS_IDENTITY_LOG_BUDGET_EXCEEDED')
    except (OSError, ValueError, TimeoutError) as exc:
        failure = str(exc)
    finally:
        if not reaped:
            try: os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
            try: os.waitpid(pid, 0)
            except ChildProcessError: pass
    result = seal({'schemaVersion': 'riscv2x86.process-map-capture.v3',
        'backend': ('linux-x86_64-ptrace-syscall-single-process.v1' if entry_probe is None else
                    'linux-x86_64-ptrace-single-shot-function-entry.v1'),
        'syscallPhaseSource':'PTRACE_GET_SYSCALL_INFO',
        'processId': pid, 'arguments': list(argv), 'directory': str(Path(cwd).resolve()),
        'environment': dict(environment), 'timeoutSeconds': timeout, 'returnCode': code,
        'logLimit':log_limit,'imageLimit':image_limit,'stopLimit':stop_limit,'stopCount':stops,
        'failureReason': failure, 'epochs': epochs, 'stderrWrites': writes,
        **({'entryProbeEvidence':entry_probe.evidence()} if entry_probe is not None else {}),
        'stdoutDigest': digest(root/'stdout.log'), 'stderrDigest': digest(root/'stderr.log'),
        'intervention': 'ptrace', 'untracedRunEquivalenceVerified': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False}, 'processCaptureIdentity')
    (root/'capture.json').write_text(json.dumps(result, indent=2)+'\n')
    if failure is not None: raise ValueError(failure)
    return result
