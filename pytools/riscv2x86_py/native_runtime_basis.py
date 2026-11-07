"""Read-only compiler/runtime file inventory, not symbol resolution or acceptance."""
from pathlib import Path
import os
import subprocess

from .project_compile_context import digest
from .project_build_records import identity
from .project_tool_resolution import resolve_executable


def collect(compilers, libraries, files, readelf):
    """Keep full tool output so versions, symbols and loader metadata are inspectable.

    Compiler queries locate candidates only. Never interpret linker scripts or
    infer the library actually selected by a link/load from this inventory.
    """
    inspector = str(resolve_executable(readelf))
    snapshots = {}; aliases = {}; commands = []; candidates = []; blockers = []

    def bind(path):
        lexical = str(Path(path).absolute())
        path = str(Path(path).resolve(strict=True))
        if lexical in aliases and aliases[lexical] != path:
            raise ValueError('RUNTIME_BASIS_PATH_CHANGED')
        aliases[lexical] = path
        value = digest(path)
        if path in snapshots and snapshots[path] != value:
            raise ValueError('RUNTIME_BASIS_FILE_CHANGED:' + path)
        snapshots[path] = value
        return path

    def command(argv):
        bind(argv[0])
        result = subprocess.run(argv,capture_output=True,text=True,timeout=60,
                                env=dict(os.environ,LC_ALL='C'))
        row = {'arguments':argv,'returnCode':result.returncode,
               'stdout':result.stdout,'stderr':result.stderr}
        commands.append(row)
        if result.returncode:
            blockers.append({'reason':'RUNTIME_BASIS_COMMAND_FAILED','commandIndex':len(commands)-1})
        return result

    command([inspector,'--version'])
    for compiler in compilers:
        executable = str(resolve_executable(compiler))
        command([executable,'--version']);command([executable,'-dumpmachine'])
        command([executable,'-print-sysroot'])
        for library in libraries:
            if not library or library.startswith('-') or '/' in library:
                raise ValueError('RUNTIME_LIBRARY_BASENAME_REQUIRED')
            result = command([executable,'-print-file-name='+library])
            requested = result.stdout.strip()
            if result.returncode or not Path(requested).is_absolute():
                blockers.append({'reason':'RUNTIME_LIBRARY_QUERY_UNRESOLVED',
                                 'compiler':executable,'library':library,'result':requested})
                continue
            candidates.append({'compiler':executable,'query':library,'path':requested})
    candidates.extend({'path':str(Path(p).absolute()),'query':'explicit-file'} for p in files)
    for row in candidates:
        path = Path(row['path'])
        try:
            resolved = bind(path)
        except (OSError,ValueError) as exc:
            row.update(status='unavailable',detail=str(exc))
            blockers.append({'reason':'RUNTIME_CANDIDATE_UNAVAILABLE','path':str(path)})
            continue
        row.update(resolvedPath=resolved,digest=snapshots[resolved])
        with Path(resolved).open('rb') as stream:header=stream.read(4)
        if header != b'\x7fELF':
            row['status']='uninterpreted-non-ELF'
            blockers.append({'reason':'RUNTIME_NON_ELF_CONTRACT_REQUIRED','path':str(path)})
            continue
        row['status']='ELF-inspected'
        row['commandIndex']=len(commands)
        command([inspector,'--wide','--file-header','--program-headers','--dynamic',
                 '--dyn-syms','--version-info',resolved])
        if str(path.resolve(strict=True)) != resolved:
            raise ValueError('RUNTIME_BASIS_PATH_CHANGED')
    for lexical,resolved in aliases.items():
        if str(Path(lexical).resolve(strict=True)) != resolved:
            raise ValueError('RUNTIME_BASIS_PATH_CHANGED')
    for path,expected in snapshots.items():
        if digest(path) != expected:raise ValueError('RUNTIME_BASIS_CLOSING_FILE_CHANGED:'+path)
    body={'schemaVersion':'riscv2x86.native-runtime-provider-basis.v1',
          'commands':commands,'candidates':candidates,'blockers':blockers,
          'fileDigests':snapshots,'actualLinkSelectionVerified':False,
          'runtimeLibrarySelectionVerified':False,'typedCallContractVerified':False,
          'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,basisIdentity=identity(body))
