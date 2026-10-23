"""Bounded, probed compiler/assembler/linker configurations for M-mode builds.

Capability records never approve translation. Each candidate retains linker
no-relaxation, the reviewed boot's local gp protection, and final ELF checks.
Assembler relaxation metadata is not a claim that a final image was relaxed.
"""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

from .semantic_content import semantic_identity
from .system_instruction_ingress import digest

SCHEMA = 'riscv2x86.system-build-profile.v2'
POLICY = 'rv64i-lp64-bare-no-relax.v3'
OPTIMIZATIONS = ('-O0', '-O2', '-O3')
RELAX_FLAGS = {
    'driver-norelax': ('-mno-relax', '-Wl,--no-relax'),
    'assembler-norelax': ('-Wa,-mno-relax', '-Wl,--no-relax'),
    # Older assemblers accept .option norelax in the reviewed boot but do not
    # expose -mno-relax. Keep linker relaxation disabled; never retry an actual
    # production build with fewer flags. Select only after the full matrix.
    'linker-norelax': ('-Wl,--no-relax',),
}


def check_build_implementation(value):
    """Bind every strategy to the reviewed boot/kernel/linker implementation.

    In particular linker-norelax relies on the boot's .option norelax around
    gp initialization. The source review, full builds and final gp check are
    complementary obligations, not replaceable by a caller-supplied hash.
    """
    from .controlled_system_backend import FILES, ROOT, implementation_identity
    if (value['implementationIdentity'] != implementation_identity()
            or value['sourceMarch'] not in ('rv64i', 'rv64i_zicsr')):
        raise ValueError('SYSTEM_BUILD_IMPLEMENTATION_POLICY_MISMATCH')
    implementation = Path(value['implementationDirectory'])
    if any((implementation/name).read_bytes() != (ROOT/name).read_bytes() for name in FILES):
        raise ValueError('SYSTEM_BUILD_IMPLEMENTATION_COPY_CHANGED')


class SystemBuildError(ValueError):
    def __init__(self, reason, diagnostic):
        self.reason = reason
        self.diagnostic = diagnostic
        super().__init__(reason + ':' + json.dumps(diagnostic, sort_keys=True))


def run_command(command, *, log=None, timeout=120, cwd=None):
    record = {'command': [str(x) for x in command], 'cwd': str(Path(cwd or Path.cwd()).resolve()), 'returnCode': None,
              'timedOut': False, 'stdout': '', 'stderr': ''}
    try:
        result = subprocess.run(record['command'], capture_output=True, text=True,
                                timeout=timeout, check=False, cwd=cwd)
        record.update(returnCode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired as exc:
        def text(x): return x.decode(errors='replace') if isinstance(x, bytes) else x or ''
        record.update(timedOut=True, stdout=text(exc.stdout), stderr=text(exc.stderr))
    except OSError as exc:
        record['stderr'] = str(exc)
    if log is not None:
        log = Path(log)
        log.write_text(record['stdout'] + record['stderr'])
        log.with_suffix(log.suffix + '.json').write_text(json.dumps(record, indent=2) + '\n')
    if record['returnCode'] != 0:
        raise SystemBuildError('SYSTEM_BUILD_COMMAND_FAILED', record)
    return record


def _tool(path):
    resolved = shutil.which(str(path))
    if resolved is None:
        raise ValueError('SYSTEM_BUILD_TOOL_UNAVAILABLE:' + str(path))
    actual = Path(resolved).resolve()
    return {'path': str(actual), 'digest': digest(actual.read_bytes())}


def toolchain(compiler):
    compiler = str(Path(compiler).resolve())
    tools = {'driver': _tool(compiler)}
    # These are selected by the driver, not guessed from a target prefix.
    for name in ('cc1', 'as', 'ld', 'collect2'):
        selected = run_command([compiler, '-print-prog-name=' + name])['stdout'].strip()
        tools[name] = _tool(selected)
    specs = run_command([compiler, '-dumpspecs'])['stdout']
    inputs = {}
    for name in ('specs','libgcc.a','crtbegin.o','crtend.o','crt1.o','crti.o','crtn.o','libc.so'):
        selected = run_command([compiler, '-print-file-name=' + name])['stdout'].strip()
        path = Path(selected)
        inputs[name] = ({'path':str(path.resolve()),'digest':digest(path.read_bytes())}
                        if path.is_file() else None)
    return {'tools': tools, 'inputs': inputs, 'specsDigest': digest(specs.encode()),
            'target': run_command([compiler, '-dumpmachine'])['stdout'].strip(),
            'version': run_command([compiler, '--version'])['stdout']}


def compiler_environment():
    # A changed search environment requires reprobe even when driver bytes match.
    return {k: os.environ.get(k, '') for k in (
        'PATH', 'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH',
        'CPATH', 'C_INCLUDE_PATH', 'LD_LIBRARY_PATH', 'LD_PRELOAD')}


def program_command(value, *, side, source, symbol, operation, output,
                    optimization, relax_mode):
    if side not in ('source', 'target') or operation not in ('ecall', 'wfi') or optimization not in OPTIMIZATIONS:
        raise ValueError('SYSTEM_BUILD_PROFILE_INVALID')
    if relax_mode not in RELAX_FLAGS:
        raise ValueError('SYSTEM_BUILD_RELAX_POLICY_INVALID')
    output = Path(output).resolve(); source = Path(source).resolve()
    impl = Path(value['implementationDirectory']).resolve()
    workspace = output.parent / (output.name + '.build')
    number = 1 if operation == 'ecall' else 2
    text = '#include ' + json.dumps(str(source)) + '\n'
    if side == 'source':
        text += 'void __rv2x86_probe(void){' + symbol + '();}\n'
        flags = ['-std=gnu11', optimization, '-Wall', '-Wextra', '-Werror',
            '-march=' + value['sourceMarch'], '-mabi=lp64', '-mcmodel=medany',
            *RELAX_FLAGS[relax_mode], '-msmall-data-limit=0',
            '-ffreestanding', '-fno-builtin', '-fno-inline', '-fno-pic', '-fno-pie', '-fno-stack-protector',
            '-fno-asynchronous-unwind-tables', '-nostdlib', '-nostartfiles', '-static',
            '-D__RV2X86_OPERATION=' + str(number)]
        inputs = [('wrapper', 'system-wrapper.c'), ('kernel', str(impl/'controlled_system_kernel.c')),
                  ('boot', str(impl/'controlled_system_boot.S'))]
        link_inputs = ['wrapper.o', 'kernel.o', 'boot.o', '-Wl,-T,' + str(impl/'controlled_system.ld')]
    else:
        text += '#include "controlled_system.h"\nint main(void){__rv2x86_system_initialize(' + str(number) + ');'
        text += '__rv2x86_system_event(' + str(1 if number == 1 else 4) + ');' + symbol + '();'
        text += '__rv2x86_system_event(' + str(3 if number == 1 else 5) + ');__rv2x86_system_finish();return 0;}\n'
        flags = ['-std=gnu11', optimization, '-Wall', '-Wextra', '-Werror', '-fno-inline',
                 '-I', str(impl), '-include', str(impl/'controlled_system.h')]
        inputs = [('wrapper', 'system-wrapper.c')]
        link_inputs = ['wrapper.o', str(Path(value['runtimeLibrary']).resolve())]
    compiler = value[side+'Compiler']
    # A relative object basename at link time is essential: a full random work
    # path can become STT_FILE even when the object's basename is stable.
    steps = [{'stage':'compile-'+name, 'cwd':str(workspace),
              'command':[compiler, *[f for f in flags if not f.startswith('-Wl,')],
                         '-c', source_file, '-o', name+'.o'], 'output':name+'.o',
              'inputs':[source_file] + ([str(source)] if name=='wrapper' else [])
                  + ([str(impl/'controlled_system.h')] if side=='target' else [])}
             for name, source_file in inputs]
    steps.append({'stage':'link', 'cwd':str(workspace),
                  'command':[compiler, *flags, *link_inputs, '-Wl,--build-id=none', '-o', str(output)],
                  'output':str(output), 'inputs':([name+'.o' for name,_ in inputs]
                      + [str(impl/'controlled_system.ld')] if side=='source'
                      else ['wrapper.o',str(Path(value['runtimeLibrary']).resolve())])})
    return text, steps


def inspect_elf(path, side):
    """Check ELF64 LE and the pinned bare boot/link contract, without readelf text parsing."""
    data = Path(path).read_bytes()
    try:
        if data[:6] != b'\x7fELF\x02\x01' or len(data) < 64:
            raise ValueError('format')
        kind, machine = struct.unpack_from('<HH', data, 16)
        entry, phoff, shoff = struct.unpack_from('<QQQ', data, 24)
        flags = struct.unpack_from('<I', data, 48)[0]
        _, phsize, phnum, shsize, shnum, _ = struct.unpack_from('<HHHHHH', data, 52)
        if machine != (243 if side == 'source' else 62) or kind not in ((2,) if side == 'source' else (2, 3)):
            raise ValueError('architecture-or-kind')
        if phsize != 56 or not phnum or phoff + phnum*phsize > len(data):
            raise ValueError('program-headers')
        programs = [struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize) for i in range(phnum)]
        loads = [p for p in programs if p[0] == 1]
        if not loads or not any(p[1]&1 and p[3] <= entry < p[3]+p[6] for p in loads):
            raise ValueError('entry-not-executable')
        for p in loads:
            if p[5] > p[6] or p[2]+p[5] > len(data): raise ValueError('load-bounds')
        checks = {'elfClass': 64, 'littleEndian': True, 'machine': machine, 'type': kind, 'entry': entry}
        if side == 'source':
            if kind != 2 or flags != 0 or entry != 0x80000000 or any(p[0] in (2,3) for p in programs):
                raise ValueError('bare-lp64-entry-or-dynamic')
            if any(p[3] != p[4] or p[3] < 0x80000000 or p[3]+p[6] > 0x82000000 for p in loads):
                raise ValueError('bare-load-address')
            if shsize != 64 or not shnum or shoff+shnum*shsize > len(data): raise ValueError('section-headers')
            sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(shnum)]
            symbols = {}
            for section in sections:
                if section[1] != 2: continue
                if section[9] != 24 or section[5]%24 or section[4]+section[5] > len(data): raise ValueError('symbols')
                strings_section = sections[section[6]]
                strings = data[strings_section[4]:strings_section[4]+strings_section[5]]
                for offset in range(section[4], section[4]+section[5], 24):
                    name, _, _, index, address, _ = struct.unpack_from('<IBBHQQ', data, offset)
                    if name >= len(strings): raise ValueError('symbol-name')
                    name = strings[name:].split(b'\0',1)[0].decode('ascii')
                    if name and index == 0: raise ValueError('undefined-symbol:' + name)
                    if name: symbols[name] = address
            required = ('_start','__global_pointer$','__bss_start','__bss_end','__stack_top','__rv2x86_trap','__rv2x86_probe')
            if any(n not in symbols for n in required): raise ValueError('boot-symbols')
            start, end, stack = (symbols[n] for n in ('__bss_start','__bss_end','__stack_top'))
            if symbols['_start'] != entry or not 0x80000000 <= start <= end < stack <= 0x82000000:
                raise ValueError('boot-layout')
            if start%8 or end%16 or stack%16 or stack-end != 0x10000: raise ValueError('boot-alignment')
            # gp initialization must remain AUIPC gp + ADDI gp,gp,imm, and
            # resolve to the symbol. This detects a relaxed/incorrect boot pair.
            p = next(p for p in loads if p[3] <= entry < p[3]+p[5])
            offset = p[2]+entry-p[3]
            first, second = struct.unpack_from('<II', data, offset)
            def signed(x, bits): return x-(1<<bits) if x & (1<<(bits-1)) else x
            if first & 0xfff != 0x197 or second & 0xfffff != 0x18193:
                raise ValueError('gp-init-instructions')
            if entry + signed(first & 0xfffff000,32) + signed(second>>20,12) != symbols['__global_pointer$']:
                raise ValueError('gp-init-address')
            checks.update(symbols={n:symbols[n] for n in required}, noDynamicLoader=True,
                          lp64SoftFloat=True, gpInitialization='auipc-addi-to-symbol')
        return checks
    except (ValueError, struct.error, IndexError, UnicodeError, StopIteration) as exc:
        raise ValueError('SYSTEM_PROGRAM_ELF_CONTRACT_INVALID:' + str(exc)) from exc


def compile_program(value, *, side, source, symbol, operation, output, optimization, relax_mode):
    output = Path(output).resolve()
    if output.exists(): raise ValueError('SYSTEM_PROGRAM_OUTPUT_EXISTS')
    output.parent.mkdir(parents=True, exist_ok=True)
    text, plan = program_command(value, side=side, source=source, symbol=symbol,
        operation=operation, output=output, optimization=optimization, relax_mode=relax_mode)
    workspace = Path(plan[0]['cwd'])
    workspace.mkdir()  # Never reuse or overwrite retained build evidence.
    wrapper = workspace/'system-wrapper.c'; wrapper.write_text(text)
    log = output.with_name(output.name + '.build.log')
    steps = []; stage = 'compile-link'; command = plan[0]['command']
    try:
        for item in plan:
            command = item['command']
            stage_log = workspace/(item['stage']+'.log')
            input_digests = {name:digest((workspace/name).read_bytes()) for name in item['inputs']}
            result = run_command(command, cwd=workspace, log=stage_log)
            product = workspace/item['output']
            if not product.is_file(): raise ValueError('SYSTEM_BUILD_STAGE_OUTPUT_MISSING:'+item['stage'])
            steps.append(dict(item, returnCode=result['returnCode'], outputDigest=digest(product.read_bytes()),
                              inputDigests=input_digests,
                              stdout=result['stdout'], stderr=result['stderr'], timedOut=result['timedOut']))
        stage = 'elf-inspection'
        checks = inspect_elf(output, side)
    except (ValueError, OSError) as exc:
        diagnostic = {'side':side, 'operation':operation, 'optimization':optimization,
            'output':str(output), 'logPath':str(log), 'outputExists':output.exists(),
            'workspace':str(workspace), 'steps':steps, 'command':command, 'stage':stage,
            'returnCode':0 if stage=='elf-inspection' else getattr(exc,'diagnostic',{}).get('returnCode'),
            'cause':getattr(exc,'diagnostic',str(exc))}
        log.write_text(json.dumps(diagnostic,indent=2)+'\n')
        log.with_name(log.name+'.failure.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
        raise SystemBuildError('SYSTEM_PROGRAM_BUILD_FAILED', diagnostic) from exc
    record = {'schemaVersion':'riscv2x86.system-program-build.v2',
        'programDigest':digest(output.read_bytes()), 'command':plan[-1]['command'], 'steps':steps,
        'workspace':str(workspace), 'wrapperDigest':digest(wrapper.read_bytes()),
        'sourceDigest':digest(Path(source).read_bytes()), 'sourcePath':str(Path(source).resolve()),
        'programPath':str(output), 'side':side,
        'optimization':optimization, 'operation':operation, 'elfChecks':checks,
        'returnCode':0, 'relaxMode':relax_mode}
    log.write_text(''.join(r['stage']+': '+r['stdout']+r['stderr']+'\n' for r in steps))
    log.with_suffix(log.suffix+'.json').write_text(json.dumps(record,indent=2)+'\n')
    output.with_name(output.name+'.build.json').write_text(json.dumps(record,indent=2)+'\n')
    return record


def elf_difference_regions(first, second):
    """Diagnostic only: no section or segment difference is ever waived."""
    def regions(data):
        if data[:6]!=b'\x7fELF\x02\x01': raise ValueError('ELF64-LE-required')
        phoff,shoff=struct.unpack_from('<QQ',data,32)
        phsize,phnum,shsize,shnum,strings_index=struct.unpack_from('<HHHHH',data,54)
        if phsize!=56 or shsize!=64 or phoff+phnum*56>len(data) or shoff+shnum*64>len(data):
            raise ValueError('ELF-header-bounds')
        sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*64) for i in range(shnum)]
        names=sections[strings_index]
        strings=data[names[4]:names[4]+names[5]]
        result=[]
        for i,x in enumerate(sections):
            if x[1]!=8 and x[4]+x[5]>len(data): raise ValueError('ELF-section-bounds')
            name=strings[x[0]:].split(b'\0',1)[0].decode('utf-8',errors='replace')
            result.append({'index':i,'name':name,'type':x[1],'flags':x[2],'address':x[3],
                'offset':x[4],'size':x[5],'digest':None if x[1]==8 else digest(data[x[4]:x[4]+x[5]])})
        loads=[]
        for i in range(phnum):
            p=struct.unpack_from('<IIQQQQQQ',data,phoff+i*56)
            if p[0]==1:
                if p[2]+p[5]>len(data):raise ValueError('ELF-load-bounds')
                loads.append({'header':list(p),'digest':digest(data[p[2]:p[2]+p[5]])})
        return result,loads
    try:
        a,la=regions(first);b,lb=regions(second)
        changed=[{'original':a[i] if i<len(a) else None,'rebuilt':b[i] if i<len(b) else None}
                 for i in range(max(len(a),len(b))) if i>=len(a) or i>=len(b) or a[i]!=b[i]]
        return {'changedSections':changed,'loadSegmentsEqual':la==lb}
    except (ValueError,IndexError,struct.error) as exc:
        return {'inspectionError':str(exc)}


def require_identical_rebuild(original, rebuilt, *, reason):
    """Keep full-byte identity mandatory; a difference report never grants permission."""
    first = Path(original['path']); second = Path(rebuilt['programPath'])
    a = first.read_bytes(); b = second.read_bytes()
    if digest(a) == original['digest'] == digest(b): return
    evidence = second.parent/'rebuild-mismatch'; evidence.mkdir()
    (evidence/'original.elf').write_bytes(a); (evidence/'rebuilt.elf').write_bytes(b)
    offset = next((i for i,(x,y) in enumerate(zip(a,b)) if x!=y), min(len(a),len(b)))
    diagnostic = {'reasonCode':reason, 'originalPath':str(first), 'rebuiltPath':str(second),
        'expectedDigest':original['digest'], 'originalDigest':digest(a), 'rebuiltDigest':digest(b),
        'originalSize':len(a), 'rebuiltSize':len(b), 'firstDifferenceOffset':offset,
        'originalBytes':a[offset:offset+32].hex(), 'rebuiltBytes':b[offset:offset+32].hex(),
        'buildRecord':rebuilt, 'evidenceDirectory':str(evidence),
        'elfDifference':elf_difference_regions(a,b)}
    (evidence/'comparison.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
    raise SystemBuildError(reason, diagnostic)


def probe_source_text(operation, side):
    if operation not in ('ecall','wfi') or side not in ('source','target'):
        raise ValueError('SYSTEM_BUILD_PROBE_INVALID')
    if side == 'source':
        return 'void probe(void){__asm__ volatile("'+operation+'" ::: "memory");}\n'
    return 'void probe(void){'+('rv2x86_m_ecall_v1' if operation=='ecall' else 'rv2x86_m_wfi_pending_v1')+'();}\n'


def probe_profile(value, output):
    output = Path(output); output.mkdir(parents=True,exist_ok=True)
    check_build_implementation(value)
    tools = {side:toolchain(value[side+'Compiler']) for side in ('source','target')}
    attempts = []
    for mode in RELAX_FLAGS:
        records = []
        try:
            for operation in ('ecall','wfi'):
                source = output/(mode+'-'+operation+'.c')
                source.write_text(probe_source_text(operation,'source'))
                target = output/(mode+'-'+operation+'-target.c')
                target.write_text(probe_source_text(operation,'target'))
                for opt in OPTIMIZATIONS:
                    for side in ('source','target'):
                        path=output/mode/operation/opt[1:]/side/'program.elf'
                        record=compile_program(value,side=side,source=source if side=='source' else target,
                            symbol='probe',operation=operation,output=path,optimization=opt,relax_mode=mode)
                        repeated=compile_program(value,side=side,source=source if side=='source' else target,
                            symbol='probe',operation=operation,output=path.parent/'repeat'/'program.elf',
                            optimization=opt,relax_mode=mode)
                        require_identical_rebuild({'path':record['programPath'],'digest':record['programDigest']},
                            repeated,reason='SYSTEM_BUILD_PROFILE_REPRODUCTION_MISMATCH:'+side)
                        record['reproduction']=repeated
                        records.append(record)
        except (ValueError,OSError) as exc:
            attempts.append({'relaxMode':mode,'failure':getattr(exc,'diagnostic',str(exc))})
            (output/'probe-attempts.json').write_text(json.dumps(attempts,indent=2)+'\n')
            continue
        value = {'schemaVersion':SCHEMA,'policy':POLICY,'relaxMode':mode,
            'sourceMarch':value['sourceMarch'],'implementationIdentity':value['implementationIdentity'],
            'toolchains':tools,'searchEnvironment':compiler_environment(), 'records':records,
            'recipeDigest':digest(Path(__file__).read_bytes())}
        value['profileIdentity']=semantic_identity(value)
        (output/'profile.json').write_text(json.dumps(value,indent=2)+'\n')
        return value
    raise SystemBuildError('SYSTEM_BUILD_PROFILE_UNAVAILABLE', {'attempts':attempts,'output':str(output)})


def _validate_profile(profile, value):
    fields={'schemaVersion','policy','relaxMode','sourceMarch','implementationIdentity','toolchains',
            'searchEnvironment','records','profileIdentity','recipeDigest'}
    if not isinstance(profile,dict) or set(profile)!=fields or profile['schemaVersion']!=SCHEMA or profile['policy']!=POLICY:
        raise ValueError('SYSTEM_BUILD_PROFILE_SCHEMA_INVALID')
    if profile['profileIdentity']!=semantic_identity({k:v for k,v in profile.items() if k!='profileIdentity'}):
        raise ValueError('SYSTEM_BUILD_PROFILE_IDENTITY_MISMATCH')
    if profile['recipeDigest']!=digest(Path(__file__).read_bytes()): raise ValueError('SYSTEM_BUILD_RECIPE_CHANGED:reprobe-required')
    if profile['relaxMode'] not in RELAX_FLAGS or profile['sourceMarch']!=value['sourceMarch'] or profile['implementationIdentity']!=value['implementationIdentity']:
        raise ValueError('SYSTEM_BUILD_PROFILE_POLICY_MISMATCH')
    check_build_implementation(value)
    if profile['searchEnvironment']!=compiler_environment(): raise ValueError('SYSTEM_BUILD_SEARCH_ENVIRONMENT_CHANGED:reprobe-required')
    for side in ('source','target'):
        if profile['toolchains'][side]!=toolchain(value[side+'Compiler']):
            raise ValueError('SYSTEM_BUILD_TOOLCHAIN_CHANGED:'+side)
    expected={(s,o,opt) for s in ('source','target') for o in ('ecall','wfi') for opt in OPTIMIZATIONS}
    records=profile['records']
    if not isinstance(records,list) or len(records)!=len(expected) or {(r['side'],r['operation'],r['optimization']) for r in records}!=expected:
        raise ValueError('SYSTEM_BUILD_PROFILE_MATRIX_INCOMPLETE')
    for r in records:
        validate_build_record(r, value, profile['relaxMode'])
        repeated=r['reproduction']
        if any(repeated[k]!=r[k] for k in ('side','operation','optimization','sourcePath','sourceDigest','programDigest')):
            raise ValueError('SYSTEM_BUILD_PROFILE_REPRODUCTION_MISMATCH')
        if Path(repeated['programPath'])!=Path(r['programPath']).parent/'repeat'/'program.elf':
            raise ValueError('SYSTEM_BUILD_PROFILE_REPRODUCTION_PATH_INVALID')
        validate_build_record(repeated, value, profile['relaxMode'])


def validate_build_record(r, value, mode):
    if r['schemaVersion']!='riscv2x86.system-program-build.v2' or r['returnCode']!=0 or r['relaxMode']!=mode:
        raise ValueError('SYSTEM_BUILD_PROFILE_MATRIX_FAILED')
    source=Path(r['sourcePath']); program=Path(r['programPath'])
    if source.read_text()!=probe_source_text(r['operation'],r['side']) or digest(source.read_bytes())!=r['sourceDigest']:
        raise ValueError('SYSTEM_BUILD_PROFILE_PROBE_CHANGED')
    text, plan=program_command(value,side=r['side'],source=source,symbol='probe',operation=r['operation'],
        output=program,optimization=r['optimization'],relax_mode=mode)
    if (r['command']!=plan[-1]['command'] or r['workspace']!=plan[0]['cwd']
            or len(r['steps'])!=len(plan)):
        raise ValueError('SYSTEM_BUILD_PROFILE_COMMAND_CHANGED')
    wrapper=Path(r['workspace'])/'system-wrapper.c'
    if wrapper.read_text()!=text or digest(wrapper.read_bytes())!=r['wrapperDigest']:
        raise ValueError('SYSTEM_BUILD_PROFILE_WRAPPER_CHANGED')
    for actual, expected in zip(r['steps'],plan):
        if (any(actual[k]!=v for k,v in expected.items()) or actual['returnCode']!=0
                or actual['timedOut'] is not False):
            raise ValueError('SYSTEM_BUILD_PROFILE_STAGE_CHANGED')
        product=Path(actual['cwd'])/actual['output']
        if actual['inputDigests']!={name:digest((Path(actual['cwd'])/name).read_bytes()) for name in expected['inputs']}:
            raise ValueError('SYSTEM_BUILD_PROFILE_INPUT_CHANGED')
        if digest(product.read_bytes())!=actual['outputDigest']:
            raise ValueError('SYSTEM_BUILD_PROFILE_OBJECT_CHANGED')
    if digest(program.read_bytes())!=r['programDigest'] or inspect_elf(program,r['side'])!=r['elfChecks']:
        raise ValueError('SYSTEM_BUILD_PROFILE_ARTIFACT_CHANGED')


def validate_profile(profile, value):
    try:
        _validate_profile(profile, value)
    except (KeyError, TypeError, OSError, IndexError) as exc:
        raise ValueError('SYSTEM_BUILD_PROFILE_INPUT_INVALID:' + str(exc)) from exc
