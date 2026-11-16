"""Bounded SLEIGH instruction inventories, not an ABI or execution proof.

Linear decoding covers a sized ELF function's bytes, including unreachable
instructions and padding. P-code facts describe the pinned decoder's model;
they do not establish a complete CFG, input locations, legal accesses or calls.
"""
from collections import Counter
from pathlib import Path
import struct

from .verification_session import measured
from . import native_captured_deployment as d

LANGUAGES = {62: 'x86:LE:64:default', 243: 'RISCV:LE:64:RV64GC'}
MAX_BYTES = 65536
MAX_OPS = 100000


def decoder(machine):
    import importlib
    import pypcode
    if machine not in LANGUAGES: raise ValueError('MACHINE_INVENTORY_ARCHITECTURE_UNSUPPORTED')
    backend = importlib.import_module(pypcode.Context.__mro__[1].__module__)
    language = pypcode.Context(LANGUAGES[machine]).language
    return {'language': LANGUAGES[machine], 'version': pypcode.__version__,
            'extension': d.snapshot(backend.__file__), 'adapter': d.snapshot(pypcode.__file__),
            'sleigh': d.snapshot(language.slafile_path), 'processorSpec': d.snapshot(language.pspec_path)}


def function_region(raw, symbol):
    elf = d.parse(raw)
    if elf['machine'] not in LANGUAGES or elf['elfType'] not in (2, 3):
        raise ValueError('MACHINE_INVENTORY_LINKED_RV64_OR_AMD64_REQUIRED')
    matches = {(s['value'], s['size'], s['sectionIndex']) for s in elf['staticSymbols'] + elf['dynamicSymbols']
               if s['name'] == symbol and s['defined'] and s['type'] == 2 and s['size'] > 0}
    if len(matches) != 1: raise ValueError('MACHINE_INVENTORY_UNIQUE_SIZED_SYMBOL_REQUIRED')
    address, size, section = next(iter(matches))
    if size > MAX_BYTES: raise ValueError('MACHINE_INVENTORY_FUNCTION_BUDGET_EXCEEDED')
    shoff = struct.unpack_from('<Q', raw, 40)[0]; stride, count = struct.unpack_from('<HH', raw, 58)
    if stride != 64 or not 0 < section < count: raise ValueError('MACHINE_INVENTORY_SECTION_REQUIRED')
    _, kind, flags, vaddr, offset, extent, *_ = struct.unpack_from('<IIQQQQIIQQ', raw, shoff + stride * section)
    start = offset + address - vaddr
    if (kind != 1 or not flags & 4 or address < vaddr or address + size > vaddr + extent
            or start < 0 or start + size > len(raw)):
        raise ValueError('MACHINE_INVENTORY_EXECUTABLE_FILE_RANGE_REQUIRED')
    return elf, address, raw[start:start + size]


@measured('program_machine_inventory.derive')
def derive(raw, symbol):
    import pypcode
    elf, address, code = function_region(raw, symbol)
    ctx = pypcode.Context(LANGUAGES[elf['machine']])
    def var(v):
        return {'space': v.space.name, 'offset': v.offset, 'size': v.size,
                'registerName': v.getRegisterName() if v.space.name == 'register' else None}
    cursor = 0; rows = []; total_ops = 0; gaps = []; counts = Counter()
    while cursor < len(code):
        # Neither supported ISA has delay slots. AMD64 instructions are at
        # most 15 bytes and RV64GC instructions at most 4. A bounded window
        # avoids copying the entire remaining function for every instruction.
        window = code[cursor:cursor + 16]
        try:
            translated = ctx.translate(window, base_address=address + cursor,
                                       max_bytes=len(window), max_instructions=1)
        except (pypcode.BadDataError, pypcode.UnimplError, pypcode.LowlevelError):
            gaps.append({'reasonCode': 'MACHINE_INSTRUCTION_DECODE_UNAVAILABLE', 'address': address + cursor})
            break
        ops = list(translated.ops)
        marks = [op for op in ops if op.opcode.name == 'IMARK']
        if (len(marks) != 1 or len(marks[0].inputs) != 1
                or marks[0].inputs[0].offset != address + cursor
                or not 0 < marks[0].inputs[0].size <= min(len(window), 15 if elf['machine'] == 62 else 4)):
            gaps.append({'reasonCode': 'MACHINE_SINGLE_INSTRUCTION_BOUNDARY_UNPROVEN', 'address': address + cursor})
            break
        if total_ops + len(ops) > MAX_OPS:
            gaps.append({'reasonCode': 'MACHINE_PCODE_BUDGET_EXCEEDED', 'address': address + cursor}); break
        size = marks[0].inputs[0].size; semantics = []
        for op in ops:
            name = op.opcode.name
            if name == 'IMARK': continue
            inputs = [{'addressSpace': v.getSpaceFromConst().name} if name in ('LOAD', 'STORE') and i == 0
                      else var(v) for i, v in enumerate(op.inputs)]
            semantics.append({'opcode': name, 'output': var(op.output) if op.output else None, 'inputs': inputs})
            counts[name] += 1
        rows.append({'address': address + cursor, 'size': size, 'bytes': code[cursor:cursor + size].hex(),
                     'structuredPcode': semantics})
        total_ops += len(ops); cursor += size
    memory = []; control = []
    for ins in rows:
        for index, op in enumerate(ins['structuredPcode']):
            ref = {'instructionAddress': ins['address'], 'pcodeIndex': index, **op}
            if op['opcode'] in ('LOAD', 'STORE'): memory.append(ref)
            if op['opcode'] in ('CALL', 'CALLIND', 'BRANCH', 'CBRANCH', 'BRANCHIND', 'RETURN', 'CALLOTHER'):
                control.append(ref)
    return {'functionSymbol': symbol, 'machine': elf['machine'], 'language': LANGUAGES[elf['machine']],
            'virtualAddress': address, 'byteSize': len(code), 'codeDigest': d.identity(code.hex()),
            'decodedByteCount': cursor, 'linearByteDecodeComplete': cursor == len(code),
            'instructions': rows, 'opcodeCounts': dict(sorted(counts.items())),
            'memoryOperations': memory, 'controlOperations': control,
            'relocations': [r for r in elf['relocations'] if address <= r['offset'] < address + len(code)],
            'gaps': gaps, 'controlFlowGraphVerified': False, 'machineAbiClosureVerified': False,
            'legalObjectDomainVerified': False, 'candidateInstructionExecutionCoverageVerified': False,
            'scope': 'linear-sized-function-bytes-and-decoder-pcode-not-reachability-or-program-proof'}


@measured('program_machine_inventory.project_facts')
def project_facts(spec_path, builds):
    """Select symbols from compiler AST owners of exact ORIGINAL edits."""
    from . import native_original_applicability as applicability
    from .compiler_native_instance_binding import _nodes
    spec, ast, records, _, _ = applicability.context(spec_path)
    nodes = {tuple(path): node for node, path, _ in _nodes(ast)}
    owners = {}
    for record in records:
        path = tuple(record['functionAstPath'] or ())
        owners.setdefault(path, []).append(record['instanceBindingIdentity'])
    rows = []; decoders = {}
    for path, instances in sorted(owners.items()):
        node = nodes.get(path, {}); symbol = node.get('mangledName')
        for side in ('source', 'target'):
            build = builds[side]; library = build['library']; obj = build['object']
            for ref in (library, obj): d.verify_snapshot(ref)
            machine = spec['profiles'][side]['machine']
            row = {'side': side, 'functionAstPath': list(path), 'instanceBindingIdentities': instances,
                   'compilerDeclarationIdentity': node.get('id'), 'compilerLinkerName': symbol,
                   'library': library, 'object': obj, 'facts': None, 'reasonCodes': []}
            if node.get('kind') != 'FunctionDecl' or not isinstance(symbol, str) or not symbol:
                row['reasonCodes'].append('COMPILER_EXPLICIT_LINKER_NAME_REQUIRED')
            else:
                object_elf = d.parse(Path(obj['path']).read_bytes())
                definitions = [s for s in object_elf['staticSymbols'] if s['name'] == symbol and s['defined'] and s['type'] == 2]
                if object_elf['machine'] != machine or len(definitions) != 1:
                    row['reasonCodes'].append('OBJECT_FUNCTION_SYMBOL_JOIN_UNAVAILABLE')
                else:
                    try:
                        raw = Path(library['path']).read_bytes()
                        if d.parse(raw)['machine'] != machine: raise ValueError('MACHINE_BUILD_ARCHITECTURE_MISMATCH')
                        row['facts'] = derive(raw, symbol)
                        if not row['facts']['linearByteDecodeComplete']:
                            row['reasonCodes'].append('MACHINE_LINEAR_DECODE_INCOMPLETE')
                        if machine not in decoders: decoders[machine] = decoder(machine)
                    except ValueError as exc:
                        row['reasonCodes'].append(str(exc))
            for ref in (library, obj): d.verify_snapshot(ref)
            rows.append(row)
    return {'schemaVersion': 'riscv2x86.original-project-machine-inventory.v1',
            'projectEvaluationIdentity': spec['projectEvaluationIdentity'],
            'decoders': {str(k): v for k, v in sorted(decoders.items())}, 'functions': rows,
            'machineAbiClosureVerified': False, 'legalObjectDomainVerified': False,
            'canonicalInstructionCoverageVerified': False, 'semanticApproval': False,
            'scope': 'compiler-name-to-current-object-library-symbol-metadata-not-instance-machine-region-map'}


def checked_builds(spec_path, references):
    from . import native_project_evaluation as project
    from .translation_validation import ProgramArtifact
    spec = project.check(spec_path); builds = {}
    if set(references) != {'source', 'target'}: raise ValueError('MACHINE_BOTH_PROJECT_BUILDS_REQUIRED')
    for side, ref in references.items():
        d.verify_snapshot(ref); row = d.read(ref['path']); program = row['program']
        artifact = ProgramArtifact(side, program['path'], 'executable', program['digest'])
        builds[side] = project.build_record(artifact, spec, side)
        expected = Path(program['path']).parent / (Path(program['path']).name + '.project') / 'result.json'
        if d.snapshot(expected) != ref: raise ValueError('MACHINE_PROJECT_BUILD_RECORD_LOCATION_MISMATCH')
    return builds


def acquire(spec_path, builds, output):
    from .native_verifier_manifest import current
    from .project_acquisition import publish_checked
    references = {side: d.snapshot(Path(row['program']['path']).parent /
                   (Path(row['program']['path']).name + '.project') / 'result.json') for side, row in builds.items()}
    checked = checked_builds(spec_path, references)
    if checked != builds: raise ValueError('MACHINE_PROJECT_BUILD_RECORD_MISMATCH')
    value = d.seal({'schemaVersion': 'riscv2x86.original-machine-inventory-evidence.v1',
                    'project': d.snapshot(spec_path), 'builds': references, 'verifier': current(),
                    'facts': project_facts(spec_path, checked), 'semanticApproval': False,
                    'productionAcceptanceComplete': False}, 'machineInventoryIdentity')
    publish_checked(Path(output), value, check)
    return value


@measured('program_machine_inventory.check')
def check(path):
    from .native_verifier_manifest import current, compare
    from .native_external_providers import checked
    value = d.read(path); checked(value, 'machineInventoryIdentity'); compare(value['verifier'], current())
    d.verify_snapshot(value['project'])
    builds = checked_builds(value['project']['path'], value['builds'])
    expected = d.seal({'schemaVersion': 'riscv2x86.original-machine-inventory-evidence.v1',
                       'project': value['project'], 'builds': value['builds'], 'verifier': current(),
                       'facts': project_facts(value['project']['path'], builds), 'semanticApproval': False,
                       'productionAcceptanceComplete': False}, 'machineInventoryIdentity')
    if value != expected: raise ValueError('MACHINE_INVENTORY_REDERIVATION_MISMATCH')
    return value
