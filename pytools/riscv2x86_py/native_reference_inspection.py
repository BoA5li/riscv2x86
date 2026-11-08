"""Automatic, replay-bound source reference diagnostics without semantic approval.

Object paths come from captured producers, never experiment directory ancestry.
Constant witnesses use ELF sections/symbols, not .LC labels or corpus names.
"""
import json
import os
from pathlib import Path
import struct

from .native_captured_deployment import read, seal, snapshot, verify_snapshot
from .native_compiler_configuration import observe
from .native_dependency_inventory import checked_records
from .native_elf_runtime import parse
from .native_experiment_driver import command
from .native_external_providers import checked
from .native_link_attribution import sections
from .native_reference_ledger import acquire as ledger_acquire
from .project_compile_context import derive, digest, ENV_KEYS
from .project_tool_resolution import resolve_executable


def constants(raw):
    elf = parse(raw); table = sections(raw); rows = []
    if elf['elfType'] != 1:
        raise ValueError('REFERENCE_CONSTANT_RELOCATABLE_OBJECT_REQUIRED')
    start = struct.unpack_from('<Q', raw, 40)[0]
    for i, sec in enumerate(table):
        header = struct.unpack_from('<IIQQQQIIQQ', raw, start+i*64)
        sec.update(type=header[1], offset=header[4])
    for relocation in elf['relocations']:
        # These are absolute-address relocations only. PC-relative addends
        # include architecture-specific place biases and are not raw offsets.
        supported = {243: {1, 2, 26, 27, 28}, 62: {1, 10, 11}}
        if relocation['type'] not in supported.get(elf['machine'], set()):
            continue
        matches = [s for s in elf['staticSymbols'] if s['entryIndex'] == relocation['symbolIndex']
                   and s['name'] == relocation['symbol'] and s['defined']]
        if len(matches) != 1:
            continue
        s = matches[0]; index = s['sectionIndex']
        if not 0 < index < len(table):
            continue
        sec = table[index]
        # Read-only allocated PROGBITS; writable data and executable bytes are
        # not silently interpreted as immutable strings.
        if sec['type'] != 1 or sec['flags'] & 7 != 2:
            continue
        offset = s['value']+relocation.get('addend', 0)
        if not 0 <= offset < sec['size']:
            continue
        payload = raw[sec['offset']+offset:sec['offset']+sec['size']]
        end = payload.find(b'\0', 0, 65536)
        if end < 0:
            continue
        data = payload[:end+1]
        rows.append({'reference': relocation, 'symbol': s, 'section': sec['name'],
                     'sectionOffset': offset, 'nulTerminatedBytes': data.hex(),
                     'interpretation': 'bounded-readonly-byte-witness-not-a-C-type-contract'})
    return rows


def acquire(requirements_path, output, objdump, *, timeout=120):
    from .native_deployment_prerequisites import output_path
    root = output_path(output); root.mkdir(); root = root.resolve()
    requirements_path = Path(requirements_path).resolve(strict=True)
    parent = snapshot(requirements_path); req = read(requirements_path); checked(req, 'requirementsIdentity')
    ledger_dir = root/'ledger'; ledger_dir.mkdir()
    ledger = ledger_acquire(requirements_path, ledger_dir)
    (ledger_dir/'result.json').write_text(json.dumps(ledger, indent=2)+'\n')
    provider = read(req['providerPath']); checked(provider, 'inventoryIdentity')
    deps = read(provider['dependencyPath']); checked(deps, 'inventoryIdentity')
    records = checked_records(deps['recordsPath'])
    actions = {a['actionIdentity']: a for a in records['actions']}
    tool = snapshot(resolve_executable(objdump))
    env = {k: os.environ[k] for k in ENV_KEYS if k in os.environ}
    env.update(PATH=env.get('PATH', '/usr/bin:/bin'), LC_ALL='C')
    selected = {}; obligations = []
    for r in req['requirements']:
        producer_ids = [a['actionIdentity'] for a in r['selectedBuildActions']]
        blockers = []
        if len(producer_ids) != 1:
            blockers.append('UNIQUE_CAPTURED_PRODUCER_REQUIRED')
        else:
            key = producer_ids[0]
            if key not in selected:
                action = actions[key]; context = derive(action)
                obj = snapshot(action['observedOutput']['path'])
                if obj['digest'] != r['references']['objectDigest']:
                    raise ValueError('REFERENCE_INSPECTION_OBJECT_VARIANT_MISMATCH')
                folder = root/('object-'+str(len(selected))); folder.mkdir()
                configuration = observe(action, folder/'configuration', timeout)
                commands = []
                def run(stage, argv, cwd):
                    stage_dir = folder/stage; stage_dir.mkdir()
                    code, reason = command(argv, cwd, env, stage_dir, timeout, 64*1024*1024)
                    commands.append({'stage': stage, 'arguments': argv, 'returnCode': code,
                                     'failureReason': reason})
                    if code or reason:
                        raise ValueError('REFERENCE_INSPECTION_COMMAND_FAILED:'+stage)
                run('tool-version', [tool['resolvedPath'], '--version'], str(folder))
                run('disassembly', [tool['resolvedPath'], '-drw', obj['path']], str(folder))
                run('symbols-sections', [tool['resolvedPath'], '-t', '-s', obj['path']], str(folder))
                run('preprocessed-definitions', [context['nativeCompiler'], *context['inspectionArguments'],
                    '-E', '-dD', context['sourcePath']], context['workingDirectory'])
                # Bracket preprocessing with full configuration/dependency validation.
                second = observe(action, folder/'configuration-after', timeout)
                if second != configuration:
                    raise ValueError('REFERENCE_INSPECTION_CONFIGURATION_CHANGED')
                verify_snapshot(obj)
                selected[key] = {'actionIdentity': key, 'object': obj,
                                 'configuration': configuration, 'commands': commands,
                                 'constantWitnesses': constants(Path(obj['path']).read_bytes()),
                                 'machineBehaviorVerified': False, 'compilerAbiVerified': False}
            elif selected[key]['object']['digest'] != r['references']['objectDigest']:
                raise ValueError('REFERENCE_INSPECTION_OBJECT_VARIANT_MISMATCH')
        obligations.append({'obligationIdentity': r['obligationIdentity'], 'producerIdentities': producer_ids,
                            'status': 'unresolved', 'blockers': [*blockers, 'TYPED_BEHAVIOR_PROOF_REQUIRED']})
    ledger_after = root/'ledger-after'; ledger_after.mkdir()
    if ledger_acquire(requirements_path, ledger_after) != ledger:
        raise ValueError('REFERENCE_INSPECTION_LEDGER_CHANGED')
    verify_snapshot(tool); verify_snapshot(parent)
    body = {'schemaVersion': 'riscv2x86.reference-inspection.v1', 'requirements': parent,
            'ledgerIdentity': ledger['ledgerIdentity'], 'objdump': tool,
            'objects': list(selected.values()), 'obligations': obligations,
            'parentObligationCount': ledger['parentObligationCount'], 'referenceCount': ledger['referenceCount'],
            'externalContractClosureComplete': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False}
    body['artifactDigests'] = {str(p.relative_to(root)): digest(p) for p in root.rglob('*') if p.is_file()}
    value = seal(body, 'inspectionIdentity')
    (root/'result.json').write_text(json.dumps(value, indent=2)+'\n')
    return value
