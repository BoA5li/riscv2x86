"""Original-compiler RTL observations tied to byte-identical canonical objects.

This is a bounded compiler-stage observation, not a machine-region, ABI or L3
proof. Unsupported dumps and differing objects never establish absence.
"""
import json
import re
from pathlib import Path
from . import native_captured_deployment as d
from . import native_project_evaluation as project
from .verification_session import measured


@measured('compiler-final-rtl.parse')
def rtl_facts(raw):
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError('COMPILER_RTL_BUDGET_EXCEEDED')
    text = raw.decode('utf-8'); stack = []; heads = []; names = set(); want_head = False; i = 0
    while i < len(text):
        c = text[i]
        if c.isspace(): i += 1; continue
        if c == ';':
            end = text.find('\n', i)
            line = text[i:len(text) if end < 0 else end]
            header = re.match(r';; Function ([A-Za-z_$][A-Za-z0-9_.$]*) \(', line)
            if header: names.add(header[1])
            i = len(text) if end < 0 else end + 1; continue
        if c == '"':
            # RTL string operands may have their own parentheses. They are
            # values, never RTX opcodes (including strings naming asm nodes).
            want_head = False
            i += 1
            while i < len(text):
                if text[i] == '\\': i += 2
                elif text[i] == '"': i += 1; break
                else: i += 1
            else: raise ValueError('COMPILER_RTL_STRING_UNTERMINATED')
            continue
        if c in '([':
            if want_head: raise ValueError('COMPILER_RTL_NODE_HEAD_REQUIRED')
            stack.append(c); want_head = c == '('; i += 1
            if len(stack) > 4096: raise ValueError('COMPILER_RTL_DEPTH_EXCEEDED')
            continue
        if c in ')]':
            if want_head or not stack or stack.pop() != ( '(' if c == ')' else '['):
                raise ValueError('COMPILER_RTL_DELIMITER_INVALID')
            i += 1; continue
        end = i + 1
        while end < len(text) and not text[end].isspace() and text[end] not in '()[]";': end += 1
        token = text[i:end]
        if want_head:
            heads.append(token.split('/')[0].split(':')[0]); want_head = False
        elif not stack:
            endline = text.find('\n', i)
            line = text[i:len(text) if endline < 0 else endline].strip()
            if line not in names and not (names and line == 'Dataflow summary:'):
                raise ValueError('COMPILER_RTL_TOP_LEVEL_TOKEN_INVALID')
            end = len(text) if endline < 0 else endline + 1
        i = end
    if stack or not heads: raise ValueError('COMPILER_RTL_DOCUMENT_INCOMPLETE')
    return {'nodeCount': len(heads), 'functionCount': len(names),
            'asmNodeCount': sum(h.startswith('asm_') for h in heads)}


@measured('compiler-final-rtl.inspect')
def inspect(spec, builds, output, *, readback=False):
    from .automatic_l2_operand import _emit
    root = Path(output).resolve()
    if not readback: root.mkdir(parents=True, exist_ok=True)
    rows = []; refs = []
    for side in ('source', 'target'):
        p = spec['profiles'][side]['compile']; build = builds[side]
        for ref in (p['compiler'], build['input'], build['object']):
            d.verify_snapshot(ref); refs.append(ref)
        if any(flag.startswith('-fdump-') for flag in p['flags']):
            raise ValueError('COMPILER_RTL_EXISTING_DUMP_POLICY_UNSUPPORTED')
        folder = root / side
        if not readback: folder.mkdir(exist_ok=True)
        obj = folder/'input.o'; dump = folder/'final.rtl'; command = folder/'command'
        argv = [p['compiler']['path'], *p['flags'], '-fdump-rtl-final='+str(dump),
                '-c', build['input']['path'], '-o', str(obj)]
        if not readback and not (command/'execution.json').exists():
            project.command(argv, p['directory'], p['environment'], command, spec['timeoutSeconds'])
        record = project.validate_execution_record(d.read(command/'execution.json'))
        if any(record[k] != v for k,v in {'arguments': argv, 'directory': p['directory'], 'environment': p['environment']}.items()):
            raise ValueError('COMPILER_RTL_RECIPE_CHANGED')
        facts = None; reason = None
        if record['returnCode'] != 0 or record['failureReason']:
            reason = 'COMPILER_RTL_COMMAND_UNAVAILABLE'
        elif not obj.is_file() or not dump.is_file(): reason = 'COMPILER_RTL_OUTPUT_UNAVAILABLE'
        elif d.digest(obj) != build['object']['digest']: reason = 'COMPILER_RTL_CANONICAL_OBJECT_DIFFERS'
        else:
            try: facts = rtl_facts(dump.read_bytes())
            except (ValueError, UnicodeError) as exc: reason = str(exc)
        rows.append({'side': side, 'canonicalInput': build['input'], 'canonicalObject': build['object'],
            'compiler': p['compiler'], 'execution': d.snapshot(command/'execution.json'),
            'object': d.snapshot(obj) if obj.is_file() else None,
            'rtl': d.snapshot(dump) if dump.is_file() else None, 'facts': facts, 'reasonCode': reason,
            'inlineAsmAbsenceObserved': facts is not None and facts['functionCount'] > 0 and facts['asmNodeCount'] == 0})
    for ref in refs: d.verify_snapshot(ref)
    value = d.seal({'schemaVersion': 'riscv2x86.canonical-object-compiler-rtl-observation.v1',
        'sides': rows, 'compilerInlineAsmAbsenceObserved': all(r['inlineAsmAbsenceObserved'] for r in rows),
        'canonicalInstructionCoverageVerified': False, 'machineEliminationVerified': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False,
        'scope': 'compiler-final-RTL-with-identical-objects-not-machine-elimination-or-execution'}, 'rtlObservationIdentity')
    path = root/'result.json'
    _emit(path, json.dumps(value, indent=2, sort_keys=True)+'\n', readback)
    return {'receipt': d.snapshot(path), 'compilerInlineAsmAbsenceObserved': value['compilerInlineAsmAbsenceObserved'],
            'scope': value['scope']}
