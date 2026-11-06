"""Proof-bound candidate generation for frozen native preprocessed C.

This finite route translates compiler-bound, nonvolatile unsigned RV64 MULHU
register statements. It preserves the remaining C bytes and validates typed
target AST terms and supported reachable builtins. Link/object domains and
L1--L3 remain separate obligations; object compilation is not program acceptance.
"""
from copy import deepcopy
import json
from pathlib import Path
import subprocess

from . import project_native_binding as binding
from . import project_native_input as native
from .compiler_native_instance_binding import _nodes, byte_range, call_contexts
from .compiler_operand_type import compiler_operand_type_from_dict
from .native_integer_contracts import builtin_contract, term, decode_mulhu, multiply_high_term
from .project_acquisition import Runner, StageFailure
from .project_build_records import identity
from .project_compile_context import digest
from .project_tool_resolution import resolve_executable
from .l3_trace_support import Elf, require_json_match

SCHEMA = 'riscv2x86.native-integer-candidate.v1'


def read(path):
    return json.loads(Path(path).read_text())


def c_flags(receipt, side):
    args = native.analysis_arguments(receipt['context']['inspectionArguments'])
    result = ['-std=gnu11']
    for arg in args:
        if side == 'target' and (arg.startswith(('-march=', '-mabi=', '-mcpu=', '-mtune='))
                or arg in {'-mrelax', '-mno-relax'}):
            continue
        result.append(arg)
    if side == 'source':
        pass
    elif side == 'target':
        # Match the captured plain-char model explicitly, rather than relying
        # on the host compiler default. Other data-model changes are rejected.
        model = receipt['analysisInput']['dataModels']['native']
        result += ['-funsigned-char' if model['__CHAR_UNSIGNED__'] is not None else '-fsigned-char']
    else:
        raise ValueError('NATIVE_TRANSLATION_SIDE_INVALID')
    return result


def declaration_index(ast):
    return {node['id']: node for node, _, _ in _nodes(ast)
            if node.get('id') and node.get('kind') in {'VarDecl', 'ParmVarDecl'}
            and 'range' in node}


def map_offset(offset, edits, *, inverse=False):
    if type(offset) is not int:
        raise ValueError('NATIVE_TRANSLATION_PHYSICAL_OFFSET_REQUIRED')
    delta = 0
    for edit in edits:
        start, stop = edit['sourceRange']; size = len(edit['replacement'].encode('utf-8'))
        left, right = (start+delta, start+delta+size) if inverse else (start, stop)
        if offset < left:
            break
        if offset < right:
            raise ValueError('NATIVE_TRANSLATION_REFERENCE_INSIDE_EDIT')
        delta += size-(stop-start)
    return offset-delta if inverse else offset+delta


def declaration_key(ast, edits=(), *, target=False):
    index = declaration_index(ast)
    def key(ref):
        if ref not in index:
            raise ValueError('NATIVE_TRANSLATION_DECLARATION_REQUIRED:'+str(ref))
        node = index[ref]
        # Multi-declarator statements can share a range.begin (the type token).
        # The declaration's own identifier location distinguishes a from b.
        offset = node.get('loc', {}).get('offset')
        if type(offset) is not int:
            raise ValueError('NATIVE_TRANSLATION_DECLARATION_LOCATION_REQUIRED')
        if target:
            offset = map_offset(offset, edits, inverse=True)
        return {'kind': node['kind'], 'sourceOffset': offset}
    return key


def preserve_edits(raw, edits):
    cursor = 0; result = bytearray()
    for edit in edits:
        start, stop = edit['sourceRange']
        if (type(start) is not int or type(stop) is not int or not cursor <= start < stop <= len(raw)
                or native.bytes_identity(raw[start:stop]) != edit['sourceDigest']):
            raise ValueError('NATIVE_TRANSLATION_EDIT_RANGE_OR_SOURCE_MISMATCH')
        result.extend(raw[cursor:start]); result.extend(edit['replacement'].encode('utf-8')); cursor = stop
    result.extend(raw[cursor:])
    return bytes(result)


def plan_operand(row, model, key):
    fragment = row['frontendFragment']
    if (fragment.get('isVolatile') is not False or fragment.get('clobbers')
            or any(fragment.get(k) for k in ('symbols', 'hasAsmGoto', 'gotoLabels',
                'hasExternalControlFlow', 'hasRetryLoop', 'microarchSensitive'))
            or len(fragment['outputs']) != 1 or len(fragment['inputs']) != 2):
        raise ValueError('NATIVE_TRANSLATION_PURE_REGISTER_STATEMENT_REQUIRED')
    relation = row['constraintRelation']
    from .gnu_operand_relations import validate
    validate(relation)
    if (relation['outputs'] != ['=r'] or relation['inputs'] not in (['r', 'r'], ['%r', 'r'])
            or len(row['operands']) != 3):
        raise ValueError('NATIVE_TRANSLATION_REGISTER_CONSTRAINT_CONTRACT_REQUIRED')
    expressions = []; values = []
    for index, operand in enumerate(row['operands']):
        exported = operand['compilerExport']
        typ = compiler_operand_type_from_dict(exported['compilerType'])
        if (not typ.is_integer or typ.is_pointer or typ.is_signed or typ.width_bits != 64
                or typ.alignment_bytes != 8 or typ.qualifiers or not typ.side_effect_free
                or not typ.expression_repeatable or (index == 0 and not typ.modifiable_lvalue)):
            raise ValueError('NATIVE_TRANSLATION_UNSIGNED64_PURE_OPERAND_REQUIRED')
        value = term(operand['expressionAst'], model, key)
        if value['op'] != 'value' or value['type'] != {'bits': 64, 'signed': False}:
            raise ValueError('NATIVE_TRANSLATION_SIMPLE_INTEGER_CARRIER_REQUIRED')
        expressions.append(exported['exprText']); values.append(value)
    output, left, right = expressions
    assertions = []
    for expression in expressions:
        assertions.extend([
            '_Static_assert(__builtin_classify_type(('+expression+')) == 1, "integer operand");',
            '_Static_assert(sizeof(('+expression+')) * '+str(int(model['__CHAR_BIT__']))+' == 64, "operand width");',
            '_Static_assert(((__typeof__(('+expression+')))(-1)) > 0, "unsigned operand");'])
    replacement = (f'(({output}) = (unsigned long)((((unsigned __int128)({left})) * '
                   f'((unsigned __int128)({right}))) >> 64));')
    return {'instanceBindingIdentity': row['instanceBindingIdentity'],
        'sourceRange': row['physicalStatementRange'], 'sourceDigest': row['statementDigest'],
        'replacement': replacement, 'outputTerm': values[0],
        'scopeTypeAssertions': assertions,
        'expectedTargetTerm': multiply_high_term(values[1], values[2]),
        'constraintRelationIdentity': relation['relationIdentity'],
        'inputExchangeProof': 'unsigned-product-commutativity',
        'proofScope': 'local-statement-under-unchanged-C-context',
        'surroundingObjectLegalityVerified': False}


def target_proofs(ast, edits, model):
    nodes = _nodes(ast); key = declaration_key(ast, edits, target=True); proofs = []
    delta = 0
    for edit in edits:
        start = edit['sourceRange'][0]+delta
        stop = start+len(edit['replacement'].encode('utf-8'))
        assignments = []
        for node, _, _ in nodes:
            if node.get('kind') != 'BinaryOperator' or node.get('opcode') != '=':
                continue
            try:
                begin = node['range']['begin']['offset']; end = node['range']['end']['offset']+node['range']['end']['tokLen']
            except KeyError:
                continue
            if start <= begin < end <= stop:
                assignments.append(node)
        if len(assignments) != 1 or len(assignments[0].get('inner', [])) != 2:
            raise ValueError('NATIVE_TRANSLATION_TARGET_ASSIGNMENT_REQUIRED')
        left, right = assignments[0]['inner']
        require_json_match(edit['outputTerm'], term(left, model, key), 'NATIVE_TARGET_OUTPUT_MISMATCH')
        require_json_match(edit['expectedTargetTerm'], term(right, model, key), 'NATIVE_TARGET_PRODUCT_MISMATCH')
        proof = {'instanceBindingIdentity': edit['instanceBindingIdentity'],
            'sourceInstruction': edit['sourceInstruction'], 'targetTerm': edit['expectedTargetTerm'],
            'inputExchangeProof': edit['inputExchangeProof'],
            'localIntegerStatementEquivalenceVerified': True,
            'claimScope': 'architectural-integer-values-under-compiler-and-context-contracts'}
        proofs.append(dict(proof, proofIdentity=identity(proof)))
        delta += stop-start-(edit['sourceRange'][1]-edit['sourceRange'][0])
    return proofs


def literal_witness(contract, spelling):
    typ = contract['argument']['type']
    if typ['bits'] not in (32, 64):
        raise ValueError('NATIVE_LITERAL_COMPILER_WITNESS_WIDTH_UNSUPPORTED')
    return [
        '_Static_assert(__builtin_constant_p('+spelling+') == 1, "literal contract");',
        '_Static_assert(sizeof('+spelling+') * __CHAR_BIT__ == '+str(typ['bits'])+', "literal width");',
        '_Static_assert((((__typeof__('+spelling+'))(-1)) < 0) == '+str(int(typ['signed']))+', "literal signedness");',
        '_Static_assert((unsigned __int128)('+spelling+') == (unsigned __int128)0x'+
            format(contract['argument']['value'], 'x')+'ULL, "literal value");']


def acquire(bundle_path, target_compiler, output, *, timeout=300):
    if type(timeout) is not int or timeout < 1:
        raise ValueError('NATIVE_TRANSLATION_TIMEOUT_INVALID')
    if Path(output).absolute().parent == Path('/'):
        raise ValueError('NATIVE_TRANSLATION_RESULT_PARENT_REQUIRED')
    runner = Runner(output, 'native-integer-translation')
    commands = []
    def run(stage, argv, *, data=None, cwd=None):
        runner.state['currentStage'] = stage; runner.save()
        result = subprocess.run(argv, cwd=cwd, input=data, capture_output=True, timeout=timeout, check=False)
        stdout = runner.output/(stage+'.stdout'); stderr = runner.output/(stage+'.stderr')
        stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
        commands.append({'stage': stage, 'command': argv, 'directory': str(Path(cwd or Path.cwd()).resolve()),
            'returnCode': result.returncode, 'stdinIdentity': None if data is None else native.bytes_identity(data),
            'stdoutPath': str(stdout), 'stdoutDigest': digest(stdout),
            'stderrPath': str(stderr), 'stderrDigest': digest(stderr)})
        runner.state['commands'] = commands; runner.save()
        if result.returncode:
            raise StageFailure(stage, result.returncode)
        return result.stdout
    try:
        path = Path(bundle_path).resolve(strict=True); bundle_digest = digest(path); bundle = read(path)
        runner.state['currentStage'] = 'binding-independent-replay'; runner.save()
        replayed = binding.replay(bundle, runner.output/'binding-replay', timeout=timeout)
        bindings, _ = binding.validate_artifacts(bundle)
        receipt = read(bundle['nativeInputReceiptPath']); artifacts = native.validate_artifacts(receipt)
        raw = artifacts['inputBytes']; source_ast = artifacts['canonicalAst']
        model = receipt['analysisInput']['dataModels']['native']
        if (receipt['target'] != 'riscv64' or model['__CHAR_BIT__'] != '8'
                or model['__SIZEOF_INT__'] != '4' or model['__SIZEOF_LONG__'] != '8'
                or model['__SIZEOF_POINTER__'] != '8'):
            raise ValueError('NATIVE_TRANSLATION_LP64_MODEL_REQUIRED')
        source_cc = receipt['context']['nativeCompiler']
        target_cc = str(resolve_executable(target_compiler))
        inspector = receipt['inspectionCompiler']
        tools = {p: digest(p) for p in (source_cc, target_cc, inspector)}
        source_flags = c_flags(receipt, 'source'); target_flags = c_flags(receipt, 'target')
        target_model = native.data_model(run('target-data-model',
            [target_cc, *target_flags, '-E', '-dM', '-x', 'c', '-'], data=b'').decode())
        if target_model != model:
            raise ValueError('NATIVE_TRANSLATION_TARGET_DATA_MODEL_MISMATCH')
        source_key = declaration_key(source_ast)
        edits = [plan_operand(row, model, source_key) for row in bindings['records']]
        if not edits:
            raise ValueError('NATIVE_TRANSLATION_ASM_OCCURRENCE_REQUIRED')
        from .schema import _frag_from
        from .assemble import materialize_template
        for index, (row, edit) in enumerate(zip(bindings['records'], edits)):
            material = materialize_template(_frag_from(row['frontendFragment']))
            # This route has no assembler include/macro/section contract.
            # Reject grammar-level directives and labels, not instruction
            # names; the operation is selected only by the decoded word.
            for line in material.normalized_asm.splitlines():
                code = line.split('#', 1)[0].strip()
                if code and (code.startswith('.') or ':' in code.split()[0]):
                    raise ValueError('NATIVE_TRANSLATION_ASSEMBLER_DIRECTIVE_OR_LABEL_CONTRACT_REQUIRED')
            registers = {}
            for item in material.operand_bindings:
                if not item.rv_register.startswith('x') or not item.rv_register[1:].isdigit():
                    raise ValueError('NATIVE_TRANSLATION_PHYSICAL_REGISTER_REQUIRED')
                registers[item.operand_index] = int(item.rv_register[1:])
            asm = runner.output/f'fragment-{index}.s'; obj = runner.output/f'fragment-{index}.o'
            asm.write_text('.file "riscv2x86-native-fragment.s"\n.text\n.option norvc\n.globl rv2x86_native_fragment\n'
                '.type rv2x86_native_fragment,@function\nrv2x86_native_fragment:\n'+
                material.normalized_asm+'\n.size rv2x86_native_fragment,.-rv2x86_native_fragment\n')
            isa_flags = [arg for arg in source_flags if arg.startswith(('-march=', '-mabi='))]
            run(f'source-instruction-{index}', [source_cc, *isa_flags, '-c', str(asm), '-o', str(obj)],
                cwd=receipt['context']['workingDirectory'])
            elf = Elf(obj); code = elf.code('rv2x86_native_fragment')
            if (elf.machine != 243 or elf.type != 1
                    or any(s[1] in (4, 9) and s[5] for s in elf.sections)
                    or sum(s[5] for s in elf.sections if s[2] & 2) != len(code)):
                raise ValueError('NATIVE_TRANSLATION_RELOCATION_OR_EXTRA_SECTION')
            edit['sourceInstruction'] = decode_mulhu(code, registers)
            edit['sourceObjectDigest'] = digest(obj)
        candidate = preserve_edits(raw, edits)
        candidate_path = runner.output/'candidate.i'; candidate_path.write_bytes(candidate)
        # Check actual code-generation compiler operand types in their original
        # lexical scope, not only the inspection compiler's AST. Static asserts
        # introduce no runtime evaluations; the original input stays immutable.
        checked_inputs = {}
        for side in ('source', 'target'):
            scoped = []
            for edit in edits:
                start, stop = edit['sourceRange']
                statement = raw[start:stop].decode('utf-8') if side == 'source' else edit['replacement']
                scoped.append(dict(edit, replacement='{\n'+'\n'.join(edit['scopeTypeAssertions'])+'\n'+statement+'\n}'))
            checked_inputs[side] = preserve_edits(raw, scoped)
            (runner.output/(side+'-type-witness.i')).write_bytes(checked_inputs[side])
        inspection_flags = [arg for arg in target_flags if not arg.startswith('-fexcess-precision=')]
        # Inspection is evidence, never a replacement for the code-generation
        # compiler. Only the separately retained precision option unsupported by
        # some Clang releases is omitted; this route proves integer expressions.
        raw_ast = run('target-ast', [inspector, '--target=x86_64-linux-gnu', *inspection_flags,
            '-Werror', '-Werror=unknown-attributes', '-Werror=ignored-attributes',
            '-Werror=unknown-warning-option', '-x', 'cpp-output', '-fsyntax-only',
            '-Xclang', '-ast-dump=json', '-'], data=candidate)
        target_ast = native.canonical_ast(json.loads(raw_ast))
        if any(node.get('kind') in {'GCCAsmStmt', 'MSAsmStmt', 'FileScopeAsmDecl'}
                for node, _, _ in _nodes(target_ast)):
            raise ValueError('NATIVE_TRANSLATION_TARGET_ASM_REMAINS')
        (runner.output/'target-ast.json').write_text(json.dumps(target_ast, indent=2))
        proofs = target_proofs(target_ast, edits, model)
        # Every reachable builtin remains represented. Unsupported arguments
        # stop candidate approval rather than disappearing from the denominator.
        contexts = call_contexts(source_ast, bindings, receipt['analysisInputIdentity'])
        reachable = {fid for root in contexts['asmOwningFunctionContexts'] for fid in root['reachableFunctionContexts']}
        target_calls = {}
        for node, ast_path, _ in _nodes(target_ast):
            if node.get('kind') == 'CallExpr':
                try: offset = node['range']['begin']['offset']
                except KeyError: continue
                target_calls.setdefault(offset, []).append(node)
        source_nodes = {tuple(p): n for n, p, _ in _nodes(source_ast)}
        target_key = declaration_key(target_ast, edits, target=True)
        builtin_proofs = []; witnesses = []
        for function in contexts['functions']:
            if function['functionContextIdentity'] not in reachable:
                continue
            for call in function['calls']:
                if call['resolution'] != 'builtin-contract-required':
                    continue
                node = source_nodes[tuple(call['astPath'])]
                contract = builtin_contract(node, model, source_key)
                offset = map_offset(node['range']['begin']['offset'], edits)
                peers = target_calls.get(offset, [])
                if len(peers) != 1:
                    raise ValueError('NATIVE_TRANSLATION_TARGET_BUILTIN_BINDING_REQUIRED')
                require_json_match(contract, builtin_contract(peers[0], model, target_key),
                    'NATIVE_TRANSLATION_BUILTIN_SEMANTICS_MISMATCH')
                builtin_proofs.append({'sourceCallAstPath': call['astPath'], 'contract': contract})
                if contract['operation'] == 'compiler-integer-literal-constant-query':
                    literal = node['inner'][1]; begin, end = byte_range(literal, len(raw))
                    spelling = raw[begin:end].decode('utf-8')
                    witnesses.extend(literal_witness(contract, spelling))
        witness = runner.output/'builtin-witness.c'; witness.write_text('\n'.join(witnesses)+'\n')
        for side, cc, flags, machine in [('source', source_cc, source_flags, 243), ('target', target_cc, target_flags, 62)]:
            type_obj = runner.output/(side+'-type-witness.o')
            run(side+'-operand-types', [cc, *flags, '-Werror', '-x', 'cpp-output', '-c', '-', '-o', str(type_obj)],
                data=checked_inputs[side], cwd=receipt['context']['workingDirectory'])
            if Elf(type_obj).machine != machine:
                raise ValueError('NATIVE_TRANSLATION_OPERAND_WITNESS_ARCHITECTURE_MISMATCH')
            witness_obj = runner.output/(side+'-builtin-witness.o')
            run(side+'-builtin-witness', [cc, *flags, '-Werror', '-c', str(witness), '-o', str(witness_obj)])
            if Elf(witness_obj).machine != machine:
                raise ValueError('NATIVE_TRANSLATION_COMPILER_ARCHITECTURE_MISMATCH')
            data = raw if side == 'source' else candidate
            obj = runner.output/(side+'.o')
            run(side+'-object-build', [cc, *flags, '-Werror', '-x', 'cpp-output', '-c', '-', '-o', str(obj)],
                data=data, cwd=receipt['context']['workingDirectory'])
            if Elf(obj).machine != machine or Elf(obj).type != 1:
                raise ValueError('NATIVE_TRANSLATION_OBJECT_ARCHITECTURE_MISMATCH')
        binding.validate_artifacts(bundle)
        if digest(path) != bundle_digest or any(digest(p) != h for p, h in tools.items()):
            raise ValueError('NATIVE_TRANSLATION_CLOSING_INPUT_CHANGED')
        names = ['candidate.i', 'source.o', 'target.o', 'builtin-witness.c',
            'source-builtin-witness.o', 'target-builtin-witness.o', 'target-ast.json',
            'source-type-witness.i', 'target-type-witness.i', 'source-type-witness.o', 'target-type-witness.o']
        names += [f'fragment-{index}.{suffix}' for index in range(len(edits)) for suffix in ('s', 'o')]
        artifact_digests = {name: digest(runner.output/name) for name in names}
        body = {'schemaVersion': SCHEMA, 'bindingBundlePath': str(path), 'bindingBundleDigest': bundle_digest,
            'bindingBundleIdentity': bundle['bindingBundleIdentity'], 'analysisInputIdentity': bundle['analysisInputIdentity'],
            'targetCompiler': target_cc, 'tools': tools, 'sourceFlags': source_flags, 'targetFlags': target_flags,
            'candidatePath': str(candidate_path), 'candidateDigest': digest(candidate_path),
            'sourceObjectDigest': digest(runner.output/'source.o'), 'targetObjectDigest': digest(runner.output/'target.o'),
            'sourceAstIdentity': identity(source_ast), 'targetAstIdentity': identity(target_ast),
            'edits': edits, 'localProofs': proofs, 'builtinProofs': builtin_proofs,
            'artifactDigests': artifact_digests,
            'commands': commands, 'bindingReplay': replayed,
            'bindingReplayBundlePath': str(runner.output/'binding-replay/binding-bundle.json'),
            'bindingReplayBundleDigest': digest(runner.output/'binding-replay/binding-bundle.json'),
            'allBoundAsmOccurrencesTranslated': len(proofs) == bindings['occurrenceCount'],
            'derivedTargetMaterializationComplete': True, 'localIntegerProofComplete': True,
            'compilerOperandTypeWitnessesComplete': True,
            'objectBuildsComplete': True, 'originalSourceEditAuthorized': False,
            'wholeFunctionCompositionVerified': False, 'formalEntryVerified': False,
            'requiredWork': ['PROGRAM_CALL_OBJECT_AND_EXTERNAL_EFFECT_CLOSURE_REQUIRED',
                'SOURCE_TARGET_LINK_AND_RUNTIME_CLOSURE_REQUIRED', 'L1_L3_AND_INDEPENDENT_PROGRAM_AUDIT_REQUIRED',
                'ORIGINAL_MACRO_PROVENANCE_REQUIRED_FOR_ORIGINAL_SOURCE_REWRITE'],
            'semanticApproval': False, 'productionAcceptanceComplete': False}
        result = dict(body, candidateIdentity=identity(body))
        (runner.output/'candidate.json').write_text(json.dumps(result, indent=2))
        runner.state.update(currentStage='complete', status='complete', acquisitionComplete=True,
            derivedTargetMaterializationComplete=True, localIntegerProofComplete=True,
            productionAcceptanceComplete=False)
        runner.save(); return result
    except StageFailure as exc:
        runner.state.update(status='failed', primaryFailure={'stage': exc.stage, 'returnCode': exc.code})
        runner.save(); raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        runner.failure(runner.state['currentStage'], exc); raise


def audit(value, output, *, timeout=300):
    if (value.get('schemaVersion') != SCHEMA or value.get('candidateIdentity') != identity({
            k: v for k, v in value.items() if k != 'candidateIdentity'})):
        raise ValueError('NATIVE_TRANSLATION_CANDIDATE_IDENTITY_INVALID')
    if digest(value['candidatePath']) != value['candidateDigest']:
        raise ValueError('NATIVE_TRANSLATION_CANDIDATE_BYTES_CHANGED')
    directory = Path(value['candidatePath']).parent
    for name, expected in value['artifactDigests'].items():
        if Path(name).name != name or digest(directory/name) != expected:
            raise ValueError('NATIVE_TRANSLATION_PROOF_ARTIFACT_CHANGED')
    for command in value['commands']:
        for stream in ('stdout', 'stderr'):
            if digest(command[stream+'Path']) != command[stream+'Digest']:
                raise ValueError('NATIVE_TRANSLATION_COMMAND_ARTIFACT_CHANGED')
    if digest(value['bindingReplayBundlePath']) != value['bindingReplayBundleDigest']:
        raise ValueError('NATIVE_TRANSLATION_BINDING_REPLAY_ARTIFACT_CHANGED')
    stored_replay_bundle = read(value['bindingReplayBundlePath'])
    binding.validate_artifacts(stored_replay_bundle)
    fresh = acquire(value['bindingBundlePath'], value['targetCompiler'], output, timeout=timeout)
    def projection(receipt):
        return {k: v for k, v in receipt.items() if k not in (
            'candidatePath', 'candidateIdentity', 'commands', 'bindingReplay',
            'bindingReplayBundlePath', 'bindingReplayBundleDigest')}
    require_json_match(projection(fresh), projection(value), 'NATIVE_TRANSLATION_INDEPENDENT_AUDIT_MISMATCH')
    def command_projection(receipt):
        root = str(Path(receipt['candidatePath']).parent)
        rows = []
        for command in receipt['commands']:
            argv = [('$OUTPUT/'+arg[len(root)+1:]) if arg.startswith(root+'/') else arg
                    for arg in command['command']]
            rows.append({**{k: command[k] for k in ('stage', 'returnCode', 'stdinIdentity',
                'stdoutDigest', 'stderrDigest')}, 'command': argv})
        return rows
    require_json_match(command_projection(fresh), command_projection(value),
        'NATIVE_TRANSLATION_COMMAND_RECIPE_MISMATCH')
    # This receipt has output-dependent bundle IDs, but its content identity,
    # original input and completed replay claim still must be bound exactly.
    old_replay = value['bindingReplay']
    if (old_replay.get('replayIdentity') != identity({k: v for k, v in old_replay.items() if k != 'replayIdentity'})
            or old_replay.get('originalBindingBundleIdentity') != value['bindingBundleIdentity']
            or old_replay.get('freshBindingBundleIdentity') != stored_replay_bundle['bindingBundleIdentity']
            or old_replay.get('bindingInventoryIdentity') != stored_replay_bundle['bindingInventoryIdentity']
            or old_replay.get('analysisInputIdentity') != value['analysisInputIdentity']
            or old_replay.get('nativeBindingReplayComplete') is not True
            or old_replay.get('semanticApproval') is not False
            or old_replay.get('productionAcceptanceComplete') is not False):
        raise ValueError('NATIVE_TRANSLATION_BINDING_REPLAY_RECEIPT_INVALID')
    return {'nativeCandidateIndependentAuditComplete': True, 'candidateIdentity': value['candidateIdentity'],
        'proofScope': 'local-integer-statements-and-preserved-supported-builtins',
        'productionAcceptanceComplete': False, 'semanticApproval': False}
