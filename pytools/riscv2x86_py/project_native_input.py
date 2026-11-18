"""Analyze compiler-produced CPP bytes; never authorize translation or edits.

The native compiler selects headers and macro branches once. Clang consumes
those bytes in cpp-output mode. This closes the input selection boundary, not
GCC/Clang semantic equivalence, ABI closure, macro provenance or L0--L3.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess

from .compiler_call_dependencies import parse_dependencies, _snapshot
from .project_acquisition import Runner, StageFailure
from .project_build_contract import source_arguments
from .project_build_records import identity
from .project_compile_context import validate as validate_context, digest, PAIRS
from .project_tool_resolution import resolve_executable
from .verification_session import ContentBytes, measured, pure, span, ReadOnlyDict, ReadOnlyList

SCHEMA = 'riscv2x86.native-analysis-input.v1'
AST_POLICY = 'clang-json-reference-graph-alpha-renaming.v1'
REFERENCE_KEYS = frozenset({'id', 'previousDecl', 'parentDeclContextId',
    'typeAliasDeclId', 'referencedMemberDecl', 'targetLabelDeclId', 'declId'})
MODEL_KEYS = ('__CHAR_BIT__', '__SIZEOF_SHORT__', '__SIZEOF_INT__',
    '__SIZEOF_LONG__', '__SIZEOF_LONG_LONG__', '__SIZEOF_POINTER__',
    '__SIZEOF_WCHAR_T__', '__WCHAR_TYPE__', '__CHAR_UNSIGNED__',
    '__STDC_VERSION__', '__BYTE_ORDER__')


def analysis_arguments(arguments):
    """Do not apply the original CPP recipe a second time to expanded C.

    All non-CPP inspection arguments retain their original order. Only the
    explicitly modeled CPP option families are removed. This function consumes
    an already validated inspection projection, not arbitrary user argv.
    """
    result = []; i = 0
    while i < len(arguments):
        arg = arguments[i]
        if arg in PAIRS:
            if i + 1 >= len(arguments):
                raise ValueError('NATIVE_INPUT_ARGUMENT_INCOMPLETE')
            i += 2
            continue
        if arg == '-nostdinc' or arg.startswith(('-D', '-U', '-I',
                '-isystem', '-iquote', '-include', '-imacros', '-isysroot')):
            i += 1
            continue
        result.append(arg); i += 1
    return result


@measured('native-input.canonical_ast')
def canonical_ast(ast, *, readonly=False):
    """Retain all JSON fields and reference relationships, not pointer values.

    IDs are renamed bijectively in traversal order, including references to
    declarations outside the emitted tree. Literal values and arbitrary hex
    strings are not rewritten. The raw AST is retained as separate evidence.
    This is replay identity, not a projection granting semantic authority.
    """
    if type(readonly) is not bool:
        raise ValueError('NATIVE_INPUT_READ_ONLY_POLICY_INVALID')
    identifiers = {}
    def visit(value, key=None):
        if key in REFERENCE_KEYS and isinstance(value, str):
            if not re.fullmatch(r'0x[0-9a-fA-F]+', value):
                raise ValueError('NATIVE_INPUT_AST_REFERENCE_INVALID:' + key)
            if value not in identifiers:
                identifiers[value] = 'node:' + str(len(identifiers))
            return identifiers[value]
        if isinstance(value, dict):
            result = {k: visit(v, k) for k, v in sorted(value.items())}
            return ReadOnlyDict(result) if readonly else result
        if isinstance(value, list):
            result = [visit(v) for v in value]
            return ReadOnlyList(result) if readonly else result
        return value
    if not isinstance(ast, dict) or ast.get('kind') != 'TranslationUnitDecl':
        raise ValueError('NATIVE_INPUT_TRANSLATION_UNIT_REQUIRED')
    return visit(ast)


def data_model(text):
    macros = {}
    for line in text.splitlines():
        match = re.fullmatch(r'#define ([A-Za-z_][A-Za-z_0-9]*) (.*)', line)
        if match:
            if match[1] in macros:
                raise ValueError('NATIVE_INPUT_DUPLICATE_MACRO')
            macros[match[1]] = match[2].strip()
    optional = {'__CHAR_UNSIGNED__', '__STDC_VERSION__'}
    if any(k not in macros for k in MODEL_KEYS if k not in optional):
        raise ValueError('NATIVE_INPUT_DATA_MODEL_INCOMPLETE')
    model = {k: macros.get(k) for k in MODEL_KEYS}
    order = model['__BYTE_ORDER__']
    model['__BYTE_ORDER__'] = macros.get(order, order)
    return model


@measured('native-input.ast_inventory')
def ast_inventory(ast, input_identity):
    """Whole emitted tree, with physical CPP locations; no source edit ranges."""
    rows = []; attributes = []
    def walk(node, path):
        if not isinstance(node, dict):
            raise ValueError('NATIVE_INPUT_AST_NODE_INVALID')
        kind = node.get('kind', '')
        if kind in {'GCCAsmStmt', 'MSAsmStmt', 'FileScopeAsmDecl'}:
            rows.append({'astPath': path, 'kind': kind,
                'location': deepcopy(node.get('loc', {})),
                'range': deepcopy(node.get('range', {})),
                'locationDomain': 'native-preprocessed-input',
                'sourceInstanceBindingComplete': False})
        if kind.endswith('Attr'):
            attributes.append({'astPath': path, 'kind': kind,
                'node': deepcopy(node), 'semanticInterpretationVerified': False})
        children = node.get('inner', [])
        if not isinstance(children, list):
            raise ValueError('NATIVE_INPUT_AST_CHILDREN_INVALID')
        for i, child in enumerate(children):
            walk(child, [*path, i])
    walk(ast, [])
    body = {'schemaVersion': 'riscv2x86.native-input-ast-inventory.v1',
        'analysisInputIdentity': input_identity, 'instances': rows,
        'attributes': attributes, 'inspectionAstTraversalComplete': True,
        'macroArgumentGraphComplete': False, 'sourceInstanceBindingComplete': False,
        'editAuthorizationComplete': False, 'endToEndEligibilityAssessed': False,
        'semanticApproval': False, 'productionAcceptanceComplete': False}
    return dict(body, inventoryIdentity=identity(body))


def execution_environment(context):
    # v1 records search variables, not a full historical process environment.
    # Do not inherit unrelated current values or claim the latter was captured.
    captured=context.get('environment',context.get('searchEnvironment'))
    if not isinstance(captured,dict) or not captured.get('PATH'):
        raise ValueError('NATIVE_INPUT_CAPTURED_PATH_REQUIRED')
    if any(not isinstance(k,str) or not k or '=' in k or '\0' in k
           or (v is not None and (not isinstance(v,str) or '\0' in v)) for k,v in captured.items()):
        raise ValueError('NATIVE_INPUT_ENVIRONMENT_INVALID')
    return {k:v for k,v in captured.items() if v is not None and v!=''}


def acquire(context, clang, output, *, target='riscv64', timeout=120):
    if type(timeout) is not int or timeout < 1:
        raise ValueError('NATIVE_INPUT_TIMEOUT_INVALID')
    if target not in {'riscv64', 'x86_64'}:
        raise ValueError('NATIVE_INPUT_TARGET_UNSUPPORTED')
    runner = Runner(output, 'native-analysis-input')
    try:
        runner.state['currentStage'] = 'context-binding'; runner.save()
        validate_context(context)
        if context['inspectionReady'] is not True:
            raise ValueError('NATIVE_INPUT_CONTEXT_NOT_INSPECTABLE')
        source = context['sourcePath']; cwd = Path(context['workingDirectory'])
        compiler = str(resolve_executable(clang, cwd))
        tools = {p: digest(p) for p in (context['nativeCompiler'], compiler)}
        native_args = source_arguments(context)
        inspected_args = analysis_arguments(context['inspectionArguments'])
        native = [context['nativeCompiler'], *native_args]
        inspector = [compiler, '--target=' + target + '-linux-gnu',
            '-std=gnu11', *inspected_args]
        environment = execution_environment(context)
        commands = []
        def run(stage, command, *, input_bytes=None):
            runner.state['currentStage'] = stage; runner.save()
            result = subprocess.run(command, cwd=cwd, input=input_bytes,
                capture_output=True, timeout=timeout, check=False, env=environment)
            stdout = runner.output / (stage + '.stdout')
            stderr = runner.output / (stage + '.stderr')
            stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
            commands.append({'stage': stage, 'command': command,
                'directory': str(cwd), 'returnCode': result.returncode,
                'stdinIdentity': None if input_bytes is None else bytes_identity(input_bytes),
                'stdoutPath': str(stdout), 'stdoutDigest': digest(stdout),
                'stderrPath': str(stderr), 'stderrDigest': digest(stderr)})
            runner.state['commands'] = commands; runner.save()
            if result.returncode:
                runner.state.update(status='failed', primaryFailure={
                    'stage': stage, 'returnCode': result.returncode,
                    'stderrPath': str(stderr)})
                if stage == 'inspection-native-input':
                    # The exact CPP parse is the capability probe. No type
                    # spelling replacements, dropped declarations or warning
                    # suppression may turn this failure into a valid input.
                    diagnostic = {
                        'schemaVersion':'riscv2x86.native-inspection-capability.v1',
                        'contextIdentity':context['contextIdentity'],
                        'compilerPath':compiler, 'compilerDigest':tools[compiler],
                        'inputDigest':bytes_identity(input_bytes),
                        'command':command, 'returnCode':result.returncode,
                        'integerDataModelMatched':True,
                        'exactNativeInputParsingComplete':False,
                        'reasonCode':'INSPECTION_FRONTEND_LANGUAGE_OR_TYPE_CAPABILITY_REQUIRED',
                        'stderrDigest':digest(stderr),
                        'semanticApproval':False,'productionAcceptanceComplete':False}
                    (runner.output/'inspection-capability.json').write_text(json.dumps(
                        dict(diagnostic,capabilityIdentity=identity(diagnostic)),indent=2)+'\n')
                runner.save(); raise StageFailure(stage, result.returncode)
            return result.stdout

        # GCC's CPP defaults live in cc1 as well as the driver. A driver hash
        # alone would miss replacement of the frontend providing built-in macros.
        frontend_text = run('native-frontend-location',
            [context['nativeCompiler'], '-print-prog-name=cc1']).decode('utf-8').strip()
        frontend = str(resolve_executable(frontend_text, cwd))
        tools[frontend] = digest(frontend)
        run('native-driver', [*native, '-###', '-E', source])
        run('native-specs', [context['nativeCompiler'], '-dumpspecs'])

        def dependencies(stage):
            raw = run(stage, [*native, '-M', '-MT', 'rv2x86_call_inventory', source])
            return parse_dependencies(raw.decode('utf-8'))
        paths = dependencies('native-dependencies-before')
        before = _snapshot(paths, cwd)
        if source not in {r['resolvedPath'] for r in before}:
            raise ValueError('NATIVE_INPUT_SOURCE_MISSING')
        expanded = run('native-expanded', [*native, '-E', source])
        expanded.decode('utf-8')
        run('native-definitions', [*native, '-E', '-dD', source])
        run('native-macros', [*native, '-E', '-dM', source])
        native_model = data_model(run('native-data-model',
            [*native, '-E', '-dM', '-x', 'c', '-'], input_bytes=b'').decode('utf-8'))
        inspection_model = data_model(run('inspection-data-model',
            [*inspector, '-E', '-dM', '-x', 'c', '-'], input_bytes=b'').decode('utf-8'))
        runner.state['currentStage'] = 'data-model-comparison'; runner.save()
        if native_model != inspection_model:
            raise ValueError('NATIVE_INPUT_DATA_MODEL_MISMATCH')
        # stdin names and physical CPP offsets are stable across independent
        # output directories. Never feed the original source or reapply -D/-I.
        raw_ast = run('inspection-native-input', [*inspector, '-Werror',
            '-Werror=unknown-attributes', '-Werror=ignored-attributes',
            '-Werror=unknown-warning-option', '-x', 'cpp-output',
            '-fsyntax-only', '-Xclang', '-ast-dump=json', '-'], input_bytes=expanded)
        runner.state['currentStage'] = 'ast-binding'; runner.save()
        ast = canonical_ast(json.loads(raw_ast))
        input_body = {'contextIdentity': context['contextIdentity'],
            'sourceDigest': context['sourceDigest'], 'nativeInputDigest': bytes_identity(expanded),
            'nativeDependencies': before, 'tools': tools,
            'nativeArguments': native_args, 'inspectionArguments': inspected_args,
            'target': target, 'dataModels': {'native': native_model, 'inspection': inspection_model}}
        input_id = identity(input_body)
        inventory = ast_inventory(ast, input_id)
        inventory_path = runner.output / 'native-ast-inventory.json'
        inventory_path.write_text(json.dumps(inventory, indent=2))
        canonical_path = runner.output / 'canonical-ast.json'
        canonical_path.write_text(json.dumps(ast, indent=2))
        after = dependencies('native-dependencies-after')
        runner.state['currentStage'] = 'input-consistency'; runner.save()
        if paths != after or identity(before) != identity(_snapshot(after, cwd)):
            raise ValueError('NATIVE_INPUT_DEPENDENCIES_CHANGED')
        validate_context(context)
        if any(digest(p) != value for p, value in tools.items()):
            raise ValueError('NATIVE_INPUT_TOOL_CHANGED')
        body = {'schemaVersion': SCHEMA, 'context': context,
            'executionEnvironment': environment,
            'executionEnvironmentScope':('captured-process-environment' if 'environment' in context
                                          else 'captured-search-variables-only'),
            'inspectionCompiler': compiler, 'target': target,
            'analysisInput': input_body, 'analysisInputIdentity': input_id,
            'commands': commands, 'astProjectionPolicy': AST_POLICY,
            'canonicalAstPath': str(canonical_path), 'canonicalAstDigest': digest(canonical_path),
            'canonicalAstIdentity': identity(ast),
            'inventoryPath': str(inventory_path), 'inventoryDigest': digest(inventory_path),
            'inventoryIdentity': inventory['inventoryIdentity'],
            'nativeInputConsumed': True, 'inspectionParsingComplete': True,
            'inputAcquisitionConsistent': True, 'integerDataModelMatched': True,
            'compilerEquivalenceVerified': False, 'sourceInstanceBindingComplete': False,
            'editAuthorizationComplete': False, 'semanticApproval': False,
            'productionAcceptanceComplete': False}
        receipt = dict(body, nativeInputIdentity=identity(body))
        path = runner.output / 'native-input.json'
        path.write_text(json.dumps(receipt, indent=2))
        runner.state.update(status='complete', currentStage='complete',
            acquisitionComplete=True, nativeInputConsumed=True,
            inspectionParsingComplete=True, receiptPath=str(path), receiptDigest=digest(path))
        runner.save(); return receipt
    except StageFailure:
        raise
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
        runner.failure(runner.state['currentStage'], exc)
        raise


def bytes_identity(raw):
    from hashlib import sha256
    return 'sha256:' + sha256(raw).hexdigest()


@measured('native-input._native_graph')
def _native_graph(ast_bytes, analysis_identity):
    content = ast_bytes if type(ast_bytes) is ContentBytes else ContentBytes(ast_bytes)
    def derive_graph():
        # Freeze while constructing the canonical graph, avoiding a second
        # recursive graph copy even when memoization is disabled.
        canonical = canonical_ast(json.loads(content.raw.decode('utf-8')), readonly=True)
        inventory = ast_inventory(canonical, analysis_identity)
        return {'canonicalAst': canonical, 'canonicalIdentity': identity(canonical),
                'inventory': inventory, 'inventoryBodyIdentity': identity(inventory)}
    return pure('native-canonical-graph-and-inventory.v1',
                (content, analysis_identity), derive_graph, readonly=True)


@measured('native-input._json_identity')
def _json_identity(raw):
    content = raw if type(raw) is ContentBytes else ContentBytes(raw)
    return pure('native-json-value-identity.v1', (content,),
                lambda: identity(json.loads(content.raw.decode('utf-8'))))


@measured('native-input.validate-artifacts')
def validate_artifacts(receipt, *, readonly=False):
    """Rebuild derived evidence from stored bytes; not independent acquisition."""
    if type(readonly) is not bool:
        raise ValueError('NATIVE_INPUT_READ_ONLY_POLICY_INVALID')
    if (not isinstance(receipt, dict) or receipt.get('schemaVersion') != SCHEMA
            or receipt.get('nativeInputIdentity') != identity({
                k: v for k, v in receipt.items() if k != 'nativeInputIdentity'})):
        raise ValueError('NATIVE_INPUT_RECEIPT_INVALID')
    if 'executionEnvironment' in receipt or 'executionEnvironmentScope' in receipt:
        scope=('captured-process-environment' if 'environment' in receipt['context']
               else 'captured-search-variables-only')
        if (receipt.get('executionEnvironment')!=execution_environment(receipt['context'])
                or receipt.get('executionEnvironmentScope')!=scope):
            raise ValueError('NATIVE_INPUT_EXECUTION_ENVIRONMENT_MISMATCH')
    # One current byte snapshot per path in this call. Every expected digest
    # is checked, even when two receipt fields refer to the same path.
    # No file-validity decision survives this invocation.
    contents = {}
    def read_checked(path, expected):
        key = str(Path(path))
        if key not in contents:
            contents[key] = ContentBytes(Path(path).read_bytes())
        content = contents[key]
        if 'sha256:' + content.digest.hex() != expected:
            raise ValueError('NATIVE_INPUT_ARTIFACT_CHANGED')
        return content
    for row in receipt['commands']:
        for key in ('stdout', 'stderr'):
            read_checked(row[key + 'Path'], row[key + 'Digest'])
    for prefix in ('canonicalAst', 'inventory'):
        read_checked(receipt[prefix + 'Path'], receipt[prefix + 'Digest'])
    stages = {row['stage']: row for row in receipt['commands']}
    if len(stages) != len(receipt['commands']):
        raise ValueError('NATIVE_INPUT_DUPLICATE_STAGE')
    # All bytes and receipt/tool/dependency checks remain live on every call.
    # Only canonicalization and inventory calculation share a pure result.
    ast_bytes = read_checked(stages['inspection-native-input']['stdoutPath'],
                             stages['inspection-native-input']['stdoutDigest'])
    graph = _native_graph(ast_bytes, receipt['analysisInputIdentity'])
    if not readonly:
        with span('native-input.mutable-result-copy'):
            graph = deepcopy(graph)
    canonical = graph['canonicalAst']
    raw_input = read_checked(stages['native-expanded']['stdoutPath'],
                             stages['native-expanded']['stdoutDigest']).raw
    canonical_bytes = read_checked(receipt['canonicalAstPath'], receipt['canonicalAstDigest'])
    inventory_bytes = read_checked(receipt['inventoryPath'], receipt['inventoryDigest'])
    if (identity(receipt['analysisInput']) != receipt['analysisInputIdentity']
            or bytes_identity(raw_input) != receipt['analysisInput']['nativeInputDigest']
            or stages['inspection-native-input']['stdinIdentity'] != bytes_identity(raw_input)
            or graph['canonicalIdentity'] != receipt['canonicalAstIdentity']
            or _json_identity(canonical_bytes) != graph['canonicalIdentity']):
        raise ValueError('NATIVE_INPUT_ARTIFACT_BINDING_INVALID')
    inventory = graph['inventory']
    if (inventory['inventoryIdentity'] != receipt['inventoryIdentity']
            or _json_identity(inventory_bytes) != graph['inventoryBodyIdentity']):
        raise ValueError('NATIVE_INPUT_INVENTORY_BINDING_INVALID')
    return {'canonicalAst': canonical, 'inputBytes': raw_input,
            'canonicalAstIdentity': graph['canonicalIdentity'],
            'inventory': inventory, 'stages': stages}


def replay(receipt, output, *, timeout=120):
    validate_artifacts(receipt, readonly=True)
    fresh = acquire(receipt['context'], receipt['inspectionCompiler'], output,
        target=receipt['target'], timeout=timeout)
    if identity(replay_projection(receipt)) != identity(replay_projection(fresh)):
        raise ValueError('NATIVE_INPUT_INDEPENDENT_REPLAY_MISMATCH')
    body = {'schemaVersion': 'riscv2x86.native-analysis-input-replay.v1',
        'originalNativeInputIdentity': receipt['nativeInputIdentity'],
        'freshNativeInputIdentity': fresh['nativeInputIdentity'],
        'analysisInputIdentity': fresh['analysisInputIdentity'],
        'nativeInputReplayComplete': True, 'compilerEquivalenceVerified': False,
        'sourceInstanceBindingComplete': False, 'semanticApproval': False,
        'productionAcceptanceComplete': False}
    return dict(body, replayIdentity=identity(body))


def replay_projection(value):
    """The same stored-evidence comparison used by independent acquisition."""
    result = {k: v for k, v in value.items() if k not in {
        'nativeInputIdentity', 'canonicalAstPath', 'inventoryPath', 'commands',
        # These new fields are rederived from the context in validate_artifacts.
        # Keep the captured context itself in this exact comparison. Older v1
        # receipts did not record the execution policy; replay proves identical
        # native input/AST, never an otherwise uncaptured historical environment.
        'executionEnvironment', 'executionEnvironmentScope'}}
    result['commands'] = [{k: v for k, v in row.items() if k not in {
        'stdoutPath', 'stderrPath', 'stdoutDigest'}} for row in value['commands']]
    # Raw AST addresses change by process. All other stdout bytes remain
    # exact; AST fields and reference edges are compared by canonical graph.
    for old, row in zip(value['commands'], result['commands']):
        if old['stage'] != 'inspection-native-input':
            row['stdoutDigest'] = old['stdoutDigest']
    return result
