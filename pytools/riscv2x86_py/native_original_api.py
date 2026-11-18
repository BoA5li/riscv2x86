"""Finite object-domain execution of ORIGINAL, audited project candidates.

This is an execution adapter, not a translator or an L2 approval algorithm.
Bodies and libraries come exclusively from native_project_evaluation. The same
finite typed values/alias graph are constructed on both ISAs; internal callee
access legality, machine ABI and canonical coverage remain separate obligations.
"""
import base64
from hashlib import sha256
from pathlib import Path

from . import native_api_contract as api
from . import native_captured_deployment as d
from . import native_project_evaluation as project
from .compiler_native_instance_binding import _nodes
from .native_external_providers import checked
from .project_acquisition import StageFailure, publish_checked
from .project_build_records import identity
from .translation_validation import ProgramArtifact
from .l1_differential import HarnessObservation, ProcessObservation, compare_l1_observations
from .validation_case import ComparisonContract

SCHEMA = 'riscv2x86.original-project-api-execution.v1'
REQUEST = 'riscv2x86.original-project-api-request.v1'
SIDES = ('source', 'target')
MODEL = {'__CHAR_BIT__': '8', '__SIZEOF_POINTER__': '8', '__SIZEOF_SHORT__': '2',
         '__SIZEOF_INT__': '4', '__SIZEOF_LONG__': '8', '__SIZEOF_LONG_LONG__': '8'}


def from_progress(path, *, with_applicability=False):
    """Consume the existing diagnostic checker, including all upstream joins.

    The returned build references may be reused only after build_record checks
    them again in the API operation. No old campaign receipt is relabelled.
    """
    from .native_project_diagnostic import _checked_progress
    _, ctx = _checked_progress(path)
    if ctx.spec_path is None:
        raise ValueError('ORIGINAL_API_PREPARATION_REQUIRED')
    builds = {side: str(Path(row['program']['path']).parent /
                       (Path(row['program']['path']).name + '.project/result.json'))
              for side, row in ctx.builds.items()}
    if with_applicability:
        ref = ctx.prefix['checkpoints']['applicability']
        d.verify_snapshot(ref)
        applicability = d.read(ref['path'])
        if applicability['project'] != d.snapshot(ctx.spec_path):
            raise ValueError('ORIGINAL_API_APPLICABILITY_PROJECT_MISMATCH')
        d.verify_snapshot(ref)
        return str(ctx.spec_path), builds, applicability['facts']
    return str(ctx.spec_path), builds


def selection(ast, records, raw, model, function_path):
    """Join by compiler AST path and edited instances, never by function name."""
    if (not isinstance(function_path, list) or not function_path
            or any(type(i) is not int or i < 0 for i in function_path)):
        raise ValueError('ORIGINAL_API_FUNCTION_PATH_INVALID')
    nodes = list(_nodes(ast))
    fn = project.unique([n for n, p, _ in nodes if p == function_path],
                        'ORIGINAL_API_FUNCTION_NOT_UNIQUE')
    instances = [r for r in records if r['functionAstPath'] == function_path]
    if (not instances or fn.get('kind') != 'FunctionDecl' or fn.get('storageClass') == 'static'
            or not any(n.get('kind') == 'CompoundStmt' for n in fn.get('inner', []))
            or not api.IDENT.fullmatch(fn.get('name', ''))
            or fn.get('mangledName', fn['name']) != fn['name']):
        raise ValueError('ORIGINAL_API_EDITED_EXPORTED_DEFINITION_REQUIRED')
    signature = {'type': fn['type'], 'variadic': fn.get('variadic', False),
                 'attributes': [n['kind'] for n in fn.get('inner', []) if n.get('kind', '').endswith('Attr')],
                 'parameters': [n['type'] for n in fn.get('inner', []) if n.get('kind') == 'ParmVarDecl']}
    resolved = api.resolve_signature(signature, [{'node': n} for n, _, _ in nodes])
    interface = api.signature(resolved, model)
    binding = {'functionAstPath': function_path, 'name': fn['name'],
               'compilerDeclarationIdentity': fn.get('id'), 'signature': resolved,
               'sourceDigest': 'sha256:' + sha256(raw).hexdigest(),
               'instanceBindingIdentities': sorted(r['instanceBindingIdentity'] for r in instances)}
    return {**binding, 'functionBindingIdentity': identity(binding), 'interface': interface}


def context(spec_path):
    from .native_original_applicability import context as load
    spec, ast, records, raw, model = load(spec_path)
    paths = sorted({tuple(r['functionAstPath']) for r in records if r.get('functionAstPath')})
    selections = []; unsupported = []
    for path in paths:
        try:
            selections.append(selection(ast, records, raw, model, list(path)))
        except (KeyError, TypeError, ValueError) as exc:
            unsupported.append({'functionAstPath': list(path), 'reason': str(exc)})
    return spec, selections, unsupported


def inspect(spec_path):
    spec, selections, unsupported = context(spec_path)
    return {'projectEvaluationIdentity': spec['projectEvaluationIdentity'],
            'functions': selections, 'unsupportedFunctions': unsupported,
            'requestSchema': REQUEST, 'domainSchema': api.SCHEMA, 'supportedDomainSchemas': [api.SCHEMA, api.SCHEMA_V2],
            'requestRequiredFields': ['schemaVersion', 'projectEvaluationIdentity', 'functionBindingIdentity',
                                      'domain', 'assumptionSources'],
            'inputPolicy': 'explicit-finite-cases-with-object-values-and-declared-preconditions',
            'domainAvailable': False, 'semanticApproval': False, 'productionAcceptanceComplete': False}


def request_context(spec_path, request_path):
    spec, selections, _ = context(spec_path)
    request = d.read(request_path)
    api.fields(request, ('schemaVersion', 'projectEvaluationIdentity', 'functionBindingIdentity',
                         'domain', 'assumptionSources'), 'ORIGINAL_API_REQUEST')
    if request['schemaVersion'] != REQUEST or request['projectEvaluationIdentity'] != spec['projectEvaluationIdentity']:
        raise ValueError('ORIGINAL_API_REQUEST_PROJECT_MISMATCH')
    selected = project.unique([f for f in selections if f['functionBindingIdentity'] == request['functionBindingIdentity']],
                              'ORIGINAL_API_DECLARATION_BINDING_MISMATCH')
    if (request['domain'].get('schemaVersion')==api.SCHEMA_V2
            and request['domain'].get('sourceDigest')!=selected['sourceDigest']):
        raise ValueError('ORIGINAL_API_DOMAIN_SOURCE_MISMATCH')
    sources = request['assumptionSources']
    if not isinstance(sources, list) or not sources:
        raise ValueError('ORIGINAL_API_PRECONDITION_SOURCES_REQUIRED')
    for ref in sources:
        api.fields(ref, ('path', 'resolvedPath', 'digest'), 'ORIGINAL_API_ASSUMPTION_SOURCE')
        d.verify_snapshot(ref)
    # Validation occurs before any compiler or tested program is launched.
    text, objects = api.harness(selected['name'], selected['interface'], request['domain'])
    return spec, request, selected, text, objects


def create_request(spec_path, domain_path, function_path, assumption_sources, output):
    """Bind a real finite domain; never synthesize missing object constraints."""
    domain_ref = d.snapshot(domain_path); domain = d.read(domain_path)
    spec, functions, _ = context(spec_path)
    selected = project.unique([f for f in functions if f['functionAstPath'] == function_path],
                              'ORIGINAL_API_FUNCTION_SELECTION_REQUIRED')
    # The exact original API contract validator owns domain legality checks.
    if domain.get('schemaVersion')==api.SCHEMA_V2 and domain.get('sourceDigest')!=selected['sourceDigest']:
        raise ValueError('ORIGINAL_API_DOMAIN_SOURCE_MISMATCH')
    api.validate(domain, selected['interface'])
    refs = [d.snapshot(p) for p in assumption_sources]
    if not refs: raise ValueError('ORIGINAL_API_PRECONDITION_SOURCES_REQUIRED')
    d.verify_snapshot(domain_ref)
    request = {'schemaVersion': REQUEST, 'projectEvaluationIdentity': spec['projectEvaluationIdentity'],
               'functionBindingIdentity': selected['functionBindingIdentity'], 'domain': domain,
               'assumptionSources': refs}
    publish_checked(Path(output), request, lambda p: request_context(spec_path, p))
    return request


def witness(selected):
    # Compiler type compatibility plus ABI data-model queries on BOTH sides.
    # These establish declaration/layout facts, not actual machine ABI behavior.
    # These are appended to frozen CPP bytes: predefined macros would NOT be
    # expanded under -x cpp-output. Query C types directly, including CHAR_BIT.
    checks = '\n_Static_assert((unsigned char)255==255 && (unsigned char)256==0,"API byte width");'
    checks += ''.join('\n_Static_assert(sizeof(' + t + ')==' + str(n) + ',"API model");'
                      for t, n in (('void *', 8), ('short', 2), ('int', 4), ('long', 8), ('long long', 8)))
    return ('\n' + checks + api.declaration_witness(selected['name'], selected['interface'])).encode()


def entry_object(profile):
    candidates = []
    for row in profile['entry']['inputs']:
        raw = Path(row['path']).read_bytes()
        if not raw.startswith(b'\x7fELF'):
            continue
        elf = d.parse(raw)
        if elf['elfType'] == 1 and any(s[0] == 'main' for s in d.definitions(elf)):
            candidates.append(row)
    return project.unique(candidates, 'ORIGINAL_API_MAIN_OBJECT_NOT_UNIQUE')


def recipe(spec, builds, selected, root):
    root = Path(root)
    rows = []
    for side in SIDES:
        profile = spec['profiles'][side]; compiler = profile['compile']
        library = builds[side]['library']; old_main = entry_object(profile)
        # The generated driver replaces only the captured entry's main object.
        # All library positions, link switches and dependency ordering survive.
        replacements = {i: Path(library['path']) for i in profile['entryLibraryPositions']}
        if old_main['argumentIndex'] in replacements:
            raise ValueError('ORIGINAL_API_MAIN_LIBRARY_POSITION_COLLISION')
        replacements[old_main['argumentIndex']] = root / (side + '-driver.o')
        common = (compiler['directory'], compiler['environment'])
        argv = d._argv(profile['entry'], root / (side + '-program'), replacements,
                       str(Path(library['path']).parent))
        if any(project.inputs_equal(i, builds[side]['object']) for i in profile['entry']['inputs']):
            raise ValueError('ORIGINAL_API_BODY_ALREADY_IN_ENTRY_REQUIRES_DISTINCT_RECIPE')
        # Bind the tested body explicitly, ahead of libraries; never rely on a
        # system library or archive member to supply the tested definition.
        argv.insert(1, builds[side]['object']['path'])
        argv += ['-Xlinker', '-Map', '-Xlinker', str(root / (side + '-link.map'))]
        rows += [('witness-' + side, [compiler['compiler']['path'], *compiler['flags'], '-Werror', '-c',
                     str(root / (side + '-witness.i')), '-o', str(root / (side + '-witness.o'))], *common),
                 ('driver-' + side, [compiler['compiler']['path'], *compiler['flags'], '-x', 'c', '-std=gnu11',
                     '-Werror', '-c', str(root / 'driver.c'), '-o', str(root / (side + '-driver.o'))], *common),
                 ('link-' + side, argv,
                  profile['entry']['directory'], profile['environment'])]
    for side in SIDES:
        prefix = [spec['qemu']['path'], '-L', spec['runtimePrefix']] if side == 'source' else []
        rows.append(('run-' + side, [*prefix, str(root / (side + '-program'))], str(root),
                     spec['profiles'][side]['environment']))
    return rows


def current_builds(spec, inputs):
    builds = {}
    for side in SIDES:
        ref = inputs['builds'][side]; d.verify_snapshot(ref)
        row = d.read(ref['path']); artifact = row['program']
        program = ProgramArtifact(side, artifact['path'], 'executable', artifact['digest'])
        builds[side] = project.build_record(program, spec, side)
        if row != builds[side]:
            raise ValueError('ORIGINAL_API_BUILD_CHANGED')
    return builds


def compare_runs(rows, root, selected, domain):
    """Original comparator plus mandatory per-case/object completion protocol."""
    observations = {}; protocols = {}; returns = {}; failures = {}; preservation = {}
    for side in SIDES:
        row = rows['run-' + side]; folder = Path(root) / ('run-' + side)
        stdout = (folder / 'stdout.log').read_bytes(); stderr = (folder / 'stderr.log').read_bytes()
        protocols[side] = api.output_protocol(stdout, selected['interface'], domain)
        if domain.get('schemaVersion')==api.SCHEMA_V2:
            from .native_api_projection import inspect_output
            preservation[side] = inspect_output(stdout, selected['interface'], domain)['preservationViolations']
        else: preservation[side] = []
        returns[side] = row['returnCode']; failures[side] = row['failureReason']
        observations[side] = ProcessObservation(HarnessObservation(None, (), (), (), ()), row['returnCode'],
            base64.b64encode(stdout).decode(), base64.b64encode(stderr).decode(), ())
    mismatches = list(compare_l1_observations(observations['source'], observations['target'],
                                           ComparisonContract(False, True, True, True, False, (), (), (), ())))
    status = ('failed' if any(failures.values()) or any(code != 0 for code in returns.values()) or mismatches or any(preservation.values())
              else 'inconclusive' if not all(protocols.values()) else 'observed-agreement')
    return {'processObservationStatus': status, 'mismatches': mismatches, 'protocolComplete': protocols,
            'returnCodes': returns, 'executionFailures': failures,
            'preservationViolations': preservation}


def derive(result_path):
    root = Path(result_path).resolve().parent
    inputs = d.read(root / 'inputs.json'); checked(inputs, 'apiInputIdentity')
    api.fields(inputs, ('schemaVersion', 'spec', 'request', 'builds', 'apiInputIdentity'), 'ORIGINAL_API_INPUTS')
    if inputs['schemaVersion'] != REQUEST:
        raise ValueError('ORIGINAL_API_INPUT_SCHEMA_INVALID')
    api.fields(inputs['builds'], SIDES, 'ORIGINAL_API_BUILDS')
    for k in ('spec', 'request'): d.verify_snapshot(inputs[k])
    spec, request, selected, text, objects = request_context(inputs['spec']['path'], inputs['request']['path'])
    builds = current_builds(spec, inputs)
    if (root / 'driver.c').read_text() != text:
        raise ValueError('ORIGINAL_API_DRIVER_REDERIVATION_MISMATCH')
    artifacts = [d.snapshot(root / 'driver.c')]; attribution = {}
    for side in SIDES:
        expected = Path(builds[side]['input']['path']).read_bytes() + witness(selected)
        if (root / (side + '-witness.i')).read_bytes() != expected:
            raise ValueError('ORIGINAL_API_DECLARATION_WITNESS_CHANGED')
        objelf = d.parse(Path(builds[side]['object']['path']).read_bytes())
        symbols = [s for s in d.definitions(objelf) if s[0] == selected['name'] and s[1:3] == (1, 2)]
        if len(symbols) != 1:
            raise ValueError('ORIGINAL_API_STRONG_BODY_DEFINITION_REQUIRED')
        for name, types in ((side + '-program', (2, 3)), (side + '-driver.o', (1,)), (side + '-witness.o', (1,))):
            elf = d.parse((root / name).read_bytes())
            if elf['machine'] != spec['profiles'][side]['machine'] or elf['elfType'] not in types:
                raise ValueError('ORIGINAL_API_ARTIFACT_ROLE_MISMATCH')
        artifacts.extend(d.snapshot(root / (side + suffix)) for suffix in
                         ('-program', '-driver.o', '-witness.o', '-witness.i', '-link.map'))
        try:
            facts = d.attribution(builds[side]['object']['path'], root / (side + '-program'), root / (side + '-link.map'))
            attribution[side] = [r for r in facts['definitions'] if r['symbol']['name'] == selected['name']]
        except ValueError as exc:
            attribution[side] = [{'verified': False, 'reason': str(exc)}]
    rows = {}; logs = []
    for name, argv, cwd, env in recipe(spec, builds, selected, root):
        row = project.validate_execution_record(d.read(root / name / 'execution.json'))
        expected = {'arguments': argv, 'directory': cwd, 'environment': env}
        if any(row[k] != value for k, value in expected.items()):
            raise ValueError('ORIGINAL_API_EXECUTION_RECIPE_CHANGED:' + name)
        if not name.startswith('run-') and (row['returnCode'] != 0 or row['failureReason'] is not None):
            raise ValueError('ORIGINAL_API_BUILD_EXECUTION_FAILED:' + name)
        rows[name] = row
        logs.extend(d.snapshot(root / name / f) for f in ('execution.json', 'stdout.log', 'stderr.log'))
    # Hash equality alone is not sufficient: regenerate driver, commands, type
    # witnesses, output protocol and comparison from their checked authorities.
    result = {'schemaVersion': SCHEMA, 'apiInputIdentity': inputs['apiInputIdentity'],
              'function': selected, 'caseCount': len(request['domain']['cases']),
              'objectConstructionContract': objects,
              'regionProjection': [c.get('regions') for c in api.validate(request['domain'], selected['interface'])],
              'assumptionSources': request['assumptionSources'],
              'artifacts': artifacts, 'executionEvidence': logs,
              'bodyLinkAttribution': attribution,
              **compare_runs(rows, root, selected, request['domain']),
              'compilerDeclarationWitnessesComplete': True,
              'sourceTargetInputRelation': 'same-finite-typed-values-and-object-alias-graph',
              'gaps': list(spec['gaps']), 'canonicalInstructionExecutionVerified': False,
              'internalObjectAccessProofComplete': False, 'machineAbiProofComplete': False,
              'formalValidationPerformed': False, 'semanticApproval': False, 'productionAcceptanceComplete': False,
              'scope': 'bounded-original-project-api-under-declared-preconditions-not-L2-L3-acceptance'}
    return d.seal(result, 'apiExecutionIdentity')


def check(path):
    value = d.read(path); checked(value, 'apiExecutionIdentity')
    if value != derive(path):
        raise ValueError('ORIGINAL_API_REDERIVATION_MISMATCH')
    return value


def acquire(spec_path, request_path, output, *, builds=None):
    spec_ref, request_ref = d.snapshot(spec_path), d.snapshot(request_path)
    spec, request, selected, text, _ = request_context(spec_path, request_path)
    d.verify_snapshot(spec_ref); d.verify_snapshot(request_ref)
    root = Path(output).absolute()
    if root.exists() or root.is_symlink(): raise FileExistsError(str(root))
    root.mkdir(parents=True); root = root.resolve()
    project.write(root / 'acquisition-status.json', {'status': 'running', 'semanticApproval': False})
    try:
        refs = {}
        for side in SIDES:
            if builds is not None and side in builds:
                ref = d.snapshot(builds[side]); refs[side] = ref
            else:
                run = d.read(spec['run']['path'])
                if side == 'source':
                    inp = d.read(run['input']['path'])['source']['path']
                else:
                    inp = str(Path(d.read(run['translation']['path'])['candidateManifest']['path']).parent /
                              'candidate-staging/input.i')
                project.build_side(spec_path, side, inp, root / (side + '-baseline'))
                refs[side] = d.snapshot(root / (side + '-baseline.project/result.json'))
        d.verify_snapshot(spec_ref); d.verify_snapshot(request_ref)
        inputs = d.seal({'schemaVersion': REQUEST, 'spec': spec_ref, 'request': request_ref,
                         'builds': refs}, 'apiInputIdentity')
        project.write(root / 'inputs.json', inputs)
        verified = current_builds(spec, inputs)
        (root / 'driver.c').write_text(text)
        for side in SIDES:
            (root / (side + '-witness.i')).write_bytes(Path(verified[side]['input']['path']).read_bytes() + witness(selected))
        for name, argv, cwd, env in recipe(spec, verified, selected, root):
            code, failure = project.command(argv, cwd, env, root / name, spec['timeoutSeconds'])
            if not name.startswith('run-') and (code != 0 or failure):
                raise StageFailure('api-' + name, code or 2)
        value = derive(root / 'result.json')
        publish_checked(root / 'result.json', value, check)
        project.write(root / 'acquisition-status.json', {'status': 'complete', 'semanticApproval': False})
        return value
    except Exception as exc:
        project.write(root / 'acquisition-status.json', {'status': 'failed', 'error': type(exc).__name__,
                                                      'detail': str(exc), 'semanticApproval': False})
        raise
