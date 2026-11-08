"""Evidence bridge to the existing project input/binding and L2 vocabulary.

This inventory is NOT an eligibility certificate. Source lineage is distinct
from target-context equivalence, ABI, object legality and program behavior.
All conclusions are rederived; input JSON approval booleans are never imported.
"""
import json
from pathlib import Path

from . import native_captured_deployment as deployment
from . import project_native_input as native
from . import project_native_binding as binding
from .project_compile_context import derive as compile_context, validate as validate_context
from .project_build_records import identity
from .project_compile_context import digest
from .compiler_native_instance_binding import _nodes
from .native_project_translation import preserve_edits
from .l2_dimensions import L2DimensionStatus

SCHEMA = 'riscv2x86.native-context-bridge.v1'


def declarations(ast, ast_identity):
    """Preserve references/AST paths; names and type strings are evidence only."""
    rows = []
    for node, path, function in _nodes(ast):
        if node.get('kind') not in ('FunctionDecl', 'CallExpr', 'VarDecl'):
            continue
        row = {'astIdentity': ast_identity, 'astPath': path, 'functionAstPath': function,
               'kind': node['kind'], 'declarationId': node.get('id'),
               'name': node.get('name'), 'type': node.get('type'),
               'variadic': node.get('variadic', False), 'range': node.get('range'),
               'parameters': [{'declarationId': n.get('id'), 'name': n.get('name'),
                               'type': n.get('type'), 'range': n.get('range')}
                              for n in node.get('inner', []) if n.get('kind') == 'ParmVarDecl'],
               'storageClass': node.get('storageClass'),
               'attributes': [n for n in node.get('inner', []) if n.get('kind', '').endswith('Attr')],
               'referencedDeclarations': [n['referencedDecl'] for n, _, _ in _nodes(node)
                                          if 'referencedDecl' in n],
               'abiContractVerified': False, 'objectContractVerified': False}
        rows.append(dict(row, evidenceIdentity=identity(row)))
    return rows


def dependency_changes(source, target):
    """Compare exact resolved dependencies; different headers are not approved."""
    def index(receipt):
        result = {}
        for row in receipt['analysisInput']['nativeDependencies']:
            key = row['resolvedPath']
            if key in result and result[key] != row:
                raise ValueError('CONTEXT_BRIDGE_DEPENDENCY_AMBIGUOUS')
            result[key] = row
        return result
    left, right = index(source), index(target)
    return [{'resolvedPath': p, 'source': left.get(p), 'target': right.get(p)}
            for p in sorted(left.keys() | right.keys()) if left.get(p) != right.get(p)]


def validated_input(receipt):
    artifacts = native.validate_artifacts(receipt)
    validate_context(receipt['context'])
    analysis = receipt['analysisInput']
    if (analysis['contextIdentity'] != receipt['context']['contextIdentity']
            or analysis['sourceDigest'] != receipt['context']['sourceDigest']
            or analysis['target'] != receipt['target']
            or analysis['dataModels']['native'] != analysis['dataModels']['inspection']):
        raise ValueError('CONTEXT_BRIDGE_INPUT_CONTEXT_MISMATCH')
    for path, expected in analysis['tools'].items():
        if digest(path) != expected:
            raise ValueError('CONTEXT_BRIDGE_INPUT_TOOL_CHANGED')
    for row in analysis['nativeDependencies']:
        path = Path(row['compilerPath'])
        if not path.is_absolute():
            path = Path(receipt['context']['workingDirectory'])/path
        if (str(path.resolve(strict=True)) != row['resolvedPath']
                or digest(path) != row['digest']):
            raise ValueError('CONTEXT_BRIDGE_INPUT_DEPENDENCY_CHANGED')
    if any(type(r['returnCode']) is not int or r['returnCode'] != 0 for r in receipt['commands']):
        raise ValueError('CONTEXT_BRIDGE_INPUT_COMMAND_FAILED')
    return artifacts


def commands(candidate):
    rows = {}
    for row in candidate['commands']:
        if row['stage'] in rows:
            raise ValueError('CONTEXT_BRIDGE_DUPLICATE_COMMAND')
        if type(row['returnCode']) is not int or row['returnCode'] != 0:
            raise ValueError('CONTEXT_BRIDGE_CANDIDATE_COMMAND_FAILED')
        for stream in ('stdout', 'stderr'):
            if digest(row[stream+'Path']) != row[stream+'Digest']:
                raise ValueError('CONTEXT_BRIDGE_COMMAND_CHANGED')
        rows[row['stage']] = row
    return rows


def inputs(plan):
    deployment.validate(plan)
    candidate, _, _ = deployment.candidate_inputs(plan['candidatePath'])
    if digest(candidate['bindingBundlePath']) != candidate['bindingBundleDigest']:
        raise ValueError('CONTEXT_BRIDGE_BUNDLE_CHANGED')
    bundle = deployment.read(candidate['bindingBundlePath'])
    bindings, contexts = binding.validate_artifacts(bundle)
    source = deployment.read(bundle['nativeInputReceiptPath'])
    artifacts = validated_input(source)
    if (candidate['bindingBundleIdentity'] != bundle['bindingBundleIdentity']
            or candidate['analysisInputIdentity'] != source['analysisInputIdentity']
            or source['target'] != 'riscv64'):
        raise ValueError('CONTEXT_BRIDGE_SOURCE_BINDING_MISMATCH')
    producer = compile_context(plan['originalObjectProducer'])
    validate_context(producer)
    return candidate, source, artifacts, producer, bindings, contexts


def observation_inventory(path, plan):
    from .native_deployment_observation import check_observation
    from .native_dynamic_obligations import inspect
    observed = check_observation(path)
    deployed = deployment.check_result(observed['deploymentPath'])
    if deployed['deploymentPlanIdentity'] != plan['deploymentPlanIdentity']:
        raise ValueError('CONTEXT_BRIDGE_OBSERVATION_PLAN_MISMATCH')
    # Corrected metadata derivation also applies when the preserved observation
    # uses the older v2 policy. It does not rewrite the old observation.
    objects = [o['file']['path'] for o in observed['dynamicObligations']['objects']]
    dynamic = inspect(objects)
    endpoints = [row[k] for row in observed['diagnosticBindings'] for k in ('requester', 'provider')]
    return {'observationIdentity': observed['observationIdentity'],
            'schemaVersion': observed['schemaVersion'],
            'diagnosticEventCount': len(observed['diagnosticBindings']),
            'unparsedLineCount': len(observed['unparsedBindingLines']),
            'unverifiedEndpointOccurrences': sum(e['runtimeIdentityVerified'] is not True for e in endpoints),
            'unsupportedRelocations': [{'file': o['file'], **r}
                for o in dynamic['objects'] for r in o['relocationObligations'] if r['role'] == 'unsupported'],
            'runtimeBindingClosureComplete': False, 'eventsProveCalls': False}


def derive(plan, candidate, source, artifacts, producer, target, target_artifacts, bindings, contexts, observation_path=None):
    rows = commands(candidate)
    raw = artifacts['inputBytes']
    if (rows['source-object-build']['stdinIdentity'] != native.bytes_identity(raw)
            or rows['target-object-build']['stdinIdentity'] != candidate['candidateDigest']
            or preserve_edits(raw, candidate['edits']) != Path(candidate['candidatePath']).read_bytes()):
        raise ValueError('CONTEXT_BRIDGE_FROZEN_INPUT_MISMATCH')
    # Comparing bytes proves common input lineage only, never cross-ISA ABI.
    lineage = (source['context']['sourceDigest'] == producer['sourceDigest']
               and source['context']['sourceDigest'] is not None)
    if (target['target'] != 'x86_64' or target['context'] != producer):
        raise ValueError('CONTEXT_BRIDGE_TARGET_PRODUCER_MISMATCH')
    # Verify the original native capture's output is the selected object.
    if (Path(producer['outputPath']).resolve(strict=True)
            != Path(plan['originalObject']['resolvedPath']).resolve(strict=True)):
        raise ValueError('CONTEXT_BRIDGE_PRODUCER_OUTPUT_MISMATCH')
    from .native_audit_evidence import canonical_stdout
    canonical_stdout(candidate, rows['target-ast'])
    candidate_ast = deployment.read(Path(candidate['candidatePath']).parent/'target-ast.json')
    source_stages = artifacts['stages']; target_stages = target_artifacts['stages']
    comparisons = {}
    for stage in ('native-expanded', 'native-definitions', 'native-macros', 'native-specs'):
        comparisons[stage] = {'sourceDigest': source_stages[stage]['stdoutDigest'],
                              'targetDigest': target_stages[stage]['stdoutDigest'],
                              'bytesEqual': source_stages[stage]['stdoutDigest'] == target_stages[stage]['stdoutDigest']}
    instance_rows = []
    for edit in candidate['edits']:
        selected = [r for r in bindings['records']
                    if r['instanceBindingIdentity'] == edit['instanceBindingIdentity']
                    and r['physicalStatementRange'] == edit['sourceRange']
                    and r['statementDigest'] == edit['sourceDigest']]
        if len(selected) != 1:
            raise ValueError('CONTEXT_BRIDGE_INSTANCE_BINDING_MISMATCH')
        key = {'analysisInputIdentity': source['analysisInputIdentity'],
               'instanceBindingIdentity': edit['instanceBindingIdentity'], 'sourceRange': edit['sourceRange'],
               'sourceFunctionAstPath': selected[0]['functionAstPath'],
               'candidateIdentity': candidate['candidateIdentity'],
               'producerContextIdentity': producer['contextIdentity'],
               'deploymentPlanIdentity': plan['deploymentPlanIdentity']}
        instance_rows.append(dict(key, bridgeInstanceIdentity=identity(key),
                                  executionCoverageVerified=False))
    observed = observation_inventory(observation_path, plan) if observation_path else None
    obligations = [
        ('runtime-binding', 'NATURAL_RUN_OBJECT_IDENTITY_AND_APPLICABLE_BINDINGS_REQUIRED'),
        ('entry-abi', 'DECLARATIONS_REQUIRE_NATIVE_ABI_AND_MACHINE_JOIN'),
        ('legal-objects-inputs', 'INITIALIZATION_LIFETIME_BOUNDS_ALIAS_AND_PRECONDITIONS_REQUIRED'),
        ('output-termination', 'SOURCE_TARGET_EFFECT_AND_TERMINATION_RELATION_REQUIRED'),
        ('program-validation', 'INSTANCE_EXECUTION_L0_L3_AND_INDEPENDENT_PROGRAM_AUDIT_REQUIRED'),
        ('target-context', 'FROZEN_SOURCE_CPP_TO_NATIVE_TARGET_CONTEXT_RELATION_REQUIRED')]
    if not lineage:
        obligations.append(('source-lineage', 'SOURCE_CONTENT_LINEAGE_MISMATCH'))
    body = {'schemaVersion': SCHEMA, 'deploymentPlanIdentity': plan['deploymentPlanIdentity'],
            'candidateIdentity': candidate['candidateIdentity'],
            'sourceNativeInputIdentity': source['nativeInputIdentity'],
            'targetNativeInputIdentity': target['nativeInputIdentity'],
            'bindingInventoryIdentity': bindings['bindingInventoryIdentity'],
            'contextInventoryIdentity': contexts['contextInventoryIdentity'],
            'sourceContextIdentity': source['context']['contextIdentity'],
            'targetContextIdentity': producer['contextIdentity'],
            'sourceContentLineageVerified': lineage,
            'sourceAndTargetSourcePathEqual': source['context']['sourcePath'] == producer['sourcePath'],
            'targetNativeInputAcquired': True,
            'candidateTargetArguments': rows['target-object-build']['command'],
            'producerTargetArguments': producer['originalAction']['arguments'],
            'preprocessingComparisons': comparisons,
            'dependencyDifferences': dependency_changes(source, target),
            'candidateTargetDeclarations': declarations(candidate_ast, candidate['targetAstIdentity']),
            'sourceDeclarations': declarations(artifacts['canonicalAst'], source['canonicalAstIdentity']),
            'targetNativeDeclarations': declarations(target_artifacts['canonicalAst'], target['canonicalAstIdentity']),
            'instances': instance_rows, 'runtimeObservationInventory': observed,
            'frameworkEvaluationReadiness': {level: {'status': L2DimensionStatus.NOT_RUN.value,
                'reasonCode': 'COMMON_FRAMEWORK_ADMISSION_AND_PROGRAM_EVIDENCE_REQUIRED'}
                for level in ('L0', 'L1', 'L2', 'L3')},
            'obligations': [{'stage': stage, 'reasonCode': reason,
                             'status': L2DimensionStatus.INCONCLUSIVE.value} for stage, reason in obligations],
            'targetContextCompatibilityVerified': False, 'entryAbiContractComplete': False,
            'legalObjectInputContractComplete': False, 'outputTerminationContractComplete': False,
            'translatedInstanceExecutionVerified': False, 'l0L3AcceptanceComplete': False,
            'externalContractClosureComplete': False,
            'scope': 'input-lineage-and-native-target-context-inventory-not-semantic-eligibility',
            'semanticApproval': False, 'productionAcceptanceComplete': False}
    return deployment.seal(body, 'contextBridgeIdentity')


def acquire(plan_path, output, *, clang, timeout=300, observation_path=None):
    from .native_deployment_prerequisites import output_path
    root = output_path(output)
    plan = deployment.read(plan_path)
    candidate, source, artifacts, producer, bindings, contexts = inputs(plan)
    # Reject an incompatible observation/audit before expensive target CPP
    # acquisition or creating an incomplete output directory. Recheck later
    # during derivation to detect changes during acquisition.
    if observation_path is not None:
        observation_inventory(observation_path, plan)
    root.mkdir()
    # Reuse the native input acquisition and its dependency/tool/data-model
    # checks. In particular, do not add -DPIC to already expanded source CPP.
    target = native.acquire(producer, clang, root/'target-native-input', target='x86_64', timeout=timeout)
    target_artifacts = validated_input(target)
    candidate, source, artifacts, producer, bindings, contexts = inputs(plan)
    report = derive(plan, candidate, source, artifacts, producer, target, target_artifacts, bindings, contexts, observation_path)
    body = {'schemaVersion': 'riscv2x86.native-context-bridge-inputs.v1',
            'plan': deployment.snapshot(plan_path),
            'targetReceipt': deployment.snapshot(root/'target-native-input/native-input.json'),
            'observation': deployment.snapshot(observation_path) if observation_path else None}
    manifest = deployment.seal(body, 'contextBridgeInputsIdentity')
    (root/'inputs.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (root/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    check(root/'result.json')
    return report


def check(path):
    from .native_external_providers import checked
    path = Path(path).resolve(strict=True)
    stored = deployment.read(path)
    checked(stored, 'contextBridgeIdentity')
    manifest = deployment.read(path.parent/'inputs.json')
    checked(manifest, 'contextBridgeInputsIdentity')
    if manifest['schemaVersion'] != 'riscv2x86.native-context-bridge-inputs.v1':
        raise ValueError('CONTEXT_BRIDGE_INPUT_SCHEMA_INVALID')
    for key in ('plan', 'targetReceipt'):
        deployment.verify_snapshot(manifest[key])
    if manifest['observation'] is not None:
        deployment.verify_snapshot(manifest['observation'])
    plan = deployment.read(manifest['plan']['path'])
    candidate, source, artifacts, producer, bindings, contexts = inputs(plan)
    target = deployment.read(manifest['targetReceipt']['path'])
    target_artifacts = validated_input(target)
    fresh = derive(plan, candidate, source, artifacts, producer, target, target_artifacts, bindings, contexts,
                   manifest['observation']['path'] if manifest['observation'] else None)
    if stored != fresh:
        raise ValueError('CONTEXT_BRIDGE_REDERIVATION_MISMATCH')
    return stored
