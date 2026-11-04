"""Bounded SYSTEM L3: reviewed machine mechanism plus actual logical state.

This is a separate versioned policy, not the legacy compiler-region policy.
The kernel/adapter event IDs are protocol observations, NOT a hardware PC trace.
No native privilege, future interrupt, timing or physical equivalence is claimed.
"""
import json
from pathlib import Path
import tempfile
import subprocess

from . import controlled_system_runner as system
from .controlled_system_backend import build_program, require_build_profile
from .l3_trace_support import Elf, digest, identity, require_json_document, require_json_match
from .translation_validation import ValidationLevel, ValidationLayerResult
from .validation_status import ValidationStatus
from .validation_timing import timed

SCHEMA = 'riscv2x86.controlled-system-l3-result.v1'
POLICY = {
    'policyId': 'bounded-controlled-system-intent.v1',
    'domain': 'single-hart-m-bare-trap-or-prepending-mtip',
    'properties': ['approved-shell', 'attributed-machine-operation',
                   'actual-logical-state-and-protocol', 'complete-execution'],
    'observationKind': 'reviewed-kernel-and-adapter-state-protocol',
    'excluded': ['hardware-pc-trace', 'native-linux-user-equivalence',
                 'future-interrupt-arrival', 'unbounded-liveness', 'cross-hart',
                 'program-mmio', 'physical-timing', 'physical-microarchitecture',
                 'full-native-machine-state', 'multiple-system-instructions'],
}


def _seal(body):
    require_json_document(body)
    return dict(body, evidenceIdentity=identity(body))


def implementation_identity():
    from .l3_implementation_dependencies import implementation_dependencies
    root = Path(__file__).resolve().parent
    return identity({name:digest(root/name) for name in implementation_dependencies()})


def _json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('SYSTEM_L3_DUPLICATE_JSON_KEY:'+key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('SYSTEM_L3_NONFINITE_JSON:'+value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def validate_observation(observation):
    require_json_document(observation)
    if observation.get('schemaVersion') != system.RESULT or observation.get('level') != 'L1':
        raise ValueError('SYSTEM_L3_OBSERVATION_SCHEMA_INVALID')
    system.validate_persisted_result(observation)
    if observation.get('status') != 'verified':
        raise ValueError('SYSTEM_L3_VERIFIED_OBSERVATION_REQUIRED')
    for side in ('source','target'):
        record = observation['executions'][side]
        if (type(record.get('returnCode')) is not int or record['returnCode'] != 0
                or record.get('timedOut') is not False
                or type(record.get('stdout')) is not str or type(record.get('stderr')) is not str):
            raise ValueError('SYSTEM_L3_EXECUTION_TYPES_INVALID')
        require_json_match(system.expected(observation['nonce']['operation']), record['state'],
                           'SYSTEM_L3_STATE_RELATION_MISMATCH')
        rows = record['stdout'].splitlines()
        if len(rows) != 1 or not rows[0].startswith('RV2X86_SYSTEM:'):
            raise ValueError('SYSTEM_L3_RAW_PROTOCOL_INVALID')
        require_json_match(record['state'], _json(rows[0][len('RV2X86_SYSTEM:'):]),
                           'SYSTEM_L3_RAW_PROTOCOL_MISMATCH')
    return observation


@timed('system.l3-machine-attribution')
def mechanism(programs, config, finding):
    """Decode the entire bounded entry, never search arbitrary byte substrings."""
    from .l3_atomic_machine import decode
    symbol = config['scope']['functionSymbol']
    source = Elf(programs['source']['path'])
    target = Elf(programs['target']['path'])
    if source.machine != 243 or target.machine != 62:
        raise ValueError('SYSTEM_L3_MACHINE_MISMATCH')
    raw = source.code(symbol)
    base = source.symbol(symbol)[0]
    if len(raw) % 4:
        raise ValueError('SYSTEM_L3_RV64I_ALIGNED_ENTRY_REQUIRED')
    opcode = {'ecall': bytes.fromhex('73000000'),
              'wfi': bytes.fromhex('73005010')}[config['operation']]
    offsets = [i for i in range(0, len(raw), 4) if raw[i:i+4] == opcode]
    if len(offsets) != 1:
        raise ValueError('SYSTEM_L3_SINGLE_MACHINE_OPERATION_REQUIRED')
    offset = offsets[0]
    patched = raw[:offset] + bytes.fromhex('13000000') + raw[offset+4:]
    rows = decode(patched, base, source.machine)
    if (not rows or rows[-1]['op'] != 'return'
            or any(r['op'] == 'return' for r in rows[:-1])
            or any(r['op'] not in {'add', 'load', 'store', 'return'} for r in rows)
            or not any(r['pc'] == base+offset and r['size'] == 4 for r in rows)):
        raise ValueError('SYSTEM_L3_SOURCE_STRAIGHT_ENTRY_REQUIRED')
    # The approved source scope is a sole no-operand SYSTEM asm. Ordinary
    # decoded instructions are compiler shell; whole-image rebuild binds them.
    target_raw = target.code(symbol)
    target_base = target.symbol(symbol)[0]
    callee = finding['approvalArtifact']['privilegedCallableIdentifier']
    callee_address = target.symbol(callee)[0]
    calls = []
    decoded = []
    i = 0
    while i < len(target_raw):
        if target_raw[i] == 0xe8:
            if i+5 > len(target_raw):
                raise ValueError('SYSTEM_L3_TARGET_CALL_TRUNCATED')
            destination = target_base+i+5+int.from_bytes(target_raw[i+1:i+5], 'little', signed=True)
            calls.append({'pc': target_base+i, 'target': destination})
            decoded.append({'op': 'call', 'pc': target_base+i, 'size': 5})
            i += 5
            continue
        found = None
        for size in range(1, min(15, len(target_raw)-i)+1):
            try:
                part = decode(target_raw[i:i+size], target_base+i, target.machine)
                if len(part) == 1 and part[0]['size'] == size:
                    found = part[0]
                    break
            except (ValueError, IndexError):
                pass
        if found is None:
            raise ValueError('SYSTEM_L3_TARGET_ENCODING_UNSUPPORTED:'+hex(target_base+i))
        decoded.append(found)
        i += found['size']
    if (len(calls) != 1 or calls[0]['target'] != callee_address or not decoded
            or decoded[-1]['op'] != 'return'
            or any(r['op'] not in {'call','nop','push','move','add','auxiliary','return'} for r in decoded)
            or any(r['op'] == 'return' for r in decoded[:-1])):
        raise ValueError('SYSTEM_L3_APPROVED_DIRECT_CALLEE_REQUIRED')
    return {'sourceEntry': {'symbol': symbol, 'address': base, 'bytes': raw.hex(),
                           'operationPC': base+offset, 'operationBytes': opcode.hex()},
            'targetEntry': {'symbol': symbol, 'address': target_base, 'bytes': target_raw.hex(),
                            'callee': callee, 'calleeAddress': callee_address, 'call': calls[0]},
            'basis': 'whole-entry-decoding-and-independent-whole-image-rebuild',
            'hardwarePCTraceObserved': False}


@timed('system.l3-independent-build-matrix')
def rebuild(programs, config, matrix):
    """Fresh build in an independent workspace; no digest-only approval."""
    from .system_build_profile import require_identical_rebuild, program_command, inspect_elf
    backend = system.load_config(config)
    expected = {(side, opt) for side in ('source','target') for opt in ('-O0','-O2','-O3')}
    if (not isinstance(matrix, list) or len(matrix) != len(expected)
            or {(r['side'], r['optimization']) for r in matrix} != expected):
        raise ValueError('SYSTEM_L3_L0_MATRIX_INCOMPLETE')
    with tempfile.TemporaryDirectory(prefix='rv2x86-system-l3-rebuild-') as directory:
        for old in matrix:
            side, opt = old['side'], old['optimization']
            source = config['sourcePath'] if side == 'source' else config['targetPath']
            mode = require_build_profile(backend)['relaxMode']
            text, plan = program_command(backend, side=side, source=source,
                symbol=config['scope']['functionSymbol'], operation=config['operation'],
                output=old['programPath'], optimization=opt, relax_mode=mode)
            if (old['schemaVersion'] != 'riscv2x86.system-program-build.v2'
                    or type(old['returnCode']) is not int or old['returnCode'] != 0
                    or old['operation'] != config['operation'] or old['relaxMode'] != mode
                    or Path(old['sourcePath']).resolve() != Path(source).resolve()
                    or old['sourceDigest'] != digest(source)
                    or old['wrapperDigest'] != digest(Path(old['workspace'])/'system-wrapper.c')
                    or (Path(old['workspace'])/'system-wrapper.c').read_text() != text
                    or old['command'] != plan[-1]['command'] or old['workspace'] != plan[0]['cwd']
                    or len(old['steps']) != len(plan)
                    or old['programDigest'] != digest(old['programPath'])):
                raise ValueError('SYSTEM_L3_L0_BUILD_RECORD_CHANGED')
            require_json_match(inspect_elf(old['programPath'], side), old['elfChecks'], 'SYSTEM_L3_L0_ELF_CHANGED')
            for actual, step in zip(old['steps'], plan):
                require_json_match(step, {k:actual[k] for k in step}, 'SYSTEM_L3_L0_COMMAND_CHANGED')
                if (type(actual['returnCode']) is not int or actual['returnCode'] != 0 or actual['timedOut'] is not False
                        or digest(Path(actual['cwd'])/actual['output']) != actual['outputDigest']):
                    raise ValueError('SYSTEM_L3_L0_PRODUCT_CHANGED')
                require_json_match({name:digest(Path(actual['cwd'])/name) for name in step['inputs']},
                    actual['inputDigests'], 'SYSTEM_L3_L0_INPUT_CHANGED')
            record = build_program(backend_path=config['backendPath'], side=side,
                source=source, optimization=opt,
                symbol=config['scope']['functionSymbol'], operation=config['operation'],
                output=Path(directory)/side/opt[1:]/'program.elf')
            require_identical_rebuild({'path':old['programPath'],'digest':old['programDigest']}, record,
                reason='SYSTEM_L3_INDEPENDENT_REBUILD_MISMATCH:'+side)
            if opt == '-O0':
                require_identical_rebuild(programs[side], record, reason='SYSTEM_L3_DEPLOYMENT_REBUILD_MISMATCH:'+side)


def _programs(kwargs):
    programs = {}
    for side in ('source', 'target'):
        artifact = kwargs[side+'_program_artifact']
        programs[side] = {'path': str(Path(artifact.artifact_path).resolve()),
                          'digest': artifact.artifact_digest, 'buildIdentity': artifact.build_identity}
    return programs


def _closing(programs, config):
    system.load_config(config)
    for program in programs.values():
        if digest(program['path']) != program['digest']:
            raise ValueError('SYSTEM_L3_DEPLOYED_PROGRAM_CHANGED')


@timed('system.l3-intent-replay')
def intent_evidence(config, artifact, report_path):
    from .l3_intent_ingress import validate_receipt
    from .l3_system_intent import specification, profile
    from .requirement_staging import read_staged_requirements
    report = Path(report_path).resolve()
    original = digest(report)
    payload = _json(report.read_text())
    findings = payload['findings']
    if len(findings) != 1 or findings[0]['fragment']['id'] != artifact.fragment_id:
        raise ValueError('SYSTEM_L3_SINGLE_COMPLETE_REPORT_REQUIRED')
    finding = findings[0]
    parsed = validate_receipt(finding, artifact, config['sourcePath'], report)
    functions = _json(report.with_name('compiler-candidates.json').read_text())['functions']
    spec = specification(finding, artifact, functions, config)
    require_json_match(profile(spec, parsed.producer_identity), parsed.to_dict(), 'SYSTEM_L3_INTENT_REPLAY_MISMATCH')
    manifest = read_staged_requirements(report)['l3']
    from .l3_intent_requirements import classify_l3_requirements
    require_json_match(classify_l3_requirements(payload).to_dict(), manifest, 'SYSTEM_L3_REQUIREMENT_REPLAY_MISMATCH')
    requirements = manifest['requirements']
    if (len(requirements) != 1 or requirements[0]['eligibilityStatus'] != 'eligible'
            or requirements[0]['profileIdentity'] != parsed.profile_identity):
        raise ValueError('SYSTEM_L3_ELIGIBLE_REQUIREMENT_REQUIRED')
    if digest(report) != original:
        raise ValueError('SYSTEM_L3_INTENT_REPORT_CHANGED')
    return {'reportPath':str(report), 'reportDigest':original, 'specification':spec,
            'profile':parsed.to_dict(), 'requirementManifest':manifest,
            'receiptIdentity':finding['l3IntentReceipt']['receiptIdentity']}


@timed('system.l3-production-validation')
def run(config, *, report_path=None, **kwargs):
    try:
        if kwargs['level'] is not ValidationLevel.L3:
            raise ValueError('SYSTEM_L3_LEVEL_REQUIRED')
        prior = kwargs.get('prior_layer_results', ())
        if ([r.level for r in prior] != [ValidationLevel.L0, ValidationLevel.L1, ValidationLevel.L2]
                or any(r.status is not ValidationStatus.VERIFIED for r in prior)):
            raise ValueError('SYSTEM_L3_COMPLETED_PREREQUISITES_REQUIRED')
        implementation = implementation_identity()
        context = kwargs.get('l3_execution_context')
        if context is None: raise ValueError('SYSTEM_L3_EXECUTION_CONTEXT_REQUIRED')
        context.validate(kwargs['source_program_artifact'], kwargs['target_program_artifact'])
        backend = system.load_config(config)
        require_build_profile(backend)
        artifact = kwargs['translation_artifact']
        intent = intent_evidence(config, artifact, report_path)
        finding = {'approvalArtifact':{'privilegedCallableIdentifier':intent['specification']['targetCallable']}}
        require_json_match(intent['requirementManifest'], kwargs.get('l3_requirement_manifest'),
                           'SYSTEM_L3_RUNTIME_REQUIREMENT_MISMATCH')
        require_json_match(intent['profile'], kwargs.get('l3_intent_profile'), 'SYSTEM_L3_RUNTIME_PROFILE_MISMATCH')
        programs = _programs(kwargs)
        _closing(programs, config)
        l0 = _json(prior[0].detail)
        rebuild(programs, config, l0['builds'])
        machine = mechanism(programs, config, finding)
        # A new execution, not a relabelled or cached L2 result. Keep the old
        # observation's original claim and identity under its own schema.
        observed = system.run(config, **dict(kwargs, level=ValidationLevel.L1))
        if observed.status is not ValidationStatus.VERIFIED:
            return ValidationLayerResult(ValidationLevel.L3, observed.status, detail=observed.detail)
        observation = validate_observation(_json(observed.detail))
        require_json_match(programs, observation['nonce']['programs'], 'SYSTEM_L3_PROGRAM_BINDING_MISMATCH')
        _closing(programs, config)
        if implementation != implementation_identity(): raise ValueError('SYSTEM_L3_IMPLEMENTATION_CHANGED')
        body = {'schemaVersion': SCHEMA, 'status': 'verified', 'policy': POLICY,
            'implementationIdentity': implementation,
            'systemL3': True, 'claimScope': 'bounded-controlled-environment-intent',
            'physicalMicroarchitectureEquivalenceClaimed': False,
            'fragmentId': artifact.fragment_id, 'translationArtifactIdentity': artifact.identity,
            'proofIdentity': artifact.proof_identity, 'environmentId': observation['environmentId'],
            'config': config, 'programs': programs, 'machineMechanism': machine,
            'observation': observation, 'systemIntent': intent,
            'executionBindings':{side:context.request_binding(side) for side in ('source','target')},
            'prerequisites': {r.level.value: r.evidence_identity for r in prior}}
        detail = _seal(body)
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.VERIFIED,
            detail['evidenceIdentity'], json.dumps(detail, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        return ValidationLayerResult(ValidationLevel.L3, ValidationStatus.INCONCLUSIVE,
            detail=json.dumps({'reasonCodes': [str(exc)], 'failureStage': 'controlled-system-l3',
                               'evidenceProductionDisposition': 'not_complete'}))


def _audit_result(evaluation):
    """Fresh proof/build/machine replay and strict raw observation comparison."""
    from .translation_validation import translation_artifact_from_dict
    attempts = evaluation.get('attempts', [])
    if evaluation.get('status') != 'verified' or len(attempts) != 1:
        raise ValueError('SYSTEM_L3_SINGLE_COMPLETE_ATTEMPT_REQUIRED')
    attempt = attempts[0]
    validation = attempt.get('validation') or {}
    layers = validation.get('layers', [])
    if (attempt.get('status') != 'verified' or validation.get('status') != 'verified'
            or [r.get('level') for r in layers] != ['L0','L1','L2','L3']
            or any(r.get('status') != 'verified' for r in layers)):
        raise ValueError('SYSTEM_L3_FULL_LAYER_CHAIN_REQUIRED')
    detail = _json(layers[-1]['detail'])
    fields = {'schemaVersion','status','policy','systemL3','claimScope','implementationIdentity',
              'physicalMicroarchitectureEquivalenceClaimed','fragmentId','translationArtifactIdentity',
              'proofIdentity','environmentId','config','programs','machineMechanism','observation',
              'prerequisites','evidenceIdentity','systemIntent','executionBindings'}
    require_json_document(detail)
    if set(detail) != fields or detail['schemaVersion'] != SCHEMA:
        raise ValueError('SYSTEM_L3_RESULT_SCHEMA_INVALID')
    require_json_match(POLICY, detail['policy'], 'SYSTEM_L3_POLICY_CHANGED')
    if detail['implementationIdentity'] != implementation_identity():
        raise ValueError('SYSTEM_L3_IMPLEMENTATION_CHANGED')
    if (detail['systemL3'] is not True or detail['status'] != 'verified'
            or detail['physicalMicroarchitectureEquivalenceClaimed'] is not False
            or detail['claimScope'] != 'bounded-controlled-environment-intent'
            or detail['evidenceIdentity'] != identity({k:v for k,v in detail.items() if k != 'evidenceIdentity'})
            or layers[-1]['evidenceIdentity'] != detail['evidenceIdentity']):
        raise ValueError('SYSTEM_L3_RESULT_IDENTITY_OR_CLAIM_INVALID')
    artifact = translation_artifact_from_dict(attempt['translationArtifact'])
    if (attempt['fragmentId'] != detail['fragmentId'] or artifact.fragment_id != detail['fragmentId']
            or artifact.identity != detail['translationArtifactIdentity'] or artifact.proof_identity != detail['proofIdentity']):
        raise ValueError('SYSTEM_L3_TRANSLATION_BINDING_MISMATCH')
    require_json_match({r['level']: r['evidenceIdentity'] for r in layers[:3]},
                       detail['prerequisites'], 'SYSTEM_L3_PREREQUISITE_BINDING_MISMATCH')
    programs = detail['programs']; config = detail['config']
    if set(programs) != {'source','target'}:
        raise ValueError('SYSTEM_L3_PROGRAM_SET_INVALID')
    for side in ('source','target'):
        outer = evaluation[side+'ProgramArtifact']
        # Actual program records in the case are authoritative, not arbitrary
        # program paths supplied in an L3 result.
        from .translation_validation import program_artifact_from_dict
        parsed = program_artifact_from_dict(outer)
        require_json_match({'path': str(Path(parsed.artifact_path).resolve()),
            'digest': parsed.artifact_digest, 'buildIdentity': parsed.build_identity},
            programs[side], 'SYSTEM_L3_CASE_PROGRAM_MISMATCH')
    from .l3_execution_context import L3ExecutionContext
    from .translation_validation import program_artifact_from_dict
    bindings = detail['executionBindings']
    context = L3ExecutionContext(program_artifact_from_dict(evaluation['sourceProgramArtifact']),
        program_artifact_from_dict(evaluation['targetProgramArtifact']), bindings['source']['invocationId'])
    context.validate(context.source, context.target)
    require_json_match({side:context.request_binding(side) for side in ('source','target')},
                       bindings, 'SYSTEM_L3_EXECUTION_CONTEXT_MISMATCH')
    plan = evaluation.get('validationPlan') or {}
    if plan.get('profile') != 'microarch' or plan.get('experimentContractId') != POLICY['policyId']:
        raise ValueError('SYSTEM_L3_CASE_POLICY_MISMATCH')
    _closing(programs, config)
    require_build_profile(system.load_config(config))
    replayed_intent = intent_evidence(config, artifact, detail['systemIntent']['reportPath'])
    require_json_match(replayed_intent, detail['systemIntent'], 'SYSTEM_L3_INTENT_EVIDENCE_CHANGED')
    finding = {'approvalArtifact':{'privilegedCallableIdentifier':replayed_intent['specification']['targetCallable']}}
    require_json_match(evaluation['translationEvaluationLink']['l3Requirements'],
                       detail['systemIntent']['requirementManifest'], 'SYSTEM_L3_CASE_REQUIREMENT_MISMATCH')
    from .l2_evidence_reader import read_l2_fragment_results
    from .l2_provider_artifacts import read_provider_evidence
    fragments = read_l2_fragment_results(evaluation)
    if len(fragments) != 1 or fragments[0][1].provider_evidence_index is None:
        raise ValueError('SYSTEM_L3_L2_PROVIDER_EVIDENCE_REQUIRED')
    fragment = fragments[0][1]
    index = Path(fragment.provider_evidence_index['artifactPath'])
    if not index.is_absolute():
        raise ValueError('SYSTEM_L3_ABSOLUTE_PROVIDER_INDEX_REQUIRED')
    records = read_provider_evidence(fragment, case_root=index.parent,
                                    translation_artifact=attempt['translationArtifact'])
    if len(records) != 1 or records[0]['providerDefinition']['validatorType'] != 'controlled-system-validation':
        raise ValueError('SYSTEM_L3_SYSTEM_PROVIDER_REQUIRED')
    require_json_match(config, records[0]['providerDefinition']['config'], 'SYSTEM_L3_L2_PROVIDER_CONFIG_MISMATCH')
    system.audit_case_environment(evaluation, records)
    l0 = _json(layers[0]['detail'])
    if l0.get('schemaVersion') != system.RESULT or l0.get('level') != 'L0':
        raise ValueError('SYSTEM_L3_L0_RECORD_REQUIRED')
    rebuild(programs, config, l0['builds'])
    require_json_match(mechanism(programs, config, finding), detail['machineMechanism'],
                       'SYSTEM_L3_MACHINE_REPLAY_MISMATCH')
    observation = detail['observation']
    validate_observation(observation)
    require_json_match(programs, observation['nonce']['programs'], 'SYSTEM_L3_PROGRAM_BINDING_MISMATCH')
    require_json_match(system.environment(config), observation['environment'], 'SYSTEM_L3_ENVIRONMENT_REPLAY_MISMATCH')
    if (detail['environmentId'] != observation['environmentId']
            or evaluation['targetEnvironment']['environmentId'] != detail['environmentId']
            or observation['fragmentId'] != detail['fragmentId'] or observation['proofIdentity'] != artifact.proof_identity
            or observation['nonce']['operation'] != config['operation'] or observation['status'] != 'verified'):
        raise ValueError('SYSTEM_L3_OBSERVATION_BINDING_MISMATCH')
    _closing(programs, config)
    if detail['implementationIdentity'] != implementation_identity(): raise ValueError('SYSTEM_L3_IMPLEMENTATION_CHANGED')
    return {'status': 'verified', 'policyIdentity': identity(POLICY),
        'requirementManifestIdentity':detail['systemIntent']['requirementManifest']['manifestIdentity'],
        'fragments': [{'fragmentId': detail['fragmentId'], 'status': 'verified',
                       'resultIdentity': detail['evidenceIdentity'], 'claimScope': detail['claimScope']}],
        'programExecutionUnitCount': 1, 'physicalMicroarchitectureEquivalenceClaimed': False}


@timed('system.l3-independent-audit')
def audit_result(evaluation):
    try:
        return _audit_result(evaluation)
    except (OSError, KeyError, TypeError, IndexError, AttributeError, subprocess.SubprocessError) as exc:
        raise ValueError('SYSTEM_L3_AUDIT_INCOMPLETE:'+str(exc)) from exc


def build_validator(config):
    if (not isinstance(config, dict) or set(config) != {'schemaVersion','systemConfig','reportPath'}
            or config['schemaVersion'] != 'riscv2x86.controlled-system-l3-route.v1'):
        raise ValueError('SYSTEM_L3_ROUTE_CONFIG_INVALID')
    system.load_config(config['systemConfig'])
    return lambda **kwargs: run(config['systemConfig'], report_path=config['reportPath'], **kwargs)
