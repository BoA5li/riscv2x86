"""Versioned, content-bound provider invocation evidence and audit ingress."""
from dataclasses import replace
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from .requirement_staging import atomic_json

REFERENCE_SCHEMA = 'riscv2x86.l2-provider-index-reference.v1'
INDEX_SCHEMA = 'riscv2x86.l2-provider-invocation-index.v1'
RESULT_SCHEMA = 'riscv2x86.l2-provider-invocation-result.v1'


def identity(value):
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=False).encode()).hexdigest()


def context_payload(artifact):
    def encode(value):
        if isinstance(value, Enum): return value.value
        raise TypeError('non-serializable translation context: ' + type(value).__name__)
    return json.loads(json.dumps(vars(artifact), default=encode))


def raw_result(result):
    from .translation_validation import ValidationLayerResult
    if not isinstance(result, ValidationLayerResult):
        return {'invalidPythonType': type(result).__name__, 'representation': repr(result)}
    def field(value):
        if isinstance(value, Enum): return value.value
        if isinstance(value, (str, int, float, bool)) or value is None: return value
        return {'invalidPythonType':type(value).__name__, 'representation':repr(value)}
    return {'level': field(result.level), 'status': field(result.status),
            'evidenceIdentity': field(result.evidence_identity), 'detail': field(result.detail)}


def persist_provider_evidence(root, plan, artifact, records, fragment_result):
    """Commit all invoked providers before publishing a passing fragment result."""
    root = Path(root).resolve()
    context = context_payload(artifact)
    binding = {'fragmentId': fragment_result.fragment_id,
               'requirementIdentity': fragment_result.requirement_identity,
               'resolvedPlanIdentity': plan.to_dict()['planIdentity'],
               'translationContextIdentity': identity(context),
               'invocationNonce': uuid4().hex}
    group_id = identity(binding)
    directory = root / 'l2-provider-evidence' / group_id.split(':')[1]
    directory.mkdir(parents=True, exist_ok=False)
    entries = []
    for ordinal, (provider_id, record) in enumerate(sorted(records.items())):
        value = {'schemaVersion': RESULT_SCHEMA, 'invocationGroupIdentity': group_id,
                 'providerId': provider_id, **record}
        value['invocationIdentity'] = identity(value)
        path = directory / f'provider-{ordinal}.json'
        atomic_json(path, value)
        # Verify the committed file before making it reachable from an index.
        if json.loads(path.read_text(encoding='utf-8')) != value:
            raise ValueError('provider result write verification failed')
        entries.append({'providerId':provider_id, 'artifactPath':path.name,
                        'invocationIdentity':value['invocationIdentity']})
    index = {'schemaVersion': INDEX_SCHEMA, 'binding':binding,
             'invocationGroupIdentity':group_id, 'translationContext':context,
             'resolvedPlan':plan.to_dict(),
             'fragmentResultIdentity':fragment_result.evidence_identity,
             'invocations':entries}
    index['indexIdentity'] = identity(index)
    path = directory / 'index.json'
    atomic_json(path, index)
    if json.loads(path.read_text(encoding='utf-8')) != index:
        raise ValueError('provider index write verification failed')
    return {'schemaVersion':REFERENCE_SCHEMA, 'artifactPath':str(path),
            'indexIdentity':index['indexIdentity']}


def validate_reference(ref):
    import re
    if (not isinstance(ref, dict) or set(ref) != {'schemaVersion','artifactPath','indexIdentity'}
            or ref['schemaVersion'] != REFERENCE_SCHEMA
            or not isinstance(ref['artifactPath'], str) or not ref['artifactPath']
            or not isinstance(ref['indexIdentity'], str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}',ref['indexIdentity']) is None):
        raise ValueError('l2.provider-artifact.reference-invalid')


def _read(path, root, field, expected, schema):
    path = path.resolve()
    if not path.is_relative_to(root):
        raise ValueError('l2.provider-artifact.path-outside-case')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ValueError(f'l2.provider-artifact.unreadable: {path}: {exc}') from exc
    if (not isinstance(value, dict) or value.get('schemaVersion') != schema
            or value.get(field) != expected
            or identity({k:v for k,v in value.items() if k != field}) != expected):
        raise ValueError('l2.provider-artifact.identity-or-schema-invalid: ' + str(path))
    return value


def _read_provider_evidence(fragment_result, *, case_root, translation_artifact=None):
    """Audit exact invocation references and re-run the evidence validators.

    No directory search, status inference, or merging of different invocations.
    Returns the preserved envelopes, not synthesized provider summaries.
    """
    from .l2_validator_resolution import validate_resolved_execution_plan, provider_from_dict
    from .l2_evidence_closure import (provider_execution_disposition,
        provider_evidence_production_disposition, validate_provider_dimension_contract,
        validated_provider_evidence, partial_provider_evidence)
    from .l2_results import L2DimensionResult
    ref = fragment_result.provider_evidence_index
    if ref is None:
        raise ValueError('l2.provider-artifact.reference-missing')
    validate_reference(ref)
    root = Path(case_root).resolve()
    path = Path(ref['artifactPath'])
    if not path.is_absolute(): path = root / path
    index = _read(path, root, 'indexIdentity', ref['indexIdentity'], INDEX_SCHEMA)
    if set(index) != {'schemaVersion','binding','invocationGroupIdentity','translationContext',
                      'resolvedPlan','fragmentResultIdentity','invocations','indexIdentity'}:
        raise ValueError('l2.provider-artifact.index-fields-invalid')
    plan, binding, context = index['resolvedPlan'], index['binding'], index['translationContext']
    validate_resolved_execution_plan(plan)
    if (identity(binding) != index['invocationGroupIdentity']
            or binding['fragmentId'] != fragment_result.fragment_id
            or binding['requirementIdentity'] != fragment_result.requirement_identity
            or binding['resolvedPlanIdentity'] != plan['planIdentity']
            or plan['fragmentId'] != fragment_result.fragment_id
            or plan['requirementIdentity'] != fragment_result.requirement_identity
            or binding['translationContextIdentity'] != identity(context)
            or context['fragment_id'] != fragment_result.fragment_id
            or index['fragmentResultIdentity'] != replace(fragment_result,provider_evidence_index=None).evidence_identity):
        raise ValueError('l2.provider-artifact.binding-mismatch')
    if translation_artifact is not None:
        for key, value in translation_artifact.items():
            if key in context and context[key] != value:
                raise ValueError('l2.provider-artifact.translation-context-mismatch:' + key)
    artifact = SimpleNamespace(**context)
    expected = {}
    for item in plan['bindings']:
        if item['bindingStatus'] == 'resolved':
            expected.setdefault(item['providerId'],[]).append(item['dimension'])
    entries = index['invocations']
    if (not isinstance(entries,list) or len(entries) != len(expected)
            or {x.get('providerId') for x in entries} != set(expected)):
        raise ValueError('l2.provider-artifact.invocation-set-mismatch')
    final = {x.dimension.value:x.to_dict() for x in fragment_result.dimension_results}
    records = []
    for entry in entries:
        if set(entry) != {'providerId','artifactPath','invocationIdentity'} or Path(entry['artifactPath']).is_absolute():
            raise ValueError('l2.provider-artifact.invocation-reference-invalid')
        record_path = (path.parent / entry['artifactPath']).resolve()
        if not record_path.is_relative_to(path.parent.resolve()):
            raise ValueError('l2.provider-artifact.invocation-path-outside-index')
        record = _read(record_path, root, 'invocationIdentity',
                       entry['invocationIdentity'], RESULT_SCHEMA)
        if set(record) != {'schemaVersion','invocationGroupIdentity','providerId','providerDefinition',
                           'observationSnapshot','reportedResult','normalizedResult','normalizationDisposition','exception',
                           'centralAssessments','invocationIdentity'}:
            raise ValueError('l2.provider-artifact.result-fields-invalid')
        provider = entry['providerId']
        if record['providerId'] != provider or record['invocationGroupIdentity'] != index['invocationGroupIdentity']:
            raise ValueError('l2.provider-artifact.provider-binding-mismatch')
        if record['providerDefinition']['providerId'] != provider:
            raise ValueError('l2.provider-artifact.provider-definition-mismatch')
        definition = record['providerDefinition']
        provider_from_dict(definition)
        for planned in plan['bindings']:
            if planned['providerId'] == provider and planned['bindingStatus'] == 'resolved':
                if (planned['bindingKind'] != definition['bindingKind']
                        or planned['validatorType'] != definition['validatorType']):
                    raise ValueError('l2.provider-artifact.provider-plan-mismatch')
        if set(definition['supportedDimensions']) != set(expected[provider]):
            raise ValueError('l2.provider-artifact.provider-dimensions-mismatch')
        normalized = record['normalizedResult']
        normalization = record['normalizationDisposition']
        if (normalization not in {'unchanged','provider_exception','rejected_invalid_result'}
                or (normalization == 'unchanged' and record['reportedResult'] != normalized)
                or (normalization != 'unchanged' and normalized['status'] == 'verified')
                or (normalization == 'provider_exception' and not record['exception'])):
            raise ValueError('l2.provider-artifact.normalization-invalid')
        try:
            detail = json.loads(normalized['detail'])
        except (ValueError, TypeError): detail = {}
        if not isinstance(detail,dict): detail = {}
        validate_observation_snapshot(record.get('observationSnapshot'),detail)
        if (detail.get('schemaVersion') in {'riscv2x86.auto-l2-operand-result.v2','riscv2x86.auto-l2-effect-result.v2'}
                and record.get('observationSnapshot') is not None
                and normalized['evidenceIdentity'] != record['observationSnapshot']['contentIdentity']):
            raise ValueError('l2.provider-artifact.result-evidence-identity-invalid')
        disposition, disposition_reasons = provider_execution_disposition(detail,normalized['status'])
        production, production_reasons = provider_evidence_production_disposition(detail,disposition)
        assessments = record['centralAssessments']
        if set(assessments) != set(expected[provider]):
            raise ValueError('l2.provider-artifact.assessment-set-mismatch')
        for dimension in expected[provider]:
            assessed = assessments[dimension]
            L2DimensionResult.from_dict(assessed['dimensionResult'])
            if (assessed['closureDisposition'] != final[dimension]['status']
                    or assessed['reasonCodes'] != final[dimension]['reasonCodes']
                    or assessed['ingressValidationDisposition'] not in {'accepted','rejected','not_evaluated'}):
                raise ValueError('l2.provider-artifact.assessment-disposition-invalid')
            if assessed['dimensionResult'] != final[dimension]:
                raise ValueError('l2.provider-artifact.dimension-result-mismatch')
            enabled = (production.value in {'partial','complete'}
                       and disposition.value != 'precondition_rejected'
                       and bool(context.get('l2_authority_complete')))
            contract_reasons = (validate_provider_dimension_contract(detail, expected[provider])
                                if enabled and production.value == 'complete' else ())
            evidence, closure_reasons = ({}, ())
            if enabled and production.value == 'complete':
                evidence, closure_reasons = validated_provider_evidence(detail,artifact,dimension=dimension,provider_id=provider)
            elif enabled:
                evidence, closure_reasons = partial_provider_evidence(detail,artifact,dimension=dimension,provider_id=provider)
            expected_ingress = ('rejected' if disposition_reasons or production_reasons or contract_reasons or closure_reasons
                                else 'accepted' if enabled else 'not_evaluated')
            if assessed['ingressValidationDisposition'] != expected_ingress:
                raise ValueError('l2.provider-artifact.ingress-assessment-mismatch')
            if final[dimension]['status'] == 'verified':
                if (assessed['ingressValidationDisposition'] != 'accepted'
                        or disposition.value != 'executed_verified' or production.value != 'complete'
                        or validate_provider_dimension_contract(detail, expected[provider])):
                    raise ValueError('l2.provider-artifact.verified-disposition-invalid')
                if closure_reasons or evidence is None:
                    raise ValueError('l2.provider-artifact.evidence-invalid:' + ','.join(closure_reasons))
                for key in ('authorityIdentity','effectRelationIdentity','executionIdentity',
                            'sourceObservationIdentity','targetObservationIdentity'):
                    if evidence[key] != final[dimension][key]:
                        raise ValueError('l2.provider-artifact.dimension-identity-mismatch:' + key)
        records.append(record)
    return tuple(records)


def capture_observation_artifact(result, definition):
    """Snapshot a declared observation at return time, before another invocation."""
    try: detail = json.loads(result.detail)
    except (ValueError, TypeError): return None
    if not isinstance(detail,dict) or not detail.get('replayArtifact'): return None
    relative = detail['replayArtifact']
    directory = definition.get('config',{}).get('replayDirectory')
    if not isinstance(relative,str) or not directory or Path(relative).is_absolute():
        raise ValueError('provider observation reference invalid')
    root = Path(directory).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root): raise ValueError('provider observation path escapes replay')
    payload = json.loads(path.read_text(encoding='utf-8'))
    digest = identity(payload)
    if digest != detail.get('observationEvidenceIdentity'):
        raise ValueError('provider observation identity mismatch')
    if (detail.get('schemaVersion') in {'riscv2x86.auto-l2-operand-result.v2','riscv2x86.auto-l2-effect-result.v2'}
            and result.evidence_identity != digest):
        raise ValueError('provider result evidence identity does not match observation payload')
    return {'schemaVersion':'riscv2x86.l2-observation-snapshot.v1',
            'relativePath':relative,'contentIdentity':digest,'payload':payload}


def validate_observation_snapshot(snapshot, detail):
    if detail.get('schemaVersion') == 'riscv2x86.controlled-system-result.v1':
        from .controlled_system_runner import validate_persisted_result as validate_system
        validate_system(detail)
    if detail.get('schemaVersion') == 'riscv2x86.controlled-time-result.v1':
        from .time_trace_runner import validate_persisted_result as validate_time
        validate_time(detail)
    if detail.get('schemaVersion') == 'riscv2x86.instruction-visibility-result.v1':
        from .l2_instruction_visibility_runner import validate_persisted_result
        validate_persisted_result(detail)
    if snapshot is None:
        if detail.get('replayArtifact'):
            raise ValueError('l2.provider-artifact.observation-snapshot-missing')
        return
    if (set(snapshot) != {'schemaVersion','relativePath','contentIdentity','payload'}
            or snapshot['schemaVersion'] != 'riscv2x86.l2-observation-snapshot.v1'
            or snapshot['relativePath'] != detail.get('replayArtifact')
            or identity(snapshot['payload']) != snapshot['contentIdentity']
            or snapshot['contentIdentity'] != detail.get('observationEvidenceIdentity')):
        raise ValueError('l2.provider-artifact.observation-snapshot-invalid')
    observation = snapshot['payload']
    if detail.get('mode') == 'joint-program-functions':
        from .l2_joint_replay import replay
        replay(observation)
    raw_dimensions = detail.get('dimensionObservations',{})
    if detail.get('schemaVersion') == 'riscv2x86.auto-l2-operand-result.v2':
        for side in ('source','target'):
            payload = observation.get(side+'TracePayload')
            if payload is None or identity(payload) != observation[side+'TraceDigest']:
                raise ValueError('l2.provider-artifact.operand-trace-payload-invalid')
            if raw_dimensions['logical_operands'][side+'EvidenceIdentity'] != identity(payload):
                raise ValueError('l2.provider-artifact.operand-observation-binding-invalid')
    elif detail.get('schemaVersion') == 'riscv2x86.auto-l2-effect-result.v2':
        from .automatic_l2_effect import _effect_dimension_evidence
        from .l2_dimensions import L2Dimension
        projected = _effect_dimension_evidence(observation,tuple(L2Dimension(x) for x in raw_dimensions))
        for dimension, evidence in projected.items():
            for side in ('source','target'):
                if getattr(evidence,side+'_evidence_identity') != raw_dimensions[dimension.value][side+'EvidenceIdentity']:
                    raise ValueError('l2.provider-artifact.effect-observation-binding-invalid')


def provider_audit_counts(case_result, case_root):
    """Count recorded invocations and unique executions, never infer from verdicts."""
    from collections import Counter
    from .l2_evidence_reader import read_l2_fragment_results
    kinds = ('automatic','explicit','runtime_adapter')
    invocations = {k:Counter() for k in kinds}
    executions = {k:Counter() for k in kinds}
    audit = Counter()
    unique = {}
    try:
        fragments = read_l2_fragment_results(case_result)
    except (ValueError,TypeError,KeyError):
        audit['invalid_fragment_result'] += 1
        fragments = ()
    attempts = {item.get('attemptArtifactId'):item for item in case_result.get('attempts', [])}
    for attempt_id, fragment in fragments:
        if fragment.precondition is not None:
            audit['valid_precondition_rejections'] += 1
            continue
        if fragment.provider_evidence_index is None:
            audit['legacy_result_without_index'] += 1
            continue
        try:
            records = read_provider_evidence(fragment,case_root=case_root,
                translation_artifact=attempts.get(attempt_id,{}).get('translationArtifact'))
        except (OSError,ValueError,TypeError,KeyError):
            audit['invalid_provider_index'] += 1
            continue
        audit['audited_fragment_indexes'] += 1
        for record in records:
            audit['persisted_provider_invocations'] += 1
            accepted = all(v['dimensionResult']['status']=='verified'
                           for v in record['centralAssessments'].values())
            audit['centrally_verified_provider_invocations' if accepted else
                  'centrally_nonverified_provider_invocations'] += 1
            kind = record['providerDefinition']['bindingKind']
            try: detail = json.loads(record['normalizedResult']['detail'])
            except (ValueError, TypeError): detail = {}
            detail = detail if isinstance(detail,dict) else {}
            disposition = detail.get('executionDisposition','unknown')
            invocations[kind][disposition] += 1
            execution = detail.get('executionIdentity')
            if disposition.startswith('executed_'):
                if not execution:
                    audit['executed_invocations_without_execution_identity'] += 1
                    continue
                key=(kind,record['providerId'],execution)
                unique.setdefault(key,set()).add(disposition)
    for (kind,_,_), statuses in unique.items():
        status = ('executed_failed' if 'executed_failed' in statuses else
                  'executed_inconclusive' if 'executed_inconclusive' in statuses else 'executed_verified')
        executions[kind][status] += 1
    return {'providerInvocationCounts':{k:dict(sorted(v.items())) for k,v in invocations.items()},
            'auditedProviderExecutionCounts':{k:dict(sorted(v.items())) for k,v in executions.items()},
            'providerArtifactAuditCounts':dict(sorted(audit.items()))}


def read_provider_evidence(fragment_result, *, case_root, translation_artifact=None):
    try:
        return _read_provider_evidence(fragment_result,case_root=case_root,
                                      translation_artifact=translation_artifact)
    except (KeyError,TypeError,AttributeError) as exc:
        raise ValueError('l2.provider-artifact.malformed: ' + str(exc)) from exc


def main(argv=None):
    import argparse
    from .l2_evidence_reader import load_case_evaluation_result, read_l2_provider_results
    parser = argparse.ArgumentParser(description='Audit retained L2 provider evidence in a batch')
    parser.add_argument('--batch',required=True)
    parser.add_argument('--scope', choices=('all','verified-only'), default='all')
    args = parser.parse_args(argv)
    path = Path(args.batch).resolve()
    failures=[]; audited=0; invocations=0; skipped=0; validated=0; preconditions=0
    try:
        batch=json.loads(path.read_text(encoding='utf-8'))
        for case in batch['cases']:
            verified = case.get('programValidationLevels',{}).get('L2') == 'verified'
            if args.scope == 'verified-only' and not verified:
                skipped+=1
                continue
            try:
                evaluation=load_case_evaluation_result(path.parent,case)
                from .l2_evidence_reader import read_l2_fragment_results
                fragments=read_l2_fragment_results(evaluation)
                preconditions += sum(f.precondition is not None for _,f in fragments)
                records=read_l2_provider_results(evaluation,path.parent/'cases'/case['caseId'])
                if verified and (not records or any(f.status.value != 'verified' for _,f in fragments)):
                    raise ValueError('verified L2 case has no complete retained fragment/provider evidence')
                validated+=1
                if records:
                    audited+=1; invocations+=len(records)
                else:
                    skipped+=1  # No invocation exists; the case result was still validated.
            except (OSError,ValueError,TypeError,KeyError) as exc:
                failures.append({'caseId':case.get('caseId',''),'exceptionType':type(exc).__name__,
                    'failureStage':'case_result_and_provider_audit', 'artifactPath':case.get('resultPath',''),
                    'detail':str(exc)})
    except (OSError,ValueError,TypeError,KeyError) as exc:
        failures.append({'exceptionType':type(exc).__name__,'detail':str(exc)})
    print(json.dumps({'schemaVersion':'riscv2x86.l2-provider-audit-summary.v2',
        'auditDisposition':'failed' if failures else 'complete' if validated else 'not_applicable',
        'auditScope':args.scope, 'validatedCaseResults':validated,
        'preconditionRejectedFragments':preconditions,
        'auditedCases':audited,'providerInvocations':invocations,'skippedCases':skipped,
        'failures':failures},ensure_ascii=False,sort_keys=True))
    return 1 if failures else 0 if validated else 2


if __name__ == '__main__':
    raise SystemExit(main())
