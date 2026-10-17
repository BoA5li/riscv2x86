"""Read authoritative case evidence, never infer it from batch summaries."""
from collections.abc import Mapping
from hashlib import sha256
import json
from pathlib import Path

from .evaluation import EVALUATION_RESULT_SCHEMA
from .l2_results import L2FragmentResult, L2_FRAGMENT_RESULT_SCHEMAS


def _identity(value):
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=False).encode()).hexdigest()


def load_case_evaluation_result(batch_root, case):
    root = Path(batch_root).resolve()
    relative = case.get('resultPath')
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError('evaluation.result-path-invalid')
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError('evaluation.result-path-outside-batch')
    expected = root / 'cases' / str(case.get('caseId', '')) / 'evaluation-result.json'
    if path != expected or not case.get('caseId'):
        raise ValueError('evaluation.result-case-path-mismatch')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ValueError(f'evaluation.result-artifact-invalid: {path}: {exc}') from exc
    if not isinstance(value, Mapping) or value.get('schemaVersion') != EVALUATION_RESULT_SCHEMA:
        raise ValueError('evaluation.result-schema-invalid')
    unsigned = {k: v for k, v in value.items() if k not in {'evaluationIdentity', 'replayArtifact'}}
    actual = _identity(unsigned)
    if value.get('evaluationIdentity') != actual or case.get('evaluationIdentity') != actual:
        raise ValueError('evaluation.result-identity-mismatch')
    if value.get('status') != case.get('status') or not isinstance(value.get('attempts'), list):
        raise ValueError('evaluation.result-summary-mismatch')
    return value


def read_l2_fragment_results(case_result, requirements=None):
    """Parse exact L2 layer details; reject malformed or conflicting evidence.

    Returns (attempt identity, typed fragment result) pairs. Distinct attempts
    are not combined to manufacture a passing program verdict.
    """
    results = []
    seen = set()
    for attempt in case_result.get('attempts', []):
        validation = attempt.get('validation')
        if not isinstance(validation, Mapping):
            continue
        for layer in validation.get('layers', []):
            if layer.get('level') != 'L2' or layer.get('status') == 'not_run':
                continue
            try:
                raw = layer.get('detail')
                value = json.loads(raw) if isinstance(raw, str) else raw
                if not isinstance(value, Mapping) or value.get('schemaVersion') not in L2_FRAGMENT_RESULT_SCHEMAS:
                    raise ValueError('L2 fragment result schema unsupported')
                result = L2FragmentResult.from_dict(value)
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError('evaluation.l2-detail-invalid: ' + str(exc)) from exc
            if (result.provider_evidence_index is not None or result.precondition is not None) and layer.get('evidenceIdentity') != result.evidence_identity:
                raise ValueError('evaluation.l2-layer-evidence-identity-mismatch')
            if result.fragment_id != attempt.get('fragmentId'):
                raise ValueError('evaluation.l2-fragment-mismatch')
            expected_layer_status = (result.status.value if result.status.value in {'verified','failed'}
                                     else 'inconclusive')
            if layer.get('status') != expected_layer_status:
                raise ValueError('evaluation.l2-layer-status-mismatch')
            key = (attempt.get('attemptArtifactId'), result.fragment_id)
            if not key[0] or key in seen:
                raise ValueError('evaluation.l2-attempt-duplicate-or-missing')
            seen.add(key)
            results.append((key[0], result))
    if requirements is not None:
        from .l2_eligibility import validate_l2_requirement_manifest
        validate_l2_requirement_manifest(requirements)
        expected = {item['fragmentId']: item for item in requirements['requirements']
                    if item['eligibilityStatus'] != 'not_applicable'}
        actual = {result.fragment_id for _, result in results}
        if actual != set(expected):
            raise ValueError('evaluation.l2-required-fragment-set-mismatch')
        for _, result in results:
            item = expected[result.fragment_id]
            if (result.requirement_identity != item['requirementIdentity'] or
                    {d.value for d in result.required_dimensions} != set(item['requiredDimensions'])):
                raise ValueError('evaluation.l2-requirement-mismatch')
            if item['eligibilityStatus'] != 'eligible' and result.precondition is None:
                raise ValueError('evaluation.l2-noneligible-result-has-execution-claim')
    return tuple(results)


def read_l2_provider_results(case_result, case_root, requirements=None):
    """Follow only versioned invocation references attached to typed L2 results."""
    from .l2_provider_artifacts import read_provider_evidence
    attempts = {item['attemptArtifactId']: item for item in case_result.get('attempts', [])}
    records = []
    for attempt_id, result in read_l2_fragment_results(case_result, requirements):
        if result.precondition is not None:
            continue
        for envelope in read_provider_evidence(result,case_root=case_root,
                translation_artifact=attempts[attempt_id].get('translationArtifact')):
            records.append({'attemptArtifactId':attempt_id,'fragmentId':result.fragment_id,
                            'envelope':envelope})
    return tuple(records)


def audit_provider_references(case_result, case_root):
    """Recheck v3 references on export/reload; legacy v2 is never called audited."""
    from .l2_provider_artifacts import read_provider_evidence
    records = []
    for attempt in case_result.get('attempts', []):
        validation = attempt.get('validation')
        if not isinstance(validation, Mapping): continue
        for layer in validation.get('layers', []):
            if layer.get('level') != 'L2': continue
            try: value = json.loads(layer.get('detail',''))
            except (ValueError,TypeError): continue
            if not isinstance(value, Mapping) or value.get('schemaVersion') not in {
                    'riscv2x86.l2-fragment-result.v3', 'riscv2x86.l2-fragment-result.v4'}:
                continue
            result = L2FragmentResult.from_dict(value)
            if (result.fragment_id != attempt.get('fragmentId')
                    or result.evidence_identity != layer.get('evidenceIdentity')):
                raise ValueError('evaluation.l2-provider-reference-layer-mismatch')
            if result.precondition is not None:
                continue
            records.extend(read_provider_evidence(result,case_root=case_root,
                translation_artifact=attempt.get('translationArtifact')))
    return tuple(records)
