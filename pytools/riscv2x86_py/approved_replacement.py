"""Resolve approved candidate text without promoting withheld publication.

External validation consumes the durable E0 candidate, whereas the public
suggestedReplacement intentionally stays empty until publication admission.
Every consumer still replays its semantic approval against the returned text.
"""
from hashlib import sha256
from collections.abc import Mapping
from .schema import make_translation_attempt_artifact
from .semantic_content import semantic_identity


def approved_replacement(finding):
    fragment=finding['fragment']
    fid=fragment.get('id') or fragment.get('fragmentId')
    approval=finding.get('approvalArtifact') or {}
    published=finding.get('suggestedReplacement') or ''
    staged=finding.get('translationAttemptArtifact')
    if staged:
        if not isinstance(staged,Mapping):raise ValueError('CANDIDATE_ATTEMPT_INVALID')
        expected=make_translation_attempt_artifact(fragment_id=staged['fragmentId'],
            candidate_kind=staged['candidateKind'],candidate_route=staged['candidateRoute'],
            candidate_replacement=staged['candidateReplacement'],candidate_rule_name=staged['candidateRuleName'],
            translation_outcome=staged['translationOutcome'],validation_outcome=staged['validationOutcome'],
            publication_outcome=staged['publicationOutcome'],reason_codes=staged['reasonCodes'])
        if (dict(staged)!=expected or staged['fragmentId']!=fid
                or staged['translationOutcome'] not in {'emitted','strengthened','functional_fallback'}
                or finding.get('translationOutcome',staged['translationOutcome'])!=staged['translationOutcome']):
            raise ValueError('CANDIDATE_ATTEMPT_BINDING_MISMATCH')
        text=staged['candidateReplacement']
        if published and published!=text:raise ValueError('CANDIDATE_PUBLIC_TEXT_CONFLICT')
    else:
        text=published
    if not isinstance(text,str) or not text.strip():raise ValueError('CANDIDATE_APPROVAL_TEXT_MISMATCH')
    version=approval.get('artifactVersion')
    if version=='phase6-csr-runtime-v1':
        expected_digest=semantic_identity({'replacement':text})
    elif version=='phase6-approval-v2':
        # The generic cross-language Phase-6 artifact uses FNV-1a-64, just
        # as its producer and apply-side replay do. Do not accept arbitrary
        # digest algorithms based on the supplied string prefix.
        from .translate import _approval_digest
        expected_digest=_approval_digest(text)
    else:
        expected_digest='sha256:'+sha256(text.encode()).hexdigest()
    if (approval.get('sourceFragmentId')!=fid or approval.get('replacementDigest')!=expected_digest):
        raise ValueError('CANDIDATE_APPROVAL_TEXT_MISMATCH')
    return text
