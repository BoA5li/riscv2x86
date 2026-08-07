"""Microarchitecture-intent policy is explicit and never silently assumed."""
from .phase6d_common import PlanRequirement, SemanticProofReasonCode, reject
def preserve_microarchitecture(request):
    source=request.source_model.microarch
    if source.explicitly_microarch_sensitive and not request.candidate_plan.requires(PlanRequirement.PRESERVE_MICROARCH_INTENT):
        return reject(request,SemanticProofReasonCode.MICROARCH_UNPRESERVED)
    if source.explicitly_microarch_sensitive and not source.has_structured_microarch_intent:
        return reject(request,SemanticProofReasonCode.MICROARCH_UNPRESERVED)
    return None
