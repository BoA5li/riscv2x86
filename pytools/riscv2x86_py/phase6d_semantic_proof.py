"""Public Phase 6D proof-gate entry point."""
from .phase6d_common import (
    ApprovedTargetLoweringPlan, CompilerCapabilityModel,
    HelperSemanticContractRegistry, PreservationConclusion,
    SemanticProofReasonCode, SemanticProofRequest, SemanticProofResult,
    TargetSemanticCatalog, run_semantic_proof_gate,
)

__all__ = (
    "ApprovedTargetLoweringPlan", "CompilerCapabilityModel",
    "HelperSemanticContractRegistry", "PreservationConclusion",
    "SemanticProofReasonCode", "SemanticProofRequest", "SemanticProofResult",
    "TargetSemanticCatalog", "run_semantic_proof_gate",
)
