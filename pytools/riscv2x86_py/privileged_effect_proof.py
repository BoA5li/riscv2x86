"""Per-effect Phase-6D proof helpers for privileged translation.

This module consumes only Phase-6A models and Phase-6C constraints.  It never
re-reads assembly, p-code, CFG objects, or renderer text.
"""
from __future__ import annotations

from hashlib import sha256

from .phase6d_common import (
    PrivilegedEffectProofEvidence,
    SemanticProofReasonCode,
)
from .privileged_runtime_contracts import source_effect_id
from .privileged_state_analysis import AddressTranslationEffectKind


def _mapping_id(mapping: object) -> str:
    return "sha256:" + sha256(repr(mapping).encode("utf-8")).hexdigest()


def _one(mappings, effect_id):
    matched = tuple(item for item in mappings if item.source_effect_id == effect_id)
    return matched[0] if len(matched) == 1 else None


def prove_strict_effects(source, constraint):
    state = source.state
    contract = constraint.runtime_contract
    evidence = []

    for effect in state.csr_effects:
        effect_id = source_effect_id("csr", effect.block_address, effect.operation_index)
        mapping = _one(constraint.csr_mappings, effect_id)
        field_ids = tuple(field.field_id for field in effect.affected_fields)
        if (
            mapping is None or not mapping.complete or not effect.complete
            or mapping.source_csr_id != effect.csr_id
            or mapping.source_field_ids != field_ids
            or not mapping.old_new_state_relation_id
        ):
            return None, SemanticProofReasonCode.PRIVILEGED_CSR_MAPPING_UNPROVEN, effect_id
        if (
            effect.required_privilege_mode is None
            or effect.access_allowed is None
            or not effect.access_policy_complete
            or effect.may_trap is None
            or (effect.may_trap and not mapping.access_trap_mapping_id)
        ):
            return None, SemanticProofReasonCode.PRIVILEGED_TRAP_MAPPING_UNPROVEN, effect_id
        evidence.append(PrivilegedEffectProofEvidence(
            effect_id, _mapping_id(mapping), contract.contract_id,
            contract.semantic_version,
            tuple(sorted((
                "csr.access-permission-and-trap",
                "csr.old-new-state-relation",
                "execution.profile",
                "memory-and-concurrency",
                "shell",
            ))), "architecture_equivalent",
        ))

    for effect in state.trap_effects:
        effect_id = source_effect_id("trap", effect.block_address, effect.operation_index)
        mapping = _one(constraint.trap_mappings, effect_id)
        if (
            mapping is None or not mapping.complete or not effect.complete
            or not all((mapping.cause_mapping_id, mapping.tval_mapping_id,
                        mapping.handler_mapping_id,
                        mapping.continuation_mapping_id))
            or effect.cause is None or effect.handler_binding_id is None
            or effect.continuation is None
            or effect.source_privilege is None
            or effect.target_privilege is None
            or effect.saved_pc_binding is None
        ):
            return None, SemanticProofReasonCode.PRIVILEGED_TRAP_MAPPING_UNPROVEN, effect_id
        evidence.append(PrivilegedEffectProofEvidence(
            effect_id, _mapping_id(mapping), contract.contract_id,
            contract.semantic_version,
            tuple(sorted(("execution.profile", "trap.cause-tval-handler",
                          "trap.privilege-transition-and-saved-state",
                          "trap.continuation", "shell"))),
            "architecture_equivalent",
        ))

    if state.return_effects:
        effect = state.return_effects[0]
        return None, SemanticProofReasonCode.PRIVILEGED_RETURN_CONTINUATION_UNPROVEN, source_effect_id(
            "privilege-return", effect.block_address, effect.operation_index
        )

    for effect in state.interrupt_effects:
        effect_id = source_effect_id("interrupt", effect.block_address, effect.operation_index)
        mapping = _one(constraint.interrupt_mappings, effect_id)
        if (
            mapping is None or not mapping.complete or not effect.complete
            or not mapping.enable_pending_relation_id
            or not mapping.delegation_priority_relation_id
            or effect.interruptibility is None
        ):
            return None, SemanticProofReasonCode.PRIVILEGED_INTERRUPT_MAPPING_UNPROVEN, effect_id
        evidence.append(PrivilegedEffectProofEvidence(
            effect_id, _mapping_id(mapping), contract.contract_id,
            contract.semantic_version,
            tuple(sorted(("execution.profile", "interrupt.enable-pending",
                          "interrupt.delegation-priority", "memory-and-concurrency",
                          "shell"))), "architecture_equivalent",
        ))

    for effect in state.address_translation_effects:
        effect_id = source_effect_id("address-translation", effect.block_address, effect.operation_index)
        mapping = _one(constraint.address_translation_mappings, effect_id)
        if mapping is None or not mapping.complete or not effect.complete:
            return None, SemanticProofReasonCode.PRIVILEGED_MMU_MAPPING_UNPROVEN, effect_id
        if (
            effect.address_space_identity is None
            or not mapping.scope_relation_id
            or not mapping.synchronization_relation_id
            or not mapping.shootdown_relation_id
        ):
            return None, SemanticProofReasonCode.PRIVILEGED_MMU_MAPPING_UNPROVEN, effect_id
        if effect.kind is AddressTranslationEffectKind.TLB_INVALIDATION and (
            effect.virtual_address_scope is None
            or effect.synchronization_scope is None
            or effect.shootdown_required is None
        ):
            return None, SemanticProofReasonCode.PRIVILEGED_TLB_SCOPE_UNPROVEN, effect_id
        evidence.append(PrivilegedEffectProofEvidence(
            effect_id, _mapping_id(mapping), contract.contract_id,
            contract.semantic_version,
            tuple(sorted(("execution.profile", "mmu.address-space-identity",
                          "mmu.root-mode", "tlb.scope-and-shootdown",
                          "memory-and-concurrency", "shell"))),
            "architecture_equivalent",
        ))

    for kind, effects, mappings in (
        ("virtualization", state.virtualization_effects, constraint.virtualization_mappings),
        ("debug", state.debug_effects, constraint.debug_mappings),
    ):
        for effect in effects:
            effect_id = source_effect_id(kind, effect.block_address, effect.operation_index)
            mapping = _one(mappings, effect_id)
            if mapping is None or not mapping.complete or not effect.complete:
                return None, SemanticProofReasonCode.PRIVILEGED_VIRTUALIZATION_MAPPING_UNPROVEN, effect_id
            evidence.append(PrivilegedEffectProofEvidence(
                effect_id, _mapping_id(mapping), contract.contract_id,
                contract.semantic_version,
                tuple(sorted(("execution.profile", f"{kind}.state-relation",
                              "memory-and-concurrency", "shell"))),
                "architecture_equivalent",
            ))

    return tuple(sorted(evidence, key=lambda item: item.source_effect_id)), None, None


def prove_fallback_effects(source, constraint):
    observation = source.observability
    contract = constraint.fallback_contract
    ignored = tuple(sorted(item.state_id for item in observation.ignored_states))
    if ignored != constraint.ignored_source_state or observation.unignored_privileged_state_ids:
        return None, SemanticProofReasonCode.PRIVILEGED_IGNORED_STATE_ESCAPE, None
    if contract.required_value_source_ids != observation.required_privileged_value_sources:
        return None, SemanticProofReasonCode.PRIVILEGED_TARGET_SIDE_EFFECT_UNPROVEN, None

    required = [
        *(item.output_id for item in observation.outputs),
        "memory", "error-status", "termination", "trap-to-result",
        *(f"privileged-value:{item}" for item in observation.required_privileged_value_sources),
    ]
    mappings = constraint.observable_effect_mappings
    evidence = []
    for observable_id in sorted(set(required)):
        matched = tuple(item for item in mappings if item.source_observable_id == observable_id)
        if len(matched) != 1 or not matched[0].complete:
            return None, SemanticProofReasonCode.PRIVILEGED_TARGET_SIDE_EFFECT_UNPROVEN, observable_id
        mapping = matched[0]
        evidence.append(PrivilegedEffectProofEvidence(
            "observable:" + observable_id, _mapping_id(mapping), contract.contract_id,
            contract.semantic_version,
            tuple(sorted(("functional.observable-effect", "functional.no-extra-side-effect",
                          "shell"))), "functional_equivalence_only",
        ))
    for state_id in ignored:
        evidence.append(PrivilegedEffectProofEvidence(
            "ignored:" + state_id, "ignored-state-authority:" + state_id,
            contract.contract_id, contract.semantic_version,
            ("functional.ignored-state-does-not-escape",),
            "architecture_and_microarchitecture_not_preserved",
        ))
    return tuple(sorted(evidence, key=lambda item: item.source_effect_id)), None, None
