"""Proof-bound shell compatibility for bounded scalar boundary observers.

`cc` is a compiler kill contract, not a request to preserve physical flags
across an observer call. This rule requires approved scalar-only effects and
whole statement boundaries; it never grants memory/register/control coverage.
"""
from dataclasses import dataclass
from typing import Mapping
import re

from .l2_effect_proof import effect_proof_facts_from_dict
from .l2_authority import l2_authority_sidecar_from_dict
from .l2_fragment_execution import identity

SCHEMA = 'riscv2x86.observer-shell-compatibility.v1'
RULE = 'scalar-register-whole-statement-normal-call-v1'
_SHA = re.compile(r'sha256:[0-9a-f]{64}')


@dataclass(frozen=True)
class ObserverShellCompatibilityDecision:
    fragment_id: str
    source_digest: str
    compiler_boundary_identity: str
    boundary_identity: str
    graph_identity: str
    proof_identity: str
    effect_facts_identity: str
    shell_relation_identity: str
    source_shell_identity: str
    target_replacement_identity: str
    renderer_contract_identity: str
    authority_identity: str
    effect_relation_set_identity: str
    source_range: tuple[int, int]
    clobber_classes: tuple[str, ...]
    reason_codes: tuple[str, ...]

    @property
    def supported(self):
        return not self.reason_codes

    def to_dict(self):
        payload = {
            'schemaVersion': SCHEMA, 'ruleIdentity': RULE,
            'fragmentId': self.fragment_id, 'sourceDigest': self.source_digest,
            'compilerBoundaryIdentity': self.compiler_boundary_identity,
            'boundaryIdentity': self.boundary_identity, 'graphIdentity': self.graph_identity,
            'proofIdentity': self.proof_identity, 'effectFactsIdentity': self.effect_facts_identity,
            'shellRelationIdentity': self.shell_relation_identity,
            'sourceShellIdentity': self.source_shell_identity,
            'targetReplacementIdentity': self.target_replacement_identity,
            'rendererContractIdentity': self.renderer_contract_identity,
            'authorityIdentity': self.authority_identity,
            'effectRelationSetIdentity': self.effect_relation_set_identity,
            'sourceRange': list(self.source_range), 'clobberClasses': list(self.clobber_classes),
            'disposition': 'supported' if self.supported else 'precondition_rejected',
            'reasonCodes': list(self.reason_codes),
        }
        return {**payload, 'decisionIdentity': identity(payload)}


def assess_observer_shell(finding, compiler_boundary, boundary, graph, statement):
    """Evaluate structured facts; source mnemonics and variable names are unused."""
    approval = finding.get('approvalArtifact', {})
    fragment = finding.get('fragment', {})
    reasons, classes = set(), set()
    clobbers = fragment.get('clobbers', [])
    if not isinstance(clobbers, list) or any(not isinstance(x, str) for x in clobbers):
        clobbers = []
        reasons.add('L2_OBSERVER_CLOBBER_CONTRACT_INVALID')
    for raw_name in clobbers:
        name = raw_name.strip().lower()
        if name == 'cc':
            classes.add('condition_code')
        elif name == 'memory':
            classes.add('memory')
            reasons.add('L2_OBSERVER_MEMORY_CLOBBER_UNSUPPORTED')
        else:
            classes.add('unmodelled_register_or_state')
            reasons.add('L2_OBSERVER_REGISTER_OR_STATE_CLOBBER_UNSUPPORTED')
    if (approval.get('proofStatus') != 'approved'
            or approval.get('architectureSemanticsPreserved') is not True
            or approval.get('shellSemanticsPreserved') is not True):
        reasons.add('L2_OBSERVER_TRANSLATION_PROOF_UNAPPROVED')
    outputs, inputs = fragment.get('outputs'), fragment.get('inputs')
    if (not isinstance(outputs, list) or not isinstance(inputs, list)
            or any(not isinstance(x, Mapping) or x.get('constraint') not in
                   {'=r', '+r', 'r', '=&r', '+&r'} for x in (outputs or []) + (inputs or []))):
        reasons.add('L2_OBSERVER_OPERAND_CONSTRAINT_UNSUPPORTED')
    expected_proof = identity({key: approval.get(key, '') for key in (
        'sourceModelId', 'preservationDecisionId', 'planId', 'constraintsId',
        'proofStatus', 'targetEnvironmentId', 'targetCatalogVersion')})
    if approval.get('proofIdentity') != expected_proof:
        reasons.add('L2_OBSERVER_TRANSLATION_PROOF_IDENTITY_MISMATCH')
    facts = None
    try:
        facts = effect_proof_facts_from_dict(approval.get('l2EffectProofFacts', {}))
    except (ValueError, TypeError, KeyError):
        reasons.add('L2_OBSERVER_EFFECT_PROOF_INVALID')
    shell_id = effect_id = renderer_id = ''
    if facts is not None:
        effect_id = facts.to_dict()['factsIdentity']
        renderer_id = facts.renderer_contract_identity
        shell_id = identity(facts.shell_relation.to_dict())
        if ((facts.fragment_id, facts.proof_identity, facts.plan_identity,
             facts.constraint_identity, facts.renderer_contract_identity)
                != (boundary.fragment_id, approval.get('proofIdentity'),
                    approval.get('planId'), approval.get('constraintsId'),
                    approval.get('rendererContractIdentity'))):
            reasons.add('L2_OBSERVER_EFFECT_PROOF_BINDING_MISMATCH')
        if not facts.complete or not all(x.complete for x in (*facts.source_effects, *facts.target_effects, *facts.relations)):
            reasons.add('L2_OBSERVER_EFFECT_PROOF_INCOMPLETE')
        if (not facts.source_effects or not facts.target_effects
                or any(x.effect_kind != 'ScalarResult' for x in (*facts.source_effects, *facts.target_effects))
                or any(x.relation_kind != 'exact' for x in facts.relations)):
            reasons.add('L2_OBSERVER_NONSCALAR_EFFECT_UNSUPPORTED')
        shell = facts.shell_relation
        expected_shell = identity({
            'schemaVersion': 'riscv2x86.shell-relation-binding.v1',
            'fragmentId': boundary.fragment_id, 'proofIdentity': facts.proof_identity,
            'shellRelation': shell.to_dict()})
        if approval.get('shellFactsIdentity') != expected_shell:
            reasons.add('L2_OBSERVER_SHELL_FACT_IDENTITY_MISMATCH')
        if not shell.complete or not shell.compiler_visibility_preserved:
            reasons.add('L2_OBSERVER_COMPILER_VISIBILITY_UNAPPROVED')
        if not shell.volatile_placement_preserved:
            reasons.add('L2_OBSERVER_VOLATILE_PLACEMENT_UNAPPROVED')
        if not shell.continuation_preserved:
            reasons.add('L2_OBSERVER_CONTINUATION_UNAPPROVED')
        if 'condition_code' in classes and not shell.cc_clobber_preserved:
            reasons.add('L2_OBSERVER_CC_RELATION_UNAPPROVED')
    authority_id = relation_set_id = ''
    try:
        sidecar = l2_authority_sidecar_from_dict(
            approval.get('l2AuthoritySidecar', {}), expected_fragment_id=boundary.fragment_id)
        authority_id = sidecar.authority_identity
        relation_set_id = sidecar.effect_relation_set_identity
        if (not sidecar.complete or sidecar.shell_fact_identity != approval.get('shellFactsIdentity')):
            reasons.add('L2_OBSERVER_SIDECAR_SHELL_MISMATCH')
        if facts is not None and (
                [x.to_dict() for x in sidecar.source_effects]
                != [x.to_dict() for x in sorted(facts.source_effects, key=lambda x: x.effect_id)]
                or [x.to_dict() for x in sidecar.approved_effect_relations]
                != [x.approved_relation().to_dict() for x in sorted(facts.relations, key=lambda x: x.relation_id)]):
            reasons.add('L2_OBSERVER_SIDECAR_EFFECT_RELATION_MISMATCH')
        if any(x.fixed_register_contract for x in sidecar.operands):
            reasons.add('L2_OBSERVER_FIXED_REGISTER_UNSUPPORTED')
        if sidecar.memory_objects or sidecar.control_flow or sidecar.ordering or sidecar.runtime_contracts:
            reasons.add('L2_OBSERVER_NONSCALAR_AUTHORITY_UNSUPPORTED')
    except (ValueError, TypeError, KeyError):
        reasons.add('L2_OBSERVER_SIDECAR_INVALID')
    if any(fragment.get(key) for key in ('gotoLabels', 'hasAsmGoto', 'hasExternalControlFlow', 'hasNonLocalControlDependency')):
        reasons.add('L2_OBSERVER_CONTROL_FLOW_UNSUPPORTED')
    before, after = statement['beforeOffset'], statement['afterOffset']
    if finding.get('rewriteBeginOffset') != before or finding.get('rewriteEndOffset') != after:
        reasons.add('L2_OBSERVER_INSERTION_BOUNDARY_INVALID')
    replacement = finding.get('suggestedReplacement')
    if not isinstance(replacement, str) or not replacement:
        replacement = finding.get('translationAttemptArtifact', {}).get('candidateReplacement')
    if not isinstance(replacement, str) or not replacement:
        reasons.add('L2_OBSERVER_TARGET_REPLACEMENT_MISSING')
        replacement = ''
    shell_payload = {key: fragment.get(key) for key in (
        'outputs', 'inputs', 'clobbers', 'isVolatile', 'gotoLabels',
        'hasAsmGoto', 'hasExternalControlFlow', 'hasNonLocalControlDependency')}
    return ObserverShellCompatibilityDecision(
        boundary.fragment_id, compiler_boundary['sourceDigest'],
        compiler_boundary['boundaryIdentity'], boundary.boundary_identity, graph.graph_identity,
        str(approval.get('proofIdentity', '')), effect_id, shell_id, identity(shell_payload),
        identity({'replacement': replacement, 'begin': before, 'end': after}), renderer_id,
        authority_id, relation_set_id,
        (before, after), tuple(sorted(classes)), tuple(sorted(reasons)))


def validate_observer_shell_decision(value):
    """Strict readback for the approved decision carried by an observer plan."""
    fields = {'schemaVersion', 'ruleIdentity', 'fragmentId', 'sourceDigest',
              'compilerBoundaryIdentity', 'boundaryIdentity', 'graphIdentity',
              'proofIdentity', 'effectFactsIdentity', 'shellRelationIdentity',
              'sourceShellIdentity', 'targetReplacementIdentity', 'rendererContractIdentity',
              'authorityIdentity', 'effectRelationSetIdentity',
              'sourceRange', 'clobberClasses', 'disposition', 'reasonCodes', 'decisionIdentity'}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError('observer shell decision fields invalid')
    if (value['schemaVersion'] != SCHEMA or value['ruleIdentity'] != RULE
            or value['decisionIdentity'] != identity({k: v for k, v in value.items() if k != 'decisionIdentity'})
            or value['disposition'] != 'supported' or value['reasonCodes'] != []):
        raise ValueError('observer shell decision identity/disposition invalid')
    for key in fields - {'schemaVersion', 'ruleIdentity', 'fragmentId', 'sourceRange',
                         'clobberClasses', 'disposition', 'reasonCodes'}:
        if not isinstance(value[key], str) or _SHA.fullmatch(value[key]) is None:
            raise ValueError('observer shell decision identity malformed: ' + key)
    extent = value['sourceRange']
    if (not value['fragmentId'] or not isinstance(extent, list) or len(extent) != 2
            or any(isinstance(x, bool) or not isinstance(x, int) for x in extent)
            or not 0 <= extent[0] < extent[1]
            or not isinstance(value['clobberClasses'], list)
            or value['clobberClasses'] not in ([], ['condition_code'])):
        raise ValueError('observer shell decision range/clobbers invalid')
