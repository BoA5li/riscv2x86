"""Compiler/proof-produced L2 authority for bounded automatic scalar runs.

This materializer runs before candidate staging.  Validators only consume the
result and therefore never infer operand bindings or effect relations.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping, Sequence

from .compiler_provenance import bind_compiler_provenance

from .l2_authority import (
    L2AuthorityProducer,
    L2AuthoritySidecar,
    L2OperandAuthority,
    L2OrderingAuthority,
    L2SourceEffectAuthority,
    L2InternalValueAuthority,
    L2IgnoredStateAuthority,
    L2RuntimeContractBinding,
    L2_CLOSED_AUTHORITY_SIDECAR_SCHEMA,
)
from .l2_control_flow import (
    bind_control_flow_authority,
    control_flow_proof_facts_from_dict,
)
from .l2_memory_object import (
    assess_memory_authority_materializability,
    assess_memory_l2_dimension_closure,
    bind_memory_object_authority,
    memory_proof_facts_from_dict,
)
from .l2_fence_ordering import (
    fence_proof_facts_from_dict,
    validate_fence_effect_closure,
)
from .l2_internal_value import (
    bind_instrumentation_plan,
    instrumentation_plan_from_dict,
    internal_value_proof_facts_from_dict,
)
from .l2_fragment_execution import (
    boundary_as_legacy, fragment_boundary_from_dict,
    fragment_dependency_graph_from_dict,
    materialize_fragment_execution_authority,
    materialize_operand_observation_authority,
)
from .l2_semantic_profile import L2PatternKind, l2_fragment_semantic_profile_from_dict
from .l2_scalar_authority import assess_scalar_authority_materializability
from .l2_effect_proof import effect_proof_facts_from_dict
from .l2_materialization import (
    FragmentL2MaterializationDecision, assess_fragment_l2_materializability,
    required_dimensions_for_finding,
)
from .canonical_l2_operand import (
    bind_canonical_l2_operands, canonical_l2_operand_binding_set,
)


_INTEGER = re.compile(r"^(?:const |volatile )*(u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)$")
_INTEGER_POINTER = re.compile(r"^(?:const |volatile )*(?:u?int(?:8|16|32|64)_t|unsigned(?: (?:char|short|int|long|long long))?|signed(?: (?:char|short|int|long|long long))?|char|short|int|long|long long)(?: const| volatile)*\s*\*$")


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


def _width(type_name: str) -> int:
    name = " ".join(type_name.replace("const", "").replace("volatile", "").split())
    fixed = re.fullmatch(r"u?int(8|16|32|64)_t", name)
    if fixed:
        return int(fixed.group(1))
    return {"char": 8, "signed char": 8, "unsigned char": 8,
            "short": 16, "signed short": 16, "unsigned short": 16,
            "int": 32, "signed int": 32, "unsigned int": 32,
            "long": 64, "signed long": 64, "unsigned long": 64,
            "long long": 64, "signed long long": 64,
            "unsigned long long": 64}.get(name, 0)


def _signedness(type_name: str) -> str:
    name = " ".join(type_name.replace("const", "").replace("volatile", "").split())
    if not _INTEGER.fullmatch(type_name.strip()):
        return "not_applicable"
    return "unsigned" if name.startswith("u") or name.startswith("unsigned") else "signed"


def _shell_identity(approval: Mapping[str, object], fragment_id: str) -> str:
    existing = approval.get("shellFactsIdentity")
    if isinstance(existing, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", existing):
        return existing
    return _identity({
        "schemaVersion": "riscv2x86.shell-facts-binding.v1",
        "sourceFragmentId": fragment_id,
        "sourceModelId": str(approval.get("sourceModelId", "")),
        "constraintsId": str(approval.get("constraintsId", "")),
    })


def _proof_effect_authority(approval: Mapping[str, object], fragment_id: str):
    """Validate and package Phase-6D facts; never manufacture a relation."""
    raw = approval.get("l2EffectProofFacts")
    if not isinstance(raw, Mapping):
        return None
    try:
        facts = effect_proof_facts_from_dict(raw)
    except (TypeError, ValueError):
        return None
    expected = {
        "fragment_id": fragment_id,
        "proof_identity": approval.get("proofIdentity"),
        "plan_identity": approval.get("planId"),
        "constraint_identity": approval.get("constraintsId"),
        "renderer_contract_identity": approval.get("rendererContractIdentity"),
    }
    if (not facts.complete or any(getattr(facts, key) != value
                                  for key, value in expected.items())):
        return None
    try:
        relations = tuple(sorted(
            (item.approved_relation() for item in facts.relations),
            key=lambda item: item.relation_id))
    except ValueError:
        return None
    effects = tuple(sorted((L2SourceEffectAuthority(
        item.effect_id, item.effect_kind, item.logical_subject, item.complete)
        for item in facts.source_effects), key=lambda item: item.effect_id))
    shell_identity = _identity({
        "schemaVersion": "riscv2x86.shell-relation-binding.v1",
        "fragmentId": fragment_id,
        "proofIdentity": facts.proof_identity,
        "shellRelation": facts.shell_relation.to_dict(),
    })
    return effects, relations, shell_identity


def _asm_goto_authority(finding, functions, producer_digest):
    from .l2_asm_goto import validate_asm_goto_proof_facts
    from .l2_authority import L2ControlFlowAuthority
    fragment, approval=finding.get('fragment'),finding.get('approvalArtifact')
    if not isinstance(fragment,Mapping) or not isinstance(approval,Mapping):
        return None
    profile=finding.get('l2SemanticProfile',{})
    if profile.get('patternKind')!='asm_goto':
        return None
    try:
        authority=validate_asm_goto_proof_facts(approval.get('l2AsmGotoProofFacts'),fragment,approval)
        matches=[x for x in functions if x.get('name')==fragment.get('enclosingFunction')]
        if len(matches)!=1:
            return None
        function_boundary=matches[0]['l2OperandBoundary']
        boundary=approval.get('l2FragmentOperandBoundary',function_boundary)
        canonical=bind_canonical_l2_operands(fragment,boundary,function_boundary,approval['l2EffectProofFacts'])
        if len(canonical)!=1 or canonical[0].access_mode!='input':
            return None
        index=int(authority.lhs_binding.split(':')[-1])
        if canonical[0].operand_index!=index:
            return None
        operands=tuple(L2OperandAuthority(operand_id=x.operand_id,operand_index=x.operand_index,
            logical_name=x.logical_name,access_mode=x.access_mode,type_kind=x.type_kind,
            width_bits=x.width_bits,signedness=x.signedness,tied_to_operand_id=x.tied_to_operand_id,
            early_clobber=x.early_clobber,fixed_register_contract='',escape_kind=x.escape_kind,
            value_node_identity=x.value_node_identity,declaration_id=x.declaration_identity,
            parameter_index=x.parameter_index,source_constraint=x.source_constraint) for x in canonical)
        effects,relations,shell=_proof_effect_authority(approval,authority.fragment_id)
        if (len(effects)!=1 or effects[0].effect_kind!='ControlTransfer'
                or len(relations)!=1 or not {'branch_continuation','target'}.issubset(relations[0].observable_requirements)):
            return None
        control=L2ControlFlowAuthority('asm-goto:predicate',(operands[0].operand_id,),
            tuple(sorted((authority.taken_successor_block,authority.fallthrough_successor_block))),True,
            transfer_kind='asm_goto',condition_kind=authority.condition_kind,
            source_continuation=authority.fallthrough_successor_block,
            target_continuation=authority.taken_successor_block,termination_kind='fallthrough')
        return L2AuthoritySidecar(authority.fragment_id,
            L2AuthorityProducer('translation-proof-sidecar','automatic-asm-goto-authority','v1',producer_digest),
            shell,operands,(),effects,relations,(),(),True,control_flow=(control,))
    except (KeyError,TypeError,ValueError):
        return None


def _instruction_stream_authority_checked(finding, functions, producer_digest):
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment,Mapping) or not isinstance(approval,Mapping): return None
    if approval.get("artifactVersion") != "phase6-instruction-stream-sync-v3": return None
    from .l2_instruction_stream import validate_instruction_stream_approval
    validate_instruction_stream_approval(approval,fragment,finding.get("suggestedReplacement"),
        source_digest=finding.get("sourceDigest"))
    if finding.get("machineCodeHex") != approval["instructionStreamProof"]["machineCodeHex"]:
        raise ValueError("ISS_MACHINE_CODE_BINDING_MISMATCH")
    effects,relations,shell=_proof_effect_authority(approval,approval["sourceFragmentId"])
    runtime=L2RuntimeContractBinding(approval["runtimeContractId"],approval["runtimeContractVersion"],
        _identity(approval["instructionStreamProof"]),True)
    return L2AuthoritySidecar(approval["sourceFragmentId"],L2AuthorityProducer(
        "translation-proof-sidecar","instruction-visibility-authority","v1",producer_digest),
        shell,(),(),effects,relations,(runtime,),(),True)

def _instruction_stream_authority(finding, functions, producer_digest):
    try:
        return _instruction_stream_authority_checked(finding,functions,producer_digest)
    except (KeyError,TypeError,ValueError,AttributeError):
        return None


def _csr_runtime_authority_checked(finding, functions, producer_digest):
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    if approval.get("artifactVersion") != "phase6-csr-runtime-v1":
        return None
    from .csr_runtime_approval import validate_csr_runtime_approval
    validate_csr_runtime_approval(approval, fragment, finding.get("suggestedReplacement"))
    if finding.get("machineCodeHex") != approval["proofPayload"]["machineCodeHex"]:
        raise ValueError("CSR_RUNTIME_MACHINE_CODE_BINDING_MISMATCH")
    fid = str(fragment.get("id") or fragment.get("fragmentId") or "")
    matches = [x for x in functions if x.get("name") == fragment.get("enclosingFunction")]
    if len(matches) != 1:
        raise ValueError("CSR_RUNTIME_FUNCTION_BOUNDARY_AMBIGUOUS_OR_MISSING")
    boundary = approval.get("l2FragmentOperandBoundary")
    canonical = bind_canonical_l2_operands(fragment, boundary,
        matches[0].get("l2OperandBoundary"), approval["l2EffectProofFacts"])
    operands = tuple(L2OperandAuthority(x.operand_id,x.operand_index,x.operand_id,
        x.access_mode,x.type_kind,x.width_bits,x.signedness,x.tied_to_operand_id,
        x.early_clobber,"",x.escape_kind,x.value_node_identity,
        declaration_id=x.declaration_identity,parameter_index=x.parameter_index,
        source_constraint=x.source_constraint) for x in canonical)
    effects, relations, shell = _proof_effect_authority(approval, fid)
    runtime = L2RuntimeContractBinding(approval["runtimeContractId"],
        approval["runtimeContractVersion"],_identity(approval["proofPayload"]),True)
    ignored = tuple(L2IgnoredStateAuthority(x,"explicit-functional-observability", "non_escaping",True)
                    for x in approval.get("ignoredSourceState",()))
    return L2AuthoritySidecar(fid,L2AuthorityProducer("translation-proof-sidecar",
        "csr-runtime-authority","v1",producer_digest),shell,operands,(),effects,relations,
        (runtime,),ignored,True)

def _csr_runtime_authority(finding, functions, producer_digest):
    try:
        return _csr_runtime_authority_checked(finding,functions,producer_digest)
    except (KeyError,TypeError,ValueError,AttributeError):
        return None


def _scalar_authority(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    producer_digest: str,
) -> L2AuthoritySidecar | None:
    fragment = finding.get("fragment")
    approval = finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    if (approval.get("proofStatus") != "approved"
            or approval.get("architectureSemanticsPreserved") is False
            or approval.get("shellSemanticsPreserved") is False):
        return None
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    if not fragment_id or len(matches) != 1:
        return None
    function = matches[0]
    function_boundary = function.get("l2OperandBoundary")
    raw_fragment_boundary = approval.get("l2FragmentOperandBoundary")
    per_fragment = isinstance(raw_fragment_boundary, Mapping)
    parsed_boundary = None
    if per_fragment:
        try:
            parsed_boundary = fragment_boundary_from_dict(
                raw_fragment_boundary, expected_fragment_id=fragment_id)
        except (TypeError, ValueError):
            return None
    boundary = (boundary_as_legacy(raw_fragment_boundary, function_boundary)
                if per_fragment and isinstance(function_boundary, Mapping)
                else function_boundary)
    decision_boundary = (raw_fragment_boundary if per_fragment else function_boundary)
    decision = assess_scalar_authority_materializability(
        finding, function,
        decision_boundary if isinstance(decision_boundary, Mapping) else None)
    if not decision.materializable:
        return None
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    if (not isinstance(boundary, Mapping) or boundary.get("complete") is not True
            or not isinstance(outputs, list) or not isinstance(inputs, list)
            or not outputs + inputs):
        return None
    try:
        canonical = bind_canonical_l2_operands(
            fragment,
            raw_fragment_boundary if per_fragment else boundary,
            function_boundary if isinstance(function_boundary, Mapping) else boundary,
            approval["l2EffectProofFacts"],
        )
        operands = [L2OperandAuthority(
            operand_id=item.operand_id, operand_index=item.operand_index,
            logical_name=item.logical_name, access_mode=item.access_mode,
            type_kind=item.type_kind, width_bits=item.width_bits,
            signedness=item.signedness,
            tied_to_operand_id=item.tied_to_operand_id,
            early_clobber=item.early_clobber, fixed_register_contract="",
            escape_kind=item.escape_kind,
            value_node_identity=item.value_node_identity,
            declaration_id=item.declaration_identity,
            parameter_index=item.parameter_index,
            source_constraint=item.source_constraint,
            target_contract_carried_by_proof=True,
        ) for item in canonical]
        if isinstance(approval, dict):
            approval["l2CanonicalOperandBindings"] = \
                canonical_l2_operand_binding_set(
                    canonical, proof_identity=str(approval["proofIdentity"]))
    except (KeyError, TypeError, ValueError):
        return None
    output_ids = [item.declaration_id for item in operands
                  if item.access_mode in {"output", "read_write"}]
    arity = function.get("arity")
    if isinstance(arity, bool) or not isinstance(arity, int) or not 1 <= arity <= 4:
        return None
    raw_profile = finding.get("l2SemanticProfile")
    if not isinstance(raw_profile, Mapping):
        return None
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id,
        )
    except ValueError:
        return None
    if profile.pattern_kind not in {
            L2PatternKind.SCALAR, L2PatternKind.BRANCH, L2PatternKind.JUMP,
            L2PatternKind.COMPOSITE}:
        return None
    internal_values = ()
    instrumentation_plan_identity = ""
    if profile.pattern_kind is L2PatternKind.COMPOSITE:
        raw_internal = approval.get("l2InternalValueProofFacts")
        if not isinstance(raw_internal, Mapping):
            return None
        try:
            internal_facts = internal_value_proof_facts_from_dict(raw_internal)
            if internal_facts.fragment_id != fragment_id:
                return None
            rewrite_end = finding.get("rewriteEndOffset")
            instrumentation = bind_instrumentation_plan(
                internal_facts, boundary,
                insertion_offset=(rewrite_end if isinstance(rewrite_end, int)
                                  and not isinstance(rewrite_end, bool)
                                  and rewrite_end > 0 else None),
            )
        except (KeyError, ValueError):
            return None
        internal_values = tuple(sorted((L2InternalValueAuthority(
            point.logical_value_id, point.type_contract.type_kind,
            point.type_contract.width_bits, point.type_contract.signedness,
            "operand" if canonical[point.operand_index].escape_kind
            == "function_return" else "non_escaping",
            True,
        ) for point in instrumentation.points), key=lambda item: item.value_id))
        if isinstance(approval, dict):
            approval["l2InstrumentationPlan"] = instrumentation.to_dict()
        instrumentation_plan_identity = instrumentation.plan_identity
    control_flow = ()
    proof_facts = None
    if profile.pattern_kind in {L2PatternKind.BRANCH, L2PatternKind.JUMP}:
        raw_control = approval.get("l2ControlFlowProofFacts")
        if not isinstance(raw_control, Mapping):
            return None
        try:
            proof_facts = control_flow_proof_facts_from_dict(raw_control)
            if (proof_facts.fragment_id != fragment_id
                    or proof_facts.pattern_kind != profile.pattern_kind.value):
                return None
            control_flow = (bind_control_flow_authority(proof_facts, operands),)
        except (KeyError, ValueError):
            return None
    proof_authority = _proof_effect_authority(approval, fragment_id)
    if proof_authority is None:
        return None
    source_effects, relations, shell_identity = proof_authority
    observation_authority = None
    if parsed_boundary is not None:
        try:
            graph = fragment_dependency_graph_from_dict(
                approval["l2FragmentDependencyGraph"],
                expected_fragment_id=fragment_id)
            observation_authority = materialize_operand_observation_authority(
                parsed_boundary,
                operand_ids={item.operand_index: item.operand_id for item in canonical},
                parameter_indices={item.operand_index: item.parameter_index for item in canonical},
                proof_identity=str(approval["proofIdentity"]),
                dependency_graph_identity=graph.graph_identity,
                dependency_edges=graph.edges,
                instrumentation_plan_identity=instrumentation_plan_identity,
                canonical_bindings=canonical,
            )
        except (KeyError, TypeError, ValueError):
            return None
    return L2AuthoritySidecar(
        fragment_id,
        L2AuthorityProducer("frontend-compiler-sidecar", "automatic-fragment-authority",
                            "v6", producer_digest),
        shell_identity, tuple(operands), (), source_effects, relations,
        (), (), True, control_flow=control_flow, internal_values=internal_values,
        schema_version=(L2_CLOSED_AUTHORITY_SIDECAR_SCHEMA
                        if observation_authority is not None
                        else "riscv2x86.l2-authority-sidecar.v3"),
        operand_observation_authority=observation_authority,
    )


def _memory_operand_boundary(
    approval: Mapping[str, object], function: Mapping[str, object],
) -> Mapping[str, object] | None:
    """Join fragment value nodes with function/harness object contracts.

    Memory authority needs both granularities.  Returning either side alone
    would lose the compiler value-node identity or the bounded object fact.
    """
    function_boundary = function.get("l2OperandBoundary")
    raw_fragment_boundary = approval.get("l2FragmentOperandBoundary")
    if (isinstance(raw_fragment_boundary, Mapping)
            and isinstance(function_boundary, Mapping)):
        result = boundary_as_legacy(raw_fragment_boundary, function_boundary)
    elif isinstance(function_boundary, Mapping):
        result = dict(function_boundary)
    else:
        return None
    result["sourceDigest"] = function.get("sourceDigest", result.get("sourceDigest", ""))
    return result


def _memory_authority(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    producer_digest: str,
) -> L2AuthoritySidecar | None:
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    if (approval.get("proofStatus") != "approved"
            or approval.get("architectureSemanticsPreserved") is False
            or approval.get("shellSemanticsPreserved") is False):
        return None
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    raw_profile, raw_facts = finding.get("l2SemanticProfile"), approval.get("l2MemoryProofFacts")
    if (not fragment_id or len(matches) != 1 or not isinstance(raw_profile, Mapping)
            or not isinstance(raw_facts, Mapping)):
        return None
    function = matches[0]
    boundary = _memory_operand_boundary(approval, function)
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
        facts = memory_proof_facts_from_dict(raw_facts)
    except ValueError:
        return None
    if profile.pattern_kind not in {L2PatternKind.MEMORY_LOAD, L2PatternKind.MEMORY_STORE}:
        return None
    decision = assess_memory_authority_materializability(
        approval, facts, boundary if isinstance(boundary, Mapping) else None,
        fragment)
    if not decision.materializable or decision.authority is None:
        return None
    raw_fragment_boundary = approval.get("l2FragmentOperandBoundary")
    function_boundary = function.get("l2OperandBoundary")
    try:
        canonical = bind_canonical_l2_operands(
            fragment,
            raw_fragment_boundary if isinstance(raw_fragment_boundary, Mapping) else boundary,
            function_boundary if isinstance(function_boundary, Mapping) else boundary,
            approval["l2EffectProofFacts"],
        )
        operands = [L2OperandAuthority(
            item.operand_id, item.operand_index, item.logical_name,
            "address" if item.operand_index == facts.address_operand_index
            else item.access_mode,
            item.type_kind, item.width_bits, item.signedness,
            item.tied_to_operand_id, item.early_clobber, "",
            item.escape_kind,
            item.value_node_identity, item.declaration_identity,
            item.parameter_index, item.source_constraint, True,
        ) for item in canonical]
        if isinstance(approval, dict):
            approval["l2CanonicalOperandBindings"] = \
                canonical_l2_operand_binding_set(
                    canonical, proof_identity=str(approval["proofIdentity"]))
    except (KeyError, TypeError, ValueError):
        return None
    expected_access = {
        L2PatternKind.MEMORY_LOAD: "load",
        L2PatternKind.MEMORY_STORE: "store",
    }[profile.pattern_kind]
    by_index = {item.operand_index: item for item in operands}
    address_operand = by_index.get(facts.address_operand_index)
    value_operand = by_index.get(facts.value_operand_index)
    if (facts.access_kind != expected_access
            or address_operand is None or address_operand.type_kind != "pointer"
            or address_operand.access_mode != "address"
            or value_operand is None or value_operand.type_kind != "integer"
            or value_operand.width_bits != facts.width_bytes * 8):
        return None
    try:
        memory_object, object_id = bind_memory_object_authority(
            facts, operands, decision.authority)
    except ValueError:
        return None
    proof_authority = _proof_effect_authority(approval, fragment_id)
    if proof_authority is None:
        return None
    effects, relations, shell_identity = proof_authority
    return L2AuthoritySidecar(
        fragment_id, L2AuthorityProducer("frontend-compiler-sidecar",
          "automatic-memory-authority", "v3", producer_digest),
        shell_identity, tuple(operands), (memory_object,),
        effects, relations, (), (), True,
    )


def _fence_authority(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    producer_digest: str,
) -> L2AuthoritySidecar | None:
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    raw_profile, raw_facts = finding.get("l2SemanticProfile"), approval.get("l2FenceProofFacts")
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    if (approval.get("proofStatus") != "approved" or not fragment_id or len(matches) != 1
            or not isinstance(raw_profile, Mapping) or not isinstance(raw_facts, Mapping)):
        return None
    function = matches[0]
    if function.get("arity") != 0 or function.get("returnType") != "void":
        return None
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
        facts = fence_proof_facts_from_dict(raw_facts)
    except ValueError:
        return None
    if (profile.pattern_kind is not L2PatternKind.FENCE or facts.fragment_id != fragment_id
            or not facts.complete
            or approval.get("rendererSemanticContractId")
                != facts.target_semantic_contract_id
            or approval.get("rendererContractId") != facts.target_renderer_contract_id
            or approval.get("rendererVersion") != facts.target_renderer_version):
        return None
    proof_authority = _proof_effect_authority(approval, fragment_id)
    if proof_authority is None:
        return None
    effects, relations, shell_identity = proof_authority
    try:
        validate_fence_effect_closure(facts, effect_proof_facts_from_dict(
            approval["l2EffectProofFacts"]))
    except (KeyError, ValueError):
        return None
    ordering = (L2OrderingAuthority(
        "ordering:fence-domain", facts.before_effect_id, facts.after_effect_id, True),)
    return L2AuthoritySidecar(
        fragment_id, L2AuthorityProducer("translation-proof-sidecar",
          "automatic-fence-ordering-authority", "v1", producer_digest),
        shell_identity, (), (), effects, relations, (), (), True,
        ordering=ordering,
    )


def _functional_relation_authority(
    finding: Mapping[str, object], producer_digest: str,
) -> L2AuthoritySidecar | None:
    """Materialize only proof-declared functional relations.

    This path consumes the renderer's versioned semantic/runtime contracts. It
    never derives a relation from a mnemonic, file name, helper spelling, or C
    text.  The deliberately narrow property set is what prevents a successful
    fallback from becoming architectural L2 evidence.
    """
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return None
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    raw_profile = finding.get("l2SemanticProfile")
    if (not fragment_id or approval.get("proofStatus") != "functional_approved"
            or approval.get("preservationMode") != "functional_equivalence_only"
            or approval.get("functionalFallbackEnabled") is not True
            or approval.get("architectureSemanticsPreserved") is not False
            or not isinstance(raw_profile, Mapping)):
        return None
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
    except ValueError:
        return None
    if profile.pattern_kind not in {
            L2PatternKind.PRIVILEGED_READ,
            L2PatternKind.INSTRUCTION_VISIBILITY_FENCE}:
        return None
    runtime_id = approval.get("runtimeContractId")
    runtime_version = approval.get("runtimeContractVersion")
    source_contract = approval.get("sourceSemanticContractId")
    target_contract = approval.get("targetSemanticContractId")
    ignored = approval.get("ignoredSourceState")
    non_equivalences = approval.get("knownNonEquivalences")
    if (not all(isinstance(item, str) and item for item in (
            runtime_id, runtime_version, source_contract, target_contract))
            or not isinstance(ignored, list) or not ignored
            or ignored != sorted(set(ignored))
            or not all(isinstance(item, str) and item for item in ignored)
            or not isinstance(non_equivalences, list) or not non_equivalences
            or not all(isinstance(item, str) and item for item in non_equivalences)):
        return None
    contract_identity = _identity({
        "schemaVersion": "riscv2x86.functional-runtime-contract-binding.v1",
        "runtimeContractId": runtime_id,
        "runtimeContractVersion": runtime_version,
        "sourceSemanticContractId": source_contract,
        "targetSemanticContractId": target_contract,
        "targetEnvironmentId": approval.get("targetEnvironmentId", ""),
        "targetCatalogVersion": approval.get("targetCatalogVersion", ""),
    })
    runtime = L2RuntimeContractBinding(
        str(runtime_id), str(runtime_version), contract_identity, True)
    proof_authority = _proof_effect_authority(approval, fragment_id)
    if proof_authority is None:
        return None
    effects, relations, shell_identity = proof_authority
    ignored_state = tuple(L2IgnoredStateAuthority(
        item, "declared-functional-non-equivalence", "non_escaping", True,
    ) for item in ignored)
    return L2AuthoritySidecar(
        fragment_id, L2AuthorityProducer(
            "translation-proof-sidecar", "functional-relation-authority", "v1",
            producer_digest),
        shell_identity, (), (), effects, relations,
        (runtime,), ignored_state, True,
    )


def _memory_authority_failure_reason(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
) -> str:
    """Return the first proof-owned reason that prevents memory authority.

    This mirrors the materializer's closed contract.  It is diagnostic only:
    no missing fact is interpreted as false and no object is reconstructed
    from a raw address.
    """
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return "L2_MEMORY_APPROVAL_ARTIFACT_MISSING"
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    if (approval.get("proofStatus") != "approved"
            or approval.get("architectureSemanticsPreserved") is False
            or approval.get("shellSemanticsPreserved") is False
            or not fragment_id):
        return "L2_MEMORY_PROOF_NOT_APPROVED"
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    if len(matches) != 1:
        return "L2_MEMORY_FUNCTION_BINDING_AMBIGUOUS"
    raw_profile = finding.get("l2SemanticProfile")
    if not isinstance(raw_profile, Mapping):
        return "L2_MEMORY_SEMANTIC_PROFILE_MISSING"
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
    except ValueError:
        return "L2_MEMORY_SEMANTIC_PROFILE_INVALID"
    expected_access = {
        L2PatternKind.MEMORY_LOAD: "load",
        L2PatternKind.MEMORY_STORE: "store",
    }.get(profile.pattern_kind)
    if expected_access is None:
        return "L2_MEMORY_SEMANTIC_PROFILE_NOT_SCALAR_MEMORY"
    raw_facts = approval.get("l2MemoryProofFacts")
    if not isinstance(raw_facts, Mapping):
        return "L2_MEMORY_PROOF_FACTS_MISSING"
    try:
        facts = memory_proof_facts_from_dict(raw_facts)
    except ValueError:
        return "L2_MEMORY_PROOF_FACTS_INVALID"
    boundary = _memory_operand_boundary(approval, matches[0])
    decision = assess_memory_authority_materializability(
        approval, facts, boundary if isinstance(boundary, Mapping) else None,
        fragment)
    if not decision.materializable:
        return decision.reason_codes[0]
    if facts.access_kind != expected_access:
        return "L2_MEMORY_PROOF_FACTS_INCOMPLETE"
    outputs, inputs = fragment.get("outputs"), fragment.get("inputs")
    declarations = boundary.get("declarations")
    asm_ids = boundary.get("asmOperandDeclarationIds")
    params = boundary.get("parameterDeclarationIds")
    if (not isinstance(outputs, list) or not isinstance(inputs, list)
            or not isinstance(declarations, Mapping) or not isinstance(asm_ids, list)
            or not isinstance(params, list) or len(asm_ids) != len(outputs) + len(inputs)):
        return "L2_MEMORY_OPERAND_BINDING_INCOMPLETE"
    if (facts.address_operand_index == facts.value_operand_index
            or max(facts.address_operand_index, facts.value_operand_index) >= len(asm_ids)):
        return "L2_MEMORY_OPERAND_INDEX_OUT_OF_RANGE"
    address_declaration = declarations.get(asm_ids[facts.address_operand_index])
    value_declaration = declarations.get(asm_ids[facts.value_operand_index])
    if not isinstance(address_declaration, Mapping) or not isinstance(value_declaration, Mapping):
        return "L2_MEMORY_DECLARATION_BINDING_MISSING"
    if not _INTEGER_POINTER.fullmatch(str(address_declaration.get("type", "")).strip()):
        return "L2_MEMORY_ADDRESS_NOT_TYPED_POINTER"
    value_width = _width(str(value_declaration.get("type", "")))
    if value_width != facts.width_bytes * 8:
        return "L2_MEMORY_VALUE_WIDTH_MISMATCH"
    if asm_ids[facts.address_operand_index] not in params:
        return "L2_MEMORY_ADDRESS_NOT_FUNCTION_ARGUMENT"
    return "L2_MEMORY_AUTHORITY_MATERIALIZATION_REJECTED"


def _authority_materialization_record(
    fragment_id: str, authority_kind: str, status: str, reason_code: str,
    authority_identity: str = "",
) -> dict[str, object]:
    payload = {
        "schemaVersion": "riscv2x86.l2-authority-materialization.v1",
        "fragmentId": fragment_id,
        "authorityKind": authority_kind,
        "status": status,
        "reasonCode": reason_code,
        "authorityIdentity": authority_identity,
    }
    payload["materializationIdentity"] = _identity(payload)
    return payload


def _fence_authority_failure_reason(
    finding: Mapping[str, object], functions: Sequence[Mapping[str, object]],
) -> str:
    """Explain why a fence profile could not become proof-owned authority.

    This is diagnostic only: it never manufactures proof facts or an approved
    relation.  Keeping the cause in the translated report makes corpus results
    auditable instead of collapsing every fail-closed fence into a generic
    missing-relation result.
    """
    fragment, approval = finding.get("fragment"), finding.get("approvalArtifact")
    if not isinstance(fragment, Mapping) or not isinstance(approval, Mapping):
        return "L2_FENCE_APPROVAL_ARTIFACT_MISSING"
    fragment_id = str(fragment.get("id") or fragment.get("fragmentId") or "")
    if approval.get("proofStatus") != "approved" or not fragment_id:
        return "L2_FENCE_PROOF_NOT_APPROVED"
    matches = [item for item in functions
               if item.get("name") == fragment.get("enclosingFunction")]
    if len(matches) != 1:
        return "L2_FENCE_FUNCTION_BINDING_AMBIGUOUS"
    if matches[0].get("arity") != 0 or matches[0].get("returnType") != "void":
        return "L2_FENCE_AUTOMATIC_HARNESS_SIGNATURE_UNSUPPORTED"
    raw_profile = finding.get("l2SemanticProfile")
    if not isinstance(raw_profile, Mapping):
        return "L2_FENCE_SEMANTIC_PROFILE_MISSING"
    try:
        profile = l2_fragment_semantic_profile_from_dict(
            raw_profile, expected_fragment_id=fragment_id)
    except ValueError:
        return "L2_FENCE_SEMANTIC_PROFILE_INVALID"
    if profile.pattern_kind is not L2PatternKind.FENCE:
        return "L2_FENCE_SEMANTIC_PROFILE_NOT_MEMORY_FENCE"
    raw_facts = approval.get("l2FenceProofFacts")
    if not isinstance(raw_facts, Mapping):
        return "L2_FENCE_PROOF_FACTS_MISSING"
    try:
        facts = fence_proof_facts_from_dict(raw_facts)
    except ValueError:
        return "L2_FENCE_PROOF_FACTS_INVALID"
    if facts.fragment_id != fragment_id or not facts.complete:
        return "L2_FENCE_PROOF_FACTS_INCOMPLETE"
    if (approval.get("rendererSemanticContractId")
            != facts.target_semantic_contract_id
            or approval.get("rendererContractId") != facts.target_renderer_contract_id
            or approval.get("rendererVersion") != facts.target_renderer_version):
        return "L2_FENCE_TARGET_CONTRACT_MISMATCH"
    raw_effect = approval.get("l2EffectProofFacts")
    if not isinstance(raw_effect, Mapping):
        return "L2_FENCE_EFFECT_PROOF_FACTS_MISSING"
    try:
        effect_facts = effect_proof_facts_from_dict(raw_effect)
    except ValueError:
        return "L2_FENCE_EFFECT_PROOF_FACTS_INVALID"
    if (effect_facts.fragment_id != fragment_id or not effect_facts.complete):
        return "L2_FENCE_EFFECT_PROOF_FACTS_INCOMPLETE"
    if not effect_facts.shell_relation.memory_clobber_preserved:
        return "L2_FENCE_MEMORY_CLOBBER_SHELL_RELATION_MISSING"
    try:
        validate_fence_effect_closure(facts, effect_facts)
    except ValueError as exc:
        return str(exc)
    return "L2_FENCE_AUTHORITY_MATERIALIZATION_REJECTED"


def materialize_automatic_l2_authority(
    report: Mapping[str, object], functions: Sequence[Mapping[str, object]],
    frontend: str | Path,
) -> int:
    """Attach complete bounded authority to approved scalar findings in-place."""
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("translated report findings are unavailable")
    producer_digest = "sha256:" + sha256(Path(frontend).read_bytes()).hexdigest()
    # Build one compiler-range-bound authority per fragment before any scalar
    # sidecar is considered.  Legacy single-fragment functions remain on their
    # existing closed path when no fragment candidates were exported.
    for function in functions:
        raw_boundary = function.get("l2OperandBoundary") if isinstance(function, Mapping) else None
        candidates = raw_boundary.get("fragmentCandidates") if isinstance(raw_boundary, Mapping) else None
        if not isinstance(function, Mapping) or not isinstance(candidates, list) or not candidates:
            continue
        scoped = [item for item in findings if isinstance(item, Mapping)]
        program_id = str(function.get("programId") or _identity({
            "schemaVersion": "riscv2x86.automatic-program.v1",
            "producerDigest": producer_digest,
        }))
        boundaries, graph, execution = materialize_fragment_execution_authority(
            scoped, function, program_id)
        for finding in scoped:
            fragment = finding.get("fragment")
            approval = finding.get("approvalArtifact")
            fragment_id = (str(fragment.get("id") or fragment.get("fragmentId") or "")
                           if isinstance(fragment, Mapping) else "")
            boundary = boundaries.get(fragment_id)
            if boundary is None or not isinstance(approval, dict):
                continue
            approval["l2FragmentOperandBoundary"] = boundary.to_dict()
            approval["l2FragmentDependencyGraph"] = graph.to_dict()
            approval["l2ProgramExecutionAuthority"] = execution.to_dict()
    count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        raw_profile = finding.get("l2SemanticProfile")
        pattern_kind = (raw_profile.get("patternKind")
                        if isinstance(raw_profile, Mapping) else "")
        is_scalar = pattern_kind in {
            L2PatternKind.SCALAR.value, L2PatternKind.BRANCH.value,
            L2PatternKind.JUMP.value, L2PatternKind.COMPOSITE.value,
        }
        approval = finding.get("approvalArtifact")
        raw_fragment = finding.get("fragment")
        function_matches = [item for item in functions
                            if isinstance(raw_fragment, Mapping)
                            and item.get("name") == raw_fragment.get("enclosingFunction")]
        scalar_decision = None
        if is_scalar and isinstance(approval, dict):
            function = function_matches[0] if len(function_matches) == 1 else None
            raw_boundary = approval.get("l2FragmentOperandBoundary")
            if not isinstance(raw_boundary, Mapping) and isinstance(function, Mapping):
                raw_boundary = function.get("l2OperandBoundary")
            scalar_decision = assess_scalar_authority_materializability(
                finding, function,
                raw_boundary if isinstance(raw_boundary, Mapping) else None)
            approval["l2ScalarAuthorityDecision"] = scalar_decision.to_dict()
        from .l2_atomic_authority import materialize_atomic_authority
        version = approval.get("artifactVersion") if isinstance(approval, Mapping) else ""
        if version=="phase6-instruction-stream-sync-v3" and len(function_matches)==1:
            scope=function_matches[0].get("compilerInstructionSyncScope")
            if scope is not None:
                from .compiler_instruction_sync_scope import validate_scope
                try:
                    validate_scope(scope,raw_fragment,finding.get("sourceDigest"))
                    approval["l2InstructionSyncFunctionScope"]=scope
                except ValueError as exc:
                    approval["l2InstructionSyncScopeReasonCode"]=str(exc)
        if version in {"phase6-csr-runtime-v1", "phase6-instruction-stream-sync-v3"}:
            # A failed typed runtime join must never fall through to a legacy
            # scalar/functional route with a weaker validation contract.
            try:
                sidecar = (_csr_runtime_authority_checked(finding,functions,producer_digest)
                           if version == "phase6-csr-runtime-v1" else
                           _instruction_stream_authority_checked(finding,functions,producer_digest))
                if sidecar is None:
                    raise ValueError("CSR_RUNTIME_CANONICAL_BOUNDARY_REQUIRED" if version == "phase6-csr-runtime-v1"
                        else "ISS_RUNTIME_AUTHORITY_BINDING_INCOMPLETE")
            except (KeyError,TypeError,ValueError,AttributeError) as exc:
                sidecar=None
                reason=str(exc)
                approval["l2RuntimeAuthorityReasonCode"]=reason
                diagnostic={"schemaVersion":"riscv2x86.runtime-authority-materialization-failure.v1",
                    "failureStage":"canonical_l2_authority","fragmentId":(raw_fragment.get("id") or raw_fragment.get("fragmentId")) if isinstance(raw_fragment,Mapping) else "",
                    "sourceDigest":finding.get("sourceDigest"),"proofIdentity":approval.get("proofIdentity"),
                    "exceptionType":type(exc).__name__,"reasonCode":reason,"detail":str(exc),
                    "evidenceProductionDisposition":"not_produced"}
                diagnostic["failureIdentity"]=_identity(diagnostic)
                approval["l2RuntimeAuthorityFailure"]=diagnostic
        else:
            sidecar = (_functional_relation_authority(finding, producer_digest)
                       or materialize_atomic_authority(finding, functions, producer_digest)
                       or _asm_goto_authority(finding, functions, producer_digest)
                       or _fence_authority(finding, functions, producer_digest)
                       or _memory_authority(finding, functions, producer_digest)
                       or _scalar_authority(finding, functions, producer_digest))
        try:
            dimensions = required_dimensions_for_finding(finding)
            unified_decision = assess_fragment_l2_materializability(
                finding, dimensions, sidecar=sidecar)
        except ValueError:
            unified_decision = None
        if isinstance(approval, dict) and unified_decision is not None:
            approval["l2MaterializationDecision"] = unified_decision.to_dict()
        if (sidecar is not None
                and (unified_decision is None or not unified_decision.executable)):
            sidecar = None
        is_memory = pattern_kind in {
            L2PatternKind.MEMORY_LOAD.value, L2PatternKind.MEMORY_STORE.value,
        }
        if is_scalar and isinstance(approval, dict):
            assert scalar_decision is not None
            if sidecar is None and scalar_decision.materializable:
                scalar_decision = scalar_decision.with_reason(
                    "L2_SCALAR_EFFECT_RELATION_MISSING")
            elif sidecar is not None and not scalar_decision.materializable:
                # A sidecar must never bypass a failed common decision.
                sidecar = None
            approval["l2ScalarAuthorityDecision"] = scalar_decision.to_dict()
            approval["l2AuthorityMaterializationReasonCode"] = (
                "L2_SCALAR_AUTHORITY_MATERIALIZED" if sidecar is not None else
                scalar_decision.reason_codes[0])
        if sidecar is not None and is_scalar:
            try:
                join = raw_fragment.get("compilerFragmentJoin", {})
                if join and join.get("disposition") != "matched":
                    raise ValueError("COMPILER_FRAGMENT_REQUIRED_JOIN_UNAVAILABLE")
                if join and not raw_fragment.get("compilerFragmentAuthority"):
                    raise ValueError("COMPILER_FRAGMENT_REQUIRED_AUTHORITY_MISSING")
                provenance = bind_compiler_provenance(raw_fragment, sidecar)
                if provenance is not None:
                    approval["compilerAuthorityConsumption"] = provenance
            except ValueError as exc:
                approval["l2AuthorityMaterializationReasonCode"] = str(exc)
                sidecar = None
        if sidecar is None:
            if (pattern_kind == L2PatternKind.FENCE.value
                    and isinstance(approval, dict)):
                approval["l2AuthorityMaterializationReasonCode"] = \
                    _fence_authority_failure_reason(finding, functions)
            if is_memory and isinstance(approval, dict):
                reason = _memory_authority_failure_reason(finding, functions)
                approval["l2AuthorityMaterializationReasonCode"] = reason
                raw_fragment = finding.get("fragment")
                record_fragment_id = (
                    str(raw_fragment.get("id") or raw_fragment.get("fragmentId") or "")
                    if isinstance(raw_fragment, Mapping) else ""
                )
                approval["l2AuthorityMaterialization"] = \
                    _authority_materialization_record(
                        record_fragment_id, "object_relative_memory",
                        "rejected", reason,
                    )
                matches = [item for item in functions
                           if isinstance(raw_fragment, Mapping)
                           and item.get("name") == raw_fragment.get("enclosingFunction")]
                raw_facts = approval.get("l2MemoryProofFacts")
                decision = assess_memory_authority_materializability(
                    approval, raw_facts if isinstance(raw_facts, Mapping) else None,
                    _memory_operand_boundary(approval, matches[0])
                    if len(matches) == 1 else None,
                    raw_fragment if isinstance(raw_fragment, Mapping) else {})
                approval["l2MemoryAuthorityDecision"] = decision.to_dict()
                approval["l2MemoryDimensionClosure"] = \
                    assess_memory_l2_dimension_closure(
                        decision, approval.get("l2EffectProofFacts")
                        if isinstance(approval.get("l2EffectProofFacts"), Mapping) else None,
                    ).to_dict()
            continue
        assert isinstance(approval, dict)
        proof_payload = {
            key: approval.get(key, "") for key in (
                "sourceModelId", "preservationDecisionId", "planId", "constraintsId",
                "proofStatus", "targetEnvironmentId", "targetCatalogVersion",
            )
        }
        proof_identity = approval.get("proofIdentity")
        if not isinstance(proof_identity, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", proof_identity):
            if not all(proof_payload.values()):
                continue
            approval["proofIdentity"] = _identity(proof_payload)
        approval["shellFactsIdentity"] = sidecar.shell_fact_identity
        approval["l2AuthoritySidecar"] = sidecar.to_dict()
        fragment_outputs = (raw_fragment.get("outputs")
                            if isinstance(raw_fragment, Mapping) else None)
        if (is_scalar and isinstance(fragment_outputs, list)
                and isinstance(approval.get("l2FragmentOperandBoundary"), Mapping)):
            try:
                fragment_id = str(raw_fragment.get("id") or raw_fragment.get(
                    "fragmentId") or "") if isinstance(raw_fragment, Mapping) else ""
                boundary = fragment_boundary_from_dict(
                    approval["l2FragmentOperandBoundary"],
                    expected_fragment_id=fragment_id)
                raw_graph = approval.get("l2FragmentDependencyGraph")
                if not isinstance(raw_graph, Mapping):
                    raise ValueError("fragment dependency graph is missing")
                graph = fragment_dependency_graph_from_dict(raw_graph)
                raw_plan = approval.get("l2InstrumentationPlan")
                plan_identity = ""
                if raw_plan is not None:
                    if not isinstance(raw_plan, Mapping):
                        raise ValueError("instrumentation plan is invalid")
                    plan = instrumentation_plan_from_dict(raw_plan)
                    if plan.fragment_id != fragment_id or not plan.complete:
                        raise ValueError("instrumentation plan is incomplete")
                    plan_identity = plan.plan_identity
                observation_authority = sidecar.operand_observation_authority
                if observation_authority is None:
                    raise ValueError("sidecar observation authority is missing")
                approval["l2OperandObservationAuthority"] = \
                    observation_authority.to_dict()
            except ValueError:
                approval.pop("l2OperandObservationAuthority", None)
                approval["l2AuthorityMaterializationReasonCode"] = \
                    "L2_OPERAND_OBSERVATION_AUTHORITY_INCOMPLETE"
                if scalar_decision is not None:
                    scalar_decision = scalar_decision.with_reason(
                        "L2_OPERAND_OBSERVATION_AUTHORITY_INCOMPLETE")
                    approval["l2ScalarAuthorityDecision"] = \
                        scalar_decision.to_dict()
                dimensions = required_dimensions_for_finding(finding)
                approval["l2MaterializationDecision"] = \
                    FragmentL2MaterializationDecision(
                        fragment_id, dimensions, False, True, True, False,
                        ("L2_OPERAND_OBSERVATION_AUTHORITY_INCOMPLETE",),
                        sidecar.authority_identity,
                    ).to_dict()
        if is_memory:
            raw_fragment = finding.get("fragment")
            matches = [item for item in functions
                       if isinstance(raw_fragment, Mapping)
                       and item.get("name") == raw_fragment.get("enclosingFunction")]
            decision = assess_memory_authority_materializability(
                approval, approval.get("l2MemoryProofFacts")
                if isinstance(approval.get("l2MemoryProofFacts"), Mapping) else None,
                _memory_operand_boundary(approval, matches[0])
                if len(matches) == 1 else None,
                raw_fragment if isinstance(raw_fragment, Mapping) else {})
            approval["l2MemoryAuthorityDecision"] = decision.to_dict()
            approval["l2MemoryDimensionClosure"] = \
                assess_memory_l2_dimension_closure(
                    decision, approval.get("l2EffectProofFacts")
                    if isinstance(approval.get("l2EffectProofFacts"), Mapping) else None,
                ).to_dict()
            approval["l2AuthorityMaterializationReasonCode"] = \
                "L2_MEMORY_AUTHORITY_MATERIALIZED"
            approval["l2AuthorityMaterialization"] = \
                _authority_materialization_record(
                    sidecar.fragment_id, "object_relative_memory", "materialized",
                    "L2_MEMORY_AUTHORITY_MATERIALIZED",
                    sidecar.authority_identity,
                )
        count += 1
    return count
