"""Normal-pipeline scheduler for approved D-class definition rewrites."""
from __future__ import annotations
from .schema import Finding
from .whole_function_sidecar import WholeFunctionSidecar
from .whole_function import classify_whole_function_route, translate_whole_function

def schedule_whole_function_replacements(findings:list[Finding], sidecar:WholeFunctionSidecar|None)->tuple[Finding,...]:
    if sidecar is None:return ()
    fragment_map={f.fragment.id:f for f in findings if f.fragment is not None and f.fragment.id}
    emitted=[]; claimed=set()
    for facts in sidecar.facts:
        members=tuple(facts.fragment_ids); missing=[x for x in members if x not in fragment_map]
        if not members or missing or len(set(members))!=len(members) or any(x in claimed for x in members):continue
        cfg=facts.control_flow
        route=classify_whole_function_route(reads_registers=frozenset(),writes_registers=frozenset(),has_call=bool(cfg and any(x.kind=="call" for x in cfg.nodes)),has_return=bool(cfg and cfg.normal_exits),has_tail_call=False,stack_kind=None if facts.stack is None else facts.stack.frame_kind,dynamic_adjustment=bool(facts.stack and facts.stack.dynamic_adjustment_present),stack_complete=bool(facts.stack and facts.stack.complete),has_unwind_or_exception_edge=None if cfg is None else cfg.has_exceptional_exit)
        artifact,proof=translate_whole_function(facts=facts,route=route)
        ast=facts.ast_binding
        if artifact is None or proof is None or not proof.approved or ast is None or not ast.source_file:continue
        for member in members:
            original=fragment_map[member]; original.category="AlreadyRule"; original.ruleName="phase6.whole_function.member_suppressed"; original.suggestedReplacement=""; original.translationKind="whole_function_member"; original.verificationStatus="covered_by_whole_function"; original.notes.append("phase6-whole-function: covered by approved function-definition rewrite")
        emitted.append(Finding(category="ReplaceableByRule",subjectKind="Function",hasRewriteRange=True,rewriteBeginOffset=artifact.source_definition_range.start,rewriteEndOffset=artifact.source_definition_range.end,fileName=ast.source_file,suggestedReplacement=artifact.replacement_text,ruleName="phase6.whole_function.structured_c",translationKind="whole_function_structured_c",verificationStatus="approved",approvalArtifact={"artifactVersion":"phase6-whole-function-v1","proofStatus":"approved","replacementKind":"whole_function_structured_c","functionId":artifact.function_id,"astBindingId":artifact.ast_binding_id,"proofIdentity":artifact.proof_identity,"phase5Evidence":{"mixedCfgIdentity":artifact.phase5_evidence.mixed_cfg_identity,"frameDataflowIdentity":artifact.phase5_evidence.frame_dataflow_identity,"abiDeclarationIdentity":artifact.phase5_evidence.abi_declaration_identity,"abiMachineJoinIdentity":artifact.phase5_evidence.abi_machine_join_identity,"privilegedDataflowIdentity":artifact.phase5_evidence.privileged_dataflow_identity,"analysisVersion":artifact.phase5_evidence.analysis_version},"rendererContractId":artifact.renderer_contract_id,"rendererContractVersion":artifact.renderer_contract_version,"requiredHeaders":list(artifact.required_headers),"requiredLibraries":list(artifact.required_libraries)}))
        claimed.update(members)
    return tuple(emitted)
