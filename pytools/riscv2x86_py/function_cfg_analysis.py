"""Phase-5 fail-closed join of frontend C CFG and canonical asm regions."""
from __future__ import annotations
from dataclasses import dataclass
from .whole_function import FunctionCfgNode, FunctionCfgEdge, FunctionExitBinding, FunctionExitKind, SourceFunctionControlFlowModel

@dataclass(frozen=True)
class FrontendCfgFacts:
    entry_node_id:str; nodes:tuple[FunctionCfgNode,...]; edges:tuple[FunctionCfgEdge,...]
    exits:tuple[FunctionExitBinding,...]; complete:bool; missing_fact_codes:tuple[str,...]=()
@dataclass(frozen=True)
class AsmRegionCfgFacts:
    fragment_id:str; entry_node_id:str; exit_node_ids:tuple[str,...]
    nodes:tuple[FunctionCfgNode,...]; edges:tuple[FunctionCfgEdge,...]
    continuation_targets:tuple[str,...]; complete:bool; missing_fact_codes:tuple[str,...]=()

def build_mixed_function_cfg(*,frontend:FrontendCfgFacts|None,asm_regions:tuple[AsmRegionCfgFacts,...],expected_fragment_ids:tuple[str,...])->SourceFunctionControlFlowModel:
    reasons=[]
    if frontend is None: return SourceFunctionControlFlowModel("",(),(),(),False,("whole-function.clang-cfg-missing",))
    reasons.extend(frontend.missing_fact_codes)
    if not frontend.complete: reasons.append("whole-function.clang-cfg-incomplete")
    if len({x.node_id for x in frontend.nodes}) != len(frontend.nodes): reasons.append("whole-function.cfg-node-duplicate")
    expected=set(expected_fragment_ids); actual={x.fragment_id for x in asm_regions}
    if actual != expected: reasons.append("whole-function.asm-region-membership-mismatch")
    nodes=list(frontend.nodes); edges=list(frontend.edges)
    known={x.node_id for x in nodes}
    for region in sorted(asm_regions,key=lambda x:x.fragment_id):
        reasons.extend(region.missing_fact_codes)
        if not region.complete or not region.entry_node_id or not region.exit_node_ids: reasons.append("whole-function.asm-region-cfg-incomplete"); continue
        if any(x not in known for x in region.continuation_targets): reasons.append("whole-function.asm-continuation-target-missing")
        for node in region.nodes:
            if node.node_id in known: reasons.append("whole-function.cfg-node-duplicate")
            known.add(node.node_id); nodes.append(node)
        edges.extend(region.edges)
    node_ids={x.node_id for x in nodes}
    if frontend.entry_node_id not in node_ids: reasons.append("whole-function.cfg-entry-missing")
    for edge in edges:
        if not edge.complete or edge.source_node_id not in node_ids or edge.target_node_id not in node_ids: reasons.append("whole-function.cfg-edge-incomplete")
    exits=tuple(sorted(frontend.exits,key=lambda x:x.exit_id))
    if not exits or any(not x.complete or x.node_id not in node_ids for x in exits): reasons.append("whole-function.exit-inventory-incomplete")
    if not any(x.kind is FunctionExitKind.NORMAL_RETURN for x in exits): reasons.append("whole-function.normal-exit-missing")
    return SourceFunctionControlFlowModel(frontend.entry_node_id,tuple(sorted(nodes,key=lambda x:x.node_id)),tuple(sorted(edges,key=lambda x:(x.source_node_id,x.target_node_id,x.kind))),exits,not reasons,tuple(sorted(set(reasons))))
