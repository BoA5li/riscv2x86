"""Fail-closed replacement of compiler CFG asm placeholders by decoded regions.

No region is appended as a disconnected island. Its exits must explicitly name
compiler-bound continuations; this consumer never invents fallthrough edges.
"""
from __future__ import annotations
from dataclasses import dataclass
from .whole_function import FunctionCfgNode,FunctionCfgEdge,FunctionExitBinding,FunctionExitKind,SourceFunctionControlFlowModel

@dataclass(frozen=True)
class FrontendCfgFacts:
    entry_node_id:str; nodes:tuple[FunctionCfgNode,...]; edges:tuple[FunctionCfgEdge,...]
    exits:tuple[FunctionExitBinding,...]; complete:bool; missing_fact_codes:tuple[str,...]=()

@dataclass(frozen=True)
class AsmRegionCfgFacts:
    fragment_id:str; entry_node_id:str; exit_node_ids:tuple[str,...]
    nodes:tuple[FunctionCfgNode,...]; edges:tuple[FunctionCfgEdge,...]
    continuation_targets:tuple[str,...]; complete:bool; missing_fact_codes:tuple[str,...]=()
    frontend_node_id:str|None=None


def build_mixed_function_cfg(*,frontend:FrontendCfgFacts|None,asm_regions:tuple[AsmRegionCfgFacts,...],expected_fragment_ids:tuple[str,...])->SourceFunctionControlFlowModel:
    if frontend is None:return SourceFunctionControlFlowModel('',(),(),(),False,('whole-function.clang-cfg-missing',))
    reasons=set(frontend.missing_fact_codes)
    if frontend.complete is not True:reasons.add('whole-function.clang-cfg-incomplete')
    if len(set(expected_fragment_ids))!=len(expected_fragment_ids) or len({r.fragment_id for r in asm_regions})!=len(asm_regions):
        reasons.add('whole-function.asm-region-duplicate')
    if {r.fragment_id for r in asm_regions}!=set(expected_fragment_ids):reasons.add('whole-function.asm-region-membership-mismatch')
    front={n.node_id:n for n in frontend.nodes}
    if len(front)!=len(frontend.nodes):reasons.add('whole-function.cfg-node-duplicate')
    replacements={};valid=[]
    for region in asm_regions:
        reasons.update(region.missing_fact_codes)
        placeholder=front.get(region.frontend_node_id)
        if (placeholder is None or placeholder.kind!='asm_placeholder'
                or placeholder.source_binding_id!=region.fragment_id or region.frontend_node_id in replacements):
            reasons.add('whole-function.asm-frontend-placeholder-required');continue
        if any(e.node_id==placeholder.node_id for e in frontend.exits):
            reasons.add('whole-function.asm-placeholder-cannot-be-function-exit');continue
        internal={n.node_id:n for n in region.nodes}
        external={e.target_node_id for e in region.edges if e.target_node_id not in internal}
        outs={e.target_node_id for e in frontend.edges if e.source_node_id==placeholder.node_id}
        if (region.complete is not True or not region.exit_node_ids or not region.continuation_targets
                or region.entry_node_id not in internal or not set(region.exit_node_ids)<=set(internal)
                or len(set(region.exit_node_ids))!=len(region.exit_node_ids)
                or len(set(region.continuation_targets))!=len(region.continuation_targets)
                or external!=set(region.continuation_targets) or outs!=external
                or not external<=set(front)
                or any(e.source_node_id not in internal or e.complete is not True for e in region.edges)
                or any(e.source_node_id not in region.exit_node_ids for e in region.edges if e.target_node_id in external)
                or any(not any(e.source_node_id==exit and e.target_node_id in external for e in region.edges) for exit in region.exit_node_ids)):
            reasons.add('whole-function.asm-region-cfg-incomplete');continue
        if len(internal)!=len(region.nodes):reasons.add('whole-function.cfg-node-duplicate');continue
        replacements[placeholder.node_id]=region.entry_node_id;valid.append(region)
    def target(node):return replacements.get(node,node)
    nodes=[n for n in frontend.nodes if n.node_id not in replacements]
    if any(n.kind=='asm_placeholder' for n in nodes):reasons.add('whole-function.asm-placeholder-unresolved')
    edges=[FunctionCfgEdge(e.source_node_id,target(e.target_node_id),e.kind,e.complete)
           for e in frontend.edges if e.source_node_id not in replacements]
    known={n.node_id for n in nodes}
    for region in valid:
        for node in region.nodes:
            if node.node_id in known:reasons.add('whole-function.cfg-node-duplicate')
            else:known.add(node.node_id);nodes.append(node)
        edges.extend(FunctionCfgEdge(e.source_node_id,target(e.target_node_id),e.kind,e.complete) for e in region.edges)
    if any(n.complete is not True for n in nodes):reasons.add('whole-function.cfg-node-incomplete')
    unique={n.node_id:n for n in nodes};entry=target(frontend.entry_node_id)
    if entry not in unique:reasons.add('whole-function.cfg-entry-missing')
    if any(e.complete is not True or e.source_node_id not in unique or e.target_node_id not in unique for e in edges):
        reasons.add('whole-function.cfg-edge-incomplete')
    if len({(e.source_node_id,e.target_node_id,e.kind) for e in edges})!=len(edges):reasons.add('whole-function.cfg-edge-duplicate')
    exits=tuple(sorted(frontend.exits,key=lambda x:x.exit_id))
    if (not exits or len({e.exit_id for e in exits})!=len(exits)
            or any(e.complete is not True or e.node_id not in unique or e.kind is FunctionExitKind.UNKNOWN for e in exits)):
        reasons.add('whole-function.exit-inventory-incomplete')
    if not any(e.kind is FunctionExitKind.NORMAL_RETURN for e in exits):reasons.add('whole-function.normal-exit-missing')
    reached=set();todo=[entry]
    while todo:
        node=todo.pop()
        if node in reached or node not in unique:continue
        reached.add(node);todo.extend(e.target_node_id for e in edges if e.source_node_id==node)
    if any(e.node_id not in reached for e in exits):reasons.add('whole-function.exit-unreachable-or-unproved')
    if any(n.node_id not in reached for r in valid for n in r.nodes):reasons.add('whole-function.asm-region-unreachable-or-unproved')
    terminal={e.node_id for e in exits}
    if any(node not in terminal and not any(e.source_node_id==node for e in edges) for node in reached):
        reasons.add('whole-function.cfg-terminal-exit-missing')
    if any(e.source_node_id in terminal for e in edges):reasons.add('whole-function.cfg-exit-has-successor')
    return SourceFunctionControlFlowModel(entry,tuple(sorted(unique.values(),key=lambda n:n.node_id)),
        tuple(sorted(edges,key=lambda e:(e.source_node_id,e.target_node_id,e.kind))),exits,not reasons,tuple(sorted(reasons)))
