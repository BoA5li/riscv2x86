"""Versioned ingress for D-class whole-function facts.

The frontend/compiler sidecar owns function membership, AST ranges and all
ABI/CFG facts.  Pipeline scheduling consumes these typed facts; it never
groups inline asm by textual proximity or guesses a containing function.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path
from .whole_function import *

WHOLE_FUNCTION_SIDECAR_SCHEMA="riscv2x86.whole-function-sidecar.v1"

@dataclass(frozen=True)
class WholeFunctionSidecar:
    schema_version:str; facts:tuple[WholeFunctionTranslationFacts,...]; provenance:str
    def __post_init__(self):
        ids=tuple(x.unit.function_id for x in self.facts)
        if len(ids)!=len(set(ids)): raise ValueError("whole-function sidecar function ids must be unique")

def _t(v,what):
    if not isinstance(v,list): raise ValueError(f"{what} must be an array")
    return tuple(v)
def _d(v,what):
    if not isinstance(v,dict): raise ValueError(f"{what} must be an object")
    return v
def _rng(v):
    x=_d(v,"definitionRange"); return SourceTextRange(x["start"],x["end"])
def _facts(v,provenance):
    x=_d(v,"whole-function facts"); u=_d(x["unit"],"unit"); a=_d(x["astBinding"],"astBinding")
    unit=FunctionTranslationUnit(u["functionId"],u.get("cAstFunctionBindingId"),u["sourceAbiProfile"],bool(u.get("complete",False)),tuple(u.get("missingFactCodes",())))
    ast=FunctionAstBinding(a["functionId"],a["cAstFunctionBindingId"],_rng(a["definitionRange"]),tuple(a.get("parameterBindingIds",())),a.get("returnBindingId"),bool(a.get("hasVlaOrCleanupSensitiveScope",False)),bool(a.get("complete",False)),a.get("provenance",provenance),a.get("sourceFile",""))
    c=_d(x["controlFlow"],"controlFlow")
    nodes=tuple(FunctionCfgNode(n["nodeId"],n["kind"],n.get("sourceBindingId"),bool(n.get("complete",False))) for n in _t(c["nodes"],"nodes"))
    edges=tuple(FunctionCfgEdge(e["sourceNodeId"],e["targetNodeId"],e["kind"],bool(e.get("complete",False))) for e in _t(c["edges"],"edges"))
    exits=tuple(FunctionExitBinding(e["exitId"],e["nodeId"],FunctionExitKind(e["kind"]),bool(e.get("complete",False))) for e in _t(c["exits"],"exits"))
    cfg=SourceFunctionControlFlowModel(c["entryNodeId"],nodes,edges,exits,bool(c.get("complete",False)),tuple(c.get("missingFactCodes",())))
    s=_d(x["stack"],"stack")
    summaries=tuple(FunctionFramePathSummary(q["exitId"],q.get("finalSpOffsetBytes"),q.get("stackAlignmentBytes"),bool(q.get("complete",False))) for q in _t(s.get("exitSummaries",[]),"exitSummaries"))
    stack=SourceFunctionStackModel(s["frameKind"],s.get("netStackDeltaBytes"),bool(s.get("dynamicAdjustmentPresent",False)),bool(s.get("realStackIdentityRequired",False)),bool(s.get("complete",False)),s.get("frameSizeBytes"),s.get("requiredAlignmentBytes"),summaries,bool(s.get("allNormalExitsRestoreEntrySp",False)),bool(s.get("allCallSitesAligned",False)))
    b=_d(x["abi"],"abi"); abi=FunctionAbiFacts(b["sourceAbiProfile"],bool(b.get("entryComplete",False)),bool(b.get("exitsComplete",False)),bool(b.get("callsComplete",False)),bool(b.get("picPltTlsComplete",False)),b.get("mayUnwind"),b.get("mayTrap"),bool(b.get("complete",False)))
    effects=tuple(CalleeSavedRegisterEffect(e["register"],tuple(e.get("saveSiteIds",())),tuple(e.get("restoreSiteIds",())),tuple(e.get("modifiedSiteIds",())),bool(e.get("restoredOnAllNormalExits",False)),bool(e.get("complete",False))) for e in _t(x.get("calleeSavedEffects",[]),"calleeSavedEffects"))
    r=_d(x["rendererContract"],"rendererContract"); recipe=WholeFunctionRendererContract(r["contractId"],r["version"],r["functionId"],r["replacementText"],tuple(r.get("requiredHeaders",())),tuple(r.get("requiredLibraries",())),bool(r.get("compilerManagedStackOnly",True)),bool(r.get("complete",False)))
    return WholeFunctionTranslationFacts(unit,ast,cfg,stack,abi,effects,tuple(x.get("fragmentIds",())),recipe,bool(x.get("complete",False)),tuple(x.get("missingFactCodes",())))

def whole_function_sidecar_from_dict(value)->WholeFunctionSidecar:
    x=_d(value,"whole-function sidecar")
    if x.get("schemaVersion")!=WHOLE_FUNCTION_SIDECAR_SCHEMA: raise ValueError("unsupported whole-function sidecar schemaVersion")
    provenance=x.get("provenance")
    if not isinstance(provenance,str) or not provenance: raise ValueError("whole-function sidecar requires provenance")
    return WholeFunctionSidecar(WHOLE_FUNCTION_SIDECAR_SCHEMA,tuple(_facts(v,provenance) for v in _t(x.get("functions"),"functions")),provenance)
def load_whole_function_sidecar(path:str|Path)->WholeFunctionSidecar:
    return whole_function_sidecar_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
