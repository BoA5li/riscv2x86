"""Versioned ingress for D-class whole-function facts.

The frontend/compiler sidecar owns function membership, AST ranges and all
ABI/CFG facts.  Pipeline scheduling consumes these typed facts; it never
groups inline asm by textual proximity or guesses a containing function.
"""
from __future__ import annotations
from dataclasses import dataclass
from dataclasses import replace
import json
from pathlib import Path
from .whole_function import *
from .function_privileged_analysis import *
from .privileged_execution_sidecar import SourcePrivilegeMode

WHOLE_FUNCTION_SIDECAR_SCHEMA_V1="riscv2x86.whole-function-sidecar.v1"
WHOLE_FUNCTION_SIDECAR_SCHEMA="riscv2x86.whole-function-sidecar.v2"

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
def _priv_state(v):
    x=_d(v,"privileged machine state")
    mode=x.get("privilegeMode")
    return FunctionPrivilegedMachineState(
        None if mode is None else SourcePrivilegeMode(mode),x.get("interruptState"),
        x.get("delegationState"),x.get("addressSpaceState"),
        x.get("trapContinuationState"),x.get("savedStatusState"))
def _privileged(x,cfg,fragment_ids,provenance):
    if "privilegedExecution" not in x:return None,None,()
    p=_d(x["privilegedExecution"],"privilegedExecution")
    def exits(name):
        return tuple(sorted((FunctionPrivilegeExitMode(e["exitId"],SourcePrivilegeMode(e["privilegeMode"]),bool(e.get("complete",False))) for e in _t(p.get(name,[]),name)),key=lambda q:q.exit_id))
    handlers=tuple(sorted((FunctionTrapHandlerBinding(e["bindingId"],e["entryNodeId"],SourcePrivilegeMode(e["entryPrivilegeMode"]),bool(e.get("complete",False))) for e in _t(p.get("trapHandlerBindings",[]),"trapHandlerBindings")),key=lambda q:q.binding_id))
    regions=tuple(sorted((FunctionInterruptibilityRegion(e["regionId"],e["entryNodeId"],e["exitNodeId"],e["entryInterruptState"],e["exitInterruptState"],bool(e.get("complete",False))) for e in _t(p.get("interruptibilityRegions",[]),"interruptibilityRegions")),key=lambda q:q.region_id))
    facts=FunctionPrivilegedExecutionFacts(
        p["functionId"],SourcePrivilegeMode(p["entryPrivilegeMode"]),
        exits("normalExitPrivilegeModes"),exits("exceptionalExitModes"),handlers,regions,
        p.get("addressSpaceIdentity"),tuple(sorted(p.get("memberFragmentIds",fragment_ids))),
        bool(p.get("complete",False)),p.get("provenance",provenance),
        tuple(sorted(set(p.get("missingFactCodes",())))),p.get("hasNonlocalTransfer"),
        p.get("hasUnwind"),p.get("hasSignalSensitiveState"),p.get("hasSetjmpLongjmp"))
    if facts.member_fragment_ids != tuple(sorted(fragment_ids)):
        facts=replace(
            facts,complete=False,
            missing_fact_codes=tuple(sorted(set((*facts.missing_fact_codes,
                "whole-function.privileged-fragment-membership-mismatch"))))
        )
    transfers=tuple(sorted((FunctionPrivilegedBlockTransfer(
        e["nodeId"],FunctionPrivilegedTransferKind(e["kind"]),_priv_state(e["outputState"]),
        e.get("handlerBindingId"),e.get("continuationIdentity"),e.get("privilegeReturnKind"),bool(e.get("complete",False)))
        for e in _t(x.get("privilegedTransfers",[]),"privilegedTransfers")),key=lambda q:q.node_id))
    analysis=analyze_function_privileged_state(
        cfg=cfg,facts=facts,transfers=transfers,
        initial_interrupt_state=p.get("initialInterruptState","unknown"),
        initial_delegation_state=p.get("initialDelegationState","unknown"),
        initial_trap_continuation_state=p.get("initialTrapContinuationState","entry-continuation"),
        initial_saved_status_state=p.get("initialSavedStatusState","entry-status"))
    return facts,analysis,analysis.missing_fact_codes
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
    evidence=None
    if "phase5Evidence" in x:
        e=_d(x["phase5Evidence"],"phase5Evidence")
        evidence=WholeFunctionPhase5Evidence(e["mixedCfgIdentity"],e["frameDataflowIdentity"],e["abiDeclarationIdentity"],e["abiMachineJoinIdentity"],e.get("analysisVersion","phase5-whole-function-evidence.v1"))
    fragments=tuple(x.get("fragmentIds",()))
    privileged,privileged_analysis,privileged_reasons=_privileged(x,cfg,fragments,provenance)
    if evidence is not None and privileged_analysis is not None:
        evidence=WholeFunctionPhase5Evidence(evidence.mixed_cfg_identity,evidence.frame_dataflow_identity,evidence.abi_declaration_identity,evidence.abi_machine_join_identity,evidence.analysis_version,privileged_analysis.analysis_identity)
    missing=tuple(sorted(set((*x.get("missingFactCodes",()),*privileged_reasons))))
    complete=bool(x.get("complete",False)) and (privileged_analysis is None or privileged_analysis.complete)
    return WholeFunctionTranslationFacts(unit,ast,cfg,stack,abi,effects,fragments,recipe,complete,missing,evidence,privileged,privileged_analysis)

def whole_function_sidecar_from_dict(value)->WholeFunctionSidecar:
    x=_d(value,"whole-function sidecar")
    schema=x.get("schemaVersion")
    if schema not in {WHOLE_FUNCTION_SIDECAR_SCHEMA_V1,WHOLE_FUNCTION_SIDECAR_SCHEMA}: raise ValueError("unsupported whole-function sidecar schemaVersion")
    provenance=x.get("provenance")
    if not isinstance(provenance,str) or not provenance: raise ValueError("whole-function sidecar requires provenance")
    return WholeFunctionSidecar(schema,tuple(_facts(v,provenance) for v in _t(x.get("functions"),"functions")),provenance)
def load_whole_function_sidecar(path:str|Path)->WholeFunctionSidecar:
    return whole_function_sidecar_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
