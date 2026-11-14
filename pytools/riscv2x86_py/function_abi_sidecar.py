"""Phase-4 compiler-plugin declarations for whole-function ABI facts.

These declarations are authority inputs, not inferred ABI conclusions.  They
remain unusable for D-class approval until Phase 5 joins them with the mixed
function CFG and canonical machine facts.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path

FUNCTION_ABI_SIDECAR_SCHEMA = "riscv2x86.function-abi-sidecar.v1"
_PROFILES = frozenset(("rv64-lp64", "rv64-lp64d", "sysv-amd64"))
_SCALAR_TYPES = frozenset(("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "ptr"))

@dataclass(frozen=True)
class FunctionAbiValue:
    type_id: str; width_bits: int; signedness: str; location_kind: str
    register: str | None; stack_offset_bytes: int | None; complete: bool

@dataclass(frozen=True)
class FunctionAbiDeclarationFacts:
    function_id: str; source_abi_profile: str
    entry_arguments: tuple[FunctionAbiValue, ...]; return_values: tuple[FunctionAbiValue, ...]
    variadic_or_aggregate_abi: bool; pic_plt_mode: str | None; tls_model: str | None
    unwind_enabled: bool | None; exception_model: str | None
    complete: bool; missing_fact_codes: tuple[str, ...]; provenance: str

@dataclass(frozen=True)
class FunctionAbiSidecar:
    schema_version: str; compiler_version: str; target_triple: str
    declarations: tuple[FunctionAbiDeclarationFacts, ...]; provenance: str
    def __post_init__(self):
        ids=tuple(x.function_id for x in self.declarations)
        if len(ids)!=len(set(ids)): raise ValueError("function ABI declaration function ids must be unique")
    def for_function(self,function_id:str)->FunctionAbiDeclarationFacts|None:
        return next((x for x in self.declarations if x.function_id==function_id),None)

def _obj(v,what):
    if not isinstance(v,dict): raise ValueError(f"{what} must be an object")
    return v
def _str(v,what):
    if not isinstance(v,str) or not v: raise ValueError(f"{what} must be a non-empty string")
    return v
def _bool(v,what):
    if type(v) is not bool:raise ValueError(f"{what} must be a boolean")
    return v
def _value(v):
    x=_obj(v,"function ABI value")
    type_id=_str(x.get("typeId"),"typeId")
    if type_id not in _SCALAR_TYPES: raise ValueError("function ABI supports fixed-width scalar values only")
    width=x.get("widthBits")
    if type_id == "ptr":
        if type(width) is not int or width != 64: raise ValueError("LP64 pointer ABI value must be 64 bits")
    elif type(width) is not int or width != int(type_id[1:]): raise ValueError("function ABI scalar width is unsupported or mismatched")
    signed=x.get("signedness")
    expected_signed='none' if type_id=='ptr' else 'signed' if type_id.startswith('i') else 'unsigned'
    if signed!=expected_signed: raise ValueError("function ABI value signedness is invalid")
    kind=x.get("locationKind")
    if kind not in {"gpr","fpr","stack"}: raise ValueError("function ABI value locationKind is invalid")
    reg=x.get("register"); off=x.get("stackOffsetBytes")
    if kind=="stack":
        if reg is not None or type(off) is not int or off<0: raise ValueError("stack ABI value requires nonnegative offset and no register")
    elif not isinstance(reg,str) or not reg or off is not None: raise ValueError("register ABI value requires register and no stack offset")
    return FunctionAbiValue(type_id,width,signed,kind,reg,off,_bool(x.get("complete",False),'ABI value complete'))

def function_abi_sidecar_from_dict(value)->FunctionAbiSidecar:
    x=_obj(value,"function ABI sidecar")
    if x.get("schemaVersion")!=FUNCTION_ABI_SIDECAR_SCHEMA: raise ValueError("unsupported function ABI sidecar schemaVersion")
    provenance=_str(x.get("provenance"),"provenance")
    compiler=_str(x.get("compilerVersion"),"compilerVersion"); triple=_str(x.get("targetTriple"),"targetTriple")
    raw=x.get("functions")
    if not isinstance(raw,list): raise ValueError("function ABI sidecar functions must be an array")
    declarations=[]
    for item in raw:
        d=_obj(item,"function ABI declaration"); profile=d.get("sourceAbiProfile")
        if profile not in _PROFILES: raise ValueError("function ABI profile is unsupported")
        if (profile=='sysv-amd64' and not triple.startswith('x86_64') or
                profile!='sysv-amd64' and not triple.startswith('riscv64')):
            raise ValueError('function ABI profile and compiler target triple mismatch')
        if d.get("variadicOrAggregateAbi") is not False: raise ValueError("variadic or aggregate function ABI is unsupported")
        args=d.get("entryArguments",[]); returns=d.get("returnValues",[])
        if not isinstance(args,list) or not isinstance(returns,list): raise ValueError("function ABI value lists must be arrays")
        missing=d.get("missingFactCodes",[])
        if not isinstance(missing,list) or any(not isinstance(v,str) for v in missing): raise ValueError("missingFactCodes must be a string array")
        unwind=d.get("unwindEnabled")
        if unwind is not None and not isinstance(unwind,bool): raise ValueError("unwindEnabled must be bool or null")
        declarations.append(FunctionAbiDeclarationFacts(_str(d.get("functionId"),"functionId"),profile,tuple(_value(v) for v in args),tuple(_value(v) for v in returns),False,d.get("picPltMode"),d.get("tlsModel"),unwind,d.get("exceptionModel"),_bool(d.get("complete",False),'function complete'),tuple(missing),d.get("provenance",provenance)))
    return FunctionAbiSidecar(FUNCTION_ABI_SIDECAR_SCHEMA,compiler,triple,tuple(sorted(declarations,key=lambda x:x.function_id)),provenance)

def load_function_abi_sidecar(path:str|Path)->FunctionAbiSidecar:
    return function_abi_sidecar_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
