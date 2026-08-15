"""Phase-9 writeback for approved whole-function replacement artifacts."""
from __future__ import annotations
from dataclasses import dataclass
from .whole_function import FunctionReplacementArtifact

@dataclass(frozen=True)
class WholeFunctionWritebackResult:
    source_text:str|None; approved:bool; reason_codes:tuple[str,...]=()

def apply_function_replacements(*,source_text:str,artifacts:tuple[FunctionReplacementArtifact,...])->WholeFunctionWritebackResult:
    """Apply only distinct, in-range, non-overlapping function definitions."""
    ordered=tuple(sorted(artifacts,key=lambda x:(x.source_definition_range.start,x.source_definition_range.end)))
    if len({x.function_id for x in ordered})!=len(ordered):return WholeFunctionWritebackResult(None,False,("whole-function.writeback-duplicate-function",))
    previous=-1
    for item in ordered:
        r=item.source_definition_range
        if r.end>len(source_text) or r.start<previous:return WholeFunctionWritebackResult(None,False,("whole-function.writeback-overlap-or-range-invalid",))
        previous=r.end
    result=source_text
    for item in reversed(ordered):
        r=item.source_definition_range; result=result[:r.start]+item.replacement_text+result[r.end:]
    return WholeFunctionWritebackResult(result,True)
