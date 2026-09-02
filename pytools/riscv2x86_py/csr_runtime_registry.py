"""Versioned source-effect to runtime-contract/recipe CSR registry."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Iterable
from .csr_effect_constraints import CsrTargetMapping
from .csr_structured_renderer import CsrRuntimeRecipe
class CsrRuntimeRegistryFamily(str,Enum):
 COUNTER_OBSERVATION="counter-observation"; LOGICAL_CSR_STATE="logical-csr-state"; IDENTITY_PROFILE="identity-profile"; SYSTEM_VMM_ADAPTER="system-vmm-adapter"
@dataclass(frozen=True)
class CsrRuntimeRegistryEntry:
 contract_id:str; runtime_version:str; source_spec_version:str; source_execution_profile:str; target_execution_mode:str; supported_csr_ids:tuple[str,...]; supported_operations:tuple[str,...]; field_mappings:tuple[str,...]; access_policy_mapping:str; trap_mapping:str|None; ordering_relation:str; state_lifetime:str; callable_identifier:str; recipe_id:str; required_header:str; required_library:str; complete:bool; family:CsrRuntimeRegistryFamily
 def identity(self):return "csr-runtime:"+sha256(repr(self).encode()).hexdigest()
class CsrRuntimeRegistry:
 def __init__(self,entries:Iterable[CsrRuntimeRegistryEntry]):self.entries=tuple(entries)
 def resolve(self,*,csr_id,operation,source_spec_version,source_execution_profile,target_execution_mode):
  matches=tuple(e for e in self.entries if e.complete and csr_id in e.supported_csr_ids and operation in e.supported_operations and e.source_spec_version==source_spec_version and e.source_execution_profile==source_execution_profile and e.target_execution_mode==target_execution_mode and not(e.family is CsrRuntimeRegistryFamily.SYSTEM_VMM_ADAPTER and target_execution_mode=="ordinary-user-process"))
  return matches[0] if len(matches)==1 else None
 def mapping_for(self,*,source_effect_id,csr_id,operation,source_spec_version,source_execution_profile,target_execution_mode):
  e=self.resolve(csr_id=csr_id,operation=operation,source_spec_version=source_spec_version,source_execution_profile=source_execution_profile,target_execution_mode=target_execution_mode)
  if e is None:return None
  return CsrTargetMapping(source_effect_id,csr_id,e.contract_id,e.contract_id+":"+operation,e.runtime_version,e.source_execution_profile,e.state_lifetime,read_result_mapping="runtime-result",write_value_mapping="runtime-input",field_mappings=e.field_mappings,old_new_state_relation_id=e.contract_id+":old-new",access_policy_mapping_id=e.access_policy_mapping,denied_access_trap_mapping_id=e.trap_mapping,ordering_relation_id=e.ordering_relation)
 def recipe_for(self,entry,*,csr_token,context_expression,input_expression=None,output_expression=None):
  return CsrRuntimeRecipe(entry.recipe_id,entry.callable_identifier,csr_token,context_expression,input_expression,output_expression,entry.required_header,entry.required_library,entry.runtime_version,"runtime-trap-contract",entry.complete)
