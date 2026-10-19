"""Typed hidden-state escape and auditable transformation-granularity reasons."""
from dataclasses import dataclass
import re
from .semantic_content import semantic_identity

_SHA = re.compile(r'sha256:[0-9a-f]{64}')


@dataclass(frozen=True)
class CsrStateEscapeFact:
    state_identity: str
    scope: str
    escapes: bool
    producer_identity: str
    evidence_identity: str
    complete: bool

    def validate(self):
        if (not isinstance(self.state_identity,str) or not self.state_identity or self.scope not in {'fragment','function','external'}
                or type(self.escapes) is not bool or type(self.complete) is not bool
                or not isinstance(self.producer_identity,str) or not self.producer_identity
                or not isinstance(self.evidence_identity,str) or _SHA.fullmatch(self.evidence_identity) is None
                or (self.complete and self.escapes != (self.scope != 'fragment'))):
            raise ValueError('CSR_STATE_ESCAPE_FACT_INVALID')


@dataclass(frozen=True)
class CsrWholeFunctionRequirement:
    origin: str
    state_identity: str
    evidence_identity: str


def whole_function_requirements(flow, effects, state_facts):
    requirements=[]
    if getattr(flow,'requires_whole_function',False):
        requirements.append(CsrWholeFunctionRequirement('state_dataflow','',semantic_identity(flow)))
    for fact in state_facts:
        if fact.escapes:
            requirements.append(CsrWholeFunctionRequirement('typed_state_escape',fact.state_identity,
                                                          semantic_identity(fact)))
    # Preserve existing conservative class boundaries. Refining a class needs
    # its own effect-aware proof; removing this gate is not an escape fix.
    whole_classes={'address_translation','interrupt_state','privileged_status','pmp_state',
                   'virtualization_state','delegation','trap_vector','trap_state'}
    for effect in effects:
        kind=getattr(getattr(effect,'csr_class',None),'value',getattr(effect,'csr_semantic_class',''))
        if kind in whole_classes:
            requirements.append(CsrWholeFunctionRequirement('semantic_class:'+kind,
                getattr(effect,'csr_id','') or '',semantic_identity(effect)))
    return tuple(requirements)
