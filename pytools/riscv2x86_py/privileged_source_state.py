"""Complete an analyzed privileged state before binding runtime contracts.

Both preparation and production consume validated operand authority here.
This constructs semantic facts; it neither supplies execution permission nor
approves a translation. Keep absence of CSR effects distinct from no analysis.
"""
from dataclasses import replace

from .csr_value_flow import join_csr_operand_bindings
from .csr_state_dataflow import analyze_csr_state_dataflow
from .source_csr_semantic_model import adapt_source_csr_semantic_model


def complete_privileged_source_state(*, state, fragment, lifted_insns, blocks,
                                    cfg, execution_facts, csr_operand_authority):
    state = replace(
        state,
        csr_operand_bindings=join_csr_operand_bindings(
            lifted_insns=lifted_insns, authority=csr_operand_authority,
            fragment_shell=fragment,
        ),
        csr_state_dataflow=analyze_csr_state_dataflow(
            blocks=blocks, cfg=cfg,
            initial_privilege_mode=execution_facts.initial_privilege_mode.value,
            access_effects=state.csr_effects,
        ),
    )
    return replace(state, source_csr_semantic_model=adapt_source_csr_semantic_model(state))
