from types import SimpleNamespace
from riscv2x86_py.source_csr_semantic_model import adapt_source_csr_semantic_model

def test_6a_only_adapts_complete_phase5_facts():
    effect=SimpleNamespace(csr_id="riscv.csr.cycle",csr_class=SimpleNamespace(value="user_counter_observation"),complete=True,access_allowed=True,may_trap=False)
    binding=SimpleNamespace(complete=True,source_effect_id="e",reason_codes=())
    flow=SimpleNamespace(complete=True,entry_state="in",exit_states=((1,"out"),))
    model=adapt_source_csr_semantic_model(SimpleNamespace(csr_effects=(effect,),csr_operand_bindings=(binding,),csr_state_dataflow=flow))
    assert model.complete and model.strict_eligible and not model.fallback_eligible
    assert model.model_identity.startswith("csr-6a:")

def test_6a_rejects_missing_join_or_trap_relation():
    effect=SimpleNamespace(csr_id="riscv.csr.mstatus",csr_class=SimpleNamespace(value="privileged_status"),complete=True,access_allowed=True,may_trap=True)
    model=adapt_source_csr_semantic_model(SimpleNamespace(csr_effects=(effect,),csr_operand_bindings=(),csr_state_dataflow=SimpleNamespace(complete=False)))
    assert not model.complete and model.requires_whole_function


def test_operand_completeness_excludes_only_authoritatively_bound_csr_state():
    from riscv2x86_py.source_model import _authoritative_csr_state_registers

    effect = SimpleNamespace(csr_id="riscv.csr.vendor_counter_7", complete=True)
    bound = SimpleNamespace(
        source_effect_id="csr-effect:0x10:1:riscv.csr.vendor_counter_7",
        complete=True,
    )
    state = SimpleNamespace(
        csr_effects=(effect,), csr_operand_bindings=(bound,),
    )
    assert _authoritative_csr_state_registers(state) == frozenset({
        "vendor_counter_7"
    })


def test_operand_completeness_keeps_csr_state_when_authority_is_incomplete():
    from riscv2x86_py.source_model import _authoritative_csr_state_registers

    effect = SimpleNamespace(csr_id="riscv.csr.vendor_counter_7", complete=True)
    incomplete = SimpleNamespace(
        source_effect_id="csr-effect:0x10:1:riscv.csr.vendor_counter_7",
        complete=False,
    )
    mismatched = SimpleNamespace(
        source_effect_id="csr-effect:0x10:1:riscv.csr.another_state",
        complete=True,
    )
    assert not _authoritative_csr_state_registers(SimpleNamespace(
        csr_effects=(effect,), csr_operand_bindings=(incomplete,),
    ))
    assert not _authoritative_csr_state_registers(SimpleNamespace(
        csr_effects=(effect,), csr_operand_bindings=(mismatched,),
    ))


def test_completeness_queries_only_compiler_operand_carriers():
    from riscv2x86_py.source_model import _build_completeness_model

    class MissingAll:
        structurally_valid = True

        @staticmethod
        def missing_operand_bindings(registers):
            return tuple(registers)

        @staticmethod
        def missing_width_facts_for_registers(registers):
            return tuple(registers)

    model = _build_completeness_model(
        runtime_facts_available=True,
        runtime_status=MissingAll(),
        control_flow=SimpleNamespace(cfg_ok=True),
        memory=SimpleNamespace(has_unknown_barrier=False),
        microarch=SimpleNamespace(),
        registers=SimpleNamespace(
            referenced_registers=frozenset({"a0", "vendor_counter_7"}),
            writes_registers=frozenset({"a0"}),
            has_unresolved_register_identity=False,
        ),
        summary=SimpleNamespace(
            has_tail_call=False,
            has_timing_source=False,
            has_cache_operation=False,
            has_speculation_control=False,
        ),
        authoritative_architectural_state_registers=frozenset({
            "vendor_counter_7"
        }),
    )
    assert model.missing_operand_binding_registers == ("a0",)
    assert model.missing_operand_width_registers == ("a0",)
    assert model.missing_output_binding_registers == ("a0",)
