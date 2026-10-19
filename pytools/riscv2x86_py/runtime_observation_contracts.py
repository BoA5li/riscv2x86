"""Closed functional observation contracts shared by L1 and L2.

Registration does not establish an architectural clock relation.
"""

FUNCTIONAL_OBSERVATION_CONTRACTS = {
    "riscv2x86_rt_monotonic_time_ns@v1": {
        "patterns": ("privileged_read",),
        "observationContracts": ("riscv2x86.time.monotonic-observation.v1",
                                 "riscv2x86.time.monotonic-relation-result.v1"),
        "verifiedProperties": ("declared-return-relation", "monotonicity", "progress"),
        "notClaimedProperties": ("absolute-value-equivalence", "epoch-equivalence",
                                 "frequency-equivalence", "resolution-equivalence"),
    },
    "riscv2x86_rt_tsc_ticks@v1": {
        "patterns": ("privileged_read",),
        "observationContracts": ("riscv2x86.cycle.tsc-observation.v1",
                                 "riscv2x86.cycle.tsc-relation-result.v1"),
        "verifiedProperties": ("declared-return-relation", "monotonicity", "progress"),
        "notClaimedProperties": ("absolute-value-equivalence", "epoch-equivalence",
                                 "frequency-equivalence", "resolution-equivalence"),
    },
    "riscv2x86_rt_instruction_stream_sync_local@v1": {
        "patterns": ("instruction_visibility_fence",),
        "observationContracts": ("process-and-declared-return-values-v1",),
        "verifiedProperties": ("normal-termination", "registered-local-thread-runtime-contract"),
        "notClaimedProperties": ("architectural-instruction-visibility-equivalence",
                                 "cross-thread-code-publication"),
    },
}

# Same checked implementation/semantic family, with its own ABI identity.
FUNCTIONAL_OBSERVATION_CONTRACTS["rv2x86.read-counter.monotonic.checked.v1@v1"] = dict(
    FUNCTIONAL_OBSERVATION_CONTRACTS["riscv2x86_rt_monotonic_time_ns@v1"])

COUNTER_OBSERVATION_CONTRACTS = {
    key: value["observationContracts"][0]
    for key, value in FUNCTIONAL_OBSERVATION_CONTRACTS.items()
    if value["patterns"] == ("privileged_read",)
}
