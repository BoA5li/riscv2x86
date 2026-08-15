from riscv2x86_py.privileged_execution_sidecar import (
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA,
    SourceExecutionProfile,
    TargetExecutionMode,
    default_user_process_execution_facts,
    privileged_execution_sidecar_from_dict,
)


def _policy(*, complete=True):
    return {
        "policyId": "riscv.user.lp64.csr-access.v1",
        "readableCsrIds": ["riscv.csr.cycle", "riscv.csr.time"],
        "writableCsrIds": ["riscv.csr.fflags", "riscv.csr.frm"],
        "unknownAccess": "trap",
        "complete": complete,
    }


def _sidecar():
    return {
        "schemaVersion": PRIVILEGED_EXECUTION_SIDECAR_SCHEMA,
        "provenance": "compiler-plugin.privileged-facts.v1",
        "fragments": [{
            "fragmentId": "frag:csr",
            "sourcePrivilegeSpecVersion": "1.12",
            "sourceIsaExtensions": ["zicsr", "i"],
            "initialPrivilegeMode": "u",
            "csrAccessPolicy": _policy(),
            "complete": True,
            "missingFactCodes": [],
        }],
    }


def test_accepts_complete_user_to_user_privileged_execution_facts():
    sidecar = privileged_execution_sidecar_from_dict(_sidecar())
    facts = sidecar.facts_for("frag:csr")
    assert facts is not None and facts.complete
    assert facts.source_execution_profile is SourceExecutionProfile.RISCV_USER_PROCESS
    assert facts.target_execution_mode is TargetExecutionMode.X86_USER_PROCESS
    assert facts.source_isa_extensions == ("i", "zicsr")
    assert facts.csr_access_policy.readable_csr_ids == (
        "riscv.csr.cycle", "riscv.csr.time",
    )


def test_default_boundary_is_user_to_user_but_not_semantically_complete():
    facts = default_user_process_execution_facts("frag:unknown")
    assert facts.source_execution_profile is SourceExecutionProfile.RISCV_USER_PROCESS
    assert facts.target_execution_mode is TargetExecutionMode.X86_USER_PROCESS
    assert not facts.complete
    assert "privileged-execution.privilege-spec-version-missing" in facts.missing_fact_codes
    assert "privileged-execution.csr-access-policy-incomplete" in facts.missing_fact_codes


def test_supervisor_source_cannot_claim_complete_x86_user_target():
    value = _sidecar()
    fragment = value["fragments"][0]
    fragment["sourceExecutionProfile"] = "riscv_supervisor_kernel"
    fragment["initialPrivilegeMode"] = "s"
    facts = privileged_execution_sidecar_from_dict(value).facts_for("frag:csr")
    assert facts is not None and not facts.complete
    assert (
        "privileged-execution.source-target-profile-incompatible"
        in facts.missing_fact_codes
    )
    assert (
        "privileged-execution.declared-complete-inconsistent"
        in facts.missing_fact_codes
    )


def test_incomplete_csr_policy_forces_stable_incomplete_reason():
    value = _sidecar()
    value["fragments"][0]["csrAccessPolicy"] = _policy(complete=False)
    facts = privileged_execution_sidecar_from_dict(value).facts_for("frag:csr")
    assert facts is not None and not facts.complete
    assert (
        "privileged-execution.csr-access-policy-incomplete"
        in facts.missing_fact_codes
    )


def test_rejects_duplicate_fragment_and_extension_identities():
    value = _sidecar()
    value["fragments"].append(dict(value["fragments"][0]))
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "fragment ids" in str(exc)
    else:
        raise AssertionError("duplicate fragment identities must fail closed")

    value = _sidecar()
    value["fragments"][0]["sourceIsaExtensions"] = ["i", "I"]
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "sourceIsaExtensions" in str(exc)
    else:
        raise AssertionError("duplicate ISA extensions must fail closed")


def test_rejects_bad_schema_provenance_and_complete_unknown_csr_policy():
    value = _sidecar()
    value["schemaVersion"] = "future"
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "schemaVersion" in str(exc)
    else:
        raise AssertionError("unknown schema must fail closed")

    value = _sidecar()
    value["provenance"] = ""
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "provenance" in str(exc)
    else:
        raise AssertionError("missing provenance must fail closed")

    value = _sidecar()
    value["fragments"][0]["csrAccessPolicy"]["unknownAccess"] = "unknown"
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "complete CSR access policy" in str(exc)
    else:
        raise AssertionError("unknown complete CSR policy must fail closed")
