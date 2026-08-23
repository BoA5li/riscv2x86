from riscv2x86_py.privileged_execution_sidecar import (
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA,
    PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2,
    SourceExecutionProfile,
    TargetExecutionMode,
    default_user_process_execution_facts,
    privileged_execution_sidecar_from_dict,
)


def _policy(*, complete=True):
    return {
        "policyId": "riscv.user.lp64.csr-access.v2",
        "readableCsrIds": ["riscv.csr.cycle", "riscv.csr.time"],
        "writableCsrIds": [],
        "unknownAccess": "trap",
        "complete": complete,
    }


def _v2_sidecar():
    return {
        "schemaVersion": PRIVILEGED_EXECUTION_SIDECAR_SCHEMA_V2,
        "provenance": "compiler-plugin.privileged-facts.v2",
        "fragments": [{
            "fragmentId": "frag:csr",
            "sourcePrivilegeSpecVersion": "1.12",
            "sourceIsaExtensions": ["zicsr", "i"],
            "initialPrivilegeMode": "u",
            "csrAccessPolicy": _policy(),
            "delegationModel": {
                "modelId": "delegation:user-none.v1",
                "exceptionDelegationComplete": True,
                "interruptDelegationComplete": True,
                "delegatedExceptionCauses": [],
                "delegatedInterruptCauses": [],
                "complete": True,
            },
            "interruptModel": {
                "modelId": "interrupt:user-process.v1",
                "enableStateComplete": True,
                "pendingStateComplete": True,
                "priorityModelId": "host-os.v1",
                "externallyInterruptible": True,
                "complete": True,
            },
            "virtualMemoryModel": {
                "modelId": "vm:user-process.sv39.v1",
                "addressTranslationEnabled": True,
                "translationMode": "sv39",
                "pageSizeBytes": 4096,
                "asidWidthBits": 16,
                "complete": True,
            },
            "trapHandlerBinding": {
                "bindingId": "trap:user-process.signal.v1",
                "handlerIdentity": "linux-riscv-user",
                "trapAbiContractId": "linux-riscv-signal.v1",
                "continuationModelId": "posix-signal-return.v1",
                "complete": True,
            },
            "addressSpaceIdentity": {
                "identity": "process-address-space:test",
                "processOrGuestId": "process:test",
                "lifetimeModelId": "process-lifetime.v1",
                "sharedWithTargetRuntime": False,
                "complete": True,
            },
            "osOrRuntimeIdentity": "linux-riscv-user",
            "kernelOrVmmVersion": "linux-test",
            "targetCpuFeatureProfileId": "x86-test-profile.v1",
            "targetRuntimeContractSetId": "privileged-runtime.test.v1",
            "complete": True,
            "missingFactCodes": [],
        }],
    }


def test_accepts_complete_v2_user_to_user_environment():
    facts = privileged_execution_sidecar_from_dict(
        _v2_sidecar()
    ).facts_for("frag:csr")
    assert facts is not None and facts.complete
    assert facts.source_execution_profile is SourceExecutionProfile.RISCV_USER_PROCESS
    assert facts.target_execution_mode is TargetExecutionMode.X86_USER_PROCESS
    assert facts.source_isa_extensions == ("i", "zicsr")
    assert facts.csr_access_policy_id == "riscv.user.lp64.csr-access.v2"
    assert facts.delegation_model_id == "delegation:user-none.v1"
    assert facts.interrupt_model_id == "interrupt:user-process.v1"
    assert facts.virtual_memory_model_id == "vm:user-process.sv39.v1"
    assert facts.trap_handler_binding_id == "trap:user-process.signal.v1"
    assert facts.address_space_identity == "process-address-space:test"


def test_v1_remains_readable_but_cannot_claim_complete_environment():
    value = _v2_sidecar()
    value["schemaVersion"] = PRIVILEGED_EXECUTION_SIDECAR_SCHEMA
    facts = privileged_execution_sidecar_from_dict(value).facts_for("frag:csr")
    assert facts is not None and not facts.complete
    assert "privileged-execution.schema-v1-limited" in facts.missing_fact_codes
    assert (
        "privileged-execution.declared-complete-inconsistent"
        in facts.missing_fact_codes
    )


def test_default_boundary_is_user_to_user_but_not_semantically_complete():
    facts = default_user_process_execution_facts("frag:unknown")
    assert facts.source_execution_profile is SourceExecutionProfile.RISCV_USER_PROCESS
    assert facts.target_execution_mode is TargetExecutionMode.X86_USER_PROCESS
    assert not facts.complete
    for reason in (
        "privileged-execution.privilege-spec-version-missing",
        "privileged-execution.csr-access-policy-incomplete",
        "privileged-execution.delegation-model-missing",
        "privileged-execution.interrupt-model-missing",
        "privileged-execution.virtual-memory-model-missing",
        "privileged-execution.trap-handler-missing",
        "privileged-execution.address-space-identity-missing",
        "privileged-execution.runtime-version-missing",
    ):
        assert reason in facts.missing_fact_codes


def test_supervisor_source_cannot_claim_complete_x86_user_target():
    value = _v2_sidecar()
    fragment = value["fragments"][0]
    fragment["sourceExecutionProfile"] = "riscv_supervisor_kernel"
    fragment["initialPrivilegeMode"] = "s"
    facts = privileged_execution_sidecar_from_dict(value).facts_for("frag:csr")
    assert facts is not None and not facts.complete
    assert (
        "privileged-execution.target-profile-incompatible"
        in facts.missing_fact_codes
    )
    assert (
        "privileged-execution.source-target-profile-incompatible"
        in facts.missing_fact_codes
    )


def test_missing_or_incomplete_submodel_forces_stable_reason():
    value = _v2_sidecar()
    del value["fragments"][0]["delegationModel"]
    facts = privileged_execution_sidecar_from_dict(value).facts_for("frag:csr")
    assert facts is not None and not facts.complete
    assert (
        "privileged-execution.delegation-model-missing"
        in facts.missing_fact_codes
    )

    value = _v2_sidecar()
    value["fragments"][0]["interruptModel"]["complete"] = False
    facts = privileged_execution_sidecar_from_dict(value).facts_for("frag:csr")
    assert (
        "privileged-execution.interrupt-model-missing"
        in facts.missing_fact_codes
    )


def test_rejects_duplicate_fragment_and_extension_identities():
    value = _v2_sidecar()
    value["fragments"].append(dict(value["fragments"][0]))
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "fragment ids" in str(exc)
    else:
        raise AssertionError("duplicate fragment identities must fail closed")

    value = _v2_sidecar()
    value["fragments"][0]["sourceIsaExtensions"] = ["i", "I"]
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "sourceIsaExtensions" in str(exc)
    else:
        raise AssertionError("duplicate ISA extensions must fail closed")


def test_rejects_bad_schema_provenance_and_complete_unknown_csr_policy():
    value = _v2_sidecar()
    value["schemaVersion"] = "future"
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "schemaVersion" in str(exc)
    else:
        raise AssertionError("unknown schema must fail closed")

    value = _v2_sidecar()
    value["provenance"] = ""
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "provenance" in str(exc)
    else:
        raise AssertionError("missing provenance must fail closed")

    value = _v2_sidecar()
    value["fragments"][0]["csrAccessPolicy"]["unknownAccess"] = "unknown"
    try:
        privileged_execution_sidecar_from_dict(value)
    except ValueError as exc:
        assert "complete CSR access policy" in str(exc)
    else:
        raise AssertionError("unknown complete CSR policy must fail closed")
