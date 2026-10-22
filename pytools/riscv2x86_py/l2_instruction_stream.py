"""Versioned, replayable local instruction-visibility approval and L2 authority."""
from dataclasses import asdict, is_dataclass
from .instruction_stream_sync_contracts import (InstructionStreamSyncContract, ModifiedCodeRange,
    InstructionStreamSyncScope, InstructionStreamSyncLoweringKind, prove_instruction_stream_sync)
from .instruction_stream_domain import validate_domain
from .csr_runtime_shell import prove_runtime_shell, render_runtime_shell
from .csr_runtime_approval import _fragment_shell
from .semantic_content import semantic_identity
from .l2_effect_proof import (SourceEffectFact,TargetEffectFact,EffectRelationFact,
                             ShellRelationFact,L2EffectProofFacts)


def _facts(approval):
    runtime=approval['runtimeContractId']; payload=approval['instructionStreamProof']
    properties=('compiler_ordering','external_detail','hardware_ordering','kind','subject','value')
    shell=ShellRelationFact((),(),(),(),True,True,True,True,True,True)
    return L2EffectProofFacts(approval['sourceFragmentId'],approval['proofIdentity'],approval['planId'],
        approval['constraintsId'],approval['rendererContractIdentity'],
        (SourceEffectFact('instruction-stream:source','InstructionVisibility','bound-local-hart',True),),
        (TargetEffectFact('instruction-stream:target','InstructionVisibility','bound-local-hart',True),),
        (EffectRelationFact('relation:instruction-stream','instruction-stream:source',('instruction-stream:target',),
            'runtime_mediated',properties,(),runtime,semantic_identity(payload),True),),shell,True).to_dict()


def close_instruction_stream_approval(approval, proof, fragment, machine_code, build_contract):
    if not proof.approved or proof.contract is None or proof.contract.domain_authority is None:
        raise ValueError('ISS_DOMAIN_AUTHORITY_REQUIRED')
    source=_fragment_shell(fragment)
    if (machine_code != bytes.fromhex('0f100000') or source['inputs'] or source['outputs']
            or not source['isVolatile'] or 'memory' not in source['clobbers']):
        raise ValueError('ISS_SOURCE_SHELL_OR_ENCODING_UNSUPPORTED')
    implementation=proof.proof_payload['implementation']
    if implementation is None: raise ValueError('ISS_IMPLEMENTATION_AUTHORITY_REQUIRED')
    shell=prove_runtime_shell(fragment,semantic_identity(implementation),build_contract)
    call=proof.contract.helper_symbol+'();'
    replacement=render_runtime_shell(call,shell)
    value=dict(approval)
    payload={'schemaVersion':'riscv2x86.instruction-stream-approved-proof.v1',
        'phase6Proof':proof.proof_payload,'sourceShell':source,'machineCodeHex':machine_code.hex(),
        'shellProof':shell}
    value.update(artifactVersion='phase6-instruction-stream-sync-v3',instructionStreamProof=payload,
        proofIdentity=semantic_identity(payload),runtimeShellProof=shell,
        rendererContractIdentity=semantic_identity({'renderer':'local-iss-wrapper-v1','shell':shell,'implementation':implementation}),
        requiredBuildContract=build_contract,
        replacementDigest='sha256:'+__import__('hashlib').sha256(replacement.encode()).hexdigest())
    value['rendererContractId']=value['rendererContractIdentity']
    value['rendererRegistryId']=semantic_identity(implementation)
    value['rendererRegistryVersion']='instruction-stream-domain-v1'
    value['l2EffectProofFacts']=_facts(value)
    # The runtime shell proof and the L2 shell relation are different records.
    # Use the same canonical L2 identity as authority materialization from the
    # start, so adding a sidecar cannot invalidate independent approval replay.
    value['shellFactsIdentity']=semantic_identity({
        'schemaVersion':'riscv2x86.shell-relation-binding.v1',
        'fragmentId':value['sourceFragmentId'],'proofIdentity':value['proofIdentity'],
        'shellRelation':value['l2EffectProofFacts']['shellRelation']})
    return value,replacement


def validate_instruction_stream_approval(approval,fragment,replacement=None,*,source_digest=None):
    if approval.get('artifactVersion')!='phase6-instruction-stream-sync-v3':
        raise ValueError('ISS_APPROVAL_SCHEMA_UNSUPPORTED')
    payload=approval['instructionStreamProof']
    if (set(payload)!={'schemaVersion','phase6Proof','sourceShell','machineCodeHex','shellProof'}
            or payload['schemaVersion']!='riscv2x86.instruction-stream-approved-proof.v1'
            or semantic_identity(payload)!=approval.get('proofIdentity')
            or payload['sourceShell']!=_fragment_shell(fragment)):
        raise ValueError('ISS_APPROVAL_BINDING_MISMATCH')
    raw=dict(payload['phase6Proof']['contract'])
    raw['modified_code_range']=ModifiedCodeRange(**raw['modified_code_range'])
    raw['required_scope']=InstructionStreamSyncScope(raw['required_scope'])
    raw['lowering_kind']=InstructionStreamSyncLoweringKind(raw['lowering_kind'])
    contract=InstructionStreamSyncContract(**raw)
    if (approval.get('proofStatus')!='approved'
            or approval.get('preservationMode')!='architecture_equivalent'
            or approval.get('sourceFragmentId')!=contract.source_fragment_id
            or approval.get('planId')!='phase6b:'+contract.lowering_kind.value
            or approval.get('constraintsId')!='phase6c:'+contract.semantic_contract_id):
        raise ValueError('ISS_APPROVAL_PLAN_OR_SCOPE_MISMATCH')
    validate_domain(contract.domain_authority,fragment_id=approval['sourceFragmentId'],
        environment_id=approval['targetEnvironmentId'],cpu_profile=approval['targetCpuProfileId'],
        source_digest=source_digest)
    proof=prove_instruction_stream_sync(contract,target_cpu_profile_id=approval['targetCpuProfileId'])
    if not proof.approved or proof.proof_payload!=payload['phase6Proof']:
        raise ValueError('ISS_PHASE6_PROOF_REPLAY_FAILED')
    expected,text=close_instruction_stream_approval(approval,proof,fragment,
        bytes.fromhex(payload['machineCodeHex']),approval['requiredBuildContract'])
    # Compare the actual dependency, scope and helper used in rendering. A
    # rehashed envelope cannot redirect a proof to another implementation.
    for field,actual in {'runtimeContractId':contract.runtime_adapter_identity,
        'runtimeContractVersion':contract.semantic_version,'targetCpuProfileId':contract.target_cpu_profile_id,
        'targetEnvironmentId':contract.target_environment_id,'requiredScope':contract.required_scope.value,
        'requiredHeaders':[contract.required_header],'requiredLibraries':[contract.runtime_library]}.items():
        if approval.get(field)!=actual: raise ValueError('ISS_RUNTIME_BINDING_MISMATCH:'+field)
    if (any(approval.get(k)!=expected[k] for k in ('proofIdentity','runtimeShellProof',
            'rendererContractIdentity','replacementDigest','l2EffectProofFacts','shellFactsIdentity'))
            or (replacement is not None and replacement!=text)):
        raise ValueError('ISS_EFFECT_CLOSURE_MISMATCH')
    return expected['l2EffectProofFacts']
