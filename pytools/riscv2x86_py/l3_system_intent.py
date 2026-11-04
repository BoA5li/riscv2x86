"""Explicit proof-bound SYSTEM policy ingress. Classification grants no execution."""
import argparse
import json
from pathlib import Path
import sys

from .l3_trace_support import identity, emit_json, require_json_match
from .l3_intent_requirements import parse_l3_intent_profile, _hash
from .l3_implementation_dependencies import implementation_paths


def specification(finding, artifact, functions, config):
    from . import controlled_system_runner as system
    from .l2_authority import l2_authority_sidecar_from_dict
    from .l3_system_route import POLICY
    backend = system.load_config(config)
    approved = system.approved_finding(config, artifact)
    keys = ('proofStatus','proofIdentity','systemOperation','sourceModelId','planId','constraintsId',
            'rendererContractIdentity','replacementDigest','l2EffectProofFacts','l2AuthoritySidecar')
    a = finding['approvalArtifact']
    bindings = {'proofIdentity':artifact.proof_identity, 'sourceModelId':artifact.source_model_identity,
        'planId':artifact.translation_plan_id, 'constraintsId':artifact.constraint_id,
        'runtimeContractId':artifact.runtime_contract_id, 'runtimeContractVersion':artifact.runtime_contract_version}
    if any(a.get(k) != v for k,v in bindings.items()):
        raise ValueError('SYSTEM_L3_PRODUCER_ARTIFACT_MISMATCH')
    from .system_instruction_ingress import decode_system_instruction
    if a.get('systemOperation') != config['operation'] or decode_system_instruction(bytes.fromhex(finding['machineCodeHex'])) != config['operation']:
        raise ValueError('SYSTEM_L3_PRODUCER_OPERATION_MISMATCH')
    require_json_match({k:approved['approvalArtifact'].get(k) for k in keys},
                       {k:a.get(k) for k in keys}, 'SYSTEM_L3_PRODUCER_APPROVAL_MISMATCH')
    if (finding['fragment']['id'] != artifact.fragment_id
            or finding['machineCodeHex'] != approved['machineCodeHex']
            or finding['sourceDigest'] != config['sourceDigest']):
        raise ValueError('SYSTEM_L3_PRODUCER_SOURCE_MISMATCH')
    sidecar = l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    if (not sidecar.complete or artifact.l2_authority_complete is not True
            or sidecar.authority_identity != artifact.l2_authority_identity
            or sidecar.fragment_id != artifact.fragment_id
            or sidecar.effect_relation_set_identity != artifact.effect_relation_set_identity):
        raise ValueError('SYSTEM_L3_PRODUCER_EFFECT_CLOSURE_REQUIRED')
    matches = [f for f in functions if f.get('functionId') == config['scope']['functionIdentity']]
    if len(matches) != 1 or matches[0].get('sourceDigest') != config['sourceDigest']:
        raise ValueError('SYSTEM_L3_COMPILER_PROGRAM_REQUIRED')
    # Compiler snapshots intentionally do not carry automatic-batch programId.
    # Use a policy-specific content identity, not a guessed batch ID or path.
    program_id = identity({'schemaVersion':'riscv2x86.controlled-system-program.v1',
        'sourceDigest':config['sourceDigest'],'entryFunctionIdentity':config['scope']['functionIdentity']})
    body = {'schemaVersion':'riscv2x86.controlled-system-l3-spec.v1',
        'fragmentId':artifact.fragment_id, 'programId':program_id,
        'proofIdentity':artifact.proof_identity, 'relationIdentity':artifact.effect_relation_set_identity,
        'sourceDigest':config['sourceDigest'], 'scopeIdentity':config['scope']['scopeIdentity'],
        'operation':config['operation'], 'backendIdentity':backend['backendIdentity'],
        'targetCallable':a['privilegedCallableIdentifier'],
        'observerIdentity':config['observerIdentity'], 'policyIdentity':identity(POLICY),
        'sourceEffects':[e.to_dict() for e in sidecar.source_effects],
        'requiredProperties':[{'propertyId':p, 'dimension':'synchronization', 'unit':'fragment'}
                              for p in sorted(POLICY['properties'])]}
    return dict(body, specIdentity=identity(body))


def profile(spec, producer_identity):
    from .l3_system_route import POLICY
    body = {'schemaVersion':'riscv2x86.l3-intent-profile.v1','fragmentId':spec['fragmentId'],
        'programId':spec['programId'],'intentKind':'synchronization',
        'experimentClasses':['synchronization'],'sourceIntent':'bounded controlled M-mode SYSTEM state and mechanism',
        'approvedTargetRelationIdentity':spec['relationIdentity'],
        'requiredProperties':spec['requiredProperties'],
        'sourceCapabilities':['bounded-controlled-system-v1'], 'targetCapabilities':['bounded-controlled-system-v1'],
        'observationBoundary':{'kind':'controlled-system-operation','identity':spec['specIdentity']},
        'notClaimedProperties':sorted(POLICY['excluded']),
        'producer':{'kind':'translation-proof','producerIdentity':producer_identity,'proofIdentity':spec['proofIdentity']},
        'complete':True}
    return parse_l3_intent_profile(dict(body, profileIdentity=_hash(body))).to_dict()


def produce(request, config):
    from .translation_validation import translation_artifact_from_dict
    if (request.get('schemaVersion') != 'riscv2x86.l3-intent-producer-request.v1'
            or request.get('requestIdentity') != _hash({k:v for k,v in request.items() if k!='requestIdentity'})
            or len(request['candidates']) != 1):
        raise ValueError('SYSTEM_L3_PRODUCER_SINGLE_BOUND_CANDIDATE_REQUIRED')
    if (request['sourceDigest'] != config['sourceDigest']
            or Path(request['sourcePath']).resolve() != Path(config['sourcePath']).resolve()):
        raise ValueError('SYSTEM_L3_PRODUCER_REQUEST_SOURCE_MISMATCH')
    candidate = request['candidates'][0]
    artifact = translation_artifact_from_dict(candidate['translationArtifact'])
    spec = specification(candidate['finding'], artifact, candidate['compilerFunctions'], config)
    return {'schemaVersion':'riscv2x86.l3-intent-producer-response.v2','requestIdentity':request['requestIdentity'],
            'profiles':[profile(spec, request['producerIdentity'])],'dispositions':[]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--implementation',required=True)
    parser.add_argument('--dependency',action='append',default=[])
    parser.add_argument('--config',required=True)
    args = parser.parse_args()
    if (Path(args.implementation).resolve() != Path(__file__).resolve()
            or {str(Path(p).resolve()) for p in args.dependency} != set(implementation_paths())):
        raise ValueError('SYSTEM_L3_PRODUCER_DEPENDENCIES_UNPINNED')
    emit_json(lambda:produce(json.load(sys.stdin),json.loads(Path(args.config).read_text())))


if __name__ == '__main__': main()
