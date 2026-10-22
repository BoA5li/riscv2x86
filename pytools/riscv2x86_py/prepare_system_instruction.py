"""Bind a reviewed SYSTEM environment to real compiler and decoder identities.

Does not generate a handler, runtime guarantee, semantic registry or approval.
Those are independent reviewed inputs. Supports the explicit bounded M-mode
profile; unrestricted Linux syscall and full-system WFI are not inferred.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from .semantic_content import semantic_identity
from .system_instruction_ingress import (
    SCHEMA, PROFILE, SystemInstructionAuthority, decode_system_instruction,
    bind_system_instructions, digest,
)


def prepare(*, source, report, fragment_id, execution_sidecar, mechanism_evidence, transition):
    from .mechanism_route_checks import compiler_bound_finding
    from .privileged_execution_sidecar import load_privileged_execution_sidecar
    from .lift import lift
    finding, _ = compiler_bound_finding(source, report, fragment_id)
    fragment=finding['fragment']
    if fragment.get('inputs') or fragment.get('outputs'):
        raise ValueError('SYSTEM_PREPARATION_OPERAND_SCOPE_UNSUPPORTED')
    facts=load_privileged_execution_sidecar(execution_sidecar).facts_for(fragment_id)
    if facts is None: raise ValueError('SYSTEM_PREPARATION_EXECUTION_FRAGMENT_MISMATCH')
    path=Path(mechanism_evidence).resolve(); evidence=json.loads(path.read_text())
    fields={'schemaVersion','profile','semanticBasis','sourceArtifacts','targetArtifacts'}
    if not isinstance(evidence,dict) or set(evidence)!=fields or evidence['schemaVersion']!='riscv2x86.system-mechanism-evidence.v1' or evidence['profile']!=PROFILE:
        raise ValueError('SYSTEM_PREPARATION_MECHANISM_EVIDENCE_INVALID')
    if not isinstance(evidence['semanticBasis'],list) or not evidence['semanticBasis'] or not all(isinstance(x,str) and x.strip() for x in evidence['semanticBasis']):
        raise ValueError('SYSTEM_PREPARATION_SEMANTIC_BASIS_REQUIRED')
    for side in ('sourceArtifacts','targetArtifacts'):
        records=evidence[side]
        if not isinstance(records,list) or not records:
            raise ValueError('SYSTEM_PREPARATION_IMPLEMENTATION_ARTIFACTS_REQUIRED')
        roles=[]
        for record in records:
            if not isinstance(record,dict) or set(record)!={'role','path','digest'} or record['role'] not in ('implementation-source','runner-binary','build-record'):
                raise ValueError('SYSTEM_PREPARATION_IMPLEMENTATION_ARTIFACT_INVALID')
            relative=Path(record['path']); actual=(path.parent/relative).resolve()
            if relative.is_absolute() or not actual.is_relative_to(path.parent) or not actual.is_file() or digest(actual.read_bytes())!=record['digest']:
                raise ValueError('SYSTEM_PREPARATION_IMPLEMENTATION_DIGEST_MISMATCH')
            roles.append(record['role'])
        if not {'implementation-source','runner-binary','build-record'}.issubset(roles):
            raise ValueError('SYSTEM_PREPARATION_IMPLEMENTATION_COVERAGE_INCOMPLETE')
    code=bytes.fromhex(finding['machineCodeHex'])
    name=decode_system_instruction(code)
    if name is None: raise ValueError('SYSTEM_PREPARATION_INSTRUCTION_SCOPE_UNSUPPORTED')
    value={'schemaVersion':SCHEMA,'profile':PROFILE,'sourceDigest':digest(Path(source).read_bytes()),
        'fragmentId':fragment_id,'machineCodeDigest':digest(code),'executionIdentity':semantic_identity(facts),
        'mechanismIdentity':semantic_identity(evidence),
        'bindings':[{'instructionOffset':0,'operation':name,'transition':transition}]}
    value['authorityIdentity']=semantic_identity(value)
    selected=SystemInstructionAuthority.from_dict(value)
    lifted=lift(code,xlen=64,base_addr=0x10000,require_authoritative_register_names=True)
    if not lifted.ok: raise ValueError('SYSTEM_PREPARATION_LIFT_FAILED:'+lifted.error)
    bind_system_instructions(lifted,machine_code=code,base_addr=0x10000,
        source_digest=value['sourceDigest'],fragment_id=fragment_id,facts=facts,authority=selected)
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','report','execution-sidecar','mechanism-evidence','transition','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--fragment-id',required=True)
    args=parser.parse_args()
    try:
        if args.output.exists(): raise ValueError('SYSTEM_PREPARATION_OUTPUT_EXISTS')
        value=prepare(source=args.source,report=args.report,fragment_id=args.fragment_id,
            execution_sidecar=args.execution_sidecar,mechanism_evidence=args.mechanism_evidence,
            transition=json.loads(args.transition.read_text()))
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(value,indent=2)+'\n')
        print(json.dumps({'disposition':'prepared_pending_phase6d','semanticApproval':False,
            'authorityIdentity':value['authorityIdentity'],'path':str(args.output)}))
        return 0
    except (OSError,ValueError,KeyError,TypeError,AttributeError) as exc:
        print(json.dumps({'failureStage':'system_instruction_preparation','detail':str(exc),'semanticApproval':False}))
        return 2


if __name__=='__main__':raise SystemExit(main())
