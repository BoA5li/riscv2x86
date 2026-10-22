"""Bind the shipped observer to an existing approved synchronization relation.

Planning computes command identities only. Binding replays the Phase 6D proof,
checks compiler scope and existing domain identities, then emits an explicit
provider. Neither operation creates a visibility guarantee.
"""
import argparse
from hashlib import sha256
import json
import re
from pathlib import Path
import shutil
import sys
from .semantic_content import semantic_identity
from .compiler_instruction_sync_scope import validate_scope
from .l2_instruction_stream import validate_instruction_stream_approval
from .l2_instruction_visibility_runner import runner_identity, validate_provider, SCHEMA, OBSERVATION
from .l2_explicit_harness import _identity, ExplicitL2HarnessManifest
from .l2_validator_resolution import provider_from_dict, L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA


def digest(path):return 'sha256:'+sha256(Path(path).read_bytes()).hexdigest()


def commands(*, approval_path, symbol, source_compiler, target_compiler, source_runner, python=sys.executable):
    if not isinstance(symbol,str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",symbol) is None:
        raise ValueError("ISS_PREPARATION_SYMBOL_INVALID")
    def executable(value):
        path=Path(shutil.which(value) or value).absolute()
        if not path.is_file():raise ValueError('ISS_PREPARATION_EXECUTABLE_MISSING:'+value)
        return str(path)
    python=executable(python);source_compiler=executable(source_compiler);target_compiler=executable(target_compiler)
    if not source_runner:raise ValueError('ISS_PREPARATION_SOURCE_RUNNER_MISSING')
    runner=[executable(source_runner[0]),*source_runner[1:]]
    base=[python,'-m','riscv2x86_py.instruction_visibility_harness']
    def command(side,compiler):
        return [*base,'--side',side,'--function-symbol',symbol,'--approval',str(Path(approval_path).resolve()),'--compiler',compiler]
    source=[*command('source',source_compiler),'--runner',*runner];target=command('target',target_compiler)
    harness=Path(__file__).with_name('instruction_visibility_harness.py').resolve()
    return {'sourceCommand':source,'targetCommand':target,'harnessPath':str(harness),
        'sourceRunnerIdentity':runner_identity(source,digest(harness)),
        'targetRunnerIdentity':runner_identity(target,digest(harness)),'semanticApproval':False}


def bind(*, source, source_root, report, fragment_id, output, execution_profile,
         source_compiler, target_compiler, source_runner, python=sys.executable):
    source=Path(source).resolve();source_root=Path(source_root).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('ISS_PREPARATION_OUTPUT_EXISTS')
    relative=source.relative_to(source_root).as_posix();data=Path(report).read_bytes();raw=json.loads(data)
    matches=[f for f in raw.get('findings',[]) if (f['fragment'].get('id') or f['fragment'].get('fragmentId'))==fragment_id]
    if len(matches)!=1:raise ValueError('ISS_PREPARATION_FRAGMENT_AMBIGUOUS')
    finding=matches[0];fragment=finding['fragment'];approval=finding.get('approvalArtifact') or {}
    if finding.get('sourceDigest')!=digest(source):raise ValueError('ISS_PREPARATION_SOURCE_STALE')
    validate_instruction_stream_approval(approval,fragment,finding.get('suggestedReplacement'),source_digest=digest(source))
    if finding.get('machineCodeHex')!=approval['instructionStreamProof']['machineCodeHex']:
        raise ValueError('ISS_PREPARATION_MACHINE_BINDING_MISMATCH')
    scope=validate_scope(approval.get('l2InstructionSyncFunctionScope'),fragment,digest(source))
    plan=commands(approval_path=output/'approval.json',symbol=scope['functionSymbol'],
        source_compiler=source_compiler,target_compiler=target_compiler,source_runner=source_runner,python=python)
    domain=approval['instructionStreamProof']['phase6Proof']['contract']['domain_authority']
    if domain.get('schemaVersion')=='riscv2x86.instruction-stream-domain.v2':
        if digest(source_runner[0])!=domain['mechanismEvidence']['binaryDigest']:
            raise ValueError('ISS_MECHANISM_SOURCE_BINARY_MISMATCH')
    if (domain['sourceExecution']['runnerIdentity']!=plan['sourceRunnerIdentity']
            or domain['targetExecution']['runnerIdentity']!=plan['targetRunnerIdentity']):
        raise ValueError('ISS_PREPARATION_DOMAIN_RUNNER_MISMATCH')
    from .l2_authority import l2_authority_sidecar_from_dict
    sidecar=l2_authority_sidecar_from_dict(approval.get('l2AuthoritySidecar',{}),expected_fragment_id=fragment_id)
    if not sidecar.complete:raise ValueError('ISS_PREPARATION_CANONICAL_AUTHORITY_INCOMPLETE')
    from .automatic_l2_authority import _instruction_stream_authority_checked
    expected=_instruction_stream_authority_checked(finding,(),digest(__file__))
    for name in ('shell_fact_identity','operands','memory_objects','source_effects',
                 'approved_effect_relations','runtime_contracts','ignored_state','control_flow',
                 'ordering','internal_values','operand_observation_authority'):
        if getattr(sidecar,name)!=getattr(expected,name):
            raise ValueError('ISS_PREPARATION_APPROVAL_AUTHORITY_MISMATCH')
    relation_identity=sidecar.effect_relation_set_identity
    harness=Path(plan['harnessPath']);hd=digest(harness)
    manifest={'schemaVersion':'riscv2x86.explicit-l2-harness-manifest.v1',
        'harnessId':'approved-local-visibility','harnessVersion':'v1','producerDigest':digest(__file__),
        'supportedFragmentIdentities':[fragment_id],'supportedSemanticProfiles':[],
        'contractId':approval['runtimeContractId'],'providedDimensions':['memory_effects','shell_semantics'],
        'executionProfile':execution_profile,'sourceHarnessDigest':hd,'targetHarnessDigest':hd,
        'observationSchemaVersion':OBSERVATION,'relationSetIdentity':relation_identity,
        'nonInterferenceProofIdentity':scope['scopeIdentity'],'complete':True}
    manifest['manifestIdentity']=_identity(manifest);ExplicitL2HarnessManifest.from_dict(manifest)
    config={'schemaVersion':SCHEMA,'manifestPath':str(output/'harness-manifest.json'),
        'approvalPath':str(output/'approval.json'),'sourceHarnessPath':str(harness),'targetHarnessPath':str(harness),
        'sourceCommand':plan['sourceCommand'],'targetCommand':plan['targetCommand'],
        'contractId':approval['runtimeContractId'],'timeoutSeconds':120}
    provider={'providerId':'approved-visibility:'+scope['scopeIdentity'].split(':')[1],
        'supportedDimensions':['memory_effects','shell_semantics'],'supportedPatterns':['instruction_visibility_fence'],
        'requiredCapabilities':['instruction_visibility','shell_observation'],'executionProfiles':[execution_profile],
        'bindingKind':'explicit','validatorType':'l2-instruction-visibility-harness','configSchemaVersion':SCHEMA,
        'config':config,'fragmentIds':[fragment_id],'semanticProfileIds':[]}
    provider_from_dict(provider)
    record={'schemaVersion':L2_EXPLICIT_PROVIDER_MANIFEST_SCHEMA,'sourceRelativePath':relative,
        'sourceDigest':digest(source),'environmentCapabilities':['instruction_visibility','shell_observation'],
        'providers':[provider]};record['manifestIdentity']=_identity(record)
    output.mkdir(parents=True)
    (output/'approval.json').write_bytes(data)
    (output/'harness-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    validate_provider(provider_from_dict(provider))
    path=output/'providers'/(relative+'.l2-providers.json');path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(record,indent=2)+'\n')
    receipt={'schemaVersion':'riscv2x86.visibility-provider-preparation.v1','sourceDigest':digest(source),
        'fragmentId':fragment_id,'approvalDigest':digest(report),'proofIdentity':approval['proofIdentity'],
        'relationSetIdentity':relation_identity,'manifestIdentity':record['manifestIdentity'],
        'semanticApproval':False,'disposition':'bound_to_existing_approval'}
    receipt['preparationIdentity']=semantic_identity(receipt)
    (output/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--source-compiler',required=True)
    parser.add_argument('--target-compiler',required=True);parser.add_argument('--source-runner-json',required=True)
    parser.add_argument('--plan-symbol');parser.add_argument('--source',type=Path);parser.add_argument('--source-root',type=Path)
    parser.add_argument('--report',type=Path);parser.add_argument('--fragment-id');parser.add_argument('--execution-profile')
    args=parser.parse_args()
    try:
        runner=json.loads(args.source_runner_json)
        if not isinstance(runner,list) or not all(isinstance(x,str) and x for x in runner):raise ValueError('ISS_RUNNER_COMMAND_INVALID')
        if args.plan_symbol:
            value=commands(approval_path=args.output/'approval.json',symbol=args.plan_symbol,
                source_compiler=args.source_compiler,target_compiler=args.target_compiler,source_runner=runner)
        else:
            if any(x is None for x in (args.source,args.source_root,args.report,args.fragment_id,args.execution_profile)):
                raise ValueError('ISS_PREPARATION_BINDING_ARGUMENTS_MISSING')
            value=bind(source=args.source,source_root=args.source_root,report=args.report,fragment_id=args.fragment_id,
                output=args.output,execution_profile=args.execution_profile,source_compiler=args.source_compiler,
                target_compiler=args.target_compiler,source_runner=runner)
        print(json.dumps(value,ensure_ascii=False,indent=2));return 0
    except (OSError,ValueError,TypeError,KeyError,AttributeError) as exc:
        print(json.dumps({'failureStage':'visibility_provider_preparation','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
