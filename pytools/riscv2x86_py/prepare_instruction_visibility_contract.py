"""Prepare a mechanism-backed local synchronization registry from real facts.

The caller explicitly declares the supported memory/execution domain and cites
its reviewed basis. The installed/build/source relationship is collected
separately. This tool does not grant translation approval or infer guarantees
from the input's name, a hash, or a successful probe.
"""
import argparse
import json
from pathlib import Path
from .semantic_content import semantic_identity
from .mechanism_evidence import validate as validate_evidence
from .time_trace_harness import digest
from .prepare_instruction_visibility import commands
from .instruction_stream_sync_contracts import instruction_stream_sync_registry_from_dict
from .phase6c_constraints import FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT
from .instruction_stream_sync_contracts import instruction_stream_environment_id


def prepare(*,source,report,fragment_id,evidence,declaration,provider_output,
            source_compiler,target_compiler,source_runner):
    validate_evidence(evidence)
    required={'schemaVersion','sourceCpu','targetCpu','logicalHartIdentity','modifiedCodeRange','assumptions'}
    if not isinstance(declaration,dict) or set(declaration)!=required or declaration['schemaVersion']!='riscv2x86.local-sync-selection.v1':
        raise ValueError('ISS_EXPLICIT_DOMAIN_SELECTION_REQUIRED')
    if any(type(declaration[k]) is not int or declaration[k]<0 for k in ('sourceCpu','targetCpu')):
        raise ValueError('ISS_EXPLICIT_CPU_SELECTION_REQUIRED')
    if declaration['modifiedCodeRange']!={'objectIdentity':'probe-code-object','offsetBytes':0,'lengthBytes':4096,'addressSpaceIdentity':'observer.private.anonymous'}:
        raise ValueError('ISS_OBSERVER_RANGE_BINDING_MISMATCH')
    from .mechanism_route_checks import preparation_inputs
    f,scope=preparation_inputs(source,report,fragment_id,family='sync')
    if f['sourceDigest']!=digest(source) or f.get('machineCodeHex')!='0f100000':
        raise ValueError('ISS_PREPARATION_SOURCE_OR_ENCODING_MISMATCH')
    plan=commands(approval_path=Path(provider_output).resolve()/'approval.json',symbol=scope['functionSymbol'],
        source_compiler=source_compiler,target_compiler=target_compiler,source_runner=source_runner)
    from shutil import which
    if digest(which(source_runner[0]) or source_runner[0])!=evidence['binaryDigest']:
        raise ValueError('ISS_MECHANISM_SOURCE_BINARY_MISMATCH')
    env=FIXED_SYSV_AMD64_GNU_ATT_ENVIRONMENT
    domain={'schemaVersion':'riscv2x86.instruction-stream-domain.v2','sourceDigest':digest(source),
        'fragmentId':fragment_id,'targetEnvironmentId':instruction_stream_environment_id(env),
        'targetCpuProfileId':env.target_cpu_profile_id,
        'sourceExecution':{'runnerIdentity':plan['sourceRunnerIdentity'],'logicalHartIdentity':declaration['logicalHartIdentity'],
            'pinnedCpu':declaration['sourceCpu'],'threadCount':1},
        'targetExecution':{'runnerIdentity':plan['targetRunnerIdentity'],'logicalHartIdentity':declaration['logicalHartIdentity'],
            'pinnedCpu':declaration['targetCpu'],'threadCount':1},
        'memoryDomain':{'kind':'ordinary_cacheable_coherent_memory','targetProtocol':'x86-local-serializing-smc-v1',
            'buildContract':'automatic-gcc-separate-tu-no-lto-v1'},
        'coverage':'all_prior_visible_instruction_stores_on_bound_hart',
        'mechanismEvidence':evidence,'reviewedAssumptions':declaration['assumptions']}
    domain['domainIdentity']=semantic_identity(domain)
    from .instruction_stream_domain import validate_domain
    validate_domain(domain,fragment_id=fragment_id,environment_id=domain['targetEnvironmentId'],cpu_profile=domain['targetCpuProfileId'])
    # Positive obligations are derived only for this registered mechanism under
    # the explicitly reviewed domain. No PROVEN_NOOP or multi-hart route here.
    contract={'contractId':'reviewed-local-visibility:'+domain['domainIdentity'],'semanticVersion':'v1',
        'sourceFragmentId':fragment_id,'targetEnvironmentId':domain['targetEnvironmentId'],
        'loweringKind':'runtime_helper','modifiedCodeRange':declaration['modifiedCodeRange'],
        'dataWritePublicationRelationId':'private-coherent-local-stores-v1',
        'instructionFetchVisibilityRelationId':'qemu-smc-to-x86-serializing-local-v1','requiredScope':'local_hart',
        'cacheCoherenceModelId':'ordinary-cacheable-coherent-private-mapping-v1','crossCoreInvalidationRelationId':None,
        'targetCpuProfileId':env.target_cpu_profile_id,'runtimeAdapterIdentity':'riscv2x86_rt_instruction_stream_sync_local@v1',
        'completionAcknowledgementRelationId':'local-helper-return-v1','helperSymbol':'riscv2x86_rt_instruction_stream_sync_local',
        'requiredHeader':'riscv2x86_runtime_helpers.h','runtimeLibrary':'libriscv2x86_runtime',
        'provesDataWritePublication':True,'provesInstructionFetchVisibility':True,'provesCompletionAcknowledgement':True,
        'provesRequiredScope':True,'environmentNoopGuaranteeId':None,'complete':True,
        'preservesCompilerMemoryOrdering':True,'preservesVolatileExecution':True,'preservesCcClobber':True,
        'domainAuthority':domain}
    raw={'schemaVersion':'riscv2x86.instruction-stream-sync-registry.v3','version':'mechanism-local-v1',
        'sourceDigest':digest(source),'contracts':[contract]}
    instruction_stream_sync_registry_from_dict(raw)
    return raw


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','report','mechanism-evidence','declaration','provider-output','output'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('fragment-id','source-compiler','target-compiler','source-runner-json'):
        p.add_argument('--'+name,required=True)
    a=p.parse_args()
    try:
        if a.output.exists():raise ValueError('ISS_PREPARATION_OUTPUT_EXISTS')
        value=prepare(source=a.source,report=a.report,fragment_id=a.fragment_id,
            evidence=json.loads(a.mechanism_evidence.read_text()),declaration=json.loads(a.declaration.read_text()),
            provider_output=a.provider_output,source_compiler=a.source_compiler,target_compiler=a.target_compiler,
            source_runner=json.loads(a.source_runner_json))
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(value,indent=2)+'\n')
        print(json.dumps({'registryPath':str(a.output),'disposition':'prepared_pending_phase6d','semanticApproval':False}));return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError) as exc:
        print(json.dumps({'failureStage':'instruction_visibility_contract','detail':str(exc),'semanticApproval':False}));return 2


if __name__=='__main__':raise SystemExit(main())
