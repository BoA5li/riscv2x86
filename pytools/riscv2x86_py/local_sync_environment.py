"""Bind the functional L1 runner and visibility L2 runner to one local domain."""
import json
from pathlib import Path
from .semantic_content import semantic_identity
from .time_trace_harness import digest


def environment_binding(config,domain,*,compiler_digest=None):
    def field(key,attr):return config[key] if isinstance(config,dict) else getattr(config,attr)
    source=list(field('sourceCommand','source_command'))
    target=list(field('targetCommand','target_command'))
    if '--runner' not in source:raise ValueError('ISS_MECHANISM_SOURCE_RUNNER_REQUIRED')
    runner=source[source.index('--runner')+1:]
    if not runner:raise ValueError('ISS_MECHANISM_SOURCE_RUNNER_REQUIRED')
    compiler=source[source.index('--compiler')+1]
    payload={'schemaVersion':'riscv2x86.local-sync-environment.v1',
        'domainIdentity':domain['domainIdentity'],'sourceDigest':domain['sourceDigest'],
        'fragmentId':domain['fragmentId'],'sourceRunnerCommand':runner,
        'sourceBinaryDigest':domain['mechanismEvidence']['binaryDigest'],
        'sourceCompiler':compiler,'sourceCompilerDigest':compiler_digest or digest(compiler),
        'sourceCpu':domain['sourceExecution']['pinnedCpu'],'targetCpu':domain['targetExecution']['pinnedCpu'],
        'sourceObserverCommand':source,'targetObserverCommand':target,
        'supportDomain':'local-single-thread-private-ordinary-coherent-memory'}
    return {**payload,'environmentProfileIdentity':semantic_identity(payload)}


def environment_id(binding):return 'local-sync:'+binding['environmentProfileIdentity']


def provider_environment(provider):
    from .l2_instruction_visibility_runner import load_config
    from .l2_instruction_stream import validate_instruction_stream_approval
    from .approved_replacement import approved_replacement
    config,path=load_config(provider['config'])
    report=json.loads(Path(path).read_text())
    matches=[f for f in report['findings'] if (f['fragment'].get('id') or f['fragment'].get('fragmentId')) in provider['fragmentIds']]
    if len(provider['fragmentIds'])!=1 or len(matches)!=1:raise ValueError('ISS_ENVIRONMENT_FRAGMENT_AMBIGUOUS')
    f=matches[0];approval=f['approvalArtifact']
    validate_instruction_stream_approval(approval,f['fragment'],approved_replacement(f),source_digest=f['sourceDigest'])
    domain=approval['instructionStreamProof']['phase6Proof']['contract']['domain_authority']
    if domain['schemaVersion']!='riscv2x86.instruction-stream-domain.v2':
        raise ValueError('ISS_REVIEWED_EXECUTION_DOMAIN_REQUIRED')
    binding=environment_binding(config,domain)
    if digest(binding['sourceRunnerCommand'][0])!=binding['sourceBinaryDigest']:
        raise ValueError('ISS_MECHANISM_SOURCE_BINARY_MISMATCH')
    return binding


def audit_case_environment(case,records=()):
    outer=(case.get('targetEnvironment') or {}).get('environmentId')
    for attempt in case.get('attempts',[]):
        for layer in (attempt.get('validation') or {}).get('layers',[]):
            if layer.get('level')!='L1':continue
            try:detail=json.loads(layer.get('detail',''))
            except (ValueError,TypeError):continue
            if not isinstance(detail,dict) or detail.get('schemaVersion')!='riscv2x86.auto-l1-observation.v1':continue
            binding=detail.get('executionEnvironment')
            if binding is None:continue
            if (binding['environmentProfileIdentity']!=semantic_identity({k:v for k,v in binding.items() if k!='environmentProfileIdentity'})
                    or outer!=environment_id(binding) or detail.get('environmentId')!=outer
                    or layer['evidenceIdentity']!=semantic_identity(detail)):
                raise ValueError('ISS_CASE_LAYER_ENVIRONMENT_MISMATCH')
            commands=detail['actualCommands']
            if (commands['source'][1:4]!=['--cpu-list',str(binding['sourceCpu']),binding['sourceRunnerCommand'][0]]
                    or commands['source'][3:-1]!=binding['sourceRunnerCommand']
                    or commands['target'][1:3]!=['--cpu-list',str(binding['targetCpu'])]
                    or set(detail.get('executableDigests',{}))!={'source','target'}):
                raise ValueError('ISS_CASE_LAYER_RUNNER_MISMATCH')
    for entry in records:
        envelope=entry.get('envelope',entry)
        if envelope['providerDefinition']['validatorType']!='l2-instruction-visibility-harness':continue
        detail=json.loads(envelope['normalizedResult']['detail'])
        domain=detail.get('domainAuthority') or {}
        if domain.get('schemaVersion')!='riscv2x86.instruction-stream-domain.v2':continue
        binding=detail.get('executionEnvironment') or {}
        expected=environment_binding(envelope['providerDefinition']['config'],domain,
            compiler_digest=binding.get('sourceCompilerDigest'))
        if outer!=environment_id(expected) or binding!=expected:
            raise ValueError('ISS_CASE_PROVIDER_ENVIRONMENT_MISMATCH')
