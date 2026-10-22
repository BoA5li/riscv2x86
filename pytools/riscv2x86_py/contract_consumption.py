"""Audit real semantic consumers without confusing discovery with approval.

The stages are a dependency graph: proof approval and provider binding are
separate. This receipt never grants semantics and cannot replace proof replay.
"""
from pathlib import Path
from .semantic_content import semantic_identity,semantic_payload
from .time_trace_harness import digest


def consumption_receipt(source,report,*,csr=None,sync=None,paths=None):
    records=[]
    for family,registry in (('csr_environment',csr),('instruction_stream_sync',sync)):
        if registry is None:continue
        path=(paths or {}).get(family)
        record={'family':family,'sourceDigest':digest(source),'artifactPath':str(path or ''),
            'artifactDigest':digest(path) if path else '', 'consumer':'phase6-production-pipeline',
            'schemaValidated':True,'consumptions':[],'semanticApproval':False}
        for finding in report.get('findings',[]):
            fragment=finding['fragment'];fid=fragment.get('id') or fragment.get('fragmentId')
            approval=finding.get('approvalArtifact') or {};p=approval.get('proofPayload') or {}
            consumed=False
            if family=='csr_environment' and fid==registry.fragment_id and p:
                from .csr_runtime_approval import validate_csr_runtime_approval,_namespace
                from .csr_runtime_implementation import validate_implementation
                from .csr_structured_renderer import CsrRuntimeRecipe
                validate_csr_runtime_approval(approval,fragment,finding.get('suggestedReplacement'))
                implementation,_=validate_implementation(CsrRuntimeRecipe(**p['recipe']),
                    _namespace(p['fieldProof']['sourceModel']).effects,
                    tuple(_namespace(x) for x in p['fieldProof']['constraints']))
                expected=semantic_identity({'runtime':registry.runtime_registry,
                    'renderer':registry.renderer_registry,'implementation':implementation})
                consumed=p['fieldProof']['registryIdentity']==expected
            elif family=='instruction_stream_sync' and approval.get('artifactVersion')=='phase6-instruction-stream-sync-v3':
                from .l2_instruction_stream import validate_instruction_stream_approval
                validate_instruction_stream_approval(approval,fragment,finding.get('suggestedReplacement'),source_digest=digest(source))
                selected=registry.resolve(fid,approval['targetEnvironmentId'])
                consumed=selected is not None and semantic_payload(selected)==approval['instructionStreamProof']['phase6Proof']['contract']
            if consumed:
                record['consumptions'].append({'fragmentId':fid,'proofIdentity':approval['proofIdentity'],
                    'disposition':'consumed_by_replayed_approval','proofStatus':approval['proofStatus']})
        record['disposition']='consumed' if record['consumptions'] else 'validated_not_consumed'
        records.append(record)
    payload={'schemaVersion':'riscv2x86.contract-consumption.v1','sourceDigest':digest(source),
        'semanticApproval':False,'records':records}
    return {**payload,'receiptIdentity':semantic_identity(payload)}
