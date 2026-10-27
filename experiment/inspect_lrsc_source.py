"""Compact, read-only inspection of LR/SC source-stage production artifacts."""
import argparse
import json
from pathlib import Path


def collect(root):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError('LRSC_SOURCE_ROOT_MISSING')
    rows, errors = [], []
    for path in sorted(root.rglob('translated_report.json')):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            errors.append({'path': str(path), 'error': 'external/symlink report rejected'})
            continue
        try:
            data = json.loads(path.read_text())
            for finding in data['findings']:
                diagnostics = finding.get('routeAuthorityDiagnostics') or []
                source = [r for r in diagnostics if r.get('failureStage') == 'lrsc_source_sequence']
                binding = [r for r in diagnostics if r.get('failureStage') == 'lrsc_sequence_ingress']
                payload = source[0]['inputsPayload'] if len(source) == 1 else {}
                bound = ((binding[0]['inputsPayload'].get('compilerBinding') or {})
                         if len(binding) == 1 else {})
                rows.append({'report': str(path.relative_to(root)),
                    'fragmentId': finding.get('fragment', {}).get('id'),
                    'translationOutcome': finding.get('translationOutcome'),
                    'translationReasonCodes': finding.get('translationReasonCodes'),
                    'sourceDiagnosticCount': len(source),
                    'compilerBindingComplete': bound.get('compilerBindingComplete'),
                    'sourceStateModelComplete': payload.get('sourceStateModelComplete'),
                    'semanticApproval': payload.get('semanticApproval'),
                    'modelIdentity': payload.get('modelIdentity'),
                    'roleOperandIndexes': payload.get('role_operand_indexes'),
                    'memoryOperandIndex': payload.get('memory_operand_index'),
                    'memoryWidthBits': payload.get('memory_width_bits'),
                    'arithmeticWidthBits': payload.get('arithmetic_width_bits'),
                    'operandShape': (finding.get('l2SemanticProfile') or {}).get('operandShape'),
                    'runtimeEvidencePresent': bool((finding.get('translationRuntimeFacts') or {}).get('lrscSequenceEvidence')),
                    'approvalArtifactPresent': bool(finding.get('approvalArtifact')),
                    'proofStatus': (finding.get('approvalArtifact') or {}).get('proofStatus'),
                    'targetProofApproved': (finding.get('approvalArtifact') or {}).get('proofStatus') == 'approved',
                    'rendererSemanticContractId': (finding.get('approvalArtifact') or {}).get('rendererSemanticContractId'),
                    'l2AuthoritySidecarPresent': bool((finding.get('approvalArtifact') or {}).get('l2AuthoritySidecar')),
                    'l2MaterializationDecision': (finding.get('approvalArtifact') or {}).get('l2MaterializationDecision'),
                    'remainingObligations': payload.get('remainingObligations'),
                    'diagnostics': [{'stage': r.get('failureStage'), 'reasonCode': r.get('reasonCode'),
                        'detail': r.get('detail')} for r in diagnostics]})
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            errors.append({'path': str(path), 'error': type(exc).__name__ + ': ' + str(exc)})
    return {'schemaVersion': 'riscv2x86.lrsc-source-inspection.v1', 'records': rows,
        'errors': errors, 'note': 'Inspection only; source completeness is not translation or L3 approval.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    data = collect(args.root)
    with Path(args.output).open('x', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 1 if data['errors'] or not data['records'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
