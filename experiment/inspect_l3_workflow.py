#!/usr/bin/env python3
"""Read-only workflow inventory; report counts are not corpus coverage claims."""
import argparse
from collections import Counter
import json
from pathlib import Path


def collect(root, *, audit=False):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError('L3_INSPECTION_ROOT_REQUIRED')
    records = []
    errors = []
    for path in sorted(root.rglob('evaluation-result.json')):
        row = {'reportPath': str(path), 'independentAudit': {'status': 'not_run'}}
        try:
            report = json.loads(path.read_text(encoding='utf-8'))
            if type(report) is not dict:
                raise ValueError('L3_INSPECTION_REPORT_MAPPING_REQUIRED')
            row.update(status=report.get('status'), reasonCodes=report.get('reasonCodes', []))
            row['upstreamFailures'] = {key: report[key] for key in
                ('detail', 'orchestrationFailure', 'requirementStagingFailure') if report.get(key)}
            row['failedCommands'] = [command for command in report.get('commands', [])
                if command.get('status') != 'verified']
            row['attempts'] = [{
                'fragmentId': attempt.get('fragmentId'),
                'translationOutcome': attempt.get('translationOutcome'),
                'reasonCodes': attempt.get('reasonCodes', []),
                'layers': (attempt.get('validation') or {}).get('layers', []),
            } for attempt in report.get('attempts', [])]
            manifest = (report.get('translationEvaluationLink') or {}).get('l3Requirements') or {}
            row['requirements'] = [{key: requirement.get(key) for key in
                ('fragmentId', 'intentKind', 'requiredProperties', 'eligibilityStatus', 'reasonCodes')}
                for requirement in manifest.get('requirements', [])]
            if audit:
                if report.get('status') != 'verified':
                    row['independentAudit']['reasonCode'] = 'L3_INSPECTION_EVALUATION_NOT_VERIFIED'
                else:
                    from riscv2x86_py.l3_production_acceptance import audit_evaluation
                    row['independentAudit'] = audit_evaluation(report)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            row['inspectionError'] = type(exc).__name__ + ': ' + str(exc)
            errors.append({'reportPath': str(path), 'error': row['inspectionError']})
        records.append(row)
    return {
        'schemaVersion': 'riscv2x86.l3-workflow-inspection.v1',
        'root': str(root), 'reportCount': len(records),
        'countingUnit': 'evaluation report; not independently recognized corpus fragments',
        'declaredStatusCounts': dict(Counter(str(row.get('status', 'unreadable')) for row in records)),
        'auditRequested': audit,
        'independentlyVerifiedReportCount': sum(row['independentAudit'].get('status') == 'verified' for row in records),
        'semanticApproval': False, 'records': records, 'errors': errors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--output', required=True, help='New file; existing files are preserved')
    parser.add_argument('--audit', action='store_true', help='Replay current independent audits; requires matching tools and backends')
    args = parser.parse_args()
    result = collect(args.root, audit=args.audit)
    with Path(args.output).open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: result[key] for key in ('reportCount', 'declaredStatusCounts',
        'auditRequested', 'independentlyVerifiedReportCount', 'errors')}, ensure_ascii=False))
    # A plain inventory never promotes declared verdicts to independent acceptance.
    if (not result['reportCount'] or result['errors'] or
            args.audit and result['independentlyVerifiedReportCount'] != result['reportCount']):
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
