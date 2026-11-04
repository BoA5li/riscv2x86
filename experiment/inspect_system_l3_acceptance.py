"""Read-only fresh SYSTEM audit plus production/batch/coverage consistency checks."""
import argparse
import json
from pathlib import Path


def inspect(root, expected_runs=None):
    from riscv2x86_py.l3_system_route import _json, POLICY
    from riscv2x86_py.l3_trace_support import identity, require_json_match
    from riscv2x86_py.l3_production_acceptance import audit_evaluation
    roots = sorted({p.parent.resolve() for p in Path(root).rglob('run-status.json')})
    records, errors = [], []
    selected = []
    for directory in roots:
        try:
            state = _json((directory / 'run-status.json').read_text())
            if state.get('schemaVersion') != 'riscv2x86.controlled-system-production-run.v2':
                continue
            selected.append(directory)
            if (state.get('currentStage') != 'complete' or state.get('blockers')
                    or any(state.get(k) is not True for k in ('executionComplete',
                        'independentResultAuditComplete', 'productionAcceptanceComplete', 'boundedSystemL3Complete'))
                    or state.get('originalLinuxUserEquivalent') is not False
                    or state.get('physicalMicroarchitectureEquivalenceClaimed') is not False):
                raise ValueError('SYSTEM production state is incomplete or overclaims equivalence')
            accepted = state.get('productionAcceptance', [])
            if not accepted:
                raise ValueError('SYSTEM production acceptance records missing')
            for recorded in accepted:
                batch_path = Path(recorded['resultPath'])
                if not batch_path.is_absolute() or not batch_path.resolve().is_relative_to(directory):
                    raise ValueError('SYSTEM batch path is outside the selected production directory')
                batch = _json(batch_path.read_text())
                if batch.get('caseCount') != 1 or batch.get('statusCounts') != {'verified': 1}:
                    raise ValueError('SYSTEM batch summary not verified')
                if (batch.get('l3BoundedSystemVerifiedProgramCount') != 1
                        or batch.get('l3ArchitecturalIntentVerifiedProgramCount') != 0):
                    raise ValueError('SYSTEM batch claim-scope counters invalid')
                case, = batch['cases']
                if case.get('status') != 'verified' or any(case['programValidationLevels'].get(k) != 'verified'
                        for k in ('L0', 'L1', 'L2', 'L3')):
                    raise ValueError('SYSTEM batch layer chain incomplete')
                counts = case['l3Coverage']['counts']
                if (any(counts.get(k) != 1 for k in ('attempted', 'completeExecution', 'boundedSystemIntentVerified'))
                        or any(counts.get(k) != 0 for k in ('notRun', 'architecturalIntentVerified', 'diagnosticVerified'))):
                    raise ValueError('SYSTEM coverage counters invalid')
                persisted = _json((batch_path.parent / 'l3-production-acceptance.json').read_text())
                if any(persisted.get(k) is not True for k in ('productionAcceptanceComplete',
                        'independentResultAuditComplete', 'batchSummaryComplete')):
                    raise ValueError('SYSTEM acceptance stages incomplete')
                path = (batch_path.parent / case['resultPath']).resolve()
                if not path.is_relative_to(batch_path.parent.resolve()):
                    raise ValueError('SYSTEM case path outside batch')
                report = _json(path.read_text())
                audit = audit_evaluation(report)  # Fresh real-artifact audit, never trust summary labels.
                if (audit['status'] != 'verified' or audit['programExecutionUnitCount'] != 1
                        or audit['physicalMicroarchitectureEquivalenceClaimed'] is not False
                        or any(r['claimScope'] != 'bounded-controlled-environment-intent' for r in audit['fragments'])):
                    raise ValueError('SYSTEM independent audit incomplete')
                bounded, = case['l3BoundedSystemResults']
                if bounded['summaryIdentity'] != identity({k:v for k,v in bounded.items() if k != 'summaryIdentity'}):
                    raise ValueError('SYSTEM bounded summary identity invalid')
                for key in ('policyIdentity', 'requirementManifestIdentity', 'programExecutionUnitCount'):
                    require_json_match(bounded[key], audit[key], 'SYSTEM bounded summary audit mismatch: ' + key)
                require_json_match([{'fragmentId':r['fragmentId'], 'status':r['status'],
                    'resultIdentity':r['evidenceIdentity'], 'claimScope':r['claimScope']}
                    for r in bounded['fragments']], audit['fragments'], 'SYSTEM bounded fragment summary mismatch')
                retained, = persisted['evaluations']
                require_json_match({k:v for k,v in retained.items() if k != 'caseId'}, audit,
                    'SYSTEM retained audit differs from fresh audit')
                records.append({'production': str(directory), 'evaluation': str(path),
                    'policyId': POLICY['policyId'], 'independentAudit': audit,
                    'coverageCounts': counts})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append({'production': str(directory), 'error': str(exc)})
    if not selected:
        errors.append({'error': 'no controlled SYSTEM v2 production runs found'})
    if expected_runs is not None and len(selected) != expected_runs:
        errors.append({'error': 'production run count mismatch', 'expected': expected_runs, 'actual': len(selected)})
    return {'schemaVersion': 'riscv2x86.system-l3-consistency-audit.v1',
            'productionRunCount': len(selected), 'evaluationCount': len(records),
            'records': records, 'errors': errors,
            'productionAcceptanceComplete': bool(records) and not errors,
            'physicalMicroarchitectureEquivalenceClaimed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expected-runs', type=int)
    args = parser.parse_args()
    if args.expected_runs is not None and args.expected_runs < 1:
        parser.error('--expected-runs must be positive')
    result = inspect(args.root, args.expected_runs)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['productionAcceptanceComplete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
