#!/usr/bin/env python3
"""Inspect/execute checked native candidates with the ORIGINAL evaluator."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pytools'))
from riscv2x86_py import native_original_evaluation as evaluation
from riscv2x86_py import native_original_corpus as corpus


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    inspect = sub.add_parser('inspect'); inspect.add_argument('--run', required=True)
    inspect.add_argument('--request')
    run = sub.add_parser('evaluate'); run.add_argument('--run', required=True)
    run.add_argument('--request', required=True); run.add_argument('--output', required=True)
    check = sub.add_parser('check'); check.add_argument('--input', required=True)
    freeze = sub.add_parser('freeze-corpus'); freeze.add_argument('--input', required=True)
    freeze.add_argument('--output', required=True)
    batch = sub.add_parser('run-corpus'); batch.add_argument('--plan', required=True)
    batch.add_argument('--output', required=True); batch.add_argument('--max-seeds', type=int, default=1)
    batch.add_argument('--resume', action='store_true'); batch.add_argument('--retry-blocked', action='store_true')
    batch.add_argument('--ghidra-install-dir'); batch.add_argument('--timeout-seconds', type=int, default=600)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'inspect':
            value = evaluation.inspect(args.run, args.request)
            print(json.dumps(value)); return 0 if value['requestContractAvailable'] else 2
        if args.operation == 'evaluate':
            value = evaluation.acquire(args.run, args.request, args.output)
        elif args.operation == 'freeze-corpus':
            value = corpus.freeze(args.input, args.output)
        elif args.operation == 'run-corpus':
            value = corpus.execute(args.plan, args.output, max_seeds=args.max_seeds,
                                   resume=args.resume, retry_blocked=args.retry_blocked,
                                   ghidra_install_dir=args.ghidra_install_dir, timeout=args.timeout_seconds)
        else:
            schema = evaluation.d.read(args.input)['schemaVersion']
            value = {evaluation.SCHEMA: evaluation.check, corpus.PLAN: corpus.check_plan,
                     corpus.RESULT: corpus.check_progress}[schema](args.input)
        output = {k: value[k] for k in ('schemaVersion', 'facts', 'plannedSeedCount', 'statusCounts', 'attemptOutcomeCounts',
                  'allSeedsProcessed', 'originalEvaluationInvoked', 'semanticApproval',
                  'productionAcceptanceComplete') if k in value}
        print(json.dumps(output))
        # A check's exit status means record integrity, not semantic acceptance.
        if args.operation == 'evaluate': return 0 if value['facts']['evaluationStatus'] == 'verified' else 1
        if args.operation == 'run-corpus':
            return 0 if value['allSeedsProcessed'] and set(value['statusCounts']) == {'evaluation_verified'} else 1
        return 0
    except Exception as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc),
                          'semanticApproval': False, 'productionAcceptanceComplete': False}))
        return 2


if __name__ == '__main__': raise SystemExit(main())
