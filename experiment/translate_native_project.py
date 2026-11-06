#!/usr/bin/env python3
"""Generate/audit a proof-bound native-input integer candidate, not L0--L3 acceptance."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py.native_project_translation import acquire, audit
from riscv2x86_py.project_acquisition import StageFailure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    create = sub.add_parser('create')
    for name in ('bundle', 'target-compiler', 'output'):
        create.add_argument('--'+name, required=True)
    replay = sub.add_parser('audit')
    for name in ('candidate', 'output'):
        replay.add_argument('--'+name, required=True)
    entry = sub.add_parser('entry-metadata')
    for name in ('records', 'action-identity', 'output'):
        entry.add_argument('--'+name, required=True)
    entry_replay = sub.add_parser('replay-entry-metadata')
    entry_replay.add_argument('--input', required=True)
    for item in (create, replay):
        item.add_argument('--timeout-seconds', type=int, default=300)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'create':
            result = acquire(args.bundle, args.target_compiler, args.output, timeout=args.timeout_seconds)
            print(json.dumps({k: result[k] for k in ('candidatePath', 'candidateIdentity',
                'allBoundAsmOccurrencesTranslated', 'derivedTargetMaterializationComplete',
                'localIntegerProofComplete', 'objectBuildsComplete', 'wholeFunctionCompositionVerified',
                'requiredWork', 'semanticApproval', 'productionAcceptanceComplete')}))
        elif args.operation == 'audit':
            value = json.loads(Path(args.candidate).read_text())
            result = audit(value, args.output, timeout=args.timeout_seconds)
            print(json.dumps(result))
        elif args.operation == 'entry-metadata':
            from riscv2x86_py.native_test_entry import acquire as inspect_entry
            if Path(args.output).absolute().parent == Path('/'):
                raise ValueError('NATIVE_TRANSLATION_RESULT_PARENT_REQUIRED')
            result = inspect_entry(args.records, args.action_identity)
            with Path(args.output).open('x') as stream:
                json.dump(result, stream, indent=2)
            print(json.dumps(result))
        else:
            from riscv2x86_py.native_test_entry import replay as replay_entry
            print(json.dumps(replay_entry(json.loads(Path(args.input).read_text()))))
        return 0
    except StageFailure as exc:
        print(json.dumps({'failedStage': exc.stage, 'returnCode': exc.code,
            'productionAcceptanceComplete': False}), file=sys.stderr)
        return exc.code if exc.code > 0 else 128-exc.code
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc),
            'semanticApproval': False, 'productionAcceptanceComplete': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
