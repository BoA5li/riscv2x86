#!/usr/bin/env python3
"""Source dependency and backend evidence only; does not build or grant acceptance."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py import native_dependency_inventory as dependencies
from riscv2x86_py import native_backend_inventory as backends
from riscv2x86_py.project_acquisition import Runner


def summarize(result):
    replay = (result.get('staticBackendInventoryReplayComplete') is True
              or result.get('dependencyInventoryReplayComplete') is True)
    if replay:
        count = result.get('replayedBlockerCount')
        if type(count) is not int or count < 0:
            raise ValueError('INVENTORY_REPLAY_BLOCKER_COUNT_REQUIRED')
    else:
        if not isinstance(result.get('blockers'), list):
            raise ValueError('INVENTORY_BLOCKER_LIST_REQUIRED')
        count = len(result['blockers'])
    summary = {'operationComplete':True, 'inventoryComplete':not replay,
               'replayComplete':replay, 'blockerCount':count,
               'status':'blocked' if count else 'inventory-only',
               'semanticApproval':False, 'productionAcceptanceComplete':False}
    if replay:
        summary['replayedInventoryIdentity'] = result['replayedInventoryIdentity']
    if 'diagnosticSummary' in result:
        summary['affectedPathCount'] = result['diagnosticSummary']['affectedPathCount']
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation',required=True)
    inventory = sub.add_parser('inventory')
    for name in ('candidate','records','archive','output'):
        inventory.add_argument('--'+name,required=True)
    backend = sub.add_parser('backends')
    backend.add_argument('--paths-file',required=True); backend.add_argument('--output',required=True)
    for operation in ('replay','replay-backends'):
        p = sub.add_parser(operation); p.add_argument('--input',required=True); p.add_argument('--output',required=True)
    args = parser.parse_args(argv)
    if Path(args.output).absolute().parent == Path('/'):
        parser.error('an existing experiment parent directory is required')
    runner = Runner(args.output, 'native-'+args.operation)
    try:
        if args.operation == 'inventory':
            result = dependencies.acquire(args.candidate,args.records,args.archive)
        elif args.operation == 'backends':
            result = backends.inspect([p for p in Path(args.paths_file).read_text().splitlines() if p.strip()])
        elif args.operation == 'replay':result = dependencies.replay(dependencies.read(args.input))
        else:result = backends.replay(dependencies.read(args.input))
        summary = summarize(result)
        artifact = runner.output/'result.json'
        artifact.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        runner.state.update(status='complete', currentStage='complete',
            inventoryStatus=summary['status'],
            **{key:value for key,value in summary.items() if key != 'status'})
        runner.save()
        print(json.dumps({'resultPath':str(artifact), **summary}))
        return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        runner.state.update(status='failed',primaryFailure={'type':type(exc).__name__,'detail':str(exc)},
            semanticApproval=False,productionAcceptanceComplete=False)
        runner.save(); print(json.dumps(runner.state['primaryFailure']),file=sys.stderr); return 2


if __name__ == '__main__':raise SystemExit(main())
