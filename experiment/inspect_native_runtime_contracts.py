#!/usr/bin/env python3
"""Structured ELF providers and controlled link evidence, not L0--L3 acceptance."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py import native_external_providers as providers
from riscv2x86_py import native_link_evidence as links
from riscv2x86_py.project_acquisition import Runner


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    inventory=sub.add_parser('providers')
    for name in ('dependencies','runtime-basis','output'):inventory.add_argument('--'+name,required=True)
    summary=sub.add_parser('summary-providers');summary.add_argument('--input',required=True)
    requirements_replay=sub.add_parser('replay-requirements')
    requirements_replay.add_argument('--input',required=True);requirements_replay.add_argument('--output',required=True)
    requirements=sub.add_parser('requirements')
    requirements.add_argument('--input',required=True);requirements.add_argument('--output',required=True)
    for operation in ('reference-ledger', 'replay-reference-ledger'):
        p=sub.add_parser(operation);p.add_argument('--input',required=True);p.add_argument('--output',required=True)
    replay=sub.add_parser('replay-providers')
    for name in ('input','output'):replay.add_argument('--'+name,required=True)
    template=sub.add_parser('link-request')
    template.add_argument('--candidate',required=True);template.add_argument('--compiler',required=True)
    template.add_argument('--side',choices=('source','target'),required=True)
    template.add_argument('--mode',choices=('executable','shared'),default='executable')
    template.add_argument('--static',action='store_true')
    template.add_argument('--pie',choices=('yes','no','default'),default='default')
    template.add_argument('--input',action='append',default=[])
    template.add_argument('--abi-option',action='append',default=[])
    template.add_argument('--output',required=True)
    template.add_argument('--ordered-inputs', help='JSON ordered file/group plan; enables v2, preserves duplicates')
    template.add_argument('--positioned-inputs', help='JSON v3 file/group/candidate-slot deployment plan')
    for operation,argument in (('link','request'),('audit-link','input'),('attribute-link','input')):
        p=sub.add_parser(operation);p.add_argument('--'+argument,required=True)
        p.add_argument('--output',required=True);p.add_argument('--timeout-seconds',type=int,default=300)
    args=parser.parse_args(argv);runner=None
    try:
        if args.operation=='summary-providers':
            value=providers.read(args.input);providers.checked(value,'inventoryIdentity')
            if value['schemaVersion']!=providers.SCHEMA:raise ValueError('EXTERNAL_INVENTORY_SCHEMA_UNSUPPORTED')
            def compact(match):
                symbol=match['symbol']
                return {'path':match['providerPath'],'digest':match['providerDigest'],
                    'name':symbol['name'],'type':symbol['type'],'version':symbol['version'],
                    'specialContractRequired':match['specialContractRequired']}
            print(json.dumps({'inventoryIdentity':value['inventoryIdentity'],
                'candidateDefinitionCoverageComplete':value['candidateDefinitionCoverageComplete'],
                'obligations':[{'original':o['originalObligation'],
                    'definitionCandidates':[compact(m) for m in o['definitionCandidates']],
                    'targetNameCandidates':[compact(m) for m in o['targetNameCandidates']],
                    'pendingReasons':o['pendingReasons']} for o in value['externalObligations']],
                'blockerCount':len(value['blockers']),'actualLinkSelectionVerified':False,
                'semanticApproval':False,'productionAcceptanceComplete':False},ensure_ascii=False,indent=2));return 0
        if args.operation=='link-request':
            value=links.request(args.candidate,args.side,args.compiler,args.input,args.mode,args.static,
                {'yes':True,'no':False,'default':None}[args.pie],args.abi_option,
                ordered_inputs=None if args.ordered_inputs is None else providers.read(args.ordered_inputs),
                positioned_inputs=None if args.positioned_inputs is None else providers.read(args.positioned_inputs))
            with Path(args.output).open('x',encoding='utf-8') as stream:
                json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')
            print(json.dumps({'requestPath':args.output,'linkRequestIdentity':value['linkRequestIdentity'],
                'linkExecutionPerformed':False,'semanticApproval':False}));return 0
        if Path(args.output).absolute().parent==Path('/'):
            raise ValueError('NATIVE_RUNTIME_EXPERIMENT_PARENT_REQUIRED')
        runner=Runner(args.output,'native-runtime-'+args.operation)
        if args.operation=='providers':
            value=providers.acquire(args.dependencies,args.runtime_basis,runner.output)
        elif args.operation=='replay-providers':
            original=Path(args.input).resolve(strict=True)
            value=providers.replay(providers.read(original),original.parent,runner.output)
        elif args.operation=='replay-requirements':
            from riscv2x86_py.native_external_requirements import replay_requirements
            value=replay_requirements(providers.read(args.input),runner.output)
        elif args.operation=='requirements':
            from riscv2x86_py.native_external_requirements import acquire
            value=acquire(args.input,runner.output)
        elif args.operation=='reference-ledger':
            from riscv2x86_py.native_reference_ledger import acquire
            value=acquire(args.input,runner.output)
        elif args.operation=='replay-reference-ledger':
            from riscv2x86_py.native_reference_ledger import replay
            value=replay(providers.read(args.input),runner.output)
        elif args.operation=='link':
            value=links.build(providers.read(args.request),runner.output,args.timeout_seconds)
        elif args.operation=='attribute-link':
            from riscv2x86_py.native_link_attribution import acquire
            value=acquire(args.input,runner.output,args.timeout_seconds)
        else:
            original=Path(args.input).resolve(strict=True)
            value=links.audit(providers.read(original),original.parent,runner.output,args.timeout_seconds)
        path=runner.output/'result.json';path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
        runner.state.update(status='complete',currentStage='complete',resultPath=str(path),
            semanticApproval=False,productionAcceptanceComplete=False)
        if 'blockers' in value:runner.state['blockerCount']=len(value['blockers'])
        runner.save()
        keys=('parentObligationCount','referenceCount','referenceLedgerReplayComplete','candidateDefinitionCoverageComplete','replayedBlockerCount','linkBuildComplete',
              'requirementsReplayComplete','obligationCount','externalContractClosureComplete',
              'externalProviderReplayComplete','nativeLinkIndependentRebuildComplete',
              'candidateObjectExplicitInputVerified','candidateExportsPresent','candidateDefinitionAttributionVerified',
              'actualLinkSelectionVerified','typedCallContractVerified','translatedInstanceExecutionVerified')
        summary={k:value[k] for k in keys if k in value}
        if 'blockers' in value:summary['blockerCount']=len(value['blockers'])
        print(json.dumps({'resultPath':str(path),**summary,'semanticApproval':False,
                          'productionAcceptanceComplete':False}));return 0
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as exc:
        if runner is not None:runner.failure(args.operation,exc)
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False,
                          'productionAcceptanceComplete':False}),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
