#!/usr/bin/env python3
"""Adapt frozen native input and invoke the ORIGINAL translation/evaluation path."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))
from riscv2x86_py import native_original_pipeline as route


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    prepare=sub.add_parser('prepare');prepare.add_argument('--bundle',required=True)
    translate=sub.add_parser('translate');translate.add_argument('--input',required=True)
    translate.add_argument('--ghidra-install-dir');translate.add_argument('--ghidra-language-id')
    audit=sub.add_parser('audit');audit.add_argument('--translation',required=True);audit.add_argument('--output',required=True)
    request=sub.add_parser('prepare-evaluation');request.add_argument('--translation',required=True)
    request.add_argument('--request',required=True,help='Existing explicit original EvaluationRequest contract')
    check=sub.add_parser('check');check.add_argument('--input',required=True)
    for item in (prepare,translate):
        item.add_argument('--output',required=True);item.add_argument('--timeout-seconds',type=int,default=600)
    request.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    try:
        if args.operation=='prepare':
            value=route.prepare(args.bundle,args.output,timeout=args.timeout_seconds)
        elif args.operation=='translate':
            value=route.translate(args.input,args.output,timeout=args.timeout_seconds,
                ghidra_install_dir=args.ghidra_install_dir,ghidra_language_id=args.ghidra_language_id)
        elif args.operation=='prepare-evaluation':
            route.evaluation_request(args.translation,args.request,args.output)
            print(json.dumps({'evaluationImplementation':'riscv2x86_py.evaluation_cli',
                'output':args.output,'semanticApproval':False}));return 0
        elif args.operation=='audit':
            value=route.audit(args.translation,args.output)
        else:
            value=route.d.read(args.input)
            checker={route.PREPARED:route.check_input,route.TRANSLATED:route.check_translation,
                     'riscv2x86.native-original-replay.v1':route.check_replay}
            value=checker[value['schemaVersion']](args.input)
        print(json.dumps({k:v for k,v in value.items() if k in (
            'schemaVersion','originalInputIdentity','originalTranslationIdentity',
            'expandedInstanceCount','attemptOutcomes','artifactDomain','translationImplementation','originalBackendReplayComplete',
            'semanticApproval','productionAcceptanceComplete')}))
        # Complete diagnostic processing is not complete translation.
        outcomes=value.get('attemptOutcomes')
        return 0 if outcomes is None or (outcomes and all(x in ('emitted','keep') for x in outcomes)) else 2
    except Exception as exc:
        result={'error':type(exc).__name__,'detail':str(exc),
                'semanticApproval':False,'productionAcceptanceComplete':False}
        if isinstance(exc,route.StageFailure):result.update(failedStage=exc.stage,returnCode=exc.code)
        print(json.dumps(result));return 2


if __name__=='__main__':raise SystemExit(main())
