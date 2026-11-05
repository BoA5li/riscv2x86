#!/usr/bin/env python3
"""Source-bound qualification and native CPP evidence; not translation approval."""
from pathlib import Path
import argparse
import json
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'pytools'))

from riscv2x86_py.project_activation_batches import write_new
from riscv2x86_py.project_instance_eligibility import acquire as eligibility, validate
from riscv2x86_py.project_native_macro_preflight import acquire, replay
from riscv2x86_py.project_acquisition import StageFailure
from riscv2x86_py.gnu_operand_relations import derive


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    ledger=sub.add_parser('eligibility')
    for name in ('plan','result-root','ledger','output'):ledger.add_argument('--'+name,required=True)
    verify=sub.add_parser('verify-eligibility');verify.add_argument('--input',required=True)
    capture=sub.add_parser('capture')
    for name in ('eligibility','context-identity','output'):capture.add_argument('--'+name,required=True)
    capture.add_argument('--timeout-seconds',type=int,default=120)
    capture.add_argument('--mode',choices=('exact','native-input'),default='exact')
    audit=sub.add_parser('replay')
    for name in ('eligibility','receipt','output'):audit.add_argument('--'+name,required=True)
    audit.add_argument('--timeout-seconds',type=int,default=120)
    bind=sub.add_parser('bind-native')
    for name in ('native-input-receipt','frontend','output'):bind.add_argument('--'+name,required=True)
    bind.add_argument('--timeout-seconds',type=int,default=300)
    repeat=sub.add_parser('replay-bindings')
    for name in ('bundle','output'):repeat.add_argument('--'+name,required=True)
    repeat.add_argument('--timeout-seconds',type=int,default=300)
    inspect=sub.add_parser('inspect-bindings')
    inspect.add_argument('--bundle',required=True);inspect.add_argument('--limit',type=int,default=12)
    inspect.add_argument('--include-context',action='store_true')
    basis=sub.add_parser('build-basis')
    for name in ('bundle','records','output'):basis.add_argument('--'+name,required=True)
    relation=sub.add_parser('relations')
    relation.add_argument('--constraints',required=True);relation.add_argument('--output',required=True)
    args=parser.parse_args(argv)
    def read(p):return json.loads(Path(p).read_text())
    try:
        if args.operation=='eligibility':
            result=eligibility(args.plan,args.result_root,args.ledger);write_new(args.output,result)
            print(json.dumps({k:result[k] for k in ('occurrenceCount','definitionSliceCount','statusCounts',
                'firstBlockerCounts','recordedInspectionAstCoverageComplete','semanticApproval','productionAcceptanceComplete')}))
        elif args.operation=='verify-eligibility':
            value=validate(read(args.input));print(json.dumps({'eligibilityReplayComplete':True,
                'occurrenceCount':value['occurrenceCount'],'semanticApproval':False,'productionAcceptanceComplete':False}))
        elif args.operation=='capture':
            result=acquire(read(args.eligibility),args.context_identity,args.output,args.timeout_seconds,mode=args.mode)
            keys=('contextIdentity','sourcePreprocessingMatched','nativePreprocessingComplete','firstDifference',
                'nativeInputConsumed','inspectionParsingComplete','originalDiscoveryRebound',
                'semanticApproval','productionAcceptanceComplete')
            print(json.dumps({k:result[k] for k in keys if k in result}))
        elif args.operation=='replay':
            print(json.dumps(replay(read(args.receipt),read(args.eligibility),args.output,args.timeout_seconds)))
        elif args.operation=='bind-native':
            from riscv2x86_py.project_native_binding import acquire as bind_input
            result=bind_input(args.native_input_receipt,args.frontend,args.output,timeout=args.timeout_seconds)
            print(json.dumps({k:result[k] for k in ('analysisInputIdentity','occurrenceCount',
                'derivedInputInstanceBindingComplete','originalSourceInstanceBindingComplete',
                'editAuthorizationComplete','semanticApproval','productionAcceptanceComplete')}))
        elif args.operation=='replay-bindings':
            from riscv2x86_py.project_native_binding import replay as replay_binding
            print(json.dumps(replay_binding(read(args.bundle),args.output,timeout=args.timeout_seconds)))
        elif args.operation=='inspect-bindings':
            from riscv2x86_py.project_native_binding import validate_artifacts
            if args.limit<1:raise ValueError('NATIVE_BINDING_POSITIVE_LIMIT_REQUIRED')
            value=read(args.bundle);bindings,contexts=validate_artifacts(value)
            print(json.dumps({'occurrenceCount':bindings['occurrenceCount'],
                'functionCount':len(contexts['functions']),
                'asmOwningFunctionCount':len(contexts['asmOwningFunctionContexts']),
                'freshIndependentReplayPerformed':False,'semanticApproval':False,
                'productionAcceptanceComplete':False}))
            for row in bindings['records'][:args.limit]:
                detail={'instanceBindingIdentity':row['instanceBindingIdentity'],
                    'functionAstPath':row['functionAstPath'],'physicalAstRange':row['physicalAstRange'],
                    'asmText':row['frontendFragment']['rawAsmText'],
                    'operands':row['operands'],'constraintRelation':row['constraintRelation'],
                    'ancestry':row['ancestry'],'typedOperandContractsComplete':row['typedOperandContractsComplete'],
                    'blockers':row['blockers']}
                if args.include_context:detail['enclosingCompound']=row['enclosingCompound']
                print(json.dumps(detail,ensure_ascii=False))
            roots={r['functionContextIdentity']:r for r in contexts['asmOwningFunctionContexts']}
            selected=[f for f in contexts['functions'] if f['functionContextIdentity'] in roots]
            for function in selected[:args.limit]:
                print(json.dumps({'function':function,'entryAssessment':roots[function['functionContextIdentity']]},ensure_ascii=False))
            print(json.dumps({'printedInstances':min(args.limit,len(bindings['records'])),
                'printedAsmOwningFunctions':min(args.limit,len(selected)),
                'fullEvidenceRetained':True}))
        elif args.operation=='build-basis':
            from riscv2x86_py.project_native_binding import build_basis
            if Path(args.output).absolute().parent==Path('/'):
                raise ValueError('NATIVE_BINDING_RESULT_PARENT_REQUIRED')
            result=build_basis(read(args.bundle),args.records);write_new(args.output,result)
            print(json.dumps({k:result[k] for k in ('actionCounts','observedSuccessfulActions',
                'selectedNativeCompileActionPresent','formalEvaluationEntrySelected',
                'legalInputObjectDomainProvided','buildLinkClosureVerified',
                'semanticApproval','productionAcceptanceComplete')}))
            print(json.dumps({'unresolvedBuildRecordCount':len(result['unresolvedBuildRecords']),
                'linkAndArchiveActionCount':len(result['linkAndArchiveActions'])}))
            for action in result['linkAndArchiveActions'][:12]:
                print(json.dumps({'actionIdentity':action['actionIdentity'],'directory':action['directory'],
                    'kind':action['kind'],'exitStatusObserved':action['exitStatusObserved'],
                    'observedReturnCode':action.get('observedReturnCode'),
                    'argumentCount':len(action['arguments']),'argumentPrefix':action['arguments'][:20]}))
        else:
            value=read(args.constraints)
            if set(value)!={'outputs','inputs'}:raise ValueError('GNU_RELATION_FIELDS_INVALID')
            result=derive(value['outputs'],value['inputs']);write_new(args.output,result);print(json.dumps(result))
        return 0
    except StageFailure as exc:return exc.code if exc.code>=0 else 128-exc.code
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':type(exc).__name__,'detail':str(exc),'semanticApproval':False}),file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
