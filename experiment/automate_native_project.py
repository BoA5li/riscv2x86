#!/usr/bin/env python3
"""One-command captured-project translation and ORIGINAL evaluation."""
import argparse
import json
from pathlib import Path
import shutil
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pytools'))
from riscv2x86_py import native_project_evaluation as project
from riscv2x86_py import native_original_evaluation as evaluation
from riscv2x86_py import native_project_campaign as campaign
from riscv2x86_py import native_project_diagnostic as diagnostic
from riscv2x86_py.verification_session import session
from riscv2x86_py import project_evidence_ledger as ledger


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    run = sub.add_parser('run')
    run.add_argument('--mode', choices=('formal', 'diagnostic'), default='formal')
    run.add_argument('--diagnostic-case-indices', help='comma-separated indices; diagnostic default is explicitly [0]')
    run.add_argument('--bundle', required=True)
    plan = run.add_mutually_exclusive_group(required=True)
    plan.add_argument('--target-plan'); plan.add_argument('--target-inputs')
    run.add_argument('--source-records', action='append', default=[])
    run.add_argument('--source-baseline-inputs'); run.add_argument('--source-entry-inputs')
    run.add_argument('--source-entry-action')
    run.add_argument('--qemu', default=shutil.which('qemu-riscv64'))
    run.add_argument('--runtime-prefix', required=True)
    cases = run.add_mutually_exclusive_group(required=True)
    cases.add_argument('--cases'); cases.add_argument('--gmp-seeds')
    run.add_argument('--repetitions', type=int, default=10)
    run.add_argument('--ghidra-install-dir'); run.add_argument('--timeout-seconds', type=int, default=600)
    run.add_argument('--stop-after', metavar='STAGE'); run.add_argument('--output', required=True); run.add_argument('--resume', action='store_true')
    resume = sub.add_parser('resume'); resume.add_argument('--output', required=True)
    formal = sub.add_parser('formal'); formal.add_argument('--output', required=True)
    build = sub.add_parser('build-side'); build.add_argument('--spec', required=True)
    build.add_argument('--side', choices=('source', 'target'), required=True)
    build.add_argument('--input', required=True); build.add_argument('--output', required=True)
    check = sub.add_parser('check'); check.add_argument('--input', required=True)
    timings = sub.add_parser('timings'); timings.add_argument('--input', required=True)
    evidence = sub.add_parser('ledger'); evidence.add_argument('--input', required=True)
    replan = sub.add_parser('replan')
    replan.add_argument('--configuration', required=True, help='historical plan used only as pinned configuration')
    replan.add_argument('--output', required=True)
    replan.add_argument('--stop-after', metavar='STAGE')
    for command in (run, resume, formal, build, check, timings, evidence, replan):
        command.add_argument('--profile-output', help='new diagnostic JSON file outside the evidence output directory')
        command.add_argument('--verification-cache-mib', type=int, default=256,
                             help='operation-local pure-derivation budget; 0 disables reuse')
    args = parser.parse_args(argv)
    if not 0 <= args.verification_cache_mib <= 1024:
        parser.error('--verification-cache-mib must be between 0 and 1024')
    profile = Path(args.profile_output).resolve() if args.profile_output else None
    if profile is not None:
        if profile.exists() or profile.is_symlink() or not profile.parent.is_dir():
            parser.error('--profile-output must name a new file in an existing directory')
        output = getattr(args, 'output', None)
        if output and profile.is_relative_to(Path(output).resolve()):
            parser.error('--profile-output must be outside the evidence output directory')
        if getattr(args, 'input', None) and profile.is_relative_to(Path(args.input).resolve().parent):
            parser.error('--profile-output must be outside the checked evidence directory')
    with session(args.verification_cache_mib * 1024 * 1024) as verification:
        result = execute(args)
    if profile is not None:
        try:
            with profile.open('x', encoding='utf-8') as stream:
                json.dump(verification.profile(), stream, indent=2)
                stream.write('\n')
        except Exception as exc:
            print(json.dumps({'error': 'PROFILE_PUBLICATION_FAILED', 'detail': str(exc)}), file=sys.stderr)
            return 2
    return result


def execute(args):
    try:
        if args.operation == 'replan':
            mode, plan, reference = campaign.replan_configuration(args.configuration)
            if mode == 'diagnostic':
                value = diagnostic.execute(plan, args.output, stop_after=args.stop_after)
                print(json.dumps({'configurationSource': reference, **diagnostic.facts(value)}))
                return 2 if value['status'] == 'failed' else 1
            value = campaign.execute(plan, args.output, stop_after=args.stop_after)
            print(json.dumps({'configurationSource': reference, **campaign.facts(value)}))
            return 0 if value['evaluationStatus'] == 'verified' else 1
        if args.operation == 'ledger':
            print(json.dumps(ledger.inspect(args.input))); return 0
        if args.operation == 'formal':
            value = diagnostic.continue_formal(args.output)
            print(json.dumps({'formalProgressPath': str(Path(args.output).resolve() / 'preparation/progress.json'), **campaign.facts(value)}))
            return 0 if value['evaluationStatus'] == 'verified' else 1
        if args.operation == 'timings':
            if project.d.read(args.input).get('schemaVersion') == diagnostic.PROGRESS:
                print(json.dumps(diagnostic.facts(diagnostic.check_progress(args.input)))); return 0
            print(json.dumps(campaign.timing_report(args.input))); return 0
        if args.operation == 'resume':
            if project.d.read(Path(args.output) / 'progress.json').get('schemaVersion') == diagnostic.PROGRESS:
                value = diagnostic.resume_campaign(args.output)
                print(json.dumps(diagnostic.facts(value)))
                return 2 if value['status'] == 'failed' else 1
            value = campaign.resume_campaign(args.output)
            print(json.dumps({'progressPath': str(Path(args.output).resolve() / 'progress.json'),
                              **campaign.facts(value)}))
            return 0 if value['evaluationStatus'] == 'verified' else 1
        if args.operation == 'check':
            if project.d.read(args.input).get('schemaVersion') == diagnostic.PROGRESS:
                print(json.dumps(diagnostic.facts(diagnostic.check_progress(args.input)))); return 0
            if project.d.read(args.input).get('schemaVersion') == campaign.PROGRESS:
                value = campaign.check_progress(args.input)
                print(json.dumps(campaign.facts(value))); return 0
            value = evaluation.check(args.input)
            print(json.dumps(value['facts'])); return 0
        if args.operation == 'build-side':
            value = project.build_side(args.spec, args.side, args.input, args.output)
            print(json.dumps(value)); return 0
        if not args.qemu: raise ValueError('PROJECT_QEMU_REQUIRED')
        records = list(args.source_records)
        if args.source_baseline_inputs:
            records += [r['path'] for r in project.d.read(args.source_baseline_inputs)['records']]
        if args.source_entry_inputs:
            records.append(project.d.read(args.source_entry_inputs)['recordsPath'])
        if not records: raise ValueError('PROJECT_SOURCE_BUILD_RECORDS_REQUIRED')
        plan = args.target_plan or project.d.read(args.target_inputs)['inspectedPlanPath']
        cases = (project.d.read(args.cases) if args.cases else
                 project.gmp_cases([int(s) for s in args.gmp_seeds.split(',')], args.repetitions))
        project.validate_cases(cases)
        frozen = campaign.make_plan(args.bundle, plan, records, qemu=args.qemu,
                    runtime_prefix=args.runtime_prefix, cases=cases,
                    source_entry_action=args.source_entry_action, ghidra_install_dir=args.ghidra_install_dir,
                    timeout=args.timeout_seconds)
        if args.mode == 'diagnostic':
            indices = None if args.diagnostic_case_indices is None else [int(v) for v in args.diagnostic_case_indices.split(',')]
            plan = diagnostic.make_plan(frozen, indices)
            value = diagnostic.execute(plan, args.output, resume=args.resume, stop_after=args.stop_after)
            print(json.dumps({'progressPath': str(Path(args.output).resolve() / 'progress.json'), **diagnostic.facts(value)}))
            return 2 if value['status'] == 'failed' else 1
        if args.diagnostic_case_indices is not None: raise ValueError('FORMAL_CASE_SELECTION_NOT_ALLOWED')
        value = campaign.execute(frozen, args.output, resume=args.resume, stop_after=args.stop_after)
        print(json.dumps({'progressPath': str(Path(args.output).resolve() / 'progress.json'),
                          **campaign.facts(value)}))
        return 0 if value['evaluationStatus'] == 'verified' else 1
    except Exception as exc:
        print(json.dumps({'error': type(exc).__name__, 'detail': str(exc),
                          'semanticApproval': False, 'productionAcceptanceComplete': False}))
        return 2


if __name__ == '__main__': raise SystemExit(main())
