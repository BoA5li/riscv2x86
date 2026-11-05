"""Capture real native/inspection preprocessing without authorizing edits.

The capsule preserves full expanded C and definition output for subsequent
compiler provenance work. It is not a macro argument graph, target adaptation,
native instruction attribution or an executable translation candidate.
"""
from pathlib import Path
import json
import subprocess

from .c_preprocessing_tokens import tokens, VERSION
from .compiler_call_dependencies import parse_dependencies, _snapshot, validate as validate_dependencies
from .project_build_contract import source_arguments
from .project_build_records import identity
from .project_compile_context import validate as validate_context, digest
from .project_instance_eligibility import validate as validate_eligibility
from .project_acquisition import Runner, StageFailure


def acquire(eligibility,context_identity,output,timeout=120):
    if type(timeout) is not int or timeout<1:raise ValueError('MACRO_PREFLIGHT_TIMEOUT_INVALID')
    runner=Runner(output,'native-macro-preflight')
    runner.state.update(nativePreprocessingComplete=False,sourcePreprocessingMatched=False,
        nativeCompilerActivationConfirmed=False,sourceInstanceBindingComplete=False,
        editAuthorizationComplete=False,endToEndEligibilityAssessed=False)
    runner.save()
    try:
        runner.state['currentStage']='eligibility-replay';runner.save()
        validate_eligibility(eligibility)
        runner.state['currentStage']='context-binding';runner.save()
        selected=[r for r in eligibility['records'] if r['contextIdentity']==context_identity]
        if not selected:raise ValueError('MACRO_PREFLIGHT_CONTEXT_NOT_IN_DISCOVERY')
        reports={r['inspectionReportPath']:r['inspectionReportDigest'] for r in selected}
        if len(reports)!=1:raise ValueError('MACRO_PREFLIGHT_CONTEXT_REPORT_AMBIGUOUS')
        report_path,report_digest=next(iter(reports.items()))
        if digest(report_path)!=report_digest:raise ValueError('MACRO_PREFLIGHT_REPORT_CHANGED')
        report=json.loads(Path(report_path).read_text())
        rows=[r for r in report['records'] if r['context']['contextIdentity']==context_identity]
        if len(rows)!=1:raise ValueError('MACRO_PREFLIGHT_CONTEXT_AMBIGUOUS')
        row=rows[0];context=row['context'];snapshot=row['inspection']['snapshot'];manifest=snapshot['dependencyManifest']
        validate_context(context);validate_dependencies(manifest)
        original=manifest['compilerCommand']
        source=context['sourcePath'];cwd=Path(context['workingDirectory'])
        if original[-4:]!=['-fsyntax-only','-Xclang','-ast-dump=json',source]:
            raise ValueError('MACRO_PREFLIGHT_INSPECTION_RECIPE_INVALID')
        native=[context['nativeCompiler'],*source_arguments(context)]
        inspection=original[:-4]
        before_tools={str(p):digest(p) for p in (context['nativeCompiler'],original[0])}
        commands=[]
        def run(stage,base,options):
            command=[*base,*options,source];runner.state['currentStage']=stage;runner.save()
            result=subprocess.run(command,cwd=cwd,capture_output=True,timeout=timeout,check=False)
            stdout=runner.output/(stage+'.stdout');stderr=runner.output/(stage+'.stderr')
            with stdout.open('xb') as stream:stream.write(result.stdout)
            with stderr.open('xb') as stream:stream.write(result.stderr)
            entry={'stage':stage,'command':command,'directory':str(cwd),
                'returnCode':result.returncode,'stdoutPath':str(stdout),'stdoutDigest':digest(stdout),
                'stderrPath':str(stderr),'stderrDigest':digest(stderr)}
            commands.append(entry);runner.state['commands']=commands;runner.save()
            if result.returncode:
                runner.state.update(status='failed',primaryFailure={'stage':stage,'returnCode':result.returncode,
                    'stderrPath':str(stderr)})
                runner.save();raise StageFailure(stage,result.returncode)
            return result.stdout.decode('utf-8')
        native_deps=parse_dependencies(run('native-dependencies-before',native,['-M','-MT','rv2x86_call_inventory']))
        native_snapshot=_snapshot(native_deps,cwd)
        native_text=run('native-expanded',native,['-E','-P'])
        inspection_text=run('inspection-expanded',inspection,['-E','-P'])
        # Definitions/line directives are preserved as raw compiler evidence,
        # not parsed with regex into a purported complete macro expansion graph.
        run('native-definitions',native,['-E','-dD'])
        run('native-macros',native,['-E','-dM'])
        after=parse_dependencies(run('native-dependencies-after',native,['-M','-MT','rv2x86_call_inventory']))
        if after!=native_deps or identity(native_snapshot)!=identity(_snapshot(after,cwd)):
            raise ValueError('MACRO_PREFLIGHT_NATIVE_DEPENDENCIES_CHANGED')
        validate_context(context);validate_dependencies(manifest)
        if digest(report_path)!=report_digest or any(digest(p)!=h for p,h in before_tools.items()):
            raise ValueError('MACRO_PREFLIGHT_INPUT_CHANGED')
        a=tokens(native_text);b=tokens(inspection_text)
        count=min(len(a),len(b));first=next((i for i in range(count) if a[i]!=b[i]),count)
        body={'schemaVersion':'riscv2x86.native-macro-preflight.v1',
            'eligibilityInventoryIdentity':eligibility['eligibilityInventoryIdentity'],
            'contextIdentity':context_identity,'inspectionReportPath':report_path,'inspectionReportDigest':report_digest,
            'sourcePath':source,'sourceDigest':context['sourceDigest'],'nativeCompiler':context['nativeCompiler'],
            'nativeCompilerDigest':before_tools[context['nativeCompiler']],
            'inspectionCompiler':original[0],'inspectionCompilerDigest':before_tools[original[0]],
            'dependencyIdentity':manifest['dependencyIdentity'],'nativeDependencies':native_snapshot,
            'commands':commands,'tokenizationVersion':VERSION,
            'tokenCounts':{'native':len(a),'inspection':len(b)},
            'tokenIdentities':{'native':identity(a),'inspection':identity(b)},
            'sourcePreprocessingMatched':a==b,'nativePreprocessingComplete':True,
            'firstDifference':None if a==b else {'index':first,'native':a[max(0,first-4):first+5],
                                               'inspection':b[max(0,first-4):first+5]},
            'nativeCompilerActivationConfirmed':False,'macroArgumentGraphComplete':False,
            'compilerEquivalenceVerified':False,
            'sourceInstanceBindingComplete':False,'editAuthorizationComplete':False,
            'endToEndEligibilityAssessed':False,'semanticApproval':False,'productionAcceptanceComplete':False}
        result=dict(body,preflightIdentity=identity(body))
        with (runner.output/'preflight.json').open('x') as stream:json.dump(result,stream,indent=2)
        if a!=b:
            runner.state.update(nativePreprocessingComplete=True)
            raise ValueError('MACRO_PREFLIGHT_SOURCE_PREPROCESSING_MISMATCH')
        runner.state.update(status='complete',currentStage='complete',acquisitionComplete=True,
            nativePreprocessingComplete=True,sourcePreprocessingMatched=True,
            preflightPath=str(runner.output/'preflight.json'),preflightDigest=digest(runner.output/'preflight.json'))
        runner.save();return result
    except StageFailure:
        raise
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,subprocess.SubprocessError) as exc:
        runner.failure(runner.state['currentStage'],exc)
        raise


def replay(value,eligibility,output,timeout=120):
    if (not isinstance(value,dict) or value.get('schemaVersion')!='riscv2x86.native-macro-preflight.v1'
            or value.get('preflightIdentity')!=identity({k:v for k,v in value.items() if k!='preflightIdentity'})):
        raise ValueError('MACRO_PREFLIGHT_IDENTITY_INVALID')
    for command in value['commands']:
        for path,expected in [('stdoutPath','stdoutDigest'),('stderrPath','stderrDigest')]:
            if digest(command[path])!=command[expected]:raise ValueError('MACRO_PREFLIGHT_ARTIFACT_CHANGED')
    fresh=acquire(eligibility,value['contextIdentity'],output,timeout)
    # Artifact paths change in an independent run; bytes, commands, bindings,
    # match results and all claim flags must remain exact.
    def projection(receipt):
        result={k:v for k,v in receipt.items() if k not in {'preflightIdentity','commands'}}
        result['commands']=[{k:v for k,v in c.items() if k not in {'stdoutPath','stderrPath'}} for c in receipt['commands']]
        return result
    if identity(projection(value))!=identity(projection(fresh)):
        raise ValueError('MACRO_PREFLIGHT_INDEPENDENT_REPLAY_MISMATCH')
    body={'schemaVersion':'riscv2x86.native-macro-preflight-replay.v1',
        'contextIdentity':value['contextIdentity'],
        'eligibilityInventoryIdentity':eligibility['eligibilityInventoryIdentity'],
        'originalPreflightIdentity':value['preflightIdentity'],'freshPreflightIdentity':fresh['preflightIdentity'],
        'nativePreprocessingReplayComplete':True,'sourcePreprocessingMatched':fresh['sourcePreprocessingMatched'],
        'sourceInstanceBindingComplete':False,'editAuthorizationComplete':False,
        'semanticApproval':False,'productionAcceptanceComplete':False}
    return dict(body,replayIdentity=identity(body))
