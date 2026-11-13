"""Statement reachability in an explicitly instrumented candidate variant.

Two counters bracket each audited pure integer replacement. No function-entry,
source line, symbol name or empty trace is accepted as instance coverage. This
is instrumented statement evidence, not canonical instruction coverage or an
assertion that instrumentation preserves microarchitectural behavior.
"""
import json
from pathlib import Path
import re
from . import native_captured_deployment as d
from . import native_api_experiment as experiment
from . import native_api_contract as api
from .project_build_records import identity
from .native_external_providers import checked
from .native_dependency_evidence import bytes_digest
from .native_elf_runtime import parse

SCHEMA='riscv2x86.native-statement-probe.v1'


def materialize(candidate,raw):
    if bytes_digest(raw)!=candidate['candidateDigest']:raise ValueError('STATEMENT_PROBE_CANDIDATE_CHANGED')
    edits=candidate['edits']
    if not isinstance(edits,list) or not 1<=len(edits)<=1024:raise ValueError('STATEMENT_PROBE_INSTANCE_BUDGET_INVALID')
    symbol='__rv2x86_probe_'+identity({'candidate':candidate['candidateIdentity']})[7:31]
    # A real AST declaration collision is rejected by the caller as well; this
    # token guard prevents collision even in an isolated materializer invocation.
    if re.search(rb'\b'+symbol.encode()+rb'\b',raw):raise ValueError('STATEMENT_PROBE_SYMBOL_COLLISION')
    replacements=[];delta=0;previous=-1;seen=set();instances=[]
    for index,edit in enumerate(edits):
        if edit['proofScope']!='local-statement-under-unchanged-C-context':raise ValueError('STATEMENT_PROBE_LOCAL_STATEMENT_REQUIRED')
        start,stop=edit['sourceRange'];instance=edit['instanceBindingIdentity']
        if (type(start) is not int or type(stop) is not int or start<previous or stop<=start or instance in seen):
            raise ValueError('STATEMENT_PROBE_EDIT_ORDER_OR_ID_INVALID')
        seen.add(instance);previous=stop
        original=edit['replacement'].encode();left=start+delta;right=left+len(original)
        if left<0 or raw[left:right]!=original:raise ValueError('STATEMENT_PROBE_REPLACEMENT_BYTES_MISMATCH')
        wrapped=(f'do {{ {symbol}({2*index}); '+edit['replacement']+f' {symbol}({2*index+1}); }} while (0);').encode()
        replacements.append((left,right,wrapped));delta+=len(original)-(stop-start)
        instances.append({'index':index,'instanceBindingIdentity':instance,'candidateRange':[left,right],
                          'replacementDigest':bytes_digest(original)})
    output=raw
    for left,right,replacement in reversed(replacements):output=output[:left]+replacement+output[right:]
    output=(f'extern void {symbol}(unsigned long) __attribute__((visibility("hidden")));\n').encode()+output
    nonce=identity({'candidate':candidate['candidateIdentity'],'instances':instances})[7:31]
    observer=('extern int fprintf(void *, const char *, ...);\nextern void *stderr;\n'
        f'static unsigned long count[{len(edits)*2}];\n'
        f'__attribute__((visibility("hidden"))) void {symbol}(unsigned long i) {{ '
        f'if(i<{len(edits)*2}) __atomic_fetch_add(&count[i],1UL,__ATOMIC_RELAXED); }}\n'
        '__attribute__((destructor)) static void report(void) {\n'
        f'for(unsigned long i=0;i<{len(edits)};i++) fprintf(stderr,"r2x-probe:{nonce}:%lu:%lu:%lu\\n",i,__atomic_load_n(&count[2*i],__ATOMIC_RELAXED),__atomic_load_n(&count[2*i+1],__ATOMIC_RELAXED));\n}}\n')
    # Use the real stdio declarations rather than relying on pointer ABI guesses.
    observer=observer[observer.index('static unsigned long'):]
    observer='#include <stdio.h>\n'+observer
    return output,observer,{'symbol':symbol,'nonce':nonce,'instances':instances}


def counts(raw,metadata):
    prefix=('r2x-probe:'+metadata['nonce']+':').encode();rows={}
    for line in raw.splitlines():
        if not line.startswith(prefix):continue
        fields=line[len(prefix):].split(b':')
        if len(fields)!=3 or any(not x.isdigit() or len(x)>20 for x in fields):raise ValueError('STATEMENT_PROBE_EVENT_INVALID')
        index,begin,end=map(int,fields)
        if index in rows or not 0<=index<len(metadata['instances']) or end>begin or begin>2**64-1:
            raise ValueError('STATEMENT_PROBE_EVENT_LEDGER_INVALID')
        rows[index]={'entered':begin,'completed':end}
    return [{**item,**rows.get(item['index'],{'entered':None,'completed':None}),
        'instrumentedStatementCompleted':item['index'] in rows and rows[item['index']]['completed']>0
            and rows[item['index']]['entered']==rows[item['index']]['completed']}
            for item in metadata['instances']]


def acquire(api_path,output,*,timeout=300):
    from .native_deployment_prerequisites import output_path
    tested=experiment.check(api_path)
    if tested['processObservationStatus']!='verified':raise ValueError('STATEMENT_PROBE_COMPLETED_API_EXPERIMENT_REQUIRED')
    parent=d.read(Path(api_path).resolve().parent/'inputs.json')
    report,deployed,plan,candidate,receipt,source=experiment.context(parent['contracts']['path'])
    unit,observer,metadata=materialize(candidate,Path(candidate['candidatePath']).read_bytes())
    root=output_path(output);root.mkdir();(root/'candidate.i').write_bytes(unit);(root/'observer.c').write_text(observer)
    inputs=d.seal({'schemaVersion':'riscv2x86.native-statement-probe-inputs.v1','apiExperiment':d.snapshot(api_path),
        'timeoutSeconds':timeout},'statementProbeInputsIdentity')
    (root/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    cc=candidate['targetCompiler'];env=plan['environment']
    execute=lambda name,argv,cwd=root:experiment.execute(argv,cwd,env,root,name,timeout)
    execute('compile-candidate',[cc,*candidate['targetFlags'],'-Werror','-x','cpp-output','-c',str(root/'candidate.i'),'-o',str(root/'candidate.o')],receipt['context']['workingDirectory'])
    execute('compile-observer',[cc,'-std=gnu11','-fPIC','-Werror','-c',str(root/'observer.c'),'-o',str(root/'observer.o')])
    libdir=root/'lib';libdir.mkdir();library=libdir/Path(plan['library']['originalOutput']['path']).name
    argv=d._argv(plan['library'],library,{plan['originalObject']['argumentIndex']:root/'candidate.o'})
    argv.append(str(root/'observer.o'));execute('compile-library',argv,plan['library']['directory'])
    elf=parse(library.read_bytes())
    if elf['machine']!=62 or elf['soname']!=plan['soname']:raise ValueError('STATEMENT_PROBE_LIBRARY_PROFILE_CHANGED')
    alias=libdir/elf['soname']
    if alias!=library:alias.symlink_to(library.name)
    (root/'harness.c').write_bytes((Path(api_path).parent/'harness.c').read_bytes())
    execute('compile-driver',[cc,'-std=gnu11','-Werror',str(root/'harness.c'),str(library),'-Wl,-rpath,$ORIGIN/lib','-o',str(root/'program')])
    execute('run',[str(root/'program')])
    (root/'artifacts.json').write_text(json.dumps([d.snapshot(root/n) for n in
        ('candidate.i','observer.c','candidate.o','observer.o','harness.c','program')]+[d.snapshot(library)],indent=2)+'\n')
    result=derive(root);(root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    check(root/'result.json');return result


def derive(root):
    root=Path(root).resolve();inputs=d.read(root/'inputs.json');checked(inputs,'statementProbeInputsIdentity')
    api.fields(inputs,('schemaVersion','apiExperiment','timeoutSeconds','statementProbeInputsIdentity'),'STATEMENT_PROBE_INPUTS')
    if inputs['schemaVersion']!='riscv2x86.native-statement-probe-inputs.v1' or type(inputs['timeoutSeconds']) is not int or not 1<=inputs['timeoutSeconds']<=86400:
        raise ValueError('STATEMENT_PROBE_INPUTS_INVALID')
    d.verify_snapshot(inputs['apiExperiment']);tested=experiment.check(inputs['apiExperiment']['path'])
    if tested['processObservationStatus']!='verified':raise ValueError('STATEMENT_PROBE_COMPLETED_API_EXPERIMENT_REQUIRED')
    parent=d.read(Path(inputs['apiExperiment']['path']).parent/'inputs.json')
    report,deployed,plan,candidate,receipt,source=experiment.context(parent['contracts']['path'])
    unit,observer,metadata=materialize(candidate,Path(candidate['candidatePath']).read_bytes())
    if (root/'candidate.i').read_bytes()!=unit or (root/'observer.c').read_text()!=observer:
        raise ValueError('STATEMENT_PROBE_MATERIALIZATION_CHANGED')
    artifacts=d.read(root/'artifacts.json')
    library=root/'lib'/Path(plan['library']['originalOutput']['path']).name
    expected_paths={str(root/n) for n in ('candidate.i','observer.c','candidate.o','observer.o','harness.c','program')}|{str(library)}
    if len(artifacts)!=len(expected_paths) or {a['path'] for a in artifacts}!=expected_paths:raise ValueError('STATEMENT_PROBE_ARTIFACT_SET_INVALID')
    for snap in artifacts:d.verify_snapshot(snap)
    if (root/'harness.c').read_bytes()!=(Path(inputs['apiExperiment']['path']).parent/'harness.c').read_bytes():
        raise ValueError('STATEMENT_PROBE_HARNESS_BINDING_CHANGED')
    cc=candidate['targetCompiler'];env=plan['environment']
    argv=d._argv(plan['library'],library,{plan['originalObject']['argumentIndex']:root/'candidate.o'})+[str(root/'observer.o')]
    expected={
      'compile-candidate':([cc,*candidate['targetFlags'],'-Werror','-x','cpp-output','-c',str(root/'candidate.i'),'-o',str(root/'candidate.o')],receipt['context']['workingDirectory']),
      'compile-observer':([cc,'-std=gnu11','-fPIC','-Werror','-c',str(root/'observer.c'),'-o',str(root/'observer.o')],str(root)),
      'compile-library':(argv,plan['library']['directory']),
      'compile-driver':([cc,'-std=gnu11','-Werror',str(root/'harness.c'),str(library),'-Wl,-rpath,$ORIGIN/lib','-o',str(root/'program')],str(root)),
      'run':([str(root/'program')],str(root))}
    executions={}
    for name,(args,cwd) in expected.items():
        row=d.read(root/name/'execution.json');checked(row,'apiExecutionIdentity')
        api.fields(row,('arguments','directory','environment','returnCode','failureReason','stage','timeoutSeconds',
                        'maxLogBytes','stdout','stderr','apiExecutionIdentity'),'STATEMENT_PROBE_EXECUTION')
        if (type(row['returnCode']) is not int or row['timeoutSeconds']!=inputs['timeoutSeconds'] or row['maxLogBytes']!=16*1024*1024
                or row['arguments']!=args or row['directory']!=cwd or row['environment']!=env or row['stage']!=name
                or row['failureReason'] is not None or (name!='run' and row['returnCode']!=0)):
            raise ValueError('STATEMENT_PROBE_EXECUTION_PROFILE_INVALID')
        for stream in ('stdout','stderr'):
            if row[stream]!=d.snapshot(root/name/(stream+'.log')):raise ValueError('STATEMENT_PROBE_LOG_CHANGED')
        executions[name]=row
    elf=parse(library.read_bytes())
    if elf['machine']!=62 or elf['soname']!=plan['soname'] or parse((root/'program').read_bytes())['machine']!=62:
        raise ValueError('STATEMENT_PROBE_ELF_PROFILE_CHANGED')
    # Runtime binding of this new DSO is explicitly not claimed. Compare the API
    # protocol and observations, and report this residual identity obligation.
    run=executions['run'];rows=counts((root/'run/stderr.log').read_bytes(),metadata)
    protocol=api.output_protocol((root/'run/stdout.log').read_bytes(),tested['interface'],experiment.read_domain(parent['domain']['path'],report,
        experiment.selection(report,parent['functionAstPath'])[0]))
    original=Path(inputs['apiExperiment']['path']).parent/'run-target/stdout.log'
    agrees=(root/'run/stdout.log').read_bytes()==original.read_bytes()
    complete=run['returnCode']==0 and protocol and agrees and all(r['instrumentedStatementCompleted'] for r in rows)
    return d.seal({'schemaVersion':SCHEMA,'apiExperimentIdentity':tested['apiExperimentIdentity'],
        'contractEvidenceIdentity':report['contractEvidenceIdentity'],'deploymentIdentity':deployed['deploymentIdentity'],
        'instanceObservations':rows,'instrumentedStatementCoverageComplete':complete,
        'instrumentedOutputMatchesApiRun':agrees,'harnessObservationProtocolComplete':protocol,
        'canonicalInstructionCoverageVerified':False,'untracedRunCoverageVerified':False,
        'instrumentedLibraryRuntimeIdentityVerified':False,
        'scope':'instrumented-pure-integer-statement-begin-and-completion-only',
        'semanticApproval':False,'productionAcceptanceComplete':False},'statementProbeIdentity')


def check(path):
    path=Path(path).resolve(strict=True);value=d.read(path);checked(value,'statementProbeIdentity')
    if derive(path.parent)!=value:raise ValueError('STATEMENT_PROBE_REDERIVATION_MISMATCH')
    return value
