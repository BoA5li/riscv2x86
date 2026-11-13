"""Execute bounded typed API tests using real native candidate artifacts.

Reuses original L1 comparison. Generated allocations satisfy the declared entry
object construction, not all internal callee accesses. This diagnostic API run
is not a complete L0 matrix, L2/L3 or whole-program acceptance certificate.
"""
import json
from pathlib import Path

from . import native_captured_deployment as d
from . import native_contract_evidence as contracts
from . import native_api_contract as api
from . import project_native_input as native
from .native_external_providers import checked
from .native_experiment_driver import command
from .native_elf_runtime import parse
from .project_build_records import identity
from .l1_differential import HarnessObservation,ProcessObservation,compare_l1_observations
from .validation_case import ComparisonContract

SCHEMA='riscv2x86.native-api-experiment.v1'


def source_abi(candidate):
    import struct
    raw=(Path(candidate['candidatePath']).parent/'source.o').read_bytes()
    if d.digest(Path(candidate['candidatePath']).parent/'source.o')!=candidate['sourceObjectDigest'] or parse(raw)['machine']!=243:
        raise ValueError('API_SOURCE_OBJECT_BINDING_CHANGED')
    flags=struct.unpack_from('<I',raw,48)[0]
    profiles={0:'riscv_lp64',2:'riscv_lp64f',4:'riscv_lp64d'}
    if flags & 8 or flags & 6 not in profiles:raise ValueError('API_SOURCE_ELF_ABI_UNSUPPORTED')
    return profiles[flags & 6]


def library_machine(path):
    from .native_dependency_evidence import archive_members
    raw=Path(path).read_bytes()
    if len(raw)>128*1024*1024:raise ValueError('API_LIBRARY_BUDGET_EXCEEDED')
    if raw.startswith(b'!<arch>\n'):
        members=archive_members(raw)
        machines={parse(m['bytes'])['machine'] for m in members}
        if len(machines)!=1:raise ValueError('API_ARCHIVE_MACHINE_NOT_UNIQUE')
        return next(iter(machines))
    return parse(raw)['machine']


def selection(report,path):
    roots=report['programScope']['localScopes']['candidate']['rootAstPaths']
    if path not in roots:raise ValueError('API_TRANSLATED_FUNCTION_ROOT_REQUIRED')
    joins=[r for r in report['declarationJoins'] if r['candidateAstPath']==path
           and r['byteLineageDeclarationCorrespondenceVerified']]
    defs=[r for r in report['graphs']['candidate']['functionDefinitions'] if r['astPath']==path]
    if len(joins)!=1 or len(defs)!=1 or not defs[0].get('linkerName') or defs[0].get('storageClass')=='static':
        raise ValueError('API_UNIQUE_EXPORTED_DECLARATION_REQUIRED')
    declaration=defs[0];join=joins[0]
    source_signature=api.resolve_signature(join['sourceSignature'],report['graphs']['source']['typeGraph'])
    candidate_signature=api.resolve_signature(join['candidateSignature'],report['graphs']['candidate']['typeGraph'])
    interface=api.compatible(source_signature,candidate_signature,
                           report['dataModels']['source'],report['dataModels']['candidate'])
    # Native target context is a separate relation, not a target-signature alias.
    peers=[r for r in report['graphs']['nativeTarget'].get('functionDeclarations',
             report['graphs']['nativeTarget']['functionDefinitions'])
           if r.get('linkerName')==declaration['linkerName']]
    if not peers:raise ValueError('API_NATIVE_TARGET_DECLARATION_REQUIRED')
    for peer in peers:
        native_signature=api.resolve_signature(peer['signature'],report['graphs']['nativeTarget']['typeGraph'])
        api.compatible(candidate_signature,native_signature,
                       report['dataModels']['candidate'],report['dataModels']['nativeTarget'])
    return declaration,interface


def context(path):
    parent_data=d.read(Path(path).resolve().parent/'inputs.json')
    if any(parent_data.get(k) is not None for k in ('apiExperiment','statementProbe','frameworkExecution')):
        raise ValueError('API_BASE_WITHOUT_DERIVED_EXPERIMENTS_REQUIRED')
    report=contracts.check(path)
    parent=d.read(Path(path).resolve().parent/'inputs.json')
    from .native_deployment_observation import check_observation
    observed=check_observation(parent['observation']['path'])
    deployed=d.check_result(observed['deploymentPath']);plan=d.read(deployed['planPath'])
    candidate=d.read(plan['candidatePath'])
    bundle=d.read(candidate['bindingBundlePath']);receipt=d.read(bundle['nativeInputReceiptPath'])
    source=native.validate_artifacts(receipt)
    return report,deployed,plan,candidate,receipt,source


def execute(argv,cwd,env,root,name,timeout):
    folder=root/name;folder.mkdir()
    code,reason=command(argv,str(cwd),env,folder,timeout,16*1024*1024)
    row={'arguments':list(argv),'directory':str(cwd),'environment':env,
         'returnCode':code,'failureReason':reason,'stage':name,'timeoutSeconds':timeout,'maxLogBytes':16*1024*1024,
         'stdout':d.snapshot(folder/'stdout.log'),'stderr':d.snapshot(folder/'stderr.log')}
    (folder/'execution.json').write_text(json.dumps(d.seal(row,'apiExecutionIdentity'),indent=2)+'\n')
    if reason is not None or (name.startswith(('compile-','witness-')) and code!=0):
        raise ValueError('API_EXECUTION_FAILED:'+name+':'+str(reason or code))
    return row


def acquire(contracts_path,domain_path,function_path,source_library,output,*,source_launcher=None,
            launcher_arguments=(),timeout=300):
    from .native_deployment_prerequisites import output_path
    report,deployed,plan,candidate,receipt,source=context(contracts_path)
    declaration,interface=selection(report,function_path)
    domain=read_domain(domain_path,report,declaration);text,object_contract=api.harness(declaration['linkerName'],interface,domain)
    if type(timeout) is not int or not 1<=timeout<=86400:raise ValueError('API_TIMEOUT_INVALID')
    source_library=d.snapshot(source_library)
    if library_machine(source_library['path'])!=243:
        raise ValueError('API_RISCV_SOURCE_LIBRARY_REQUIRED')
    if source_launcher is None:raise ValueError('API_EXPLICIT_RISCV_EXECUTION_ROUTE_REQUIRED')
    launcher=d.snapshot(source_launcher)
    if not isinstance(launcher_arguments,(tuple,list)) or any(not isinstance(a,str) or '\0' in a for a in launcher_arguments):
        raise ValueError('API_LAUNCHER_ARGUMENTS_INVALID')
    library=next(a for a in deployed['artifacts'] if a['stage']=='derived-library')
    attributed=[r for r in deployed['definitions'] if r['verified'] and r['symbol']['name']==declaration['linkerName']]
    if len(attributed)!=1:raise ValueError('API_TARGET_DEFINITION_ATTRIBUTION_REQUIRED')
    root=output_path(output);root.mkdir();(root/'harness.c').write_text(text)
    inputs={'schemaVersion':'riscv2x86.native-api-inputs.v1','contracts':d.snapshot(contracts_path),
        'domain':d.snapshot(domain_path),'functionAstPath':function_path,'sourceLibrary':source_library,
        'sourceLauncher':launcher,'launcherArguments':list(launcher_arguments),'timeoutSeconds':timeout,
        'candidate':d.snapshot(plan['candidatePath']),'targetLibrary':{k:library[k] for k in ('path','resolvedPath','digest')},
        'tools':[]}
    source_cc=receipt['context']['nativeCompiler'];target_cc=candidate['targetCompiler']
    inputs['tools']=[d.snapshot(cc) for cc in dict.fromkeys([source_cc,target_cc])]
    (root/'inputs.json').write_text(json.dumps(d.seal(inputs,'apiInputsIdentity'),indent=2)+'\n')
    witness=api.declaration_witness(declaration.get('name',declaration['linkerName']),interface)
    for side,cc,raw,flags in (
        ('source',source_cc,source['inputBytes'],candidate['sourceFlags']),
        ('target',target_cc,Path(candidate['candidatePath']).read_bytes(),candidate['targetFlags'])):
        unit=root/(side+'-witness.i');unit.write_bytes(raw+witness.encode())
        execute([cc,*flags,'-Werror','-x','cpp-output','-c',str(unit),'-o',str(root/(side+'-witness.o'))],
                receipt['context']['workingDirectory'],plan['environment'],root,'witness-'+side,timeout)
    # Link source candidate object explicitly before baseline library so the
    # tested definition is this translation unit, not another archive member.
    # Actual runtime dependency selection remains a separate outstanding claim.
    source_obj=Path(candidate['candidatePath']).parent/'source.o'
    if d.digest(source_obj)!=candidate['sourceObjectDigest']:raise ValueError('API_SOURCE_OBJECT_BINDING_CHANGED')
    profiles=[('source',source_cc,[a for a in candidate['sourceFlags'] if a.startswith(('-march=','-mabi='))],
               [str(source_obj),source_library['path']]),
              ('target',target_cc,[],[library['path']])]
    for side,cc,flags,libs in profiles:
        execute([cc,*flags,'-std=gnu11','-Werror',str(root/'harness.c'),*libs,'-Wl,-rpath,'+str(Path(libs[-1]).parent),'-o',str(root/(side+'-program'))],
                root,plan['environment'],root,'compile-'+side,timeout)
        expected=243 if side=='source' else 62
        if parse((root/(side+'-program')).read_bytes())['machine']!=expected:
            raise ValueError('API_PROGRAM_MACHINE_MISMATCH')
    execute([launcher['path'],*launcher_arguments,str(root/'source-program')],root,plan['environment'],root,'run-source',timeout)
    execute([str(root/'target-program')],root,plan['environment'],root,'run-target',timeout)
    artifacts=[d.snapshot(root/name) for name in ('harness.c','source-witness.i','target-witness.i',
        'source-witness.o','target-witness.o','source-program','target-program')]
    (root/'artifacts.json').write_text(json.dumps(artifacts,indent=2)+'\n')
    result=derive(root);(root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    check(root/'result.json');return result


def derive(root):
    root=Path(root).resolve();inputs=d.read(root/'inputs.json');checked(inputs,'apiInputsIdentity')
    api.fields(inputs,('schemaVersion','contracts','domain','functionAstPath','sourceLibrary','sourceLauncher',
        'launcherArguments','timeoutSeconds','candidate','targetLibrary','tools','apiInputsIdentity'),'API_INPUTS')
    if inputs['schemaVersion']!='riscv2x86.native-api-inputs.v1':raise ValueError('API_INPUT_SCHEMA_INVALID')
    for snap in [inputs[k] for k in ('contracts','domain','sourceLibrary','sourceLauncher','candidate','targetLibrary')]+inputs['tools']:
        d.verify_snapshot(snap)
    if (type(inputs['timeoutSeconds']) is not int or not 1<=inputs['timeoutSeconds']<=86400
            or library_machine(inputs['sourceLibrary']['path'])!=243
            or not isinstance(inputs['launcherArguments'],list)
            or any(not isinstance(a,str) or '\0' in a for a in inputs['launcherArguments'])):
        raise ValueError('API_INPUT_PROFILE_INVALID')
    report,deployed,plan,candidate,receipt,source=context(inputs['contracts']['path'])
    if inputs['candidate']!=d.snapshot(plan['candidatePath']):raise ValueError('API_CANDIDATE_BINDING_CHANGED')
    expected_tools=[d.snapshot(cc) for cc in dict.fromkeys([receipt['context']['nativeCompiler'],candidate['targetCompiler']])]
    if inputs['tools']!=expected_tools:raise ValueError('API_TOOL_BINDING_CHANGED')
    declaration,interface=selection(report,inputs['functionAstPath'])
    text,object_contract=api.harness(declaration['linkerName'],interface,read_domain(inputs['domain']['path'],report,declaration))
    if (root/'harness.c').read_text()!=text:raise ValueError('API_HARNESS_REDERIVATION_MISMATCH')
    artifacts=d.read(root/'artifacts.json')
    expected_names={'harness.c','source-witness.i','target-witness.i','source-witness.o','target-witness.o','source-program','target-program'}
    if {Path(a['path']).name for a in artifacts}!=expected_names or len(artifacts)!=len(expected_names):
        raise ValueError('API_ARTIFACT_SET_INVALID')
    for snap in artifacts:
        if Path(snap['path']).parent!=root:raise ValueError('API_ARTIFACT_PATH_INVALID')
        d.verify_snapshot(snap)
    witness=api.declaration_witness(declaration.get('name',declaration['linkerName']),interface).encode()
    if ((root/'source-witness.i').read_bytes()!=source['inputBytes']+witness or
        (root/'target-witness.i').read_bytes()!=Path(candidate['candidatePath']).read_bytes()+witness):
        raise ValueError('API_DECLARATION_WITNESS_CHANGED')
    # Rebuild expected compiler/run profiles independently, including original
    # flags and working directories. Rehashing a command receipt cannot change it.
    source_cc=receipt['context']['nativeCompiler'];target_cc=candidate['targetCompiler']
    libraries=[a for a in deployed['artifacts'] if a['stage']=='derived-library']
    if len(libraries)!=1 or inputs['targetLibrary']!={k:libraries[0][k] for k in ('path','resolvedPath','digest')}:
        raise ValueError('API_TARGET_LIBRARY_BINDING_CHANGED')
    expected={}
    for side,cc in [('source',source_cc),('target',target_cc)]:
        expected['witness-'+side]=([cc,*candidate[side+'Flags'],'-Werror','-x','cpp-output','-c',
            str(root/(side+'-witness.i')),'-o',str(root/(side+'-witness.o'))],receipt['context']['workingDirectory'])
        flags=[a for a in candidate['sourceFlags'] if a.startswith(('-march=','-mabi='))] if side=='source' else []
        libs=[str(Path(candidate['candidatePath']).parent/'source.o'),inputs['sourceLibrary']['path']] if side=='source' else [inputs['targetLibrary']['path']]
        expected['compile-'+side]=([cc,*flags,'-std=gnu11','-Werror',str(root/'harness.c'),*libs,'-Wl,-rpath,'+str(Path(libs[-1]).parent),'-o',str(root/(side+'-program'))],str(root))
    expected['run-source']=([inputs['sourceLauncher']['path'],*inputs['launcherArguments'],str(root/'source-program')],str(root))
    expected['run-target']=([str(root/'target-program')],str(root))
    executions={}
    for name,(argv,cwd) in expected.items():
        row=d.read(root/name/'execution.json');checked(row,'apiExecutionIdentity')
        api.fields(row,('arguments','directory','environment','returnCode','failureReason','stage','timeoutSeconds',
                        'maxLogBytes','stdout','stderr','apiExecutionIdentity'),'API_EXECUTION')
        if (type(row['returnCode']) is not int or row['timeoutSeconds']!=inputs['timeoutSeconds'] or row['maxLogBytes']!=16*1024*1024
                or row['arguments']!=argv or row['directory']!=cwd or row['environment']!=plan['environment']
                or row['stage']!=name or row['failureReason'] is not None
                or (not name.startswith('run-') and row['returnCode']!=0)):
            raise ValueError('API_EXECUTION_PROFILE_OR_RESULT_INVALID')
        for stream in ('stdout','stderr'):
            if row[stream]!=d.snapshot(root/name/(stream+'.log')):raise ValueError('API_LOG_PATH_OR_BYTES_CHANGED')
        executions[name]=row
    for side,machine in [('source',243),('target',62)]:
        if parse((root/(side+'-witness.o')).read_bytes())['machine']!=machine:
            raise ValueError('API_WITNESS_MACHINE_MISMATCH')
        if parse((root/(side+'-program')).read_bytes())['machine']!=machine:
            raise ValueError('API_PROGRAM_MACHINE_MISMATCH')
    import base64
    def obs(side):
        row=executions['run-'+side]
        return ProcessObservation(HarnessObservation(None,(),(),(),()),row['returnCode'],
            base64.b64encode(Path(row['stdout']['path']).read_bytes()).decode(),
            base64.b64encode(Path(row['stderr']['path']).read_bytes()).decode(),())
    mismatches=compare_l1_observations(obs('source'),obs('target'),ComparisonContract(False,True,True,True,False,(),(),(),()))
    terminated=all(executions['run-'+s]['returnCode']==0 for s in ('source','target'))
    protocols={s:api.output_protocol(Path(executions['run-'+s]['stdout']['path']).read_bytes(),
        interface,read_domain(inputs['domain']['path'],report,declaration)) for s in ('source','target')}
    protocol=all(protocols.values())
    status=observation_status(executions['run-source']['returnCode'],executions['run-target']['returnCode'],
        protocols['source'],protocols['target'],mismatches)
    source_profile=source_abi(candidate)
    import struct
    source_program_flags=struct.unpack_from('<I',(root/'source-program').read_bytes(),48)[0]
    expected_flags={'riscv_lp64':0,'riscv_lp64f':2,'riscv_lp64d':4}[source_profile]
    if source_program_flags & 8 or source_program_flags & 6 != expected_flags:
        raise ValueError('API_SOURCE_PROGRAM_ABI_MISMATCH')
    return d.seal({'schemaVersion':SCHEMA,'contractEvidenceIdentity':report['contractEvidenceIdentity'],
        'deploymentIdentity':deployed['deploymentIdentity'],'apiInputsIdentity':inputs['apiInputsIdentity'],
        'interface':interface,'sourceAbiLayout':api.abi_layout(interface,source_profile),
        'targetAbiLayout':api.abi_layout(interface,'sysv_amd64'),'objectConstructionContract':object_contract,
        'compilerDeclarationWitnessesComplete':True,'processObservationStatus':
            status,
        'mismatches':list(mismatches),'sourceHarnessProtocolComplete':protocols['source'],
        'targetHarnessProtocolComplete':protocols['target'],'harnessObservationProtocolComplete':protocol,'harnessExecutionsReturnedNormally':terminated,
        'sourceRuntimeProviderClosureVerified':False,'nativeAbiClosureVerified':False,
        'legalObjectDomainVerified':False,'candidateInstructionExecutionCoverageVerified':False,
        'l0L3AcceptanceComplete':False,'scope':'bounded-api-under-declared-preconditions',
        'semanticApproval':False,'productionAcceptanceComplete':False},'apiExperimentIdentity')


def check(path):
    path=Path(path).resolve(strict=True);value=d.read(path);checked(value,'apiExperimentIdentity')
    if derive(path.parent)!=value:raise ValueError('API_EXPERIMENT_REDERIVATION_MISMATCH')
    return value


def read_domain(path,report,declaration):
    wrapper=d.read(path)
    api.fields(wrapper,('schemaVersion','contractEvidenceIdentity','functionEvidenceIdentity','domain'),'API_BOUND_DOMAIN')
    if (wrapper['schemaVersion']!='riscv2x86.native-api-bound-domain.v1'
            or wrapper['contractEvidenceIdentity']!=report['contractEvidenceIdentity']
            or wrapper['functionEvidenceIdentity']!=declaration['functionEvidenceIdentity']):
        raise ValueError('API_DOMAIN_FUNCTION_OR_CONTRACT_BINDING_MISMATCH')
    return wrapper['domain']


def prepare(contracts_path,output):
    from .native_deployment_prerequisites import output_path
    report,_,_,_,_,source=context(contracts_path);rows=[]
    for path in report['programScope']['localScopes']['candidate']['rootAstPaths']:
        try:
            declaration,interface=selection(report,path)
            rows.append({'functionAstPath':path,'functionEvidenceIdentity':declaration['functionEvidenceIdentity'],
              'linkerName':declaration['linkerName'],'interface':interface,
              'sourceFunctionForDomainReview':source_function(report,path,source),
              'domainTemplate':{'schemaVersion':'riscv2x86.native-api-bound-domain.v1',
                'contractEvidenceIdentity':report['contractEvidenceIdentity'],
                'functionEvidenceIdentity':declaration['functionEvidenceIdentity'],
                'domain':{'schemaVersion':api.SCHEMA,'claimScope':'bounded-api-under-declared-preconditions',
                          'preconditions':[],'cases':[]}}})
        except ValueError as exc:
            rows.append({'functionAstPath':path,'unsupportedReason':str(exc)})
    value=d.seal({'schemaVersion':'riscv2x86.native-api-plan.v1','contracts':d.snapshot(contracts_path),
        'functions':rows,'inputsReady':False,'semanticApproval':False,'productionAcceptanceComplete':False},'apiPlanIdentity')
    path=output_path(output)
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
    return value



def source_function(report,path,source):
    from .compiler_native_instance_binding import _nodes
    from .native_dependency_evidence import bytes_digest
    joins=[j for j in report['declarationJoins'] if j['candidateAstPath']==path and j['byteLineageDeclarationCorrespondenceVerified']]
    if len(joins)!=1:raise ValueError('API_SOURCE_FUNCTION_JOIN_REQUIRED')
    nodes=[n for n,p,_ in _nodes(source['canonicalAst']) if p==joins[0]['sourceAstPath']]
    if len(nodes)!=1:raise ValueError('API_SOURCE_FUNCTION_AST_REQUIRED')
    node=nodes[0];start=node['range']['begin']['offset'];end=node['range']['end']
    stop=end['offset']+end['tokLen'];raw=source['inputBytes']
    if not 0<=start<stop<=len(raw):raise ValueError('API_SOURCE_FUNCTION_RANGE_INVALID')
    if stop-start>65536:return {'available':False,'reasonCode':'API_SOURCE_FUNCTION_REVIEW_BUDGET_EXCEEDED'}
    text=raw[start:stop]
    return {'available':True,'range':[start,stop],'digest':bytes_digest(text),'text':text.decode('utf-8'),
            'scope':'compiler-bound-source-for-input-review-not-inferred-precondition-proof'}



def observation_status(source_code,target_code,source_protocol,target_protocol,mismatches):
    # A bad source oracle cannot establish an expected result. Once the source
    # completed the declared harness, a target crash/early exit/protocol loss is
    # a failed bounded observation, not an inconclusive result or an empty pass.
    if source_code!=0 or not source_protocol:return 'inconclusive'
    if target_code!=0 or not target_protocol or mismatches:return 'failed'
    return 'verified'
