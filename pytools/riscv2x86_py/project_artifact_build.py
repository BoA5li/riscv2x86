"""Build bound project artifacts and drivers without changing semantic options."""
from pathlib import Path
import json
import subprocess
from .project_build_contract import profile,validate,digest
from .project_build_records import identity


def build(contract,side,source,output,kind,*,include_directories=(),libraries=(),timeout=240):
    validate(contract)
    if kind not in {'object','executable','shared_library'}:raise ValueError('PROJECT_BUILD_KIND_INVALID')
    source=Path(source).resolve(strict=True);output=Path(output).resolve()
    if side=='source' and str(source)!=contract['sourceContext']['sourcePath']:
        raise ValueError('PROJECT_BUILD_SOURCE_PATH_CHANGED')
    cc,args=profile(contract,side); output.parent.mkdir(parents=True,exist_ok=True)
    obj=output if kind=='object' else output.with_name(output.name+'.o')
    if output.exists() or obj.exists():raise FileExistsError('PROJECT_BUILD_OUTPUT_EXISTS')
    commands=[];before=digest(source);target_cpp=None
    def run(argv):
        result=subprocess.run(argv,cwd=output.parent,capture_output=True,text=True,timeout=timeout,check=False)
        commands.append({'command':argv,'workingDirectory':str(output.parent),'returnCode':result.returncode,
                         'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode:raise ValueError('PROJECT_BUILD_COMMAND_FAILED:'+result.stderr[-6000:])
    try:
        if side=='target':
            from .project_compiler_compatibility import target_acquire
            target_cpp=target_acquire(contract,source,include_directories=include_directories)
            output.with_name(output.name+'.target-cpp.json').write_text(json.dumps(target_cpp,indent=2)+'\n')
            if target_cpp['targetPreprocessingMatched'] is not True:raise ValueError('PROJECT_TARGET_PREPROCESSING_MISMATCH')
        run([cc,*args,*['-I'+str(Path(p).resolve()) for p in include_directories if side=='target'],'-c',str(source),'-o',str(obj)])
        if kind!='object':
            _,link_args=profile(contract,side,driver=True)
            run([cc,*link_args,*(['-shared'] if kind=='shared_library' else []),str(obj),*map(str,libraries),'-o',str(output)])
        validate(contract)
        if digest(source)!=before:raise ValueError('PROJECT_BUILD_INPUT_CHANGED')
        if target_cpp is not None:
            from .compiler_call_dependencies import _snapshot
            cwd=Path(contract['sourceContext']['workingDirectory'])
            for rows in target_cpp['dependencies'].values():
                if identity(rows)!=identity(_snapshot([r['compilerPath'] for r in rows],cwd)):
                    raise ValueError('PROJECT_BUILD_TARGET_DEPENDENCIES_CHANGED')
        body={'schemaVersion':'riscv2x86.project-artifact-build.v1','contractIdentity':contract['contractIdentity'],
              'side':side,'sourcePath':str(source),'sourceDigest':before,'artifactPath':str(output),
              'artifactDigest':digest(output),'objectDigest':digest(obj),'artifactKind':kind,'commands':commands,
              'semanticApproval':False,'productionAcceptanceComplete':False,
              'targetPreprocessingReceipt':target_cpp}
        result=dict(body,buildIdentity=identity(body))
        output.with_name(output.name+'.project-build.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    except (OSError,ValueError,subprocess.SubprocessError):
        output.with_name(output.name+'.project-build-failure.json').write_text(json.dumps({
            'contractIdentity':contract['contractIdentity'],'commands':commands,'semanticApproval':False},indent=2)+'\n')
        raise


def build_driver(contract,side,units,output,*,libraries=(),include_directories=(),timeout=240):
    """Compile program body and harness in separate TUs with distinct profiles."""
    output=Path(output).resolve();output.parent.mkdir(parents=True,exist_ok=True)
    cc,body_args=profile(contract,side);driver_cc,driver_args=profile(contract,side,driver=True)
    if cc!=driver_cc:raise ValueError('PROJECT_DRIVER_COMPILER_MISMATCH')
    if not units or len(units)>2:raise ValueError('PROJECT_DRIVER_UNIT_SET_UNSUPPORTED')
    objects=[]
    for index,path in enumerate(units):
        path=Path(path).resolve(strict=True);obj=output.with_name(output.name+'.'+str(index)+'.o')
        if obj.exists():raise FileExistsError('PROJECT_DRIVER_OBJECT_EXISTS')
        args=body_args if index==len(units)-1 else driver_args
        cmd=[cc,*args,*['-I'+str(Path(p).resolve()) for p in include_directories],'-c',str(path),'-o',str(obj)]
        result=subprocess.run(cmd,cwd=output.parent,capture_output=True,text=True,timeout=timeout,check=False)
        (output.parent/(output.name+'.compile-'+str(index)+'.command.json')).write_text(json.dumps({'command':cmd,'returnCode':result.returncode,'stderr':result.stderr},indent=2))
        if result.returncode:return result
        objects.append(str(obj))
    if output.exists():raise FileExistsError('PROJECT_DRIVER_OUTPUT_EXISTS')
    cmd=[cc,*driver_args,*objects,*map(str,libraries),'-o',str(output)]
    result=subprocess.run(cmd,cwd=output.parent,capture_output=True,text=True,timeout=timeout,check=False)
    output.with_name(output.name+'.link.command.json').write_text(json.dumps({'command':cmd,'returnCode':result.returncode,'stderr':result.stderr},indent=2))
    validate(contract);return result
