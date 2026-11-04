"""Independent project recipe/artifact binding audit, additional to L3 audit."""
import json
from pathlib import Path
import tempfile
from .project_build_contract import load,report_contract,digest
from .project_build_records import identity


def validate_binding(evaluation):
    binding=evaluation['projectBuildBinding']
    fields={'schemaVersion','contractPath','contractIdentity','translatedReportPath',
            'sourceProgramArtifact','targetProgramArtifact','bindingIdentity'}
    if (set(binding)!=fields or binding['schemaVersion']!='riscv2x86.project-evaluation-binding.v1'
            or binding['bindingIdentity']!=identity({k:v for k,v in binding.items() if k!='bindingIdentity'})):
        raise ValueError('PROJECT_EVALUATION_BINDING_INVALID')
    contract=load(binding['contractPath'])
    if contract['contractIdentity']!=binding['contractIdentity']:raise ValueError('PROJECT_EVALUATION_CONTRACT_CHANGED')
    report=Path(binding['translatedReportPath']);data=json.loads(report.read_text())
    if identity(report_contract(data))!=identity(contract):raise ValueError('PROJECT_EVALUATION_REPORT_CONTRACT_MISMATCH')
    from .compiler_provenance import validate_compiler_snapshot
    snapshot=json.loads(report.with_name('compiler-candidates.json').read_text())
    validate_compiler_snapshot(snapshot)
    if identity(snapshot.get('projectBuildContract'))!=identity(contract):raise ValueError('PROJECT_EVALUATION_SNAPSHOT_CONTRACT_MISMATCH')
    if identity(data.get('projectCompilerCompatibility'))!=identity(snapshot.get('projectCompilerCompatibility')):
        raise ValueError('PROJECT_EVALUATION_COMPATIBILITY_MISMATCH')
    from .project_artifact_build import build
    from .runtime_dependency_binding import dependencies_from_translated_report
    dependencies=dependencies_from_translated_report(report)
    paths={'source':contract['sourceContext']['sourcePath']}
    # Actual target input is recorded by the content-bound build receipt, not
    # inferred from function names, source basenames or directory conventions.
    with tempfile.TemporaryDirectory(prefix='rv2x86-project-audit-') as tmp:
        for side in ('source','target'):
            artifact=evaluation.get(side+'ProgramArtifact')
            if artifact is None or identity(artifact)!=identity(binding[side+'ProgramArtifact']):
                raise ValueError('PROJECT_EVALUATION_ARTIFACT_BINDING_MISMATCH:'+side)
            path=Path(artifact['artifact_path']);receipt_path=path.with_name(path.name+'.project-build.json')
            receipt=json.loads(receipt_path.read_text())
            if (receipt.get('buildIdentity')!=identity({k:v for k,v in receipt.items() if k!='buildIdentity'})
                    or receipt.get('contractIdentity')!=contract['contractIdentity'] or receipt.get('side')!=side
                    or receipt.get('artifactPath')!=str(path.resolve()) or receipt.get('artifactDigest')!=artifact['artifact_digest']
                    or receipt.get('semanticApproval') is not False or receipt.get('productionAcceptanceComplete') is not False
                    or digest(path)!=artifact['artifact_digest'] or digest(receipt['sourcePath'])!=receipt['sourceDigest']):
                raise ValueError('PROJECT_EVALUATION_BUILD_RECEIPT_INVALID:'+side)
            if side=='source' and receipt['sourcePath']!=paths['source']:raise ValueError('PROJECT_EVALUATION_SOURCE_PATH_MISMATCH')
            rebuilt=build(contract,side,receipt['sourcePath'],Path(tmp)/side/path.name,artifact['artifact_kind'],
                include_directories=dependencies.include_directories,libraries=dependencies.library_paths)
            if side=='target' and identity(rebuilt['targetPreprocessingReceipt'])!=identity(receipt.get('targetPreprocessingReceipt')):
                raise ValueError('PROJECT_EVALUATION_TARGET_CPP_CHANGED')
            if rebuilt['artifactDigest']!=artifact['artifact_digest']:
                raise ValueError('PROJECT_EVALUATION_REBUILD_MISMATCH:'+side)
    return contract
