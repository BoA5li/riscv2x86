"""Instrumented whole-call L2 observations for approved direct private-object regions.

No L3 evidence is reused as an L2 prerequisite. Observations are real values in
an explicit test variant, constrained to direct register operands and private
objects; original uninstrumented machine code remains the L3 execution unit.
"""
import json
import os
import shutil
from pathlib import Path
import subprocess
from .l3_trace_support import identity,digest,run,save
from .l3_joint_deployment import bound
from .l3_joint_spec import sample_plan
from .l3_joint_observation import instrument,harness,parse_l2,JointSemanticMismatch
from .translation_validation import ValidationLayerResult,ValidationLevel
from .validation_status import ValidationStatus,PreservationMode
from .l2_materialization import required_dimensions_for_finding
from .l2_evidence_closure import provider_evidence_fields,L2ProviderExecutionDisposition


def build_validator(config):
    def validate(**kw):
        stage='prerequisites';executed=False
        try:
            from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY
            if kw.get('level') is not ValidationLevel.L2 or kw.get('comparison_policy')!=ARCHITECTURAL_COMPARISON_POLICY:raise ValueError('L2_JOINT_VALIDATION_POLICY_REQUIRED')
            artifact=kw['translation_artifact']
            if artifact.preservation_mode is not PreservationMode.ARCHITECTURE_EQUIVALENT:raise ValueError('L2_JOINT_ARCHITECTURAL_PROOF_REQUIRED')
            source,target,report=map(Path,(config['sourcePath'],config['targetPath'],config['translatedReport']))
            if digest(source)!=config['sourceDigest'] or digest(target)!=config['targetDigest']:raise ValueError('L2_JOINT_SOURCE_OR_TARGET_CHANGED')
            clang=shutil.which(os.environ.get('RV2X86_SYSTEM_CLANG','clang'))
            if not clang:raise ValueError('L2_JOINT_CLANG_UNAVAILABLE')
            program,fn=bound(source,target,report,clang);plan=sample_plan(program)
            findings=json.loads(report.read_text())['findings'];matches=[f for f in findings if f['fragment']['id']==artifact.fragment_id]
            if len(matches)!=1:raise ValueError('L2_JOINT_FRAGMENT_AMBIGUOUS')
            finding=matches[0]
            from .automatic_l2_effect import _approved_relations,_effect_dimension_evidence
            authority,reason=_approved_relations(finding,artifact,fn)
            if authority is None:raise ValueError(reason)
            from .automatic_batch_cli import inspect_entry_points
            _,functions=inspect_entry_points(target,clang=clang,target_isa='x86_64')
            targets=[f for f in functions if f['name']==program['functionName']]
            if len(targets)!=1 or not targets[0].get('compilerJointScope'):raise ValueError('L2_JOINT_TARGET_SCOPE_REQUIRED')
            work=Path(config['workDirectory']);work.mkdir(parents=True,exist_ok=True)
            tools={n:shutil.which(n) for n in ('riscv64-linux-gnu-gcc','gcc',config['qemuBinary'])}
            if not all(tools.values()):raise ValueError('L2_JOINT_TOOLS_UNAVAILABLE')
            wrapper=harness(program,plan);h=work/'harness.c';h.write_text(wrapper);observations={};semantic_errors=[];raw_outputs={};stage='execution'
            for side,path,scope in (('source',source,program['scope']),('target',target,targets[0]['compilerJointScope'])):
                c=work/(side+'.c');c.write_bytes(instrument(path.read_bytes(),scope['sites'],program));binary=work/side
                cc=tools['riscv64-linux-gnu-gcc' if side=='source' else 'gcc']
                flags=['-march=rv64gc','-mabi=lp64d','-static'] if side=='source' else []
                run([cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wl,--build-id=none',*flags,h,c,'-o',binary],work,side+'-build',config['timeoutSeconds'])
                command=[tools[config['qemuBinary']],str(binary),'a'*64] if side=='source' else [str(binary),'a'*64]
                executed=True;r=run(command,work,side+'-execute',config['timeoutSeconds'])
                if r.stderr:raise ValueError('L2_JOINT_EXECUTION_STDERR')
                raw_outputs[side]=r.stdout
                try:observations[side]=parse_l2(r.stdout,'a'*64,program,plan)
                except JointSemanticMismatch as exc:
                    observations[side]=exc.observation;semantic_errors.append(side+':'+str(exc))
            status=ValidationStatus.VERIFIED if not semantic_errors and observations['source']==observations['target'] else ValidationStatus.FAILED
            reason='' if status is ValidationStatus.VERIFIED else 'L2_JOINT_OPERAND_OR_OBJECT_MISMATCH'
            observation={'schemaVersion':'riscv2x86.l2-joint-observation.v1','mode':'joint-program-functions',
                'fragmentId':artifact.fragment_id,'programSpec':program,'samplePlan':plan,'approvedRelationAuthority':authority,
                'harnessDigest':digest(h),'rawOutputs':raw_outputs,
                'inputs':{'source':str(source.resolve()),'target':str(target.resolve()),'report':str(report.resolve())},
                'inputDigests':{str(p.resolve()):digest(p) for p in (source,target,report)},
                'clang':clang,'clangDigest':digest(clang),
                'tools':{'sourceCompiler':tools['riscv64-linux-gnu-gcc'],'targetCompiler':tools['gcc'],'sourceExecutor':tools[config['qemuBinary']]},
                'toolDigests':{p:digest(p) for p in tools.values()},
                'files':{str(p.resolve()):digest(p) for p in (h,work/'source.c',work/'target.c',work/'source',work/'target',*work.glob('*.command.json'))},**observations,'reasonCode':reason,'semanticErrors':semantic_errors}
            dimensions=required_dimensions_for_finding(finding)
            evidence=_effect_dimension_evidence(observation,dimensions)
            closure=provider_evidence_fields(artifact,provider_id=kw.get('l2_provider_id',''),harness_identity=digest(h),
                execution_nonce={'attempt':work.name,'programSpec':program['specIdentity']},dimensions=dimensions,
                dimension_evidence=evidence,execution_disposition=L2ProviderExecutionDisposition.EXECUTED_VERIFIED if status is ValidationStatus.VERIFIED else L2ProviderExecutionDisposition.EXECUTED_FAILED)
            stage='persistence'
            from .l2_joint_replay import replay
            replay(observation)
            directory=Path(config['replayDirectory']);directory.mkdir(parents=True,exist_ok=True)
            save(directory/'joint-observation.json',observation)
            return ValidationLayerResult(ValidationLevel.L2,status,identity(observation),json.dumps({
                'schemaVersion':'riscv2x86.auto-l2-effect-result.v2','status':status.value,'reasonCode':reason,
                'mode':'joint-program-functions','fragmentId':artifact.fragment_id,'attemptId':work.name,
                'observationEvidenceIdentity':identity(observation),'replayArtifact':'joint-observation.json',**closure},sort_keys=True))
        except (OSError,ValueError,KeyError,TypeError,IndexError,subprocess.TimeoutExpired) as exc:
            return ValidationLayerResult(ValidationLevel.L2,ValidationStatus.INCONCLUSIVE,detail=json.dumps({
                'reasonCode':'L2_JOINT_OBSERVATION_INCOMPLETE','failureStage':stage,'detail':str(exc),
                'executionDisposition':'executed_inconclusive' if executed else 'not_executed','evidenceProductionDisposition':'not_produced'}))
    return validate
