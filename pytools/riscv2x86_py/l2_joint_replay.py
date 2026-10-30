"""Independent semantic replay of persisted joint L2, never an L3 observation."""
import json
from pathlib import Path
import tempfile
from .l3_trace_support import digest, require_json_document, require_json_match, Elf, run
from .l3_joint_observation import harness, instrument, parse_l2, JointSemanticMismatch
from .l3_joint_spec import sample_plan


def replay(value):
    require_json_document(value, 'L2_JOINT_JSON_INVALID')
    if value.get('schemaVersion') != 'riscv2x86.l2-joint-observation.v1':
        raise ValueError('L2_JOINT_OBSERVATION_SCHEMA_REQUIRED')
    from .l3_joint_deployment import bound
    from .automatic_batch_cli import inspect_entry_points
    for key in ('inputDigests','files','toolDigests'):
        for path, sha in value[key].items():
            if digest(path) != sha:raise ValueError('L2_JOINT_REPLAY_FILE_CHANGED:'+path)
    if digest(value['clang']) != value['clangDigest']:raise ValueError('L2_JOINT_REPLAY_CLANG_CHANGED')
    paths = value['inputs'];source,target,report = (Path(paths[k]) for k in ('source','target','report'))
    program, fn = bound(source,target,report,value['clang'])
    require_json_match(program,value['programSpec'],'L2_JOINT_SPEC_REPLAY_MISMATCH')
    plan=sample_plan(program,len(value['samplePlan']['inputs']))
    require_json_match(plan,value['samplePlan'],'L2_JOINT_PLAN_REPLAY_MISMATCH')
    finding=next(f for f in json.loads(report.read_text())['findings'] if f['fragment']['id']==value['fragmentId'])
    if value.get('jointFence') is not (finding['l2SemanticProfile']['patternKind']=='fence'):
        raise ValueError('L2_JOINT_FENCE_PROJECTION_CHANGED')
    from .l2_authority import l2_authority_sidecar_from_dict
    from .automatic_l2_effect import _approved_relations
    from types import SimpleNamespace
    a=finding['approvalArtifact'];sidecar=l2_authority_sidecar_from_dict(a['l2AuthoritySidecar'])
    artifact=SimpleNamespace(fragment_id=value['fragmentId'],shell_facts_identity=sidecar.shell_fact_identity,
        proof_identity=a['proofIdentity'],l2_authority_identity=sidecar.authority_identity,
        effect_relation_set_identity=sidecar.effect_relation_set_identity)
    authority,reason=_approved_relations(finding,artifact,fn)
    if authority is None:raise ValueError(reason)
    require_json_match(authority,value['approvedRelationAuthority'],'L2_JOINT_RELATION_REPLAY_MISMATCH')
    _,functions=inspect_entry_points(target,clang=value['clang'],target_isa='x86_64')
    scopes=[f['compilerJointScope'] for f in functions if f['name']==program['functionName']]
    if len(scopes)!=1:raise ValueError('L2_JOINT_TARGET_SCOPE_REQUIRED')
    # Artifact paths are bound to the build records, not selected by a filename search.
    commands={}
    for path in value['files']:
        if path.endswith('.command.json'):commands[Path(path).name]=json.loads(Path(path).read_text())
    errors=[];observations={}
    with tempfile.TemporaryDirectory(prefix='rv2x86-l2-joint-replay-') as temp:
        work=Path(temp);h=work/'harness.c';h.write_text(harness(program,plan))
        if digest(h)!=value['harnessDigest']:raise ValueError('L2_JOINT_HARNESS_CHANGED')
        for side,path,scope in (('source',source,program['scope']),('target',target,scopes[0])):
            build=commands[side+'-build.command.json'];execution=commands[side+'-execute.command.json']
            command=build['command'];cc=value['tools'][side+'Compiler']
            if cc not in value['toolDigests']:raise ValueError('L2_JOINT_COMPILER_UNPINNED')
            flags=['-march=rv64gc','-mabi=lp64d','-static'] if side=='source' else []
            prefix=[cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wl,--build-id=none',*flags]
            if command[:len(prefix)]!=prefix or len(command)!=len(prefix)+4 or command[-2]!='-o':raise ValueError('L2_JOINT_BUILD_COMMAND_CHANGED')
            old_h,old_c,binary=map(Path,(command[-4],command[-3],command[-1]))
            if any(str(p.resolve()) not in value['files'] for p in (old_h,old_c,binary)):
                raise ValueError('L2_JOINT_BUILD_INPUT_UNBOUND')
            if old_h.read_bytes()!=h.read_bytes() or old_c.read_bytes()!=instrument(path.read_bytes(),scope['sites'],program):
                raise ValueError('L2_JOINT_VARIANT_CHANGED')
            c=work/(side+'.c');c.write_bytes(old_c.read_bytes());fresh=work/side
            run([*prefix,h,c,'-o',fresh],work,side+'-rebuild',120)
            require_json_match(Elf(fresh).execution_image(),Elf(binary).execution_image(),'L2_JOINT_EXECUTION_IMAGE_CHANGED')
            expected=[str(binary),'a'*64]
            if side=='source':
                executor=value['tools']['sourceExecutor']
                if executor not in value['toolDigests']:raise ValueError('L2_JOINT_EXECUTOR_UNPINNED')
                expected.insert(0,executor)
            if (execution['command']!=expected or execution['stdout']!=value['rawOutputs'][side]
                    or type(execution['returnCode']) is not int or execution['returnCode']!=0 or execution['timedOut'] is not False or execution['stderr']
                    or type(build['returnCode']) is not int or build['returnCode']!=0 or build['timedOut'] is not False):
                raise ValueError('L2_JOINT_EXECUTION_RECORD_CHANGED')
            try:observations[side]=parse_l2(execution['stdout'],'a'*64,program,plan)
            except JointSemanticMismatch as exc:
                observations[side]=exc.observation;errors.append(side+':'+str(exc))
    require_json_match(observations,{s:value[s] for s in ('source','target')},'L2_JOINT_OBSERVATION_REPLAY_MISMATCH')
    require_json_match(errors,value['semanticErrors'],'L2_JOINT_COUNTEREXAMPLE_REPLAY_MISMATCH')
    reason='L2_JOINT_OPERAND_OR_OBJECT_MISMATCH' if errors or observations['source']!=observations['target'] else ''
    if reason!=value['reasonCode']:raise ValueError('L2_JOINT_COMPARISON_REPLAY_MISMATCH')
    return value
