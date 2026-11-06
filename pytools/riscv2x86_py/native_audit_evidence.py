"""Raw output integrity and cross-process AST identity are distinct contracts."""
import json
from pathlib import Path

from . import project_native_input as native
from .project_compile_context import digest
from .project_build_records import identity
from .l3_trace_support import require_json_match

POLICY = 'riscv2x86.native-command-evidence.canonical-target-ast.v1'


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('NATIVE_AUDIT_DUPLICATE_AST_JSON_KEY:'+key)
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError('NATIVE_AUDIT_NONFINITE_AST_JSON:'+value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def parse_target_ast(raw):
    return native.canonical_ast(strict_json(raw))


def canonical_stdout(receipt, command):
    raw = Path(command['stdoutPath']).read_bytes()
    if native.bytes_identity(raw) != command['stdoutDigest']:
        raise ValueError('NATIVE_TRANSLATION_COMMAND_ARTIFACT_CHANGED')
    ast = parse_target_ast(raw)
    artifact = Path(receipt['candidatePath']).parent/'target-ast.json'
    if digest(artifact) != receipt['artifactDigests']['target-ast.json']:
        raise ValueError('NATIVE_TRANSLATION_PROOF_ARTIFACT_CHANGED')
    require_json_match(strict_json(artifact.read_bytes()), ast, 'NATIVE_AUDIT_RAW_CANONICAL_AST_MISMATCH')
    ast_id = identity(ast)
    if ast_id != receipt['targetAstIdentity']:
        raise ValueError('NATIVE_AUDIT_TARGET_AST_IDENTITY_MISMATCH')
    return {'kind': 'clang-json-ast', 'projectionPolicy': native.AST_POLICY,
            'canonicalAstIdentity': ast_id}


def command_projection(receipt):
    if sum(c.get('stage') == 'target-ast' for c in receipt['commands']) != 1:
        raise ValueError('NATIVE_AUDIT_SINGLE_TARGET_AST_STAGE_REQUIRED')
    root = str(Path(receipt['candidatePath']).parent)
    rows = []
    for command in receipt['commands']:
        # Every archived stream must still match its own raw byte digest.
        for stream in ('stdout', 'stderr'):
            if digest(command[stream+'Path']) != command[stream+'Digest']:
                raise ValueError('NATIVE_TRANSLATION_COMMAND_ARTIFACT_CHANGED')
        stdout = (canonical_stdout(receipt, command) if command['stage'] == 'target-ast'
                  else {'kind': 'bytes', 'digest': command['stdoutDigest']})
        argv = [('$OUTPUT/'+arg[len(root)+1:]) if arg.startswith(root+'/') else arg
                for arg in command['command']]
        rows.append({**{k: command[k] for k in ('stage', 'returnCode', 'stdinIdentity',
            'stderrDigest')}, 'stdoutEvidence': stdout, 'command': argv})
    return rows
