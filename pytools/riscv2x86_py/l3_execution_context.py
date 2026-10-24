"""Actual build bindings for L3 observations, separate from platform claims.

A build path/digest is not a CPU model, clock relation, attribution proof or
compiler identity. This context deliberately supplies none of those facts.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .translation_validation import ProgramArtifact

from .l3_intent_requirements import _hash


@dataclass(frozen=True)
class L3ExecutionContext:
    source: "ProgramArtifact"
    target: "ProgramArtifact"
    invocation_id: str

    @classmethod
    def create(cls, source, target):
        context = cls(source, target, str(uuid4()))
        context.validate(source, target)
        return context

    def binding(self, side):
        if side not in {'source', 'target'}:
            raise ValueError('l3.execution.side-invalid')
        artifact = getattr(self, side)
        return {'artifactId': artifact.artifact_id,
                'artifactPath': str(Path(artifact.artifact_path).resolve()),
                'artifactDigest': artifact.artifact_digest,
                'buildIdentity': artifact.build_identity}

    @property
    def identity(self):
        return _hash({'schemaVersion': 'riscv2x86.l3-execution-context.v1',
                      'invocationId': self.invocation_id,
                      'source': self.binding('source'), 'target': self.binding('target')})

    def validate(self, source, target):
        from .translation_validation import ProgramArtifact
        from .l3_intent_requirements import _sha
        if not isinstance(self.invocation_id, str) or not self.invocation_id:
            raise ValueError('l3.execution.invocation-missing')
        for side, expected in (('source', source), ('target', target)):
            actual = getattr(self, side)
            if not isinstance(actual, ProgramArtifact) or actual != expected or not actual.build_identity:
                raise ValueError('l3.execution.artifact-binding-mismatch:' + side)
            _sha(actual.build_identity, "L3 actual build identity")
            path = Path(actual.artifact_path)
            if 'sha256:' + sha256(path.read_bytes()).hexdigest() != actual.artifact_digest:
                raise ValueError('l3.execution.artifact-changed:' + side)

    def request_binding(self, side):
        return {'schemaVersion': 'riscv2x86.l3-observer-execution-binding.v1',
                'contextIdentity': self.identity, 'invocationId': self.invocation_id,
                'side': side, 'program': self.binding(side)}
