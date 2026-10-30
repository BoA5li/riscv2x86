"""Compiler-confirmed joint grammar, never semantic or execution approval."""
from .l3_trace_support import identity


def valid(function):
    scope=function.get('compilerJointScope') or {}
    return ((scope.get('schemaVersion'),scope.get('scope')) in {
        ('riscv2x86.compiler-joint-scope.v1','direct-unsigned64-private-object-regions'),
        ('riscv2x86.compiler-joint-scope.v2','direct-integer-object-unsigned64-carrier-regions')}
        and scope.get('scopeIdentity')==identity({k:v for k,v in scope.items() if k!='scopeIdentity'})
        and scope.get('sourceDigest')==function.get('sourceDigest')
        and scope.get('functionIdentity')==function.get('functionId'))
