from riscv2x86_py.l2_semantic_profile import (
    L2ControlFlowShape, L2FragmentSemanticProfile, L2InternalStateShape,
    L2MemoryShape, L2OperandShape, L2OrderingShape, L2PatternKind,
    L2PrivilegedShape,
)


_CAPABILITIES = {
    L2PatternKind.SCALAR: ("logical_operand_observation", "shell_observation"),
    L2PatternKind.COMPOSITE: ("composite_fragment_observation", "shell_observation"),
}


def profile_dict(fragment_id="fragment:1", kind=L2PatternKind.SCALAR):
    capabilities = _CAPABILITIES[kind]
    return L2FragmentSemanticProfile(
        fragment_id, kind, L2OperandShape(1, 1, 0, True),
        L2ControlFlowShape(False, False, False, False, False, 0, True),
        L2MemoryShape(False, False, False, False, True),
        L2OrderingShape(False, False, True, True),
        L2PrivilegedShape(False, False, False, True),
        L2InternalStateShape(False, False, True, True),
        "rv64gc-user-to-x86_64-user", tuple(sorted(capabilities)),
    ).to_dict()
