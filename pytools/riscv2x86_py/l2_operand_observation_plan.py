"""Immutable observation projection of a closed canonical operand join."""
from dataclasses import dataclass
from typing import Mapping, Sequence

from .canonical_l2_operand import CanonicalL2OperandBinding
from .l2_fragment_execution import (
    L2OperandObservationAuthority, identity,
    operand_observation_authority_from_dict,
)

SCHEMA = "riscv2x86.canonical-operand-observation-plan.v1"


@dataclass(frozen=True)
class CanonicalOperandObservationPlan:
    authority: L2OperandObservationAuthority
    instrumentation_operand_indices: tuple[int, ...] = ()

    def __post_init__(self):
        indices = tuple(item.operand_index for item in self.authority.bindings)
        if indices != tuple(range(len(indices))):
            raise ValueError("observation operand indices are not contiguous")
        slots = self.instrumentation_operand_indices
        if (len(slots) != len(set(slots))
                or any(isinstance(index, bool) or not isinstance(index, int)
                       or index not in indices for index in slots)):
            raise ValueError("instrumentation operand slots are invalid")
        required = {item.operand_index for item in self.authority.bindings
                    if item.closure_kind == "instrumentation"}
        if not required.issubset(slots):
            raise ValueError("instrumentation operand slots are missing")

    def to_dict(self):
        payload = {"schemaVersion": SCHEMA,
                   "operandObservationAuthority": self.authority.to_dict(),
                   "instrumentationOperandIndices": list(self.instrumentation_operand_indices)}
        return {**payload, "planIdentity": identity(payload)}


def bind_operand_observation_plan(
    canonical: Sequence[CanonicalL2OperandBinding],
    observation: L2OperandObservationAuthority,
    instrumentation_operand_indices: tuple[int, ...] = (),
) -> CanonicalOperandObservationPlan:
    """Perform the join once, before execution; trace consumers never rejoin."""
    if len(canonical) != len(observation.bindings):
        raise ValueError("canonical observation operand coverage mismatch")
    for fact, binding in zip(canonical, observation.bindings):
        if fact.static_operand != binding.static_operand:
            raise ValueError("canonical static observation binding mismatch")
        if ((fact.fragment_id, fact.operand_id, fact.operand_index,
             fact.declaration_identity, fact.value_node_identity,
             fact.access_mode, fact.width_bits, fact.signedness, fact.parameter_index)
                != (binding.fragment_id, binding.operand_id, binding.operand_index,
                    binding.declaration_identity, binding.value_node_identity,
                    binding.access, binding.width_bits, binding.signedness,
                    binding.parameter_index)):
            raise ValueError("canonical observation operand binding mismatch")
    return CanonicalOperandObservationPlan(observation, instrumentation_operand_indices)


def operand_observation_plan_from_dict(value: Mapping[str, object]):
    if not isinstance(value, Mapping) or set(value) != {
            "schemaVersion", "operandObservationAuthority",
            "instrumentationOperandIndices", "planIdentity"}:
        raise ValueError("canonical observation plan fields are invalid")
    payload = dict(value); claimed = payload.pop("planIdentity")
    if value["schemaVersion"] != SCHEMA or claimed != identity(payload):
        raise ValueError("canonical observation plan identity is invalid")
    raw, slots = value["operandObservationAuthority"], value["instrumentationOperandIndices"]
    if not isinstance(raw, Mapping) or not isinstance(slots, list):
        raise ValueError("canonical observation plan payload is invalid")
    return CanonicalOperandObservationPlan(
        operand_observation_authority_from_dict(raw), tuple(slots))
