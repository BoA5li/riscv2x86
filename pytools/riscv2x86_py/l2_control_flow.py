"""Proof-owned control-flow facts and strict L2 control observations."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .effect_relation import ApprovedEffectRelation
from .l2_authority import L2ControlFlowAuthority, L2OperandAuthority


L2_CONTROL_FLOW_PROOF_FACTS_SCHEMA = "riscv2x86.l2-control-flow-proof-facts.v1"
L2_CONTROL_FLOW_OBSERVATION_SCHEMA = "riscv2x86.l2-control-flow-observation.v1"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONDITIONS = {"equal", "not_equal", "signed_less", "unsigned_less",
               "signed_less_equal", "unsigned_less_equal"}


def _identity(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(data).hexdigest()


@dataclass(frozen=True)
class L2ControlFlowProofFacts:
    fragment_id: str
    pattern_kind: str
    condition_kind: str
    condition_operand_indexes: tuple[int, ...]
    true_value_operand_index: int | None
    false_value_operand_index: int | None
    selected_value_operand_index: int | None
    result_operand_index: int
    continuations: tuple[str, ...]
    source_continuation: str
    target_continuation: str
    direct: bool
    no_non_local_transfer: bool
    no_exception: bool
    no_signal: bool
    no_trap: bool
    internal_escape_complete: bool
    continuations_encodable: bool
    complete: bool
    facts_identity: str = ""
    schema_version: str = L2_CONTROL_FLOW_PROOF_FACTS_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_CONTROL_FLOW_PROOF_FACTS_SCHEMA or not self.fragment_id:
            raise ValueError("control-flow proof facts schema/fragment is invalid")
        indexes = (*self.condition_operand_indexes, self.result_operand_index,
                   *(x for x in (self.true_value_operand_index, self.false_value_operand_index,
                                 self.selected_value_operand_index) if x is not None))
        if any(isinstance(x, bool) or not isinstance(x, int) or x < 0 for x in indexes):
            raise ValueError("control-flow proof operand index is invalid")
        if self.continuations != tuple(sorted(set(self.continuations))) or not self.continuations:
            raise ValueError("control-flow proof continuations must be non-empty, unique, and sorted")
        if self.pattern_kind == "branch":
            if (self.condition_kind not in _CONDITIONS or len(self.condition_operand_indexes) != 2
                    or self.true_value_operand_index is None or self.false_value_operand_index is None
                    or self.selected_value_operand_index is not None
                    or set(self.continuations) != {"continuation:not-taken", "continuation:taken"}):
                raise ValueError("branch proof facts are incomplete")
        elif self.pattern_kind == "jump":
            if (self.condition_kind or self.condition_operand_indexes
                    or self.selected_value_operand_index is None
                    or self.true_value_operand_index is not None
                    or self.false_value_operand_index is not None
                    or self.continuations != ("continuation:target",)
                    or self.source_continuation != "entry"
                    or self.target_continuation != "continuation:target"):
                raise ValueError("jump proof facts are incomplete")
        else:
            raise ValueError("control-flow proof pattern is unsupported")
        closed = all((self.direct, self.no_non_local_transfer, self.no_exception,
                      self.no_signal, self.no_trap, self.internal_escape_complete,
                      self.continuations_encodable))
        if self.complete != closed:
            raise ValueError("control-flow proof completeness does not match safety facts")
        expected = _identity(self._payload(False))
        if self.facts_identity and self.facts_identity != expected:
            raise ValueError("control-flow proof facts identity does not match content")
        object.__setattr__(self, "facts_identity", expected)

    def _payload(self, include_identity: bool) -> dict[str, object]:
        result = {"schemaVersion": self.schema_version, "fragmentId": self.fragment_id,
          "patternKind": self.pattern_kind, "conditionKind": self.condition_kind,
          "conditionOperandIndexes": list(self.condition_operand_indexes),
          "trueValueOperandIndex": self.true_value_operand_index,
          "falseValueOperandIndex": self.false_value_operand_index,
          "selectedValueOperandIndex": self.selected_value_operand_index,
          "resultOperandIndex": self.result_operand_index,
          "continuations": list(self.continuations),
          "sourceContinuation": self.source_continuation,
          "targetContinuation": self.target_continuation,
          "direct": self.direct, "noNonLocalTransfer": self.no_non_local_transfer,
          "noException": self.no_exception, "noSignal": self.no_signal,
          "noTrap": self.no_trap, "internalEscapeComplete": self.internal_escape_complete,
          "continuationsEncodable": self.continuations_encodable, "complete": self.complete}
        if include_identity:
            result["factsIdentity"] = self.facts_identity
        return result

    def to_dict(self) -> dict[str, object]:
        return self._payload(True)


def control_flow_proof_facts_from_source_model(
    fragment_id: str, source_model: object,
) -> L2ControlFlowProofFacts | None:
    """Export only normalized Phase-6A proof facts; inspect no source text."""
    branch = getattr(source_model, "local_branch_select", None)
    jump = getattr(source_model, "local_unconditional_jump", None)
    control = getattr(source_model, "control_flow", None)
    operation = getattr(source_model, "operation", None)
    internal = getattr(source_model, "operands", None)
    safe = dict(
        direct=(not bool(getattr(control, "has_indirect_control_flow", True))
                and not bool(getattr(control, "has_unknown_target", True))
                and not bool(getattr(control, "has_external_control_flow", True))),
        no_non_local_transfer=not bool(getattr(control, "has_non_local_control_dependency", True)),
        no_exception=not any(bool(getattr(control, name, True)) for name in (
            "has_multiple_exits", "has_call", "has_return", "has_tail_call")),
        no_signal=True,
        no_trap=getattr(operation, "may_trap", None) is False,
        internal_escape_complete=bool(getattr(internal, "complete", False)),
        continuations_encodable=True,
    )
    complete = all(safe.values())
    if branch is not None:
        return L2ControlFlowProofFacts(
            fragment_id, "branch", str(getattr(branch.condition_kind, "value", "")),
            (branch.left_operand_index, branch.right_operand_index),
            branch.true_value_operand_index, branch.false_value_operand_index, None,
            branch.result_operand_index,
            ("continuation:not-taken", "continuation:taken"), "entry", "", complete=complete,
            **safe,
        )
    if jump is not None:
        return L2ControlFlowProofFacts(
            fragment_id, "jump", "", (), None, None, jump.selected_input_operand_index,
            jump.result_operand_index, ("continuation:target",), "entry",
            "continuation:target", complete=complete, **safe,
        )
    return None


def control_flow_proof_facts_from_dict(value: Mapping[str, object]) -> L2ControlFlowProofFacts:
    fields = {"schemaVersion", "fragmentId", "patternKind", "conditionKind",
      "conditionOperandIndexes", "trueValueOperandIndex", "falseValueOperandIndex",
      "selectedValueOperandIndex", "resultOperandIndex", "continuations",
      "sourceContinuation", "targetContinuation", "direct", "noNonLocalTransfer",
      "noException", "noSignal", "noTrap", "internalEscapeComplete",
      "continuationsEncodable", "complete", "factsIdentity"}
    if set(value) != fields:
        raise ValueError("control-flow proof facts fields are incomplete or unknown")
    def text(key: str, empty: bool = False) -> str:
        item = value.get(key)
        if not isinstance(item, str) or (not empty and not item):
            raise ValueError("control-flow proof " + key + " is invalid")
        return item
    def flag(key: str) -> bool:
        item = value.get(key)
        if not isinstance(item, bool):
            raise ValueError("control-flow proof " + key + " must be boolean")
        return item
    def optional_index(key: str) -> int | None:
        item = value.get(key)
        if item is not None and (isinstance(item, bool) or not isinstance(item, int)):
            raise ValueError("control-flow proof " + key + " is invalid")
        return item
    raw_indexes = value.get("conditionOperandIndexes")
    raw_continuations = value.get("continuations")
    if (not isinstance(raw_indexes, list)
            or not all(isinstance(x, int) and not isinstance(x, bool) for x in raw_indexes)
            or not isinstance(raw_continuations, list)
            or not all(isinstance(x, str) and x for x in raw_continuations)):
        raise ValueError("control-flow proof arrays are invalid")
    return L2ControlFlowProofFacts(text("fragmentId"), text("patternKind"),
      text("conditionKind", True), tuple(raw_indexes), optional_index("trueValueOperandIndex"),
      optional_index("falseValueOperandIndex"), optional_index("selectedValueOperandIndex"),
      optional_index("resultOperandIndex"), tuple(raw_continuations),
      text("sourceContinuation", True), text("targetContinuation", True),
      flag("direct"), flag("noNonLocalTransfer"), flag("noException"), flag("noSignal"),
      flag("noTrap"), flag("internalEscapeComplete"), flag("continuationsEncodable"),
      flag("complete"), text("factsIdentity"), text("schemaVersion"))


def bind_control_flow_authority(
    facts: L2ControlFlowProofFacts, operands: Sequence[L2OperandAuthority],
) -> L2ControlFlowAuthority:
    by_index = {x.operand_index: x for x in operands}
    required = {facts.result_operand_index, *facts.condition_operand_indexes,
                *(x for x in (facts.true_value_operand_index, facts.false_value_operand_index,
                              facts.selected_value_operand_index) if x is not None)}
    if not required.issubset(by_index) or not facts.complete:
        raise ValueError("control-flow proof operands/safety facts are incomplete")
    def operand_id(index: int | None) -> str:
        return "" if index is None else by_index[index].operand_id
    inputs = tuple(sorted(operand_id(x) for x in required if x != facts.result_operand_index))
    return L2ControlFlowAuthority(
        "condition:0" if facts.pattern_kind == "branch" else "transfer:0", inputs,
        facts.continuations, True,
        "conditional" if facts.pattern_kind == "branch" else "direct",
        facts.condition_kind, operand_id(facts.result_operand_index),
        operand_id(facts.true_value_operand_index), operand_id(facts.false_value_operand_index),
        operand_id(facts.selected_value_operand_index), facts.source_continuation,
        facts.target_continuation, "normal_return",
    )


@dataclass(frozen=True)
class L2ControlFlowObservation:
    event_id: str
    fragment_id: str
    event_kind: str
    logical_subject: str
    payload: Mapping[str, object]
    sample_id: str = ""
    effect_relation_identity: str = ""

    def __post_init__(self) -> None:
        if not self.event_id or not self.fragment_id:
            raise ValueError("control-flow observation identity is missing")
        branch_fields = {"conditionInputs", "conditionResult", "taken", "continuationId",
                         "result", "termination"}
        jump_fields = {"sourceContinuation", "targetContinuation", "transferKind",
                       "result", "termination"}
        expected = branch_fields if self.event_kind == "Branch" else (
            jump_fields if self.event_kind == "ControlTransfer" else None)
        if expected is None or set(self.payload) != expected:
            raise ValueError("control-flow observation payload is incomplete or unknown")
        if self.payload.get("termination") != "normal_return":
            raise ValueError("automatic control-flow observation termination is unsupported")
        if (not isinstance(self.payload.get("result"), str)
                or re.fullmatch(r"[ui](?:32|64):0x[0-9a-f]+", self.payload["result"]) is None):
            raise ValueError("control-flow observation result is not canonical")
        if self.event_kind == "Branch":
            inputs = self.payload.get("conditionInputs")
            if (not isinstance(inputs, list) or len(inputs) != 2
                    or not all(isinstance(x, str) and re.fullmatch(r"[ui](?:32|64):0x[0-9a-f]+", x)
                               for x in inputs)
                    or not isinstance(self.payload.get("conditionResult"), bool)
                    or not isinstance(self.payload.get("taken"), bool)
                    or self.payload.get("conditionResult") != self.payload.get("taken")
                    or self.payload.get("continuationId") not in {
                        "continuation:taken", "continuation:not-taken"}
                    or self.payload.get("continuationId") != (
                        "continuation:taken" if self.payload.get("taken")
                        else "continuation:not-taken")):
                raise ValueError("branch observation values are invalid")
        elif (self.payload.get("sourceContinuation") != "entry"
              or self.payload.get("targetContinuation") != "continuation:target"
              or self.payload.get("transferKind") != "direct"):
            raise ValueError("direct transfer observation is invalid")

    def to_dict(self) -> dict[str, object]:
        return {"schemaVersion": L2_CONTROL_FLOW_OBSERVATION_SCHEMA,
                "eventId": self.event_id, "fragmentId": self.fragment_id,
                "eventKind": self.event_kind, "logicalSubject": self.logical_subject,
                "payload": dict(self.payload), "sampleId": self.sample_id,
                "effectRelationIdentity": self.effect_relation_identity}


def exact_control_flow_observations_match(
    source: Sequence[L2ControlFlowObservation], target: Sequence[L2ControlFlowObservation],
    relations: Sequence[ApprovedEffectRelation],
) -> tuple[bool, str]:
    if not source or len(source) != len(target):
        return False, "L2_CONTROL_FLOW_OBSERVATION_COUNT_MISMATCH"
    source_by_id = {x.sample_id or f"sample:{index}": x
                    for index, x in enumerate(source)}
    target_by_id = {x.sample_id or f"sample:{index}": x
                    for index, x in enumerate(target)}
    if len(source_by_id) != len(source) or len(target_by_id) != len(target):
        return False, "L2_CONTROL_FLOW_DUPLICATE_EVENT_ID"
    if set(source_by_id) != set(target_by_id):
        return False, "L2_CONTROL_FLOW_APPROVED_EVENT_MISSING"
    for relation in relations:
        if relation.relation_kind != "exact" or len(relation.target_effect_ids) != 1:
            return False, "L2_CONTROL_FLOW_EXACT_RELATION_REQUIRED"
        for sample_id in source_by_id:
            left, right = source_by_id[sample_id], target_by_id[sample_id]
            required = ({"branch_condition", "branch_continuation", "branch_outcome",
                         "kind", "value"} if left.event_kind == "Branch"
                        else {"kind", "target", "value"})
            if not required.issubset(relation.observable_requirements):
                return False, "L2_CONTROL_FLOW_RELATION_OBSERVABLES_INCOMPLETE"
            if ((left.effect_relation_identity and
                 left.effect_relation_identity != relation.approval_identity)
                    or (right.effect_relation_identity and
                        right.effect_relation_identity != relation.approval_identity)
                    or left.event_id != relation.source_effect_id
                    or right.event_id not in relation.target_effect_ids
                    or left.fragment_id != right.fragment_id
                    or left.event_kind != right.event_kind
                    or left.logical_subject != right.logical_subject
                    or dict(left.payload) != dict(right.payload)):
                return False, "L2_CONTROL_FLOW_OBSERVATION_MISMATCH"
    return True, ""
