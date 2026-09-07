"""L2-A differential validation for GNU inline-asm logical operands.

The validator deliberately consumes only versioned frontend/compiler facts and
v2 execution observations.  Physical register names and reconstructed source
text are never used to establish an operand identity or type.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Mapping

from .translation_validation import ValidationLayerResult, ValidationLevel
from .validation_observation import CanonicalValue, ExecutionObservation, LogicalOperandObservation
from .validation_status import ValidationStatus
from .l1_differential import ARCHITECTURAL_COMPARISON_POLICY


LOGICAL_OPERAND_AUTHORITY_SCHEMA = "riscv2x86.logical-operand-authority.v1"
L2_OPERAND_RUNNER_SCHEMA = "riscv2x86.l2-operand-differential-runner.v1"
L2_OPERAND_COMPARISON_POLICY = ARCHITECTURAL_COMPARISON_POLICY
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACCESS = {"input", "output", "read_write"}
_SIGNEDNESS = {"signed", "unsigned", "not_applicable"}
_ROLES = {"normal", "discarded_output", "constant_zero_input"}


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + sha256(encoded.encode("utf-8")).hexdigest()


def _fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} fields are incomplete or unknown")


def _string(value: Mapping[str, object], name: str, label: str, *, empty: bool = False) -> str:
    item = value.get(name)
    if not isinstance(item, str) or (not empty and not item):
        raise ValueError(f"{label}.{name} must be a string")
    return item


def _boolean(value: Mapping[str, object], name: str, label: str) -> bool:
    item = value.get(name)
    if not isinstance(item, bool):
        raise ValueError(f"{label}.{name} must be boolean")
    return item


def _integer(value: Mapping[str, object], name: str, label: str) -> int:
    item = value.get(name)
    if isinstance(item, bool) or not isinstance(item, int):
        raise ValueError(f"{label}.{name} must be an integer")
    return item


@dataclass(frozen=True)
class LogicalOperandAuthorityFact:
    operand_index: int
    operand_name: str
    operand_id: str
    access_mode: str
    width_bits: int
    signedness: str
    tied_to_operand_index: int | None
    early_clobber: bool
    source_fixed_register_constraint: str
    target_fixed_register_constraint: str
    escaped: bool
    semantic_role: str
    target_recipe_carries_early_clobber: bool
    source_contract_satisfied: bool
    target_contract_satisfied: bool

    def __post_init__(self) -> None:
        if self.operand_index < 0 or not self.operand_name or not self.operand_id:
            raise ValueError("operand authority identity is incomplete")
        if self.access_mode not in _ACCESS or self.width_bits <= 0:
            raise ValueError("operand authority access or width is invalid")
        if self.signedness not in _SIGNEDNESS or self.semantic_role not in _ROLES:
            raise ValueError("operand authority signedness or role is invalid")
        if self.tied_to_operand_index is not None and self.tied_to_operand_index < 0:
            raise ValueError("tied operand index is invalid")
        if self.semantic_role == "discarded_output" and self.access_mode != "output":
            raise ValueError("discarded output role requires an output operand")
        if self.semantic_role == "constant_zero_input" and self.access_mode != "input":
            raise ValueError("constant-zero role requires an input operand")
        if self.target_recipe_carries_early_clobber and not self.early_clobber:
            raise ValueError("target recipe cannot carry undeclared early-clobber")


@dataclass(frozen=True)
class FragmentOperandAuthority:
    fragment_id: str
    shell_transportability_status: str
    operands: tuple[LogicalOperandAuthorityFact, ...]

    def __post_init__(self) -> None:
        if not self.fragment_id or self.shell_transportability_status not in {"verified", "failed", "inconclusive"}:
            raise ValueError("fragment authority is incomplete")
        indices = tuple(item.operand_index for item in self.operands)
        ids = tuple(item.operand_id for item in self.operands)
        if indices != tuple(sorted(set(indices))) or len(ids) != len(set(ids)):
            raise ValueError("authority operands must be unique and ordered by index")
        available = set(indices)
        if any(item.tied_to_operand_index not in available for item in self.operands if item.tied_to_operand_index is not None):
            raise ValueError("tied operand references an unknown operand index")


@dataclass(frozen=True)
class LogicalOperandAuthoritySidecar:
    producer_kind: str
    producer_id: str
    producer_version: str
    producer_binary_digest: str
    fragments: tuple[FragmentOperandAuthority, ...]
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.producer_kind not in {"frontend-sidecar", "compiler-sidecar"}:
            raise ValueError("operand facts must come from a frontend/compiler sidecar")
        if not self.producer_id or not self.producer_version or not _SHA256.fullmatch(self.producer_binary_digest):
            raise ValueError("operand sidecar producer identity is incomplete")
        ids = tuple(item.fragment_id for item in self.fragments)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("sidecar fragments must be unique and canonically ordered")

    @property
    def identity(self) -> str:
        return _canonical_digest(self.payload)

    def for_fragment(self, fragment_id: str) -> FragmentOperandAuthority | None:
        return next((item for item in self.fragments if item.fragment_id == fragment_id), None)


@dataclass(frozen=True)
class L2OperandRunnerConfig:
    authority_sidecar_path: str
    comparison_policy: str = L2_OPERAND_COMPARISON_POLICY
    schema_version: str = L2_OPERAND_RUNNER_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != L2_OPERAND_RUNNER_SCHEMA or not self.authority_sidecar_path:
            raise ValueError("L2 operand runner configuration is invalid")
        if self.comparison_policy != L2_OPERAND_COMPARISON_POLICY:
            raise ValueError("L2 operand comparison policy is unsupported")


def _parse_operand(value: Mapping[str, object]) -> LogicalOperandAuthorityFact:
    label = "operand authority"
    fields = {"operandIndex", "operandName", "operandId", "accessMode", "widthBits", "signedness",
              "tiedToOperandIndex", "earlyClobber", "sourceFixedRegisterConstraint",
              "targetFixedRegisterConstraint", "escaped", "semanticRole",
              "targetRecipeCarriesEarlyClobber", "sourceContractSatisfied", "targetContractSatisfied"}
    _fields(value, fields, label)
    tied = value.get("tiedToOperandIndex")
    if tied is not None and (isinstance(tied, bool) or not isinstance(tied, int)):
        raise ValueError("tiedToOperandIndex must be an integer or null")
    return LogicalOperandAuthorityFact(
        _integer(value, "operandIndex", label), _string(value, "operandName", label),
        _string(value, "operandId", label), _string(value, "accessMode", label),
        _integer(value, "widthBits", label), _string(value, "signedness", label), tied,
        _boolean(value, "earlyClobber", label),
        _string(value, "sourceFixedRegisterConstraint", label, empty=True),
        _string(value, "targetFixedRegisterConstraint", label, empty=True),
        _boolean(value, "escaped", label), _string(value, "semanticRole", label),
        _boolean(value, "targetRecipeCarriesEarlyClobber", label),
        _boolean(value, "sourceContractSatisfied", label),
        _boolean(value, "targetContractSatisfied", label),
    )


def logical_operand_authority_from_dict(value: Mapping[str, object]) -> LogicalOperandAuthoritySidecar:
    fields = {"schemaVersion", "producerKind", "producerId", "producerVersion",
              "producerBinaryDigest", "fragments"}
    _fields(value, fields, "logical operand authority sidecar")
    if value.get("schemaVersion") != LOGICAL_OPERAND_AUTHORITY_SCHEMA:
        raise ValueError("logical operand authority schema is unsupported")
    raw_fragments = value.get("fragments")
    if not isinstance(raw_fragments, list):
        raise ValueError("sidecar fragments must be an array")
    fragments = []
    for raw in raw_fragments:
        if not isinstance(raw, Mapping):
            raise ValueError("sidecar fragment must be an object")
        _fields(raw, {"fragmentId", "shellTransportabilityStatus", "operands"}, "fragment authority")
        raw_operands = raw.get("operands")
        if not isinstance(raw_operands, list):
            raise ValueError("fragment operands must be an array")
        operands = []
        for item in raw_operands:
            if not isinstance(item, Mapping):
                raise ValueError("operand authority must be an object")
            operands.append(_parse_operand(item))
        fragments.append(FragmentOperandAuthority(
            _string(raw, "fragmentId", "fragment authority"),
            _string(raw, "shellTransportabilityStatus", "fragment authority"), tuple(operands),
        ))
    return LogicalOperandAuthoritySidecar(
        _string(value, "producerKind", "sidecar"), _string(value, "producerId", "sidecar"),
        _string(value, "producerVersion", "sidecar"),
        _string(value, "producerBinaryDigest", "sidecar"), tuple(fragments), dict(value),
    )


def load_logical_operand_authority(path: str | Path) -> LogicalOperandAuthoritySidecar:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("logical operand authority sidecar must be an object")
    return logical_operand_authority_from_dict(value)


def load_l2_operand_runner_config(value: Mapping[str, object]) -> L2OperandRunnerConfig:
    _fields(value, {"schemaVersion", "authoritySidecarPath", "comparisonPolicy"}, "L2 operand runner")
    return L2OperandRunnerConfig(
        _string(value, "authoritySidecarPath", "L2 operand runner"),
        _string(value, "comparisonPolicy", "L2 operand runner"),
        _string(value, "schemaVersion", "L2 operand runner"),
    )


def _is_zero(value: CanonicalValue | None) -> bool:
    return value is not None and value.type_name != "ptr" and int(value.bits, 16) == 0


def _validate_observed_fact(observed: LogicalOperandObservation, fact: LogicalOperandAuthorityFact,
                            *, fixed_constraint: str, authority_identity: str) -> str | None:
    if observed.shell_fact_identity != authority_identity:
        return "authority-identity-mismatch"
    if (observed.operand_index, observed.operand_name, observed.operand_id) != (
            fact.operand_index, fact.operand_name, fact.operand_id):
        return "logical-identity-mismatch"
    if (observed.access, observed.width_bits, observed.signedness) != (
            fact.access_mode, fact.width_bits, fact.signedness):
        return "authoritative-type-or-access-mismatch"
    if observed.escaped != fact.escaped or observed.early_clobber != fact.early_clobber:
        return "shell-fact-mismatch"
    if observed.fixed_register_constraint != fixed_constraint:
        return "fixed-register-contract-mismatch"
    for value in (observed.before, observed.after):
        if value is None:
            continue
        if value.type_name == "ptr":
            if fact.signedness != "not_applicable":
                return "authoritative-value-type-mismatch"
            continue
        prefix = {"signed": "i", "unsigned": "u"}.get(fact.signedness)
        if value.width_bits != fact.width_bits or (prefix is not None and value.type_name != prefix + str(fact.width_bits)):
            return "authoritative-value-type-mismatch"
    return None


def compare_logical_operands(*, source: ExecutionObservation, target: ExecutionObservation,
                             authority: LogicalOperandAuthoritySidecar, fragment_id: str) -> tuple[str, ...]:
    fragment = authority.for_fragment(fragment_id)
    if fragment is None:
        return ("authority-fragment-missing",)
    if fragment.shell_transportability_status != "verified":
        return ("shell-transportability-not-verified",)
    source_by_index = {item.operand_index: item for item in source.logical_operands if item.fragment_id == fragment_id}
    target_by_index = {item.operand_index: item for item in target.logical_operands if item.fragment_id == fragment_id}
    reasons: list[str] = []
    facts = {item.operand_index: item for item in fragment.operands}
    allowed = set(facts)
    if set(source_by_index) - allowed or set(target_by_index) - allowed:
        reasons.append("undeclared-logical-operand")
    for fact in fragment.operands:
        prefix = f"operand:{fact.operand_index}:"
        if fact.access_mode in {"output", "read_write"} and fact.escaped:
            reasons.append(prefix + "output-escape-unproven")
        if not fact.source_contract_satisfied or not fact.target_contract_satisfied:
            reasons.append(prefix + "fixed-register-or-shell-contract-unsatisfied")
        if fact.early_clobber and not fact.target_recipe_carries_early_clobber:
            reasons.append(prefix + "early-clobber-not-carried")
        source_item, target_item = source_by_index.get(fact.operand_index), target_by_index.get(fact.operand_index)
        optional = fact.semantic_role in {"discarded_output", "constant_zero_input"}
        if source_item is None or target_item is None:
            if not optional:
                reasons.append(prefix + "observation-missing")
            continue
        for item, fixed, side in ((source_item, fact.source_fixed_register_constraint, "source"),
                                  (target_item, fact.target_fixed_register_constraint, "target")):
            problem = _validate_observed_fact(item, fact, fixed_constraint=fixed,
                                              authority_identity=authority.identity)
            if problem:
                reasons.append(prefix + side + "-" + problem)
        tied_id = ""
        if fact.tied_to_operand_index is not None:
            tied_id = facts[fact.tied_to_operand_index].operand_id
        if source_item.tied_to_operand_id != tied_id or target_item.tied_to_operand_id != tied_id:
            reasons.append(prefix + "tied-relation-mismatch")
        if fact.semantic_role == "constant_zero_input":
            if not _is_zero(source_item.before) or not _is_zero(target_item.before):
                reasons.append(prefix + "constant-zero-value-mismatch")
            continue
        if fact.semantic_role == "discarded_output":
            continue
        if fact.access_mode in {"input", "read_write"} and source_item.before != target_item.before:
            reasons.append(prefix + "initial-value-mismatch")
        if fact.access_mode in {"output", "read_write"} and source_item.after != target_item.after:
            reasons.append(prefix + "final-value-mismatch")
    return tuple(sorted(set(reasons)))


def run_l2_operand_differential(config: L2OperandRunnerConfig, **kwargs: object) -> ValidationLayerResult:
    if kwargs.get("level") is not ValidationLevel.L2:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                     detail="L2 operand validator invoked for the wrong level")
    source, target = kwargs.get("source_observation"), kwargs.get("target_observation")
    if not isinstance(source, ExecutionObservation) or not isinstance(target, ExecutionObservation):
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail="L2-A requires source and target execution observations")
    if kwargs.get("comparison_policy") != config.comparison_policy:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                     detail="L2-A comparison policy mismatch")
    artifact = kwargs.get("translation_artifact")
    fragment_id = getattr(artifact, "fragment_id", "")
    shell_identity = getattr(artifact, "shell_facts_identity", "")
    try:
        authority = load_logical_operand_authority(config.authority_sidecar_path)
    except OSError as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.INCONCLUSIVE,
                                     detail="L2-A authority sidecar unavailable: " + str(exc))
    except (ValueError, json.JSONDecodeError) as exc:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                     detail="L2-A authority sidecar is invalid: " + str(exc))
    if authority.identity != shell_identity:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED,
                                     detail="L2-A authority sidecar does not bind translation shell facts")
    reasons = compare_logical_operands(source=source, target=target, authority=authority,
                                       fragment_id=fragment_id)
    evidence = _canonical_digest({
        "schemaVersion": L2_OPERAND_RUNNER_SCHEMA, "authorityIdentity": authority.identity,
        "sourceObservationIdentity": source.identity, "targetObservationIdentity": target.identity,
        "fragmentId": fragment_id, "comparisonPolicy": config.comparison_policy,
        "reasons": list(reasons),
    })
    if reasons:
        return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.FAILED, evidence,
                                     json.dumps(reasons, separators=(",", ":")))
    return ValidationLayerResult(ValidationLevel.L2, ValidationStatus.VERIFIED, evidence,
                                 "logical operand values and shell relations match")


def build_l2_operand_validator(config: L2OperandRunnerConfig):
    def validate(**kwargs: object) -> ValidationLayerResult:
        return run_l2_operand_differential(config, **kwargs)
    return validate
