"""Strict, replayable Phase-8 L1 program-test case contracts."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import random
import re
from typing import Mapping


VALIDATION_CASE_SCHEMA = "riscv2x86.validation-case.v1"
VALIDATION_INPUT_SCHEMA = "riscv2x86.validation-input.v1"
INPUT_GENERATOR_VERSION = "boundary-and-random-v1"
_INTEGER_TYPES = {
    "i8": (8, True), "u8": (8, False), "i16": (16, True),
    "u16": (16, False), "i32": (32, True), "u32": (32, False),
    "i64": (64, True), "u64": (64, False),
}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def _fields(value: Mapping[str, object], required: set[str], optional: set[str], label: str) -> None:
    if not required <= set(value) or not set(value) <= required | optional:
        raise ValueError(label + " fields are incomplete or unknown")


def _text(value: Mapping[str, object], name: str, label: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{label}.{name} must be a non-empty string")
    return item


def _string_array(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(label + " must be an array of strings")
    result = tuple(value)
    if tuple(sorted(set(result))) != result:
        raise ValueError(label + " must be unique and sorted")
    return result


@dataclass(frozen=True)
class ArgumentDomain:
    name: str
    type_name: str
    role: str = "value"

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.name) or self.type_name not in _INTEGER_TYPES:
            raise ValueError("argument domain name/type is invalid")
        if self.role not in {"value", "shift", "immediate", "offset"}:
            raise ValueError("argument domain role is invalid")


@dataclass(frozen=True)
class MemoryInputDomain:
    object_id: str
    size_bytes: int
    offsets: tuple[int, ...]
    alignments: tuple[int, ...]

    def __post_init__(self) -> None:
        if not _SAFE_ID.fullmatch(self.object_id) or self.size_bytes <= 0:
            raise ValueError("memory input domain is invalid")
        if not self.offsets or any(x < 0 or x >= self.size_bytes for x in self.offsets):
            raise ValueError("memory offsets are invalid")
        if not self.alignments or any(x <= 0 or x & (x - 1) for x in self.alignments):
            raise ValueError("memory alignments must be positive powers of two")


@dataclass(frozen=True)
class ComparisonContract:
    return_value: bool
    exit_code: bool
    stdout: bool
    stderr: bool
    assertions: bool
    exported_state: tuple[str, ...]
    memory_objects: tuple[str, ...]
    api_results: tuple[str, ...]
    external_files: tuple[str, ...]

    def __post_init__(self) -> None:
        if not all(isinstance(x, bool) for x in (
            self.return_value, self.exit_code, self.stdout, self.stderr,
            self.assertions,
        )):
            raise ValueError("comparison switches must be booleans")
        for path in self.external_files:
            candidate = Path(path)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError("external file observations must stay inside the harness directory")


@dataclass(frozen=True)
class ValidationCase:
    test_id: str
    input_generator: str
    seed: int
    arguments: tuple[ArgumentDomain, ...]
    memory_inputs: tuple[MemoryInputDomain, ...]
    alias_pairs: tuple[tuple[str, str], ...]
    random_cases: int
    comparison: ComparisonContract
    execution_profile: str = "rv64gc-linux-user-v1"
    schema_version: str = VALIDATION_CASE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_CASE_SCHEMA or not _SAFE_ID.fullmatch(self.test_id):
            raise ValueError("validation case schema/test ID is invalid")
        if self.input_generator != INPUT_GENERATOR_VERSION:
            raise ValueError("input generator is unsupported")
        if self.execution_profile not in {
            "rv64gc-linux-user-v1", "rv64-linux-system-v1", "riscv-privileged-v1",
        }:
            raise ValueError("validation execution profile is unsupported")
        if isinstance(self.seed, bool) or self.seed < 0 or self.random_cases < 0:
            raise ValueError("validation seed/random case count is invalid")
        names = tuple(x.name for x in self.arguments)
        if not names or tuple(sorted(set(names))) != tuple(sorted(names)):
            raise ValueError("argument names must be unique")
        objects = {x.object_id for x in self.memory_inputs}
        if len(objects) != len(self.memory_inputs):
            raise ValueError("memory object IDs must be unique")
        if any(a not in objects or b not in objects or a == b for a, b in self.alias_pairs):
            raise ValueError("alias pair references invalid memory objects")
        if not set(self.comparison.memory_objects).issubset(objects):
            raise ValueError("comparison references an undeclared memory object")


def validation_case_from_dict(value: Mapping[str, object]) -> ValidationCase:
    _fields(value, {"schemaVersion", "testId", "inputGenerator", "seed", "inputDomain", "comparison"},
            {"executionProfile"}, "case")
    domain, comparison = value.get("inputDomain"), value.get("comparison")
    if not isinstance(domain, Mapping) or not isinstance(comparison, Mapping):
        raise ValueError("inputDomain/comparison must be objects")
    _fields(domain, {"arguments"}, {"memoryObjects", "aliasPairs", "randomCases"}, "input domain")
    raw_arguments = domain.get("arguments")
    if not isinstance(raw_arguments, list):
        raise ValueError("arguments must be an array")
    arguments = []
    for raw in raw_arguments:
        if not isinstance(raw, Mapping):
            raise ValueError("argument entry must be an object")
        _fields(raw, {"name", "type"}, {"role"}, "argument")
        arguments.append(ArgumentDomain(
            _text(raw, "name", "argument"), _text(raw, "type", "argument"),
            str(raw.get("role", "value")),
        ))
    memories = []
    for raw in domain.get("memoryObjects", []):
        if not isinstance(raw, Mapping):
            raise ValueError("memory object entry must be an object")
        _fields(raw, {"objectId", "sizeBytes", "offsets", "alignments"}, set(), "memory object")
        offsets, alignments = raw.get("offsets"), raw.get("alignments")
        if not isinstance(offsets, list) or not isinstance(alignments, list):
            raise ValueError("memory offsets/alignments must be arrays")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (*offsets, *alignments)):
            raise ValueError("memory offsets/alignments must be integers")
        size = raw.get("sizeBytes")
        if isinstance(size, bool) or not isinstance(size, int):
            raise ValueError("memory size must be an integer")
        memories.append(MemoryInputDomain(
            _text(raw, "objectId", "memory"), size,
            tuple(offsets), tuple(alignments),
        ))
    aliases = []
    for raw in domain.get("aliasPairs", []):
        if not isinstance(raw, list) or len(raw) != 2 or not all(isinstance(x, str) for x in raw):
            raise ValueError("alias pair must contain two object IDs")
        aliases.append((raw[0], raw[1]))
    random_cases = domain.get("randomCases", 32)
    if isinstance(random_cases, bool) or not isinstance(random_cases, int):
        raise ValueError("randomCases must be an integer")
    _fields(comparison, set(), {"returnValue", "exitCode", "stdout", "stderr", "assertions",
                                "exportedState", "memoryObjects", "apiResults", "externalFiles"}, "comparison")
    def switch(name: str, default: bool = False) -> bool:
        item = comparison.get(name, default)
        if not isinstance(item, bool):
            raise ValueError("comparison." + name + " must be boolean")
        return item
    return ValidationCase(
        _text(value, "testId", "case"), _text(value, "inputGenerator", "case"),
        value["seed"] if isinstance(value.get("seed"), int) and not isinstance(value.get("seed"), bool) else -1,
        tuple(arguments), tuple(memories), tuple(aliases), random_cases,
        ComparisonContract(
            switch("returnValue"), switch("exitCode"), switch("stdout"), switch("stderr"),
            switch("assertions", True), _string_array(comparison.get("exportedState", []), "exportedState"),
            _string_array(comparison.get("memoryObjects", []), "memoryObjects"),
            _string_array(comparison.get("apiResults", []), "apiResults"),
            _string_array(comparison.get("externalFiles", []), "externalFiles"),
        ),
        str(value.get("executionProfile", "rv64gc-linux-user-v1")),
        str(value.get("schemaVersion", "")),
    )


def load_validation_case(path: str | Path) -> ValidationCase:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("validation case must be an object")
    return validation_case_from_dict(raw)


def _integer_boundaries(argument: ArgumentDomain) -> tuple[int, ...]:
    width, signed = _INTEGER_TYPES[argument.type_name]
    mask = (1 << width) - 1
    values = {0, 1, mask, mask >> 1, 1 << (width - 1)}
    for value in (0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
        values.add(value & mask)
    if signed:
        values.update({-(1 << (width - 1)), (1 << (width - 1)) - 1, -1})
    if argument.role == "shift":
        values.update({width - 1, width, width + 1})
    return tuple(sorted(values))


def generate_validation_inputs(case: ValidationCase) -> tuple[dict[str, object], ...]:
    """Generate deterministic boundary, memory-layout, alias and random cases."""
    generated: list[dict[str, object]] = []
    zero = {argument.name: 0 for argument in case.arguments}
    generated.append({"arguments": dict(zero), "memory": {}, "aliases": []})
    for argument in case.arguments:
        for value in _integer_boundaries(argument):
            values = dict(zero)
            values[argument.name] = value
            generated.append({"arguments": values, "memory": {}, "aliases": []})
    for memory in case.memory_inputs:
        for offset in memory.offsets:
            for alignment in memory.alignments:
                generated.append({"arguments": dict(zero), "memory": {
                    memory.object_id: {"sizeBytes": memory.size_bytes, "offset": offset,
                                       "alignment": alignment, "fillByte": 0xA5},
                }, "aliases": []})
    for pair in case.alias_pairs:
        generated.append({"arguments": dict(zero), "memory": {}, "aliases": [list(pair)]})
        generated.append({"arguments": dict(zero), "memory": {}, "aliases": []})
    rng = random.Random(case.seed)
    for _ in range(case.random_cases):
        values = {}
        for argument in case.arguments:
            width, signed = _INTEGER_TYPES[argument.type_name]
            value = rng.getrandbits(width)
            if signed and value >= 1 << (width - 1):
                value -= 1 << width
            values[argument.name] = value
        generated.append({"arguments": values, "memory": {}, "aliases": []})
    unique: dict[str, dict[str, object]] = {}
    for item in generated:
        identity = json.dumps(item, sort_keys=True, separators=(",", ":"))
        unique.setdefault(identity, item)
    result = []
    for index, item in enumerate(unique.values()):
        payload = {"schemaVersion": VALIDATION_INPUT_SCHEMA, "testId": case.test_id,
                   "caseIndex": index, **item}
        payload["inputIdentity"] = "sha256:" + sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        result.append(payload)
    return tuple(result)
