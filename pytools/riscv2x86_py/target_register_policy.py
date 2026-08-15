"""Global policy for translator-emitted target register references.

The policy applies to explicit target GNU-asm constraints/templates and
renderer output.  It does *not* prohibit the target C compiler from using its
own stack/frame registers in prologues or epilogues.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import re

POLICY_VERSION = "host-stack-frame-register-policy.v1"

class TargetRegisterUseKind(str, Enum):
    FIXED_OPERAND = "fixed_operand"
    CLOBBER = "clobber"
    ASM_TEMPLATE = "asm_template"
    FRAME_ADDRESS_BUILTIN = "frame_address_builtin"

@dataclass(frozen=True)
class TargetFixedRegisterPolicy:
    target_abi: str
    forbidden_fixed_registers: frozenset[str]
    version: str

HOST_STACK_FRAME_REGISTER_POLICY = TargetFixedRegisterPolicy(
    "sysv-amd64",
    frozenset({"rsp", "esp", "sp", "spl", "rbp", "ebp", "bp", "bpl"}),
    POLICY_VERSION,
)

_ALIASES = {
    "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
}
_TEMPLATE = re.compile(r"(?<![A-Za-z0-9_])%{1,2}(?:r|e)?(?:sp|bp)|(?<![A-Za-z0-9_])%{1,2}(?:spl|bpl)(?![A-Za-z0-9_])", re.IGNORECASE)
_FIXED = re.compile(r'\{\s*(?:r|e)?(?:sp|bp)\s*\}|\{\s*(?:spl|bpl)\s*\}', re.IGNORECASE)
_CLOBBER = re.compile(r'["\'](?:r|e)?(?:sp|bp|spl|bpl)["\']', re.IGNORECASE)

def canonical_target_register_name(name: str | None) -> str | None:
    if not isinstance(name, str): return None
    value = name.strip().lower()
    if value.startswith("%"): value = value.lstrip("%")
    if value.startswith("{") and value.endswith("}"): value = value[1:-1].strip()
    return _ALIASES.get(value, value or None)

def is_forbidden_host_stack_frame_register(name: str | None) -> bool:
    return canonical_target_register_name(name) in {"rsp", "rbp"}

def validate_target_fixed_register(*, register_name: str | None, use_kind: TargetRegisterUseKind = TargetRegisterUseKind.FIXED_OPERAND) -> tuple[bool, str | None]:
    canonical = canonical_target_register_name(register_name)
    if canonical is None: return False, "target-register.unknown-fixed-register-name"
    if canonical in {"rsp", "rbp"}:
        suffix = "clobber" if use_kind is TargetRegisterUseKind.CLOBBER else "fixed-register"
        return False, "target-register.host-stack-frame-" + suffix + "-forbidden"
    return True, None

def audit_translator_emitted_target_registers(emitted_text: str | None) -> tuple[str, ...]:
    """A lexical last line of defence after structured contract validation."""
    if not isinstance(emitted_text, str): return ("target-register.emitted-text-invalid",)
    reasons = []
    if _TEMPLATE.search(emitted_text): reasons.append("target-register.host-stack-frame-template-reference-forbidden")
    if _FIXED.search(emitted_text): reasons.append("target-register.host-stack-frame-fixed-register-forbidden")
    if _CLOBBER.search(emitted_text): reasons.append("target-register.host-stack-frame-clobber-forbidden")
    if "__builtin_frame_address" in emitted_text: reasons.append("target-register.frame-address-builtin-forbidden")
    return tuple(sorted(set(reasons)))
