"""Phase-7 lexical guard for translator-emitted privileged replacements."""
from __future__ import annotations

import re


PRIVILEGED_EMITTED_TEXT_AUDIT_VERSION = (
    "privileged-emitted-text-audit.v1"
)

# Runtime/builtin routes must be C calls.  These tokens are denied even if a
# malicious or malformed recipe somehow bypasses structured identifier checks.
_FORBIDDEN_ASM = re.compile(r"\b(?:__asm__|asm)\b", re.IGNORECASE)
_X86_PRIVILEGED = re.compile(
    r"\b(?:cli|sti|hlt|lgdt|lidt|lldt|ltr|rdmsr|wrmsr|invlpg|invpcid|"
    r"vmcall|vmlaunch|vmresume|vmxoff|swapgs|sysret|iretq?|rsm|wbinvd|"
    r"xsetbv|xgetbv)\b|\bmov\s+%?(?:cr|dr)[0-9]",
    re.IGNORECASE,
)
_RISCV_PRIVILEGED = re.compile(
    r"\b(?:csrrw|csrrs|csrrc|csrrwi|csrrsi|csrrci|mret|sret|uret|wfi|sfence\.vma)\b",
    re.IGNORECASE,
)


def audit_privileged_emitted_text(
    emitted_text: str | None,
    *,
    expected_callable_identifier: str,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if not isinstance(emitted_text, str) or not emitted_text.strip():
        return ("privileged-renderer.emitted-text-invalid",)
    if _FORBIDDEN_ASM.search(emitted_text):
        reasons.append("privileged-renderer.inline-asm-forbidden")
    if _X86_PRIVILEGED.search(emitted_text):
        reasons.append("privileged-renderer.x86-privileged-instruction-forbidden")
    if _RISCV_PRIVILEGED.search(emitted_text):
        reasons.append("privileged-renderer.source-privileged-instruction-residue")
    call = re.compile(
        r"\b" + re.escape(expected_callable_identifier) + r"\s*\("
    )
    if call.search(emitted_text) is None:
        reasons.append("privileged-renderer.registered-callable-missing")
    return tuple(sorted(set(reasons)))
