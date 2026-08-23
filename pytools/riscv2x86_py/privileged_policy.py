"""Preservation policy for privileged source semantics.

The command-line flag selects only this policy.  It never fabricates source
facts, observability authority, ignored-state authority, or target contracts.
"""
from __future__ import annotations

from enum import Enum


class PrivilegedPreservationPolicy(str, Enum):
    STRICT_ARCHITECTURAL = "strict_architectural"
    FUNCTIONAL_FALLBACK_ALLOWED = "functional_fallback_allowed"

    @property
    def enabled(self) -> bool:
        """Compatibility spelling used by pipeline selection plumbing."""
        return self.allows_functional_fallback

    @property
    def allows_functional_fallback(self) -> bool:
        return self is self.FUNCTIONAL_FALLBACK_ALLOWED

    @classmethod
    def from_allow_functional_fallbacks(
        cls, enabled: bool
    ) -> "PrivilegedPreservationPolicy":
        if not isinstance(enabled, bool):
            raise TypeError("allow-functional-fallbacks must be boolean")
        return (
            cls.FUNCTIONAL_FALLBACK_ALLOWED
            if enabled
            else cls.STRICT_ARCHITECTURAL
        )
