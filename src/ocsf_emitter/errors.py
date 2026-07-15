"""Typed errors raised by ocsf_emitter."""

from __future__ import annotations


class OcsfEmitterError(Exception):
    """Base class for all errors raised by this package."""


class InvalidFindingError(OcsfEmitterError):
    """A finding failed OCSF validation.

    Carries a list of human-readable field errors so callers (and logs) can see
    exactly which field(s) were wrong without re-running validation.
    """

    def __init__(self, message: str, *, field_errors: list[str] | None = None) -> None:
        """Initialize the error.

        Args:
            message: Human-readable summary of what failed.
            field_errors: Per-field error strings (``"field.path: reason"``) that
                are appended to the message and exposed as ``field_errors``.
        """
        self.field_errors: list[str] = field_errors or []
        if self.field_errors:
            detail = "\n  - " + "\n  - ".join(self.field_errors)
            super().__init__(f"{message}{detail}")
        else:
            super().__init__(message)
