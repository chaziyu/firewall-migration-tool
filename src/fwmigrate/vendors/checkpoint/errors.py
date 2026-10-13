"""Check Point parser error definitions."""

from __future__ import annotations


class CheckPointError(ValueError):
    """Base exception for all Check Point extraction and parsing failures."""
    pass


class CheckPointParseError(CheckPointError):
    """Raised when Check Point JSON, export bundle, or syntax is malformed."""
    pass


class CheckPointResolutionError(CheckPointError):
    """Raised when a required Check Point object reference cannot be resolved safely."""
    pass
