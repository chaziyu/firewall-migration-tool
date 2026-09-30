"""Compatibility import for target.target_evidence."""

from .target import target_evidence as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
