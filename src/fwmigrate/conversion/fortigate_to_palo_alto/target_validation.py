"""Compatibility import for target.target_validation."""

from .target import target_validation as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
