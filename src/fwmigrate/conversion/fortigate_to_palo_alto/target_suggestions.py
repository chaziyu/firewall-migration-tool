"""Compatibility import for target.target_suggestions."""

from .target import target_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
