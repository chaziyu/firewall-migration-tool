"""Compatibility import for target.target_candidates."""

from .target import target_candidates as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
