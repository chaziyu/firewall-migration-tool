"""Compatibility import for target.target_object_reuse."""

from .target import target_object_reuse as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
