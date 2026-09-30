"""Compatibility import for target.target_intent."""

from .target import target_intent as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
